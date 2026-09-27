package sopscore

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/getsops/sops/v3/shamir"
	"gopkg.in/yaml.v3"
)

// MetadataKey is the top-level key SOPS stores its metadata under.
const MetadataKey = "sops"

// yamlIndent matches the default indentation of the SOPS YAML store.
const yamlIndent = 4

// Recipient describes one age recipient listed in the file's metadata.
type Recipient struct {
	PublicKey string `json:"publicKey"`
	Group     int    `json:"group"`
	// Mine is true when one of the provided identities corresponds to this recipient.
	Mine bool `json:"mine"`
}

// Session is a decrypted SOPS document together with everything needed to
// encrypt an edited version of it again (the same way `sops edit` does).
type Session struct {
	Branches   TreeBranches
	Settings   Metadata
	Recipients []Recipient

	dataKey  []byte
	cipher   Cipher
	metadata TreeBranch
}

// Open parses an encrypted SOPS YAML file, recovers the data key using the
// given age identities (the contents of an age keys.txt file) and decrypts
// the document. Unless ignoreMAC is set, the MAC is verified like SOPS does.
func Open(encrypted []byte, identities string, ignoreMAC bool) (*Session, error) {
	store := Store{}
	var branches TreeBranches
	d := yaml.NewDecoder(bytes.NewReader(encrypted))
	for {
		var data yaml.Node
		err := d.Decode(&data)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("Error unmarshaling input YAML: %s", err)
		}
		branch, err := store.yamlDocumentNodeToTreeBranch(data)
		if err != nil {
			return nil, fmt.Errorf("Error unmarshaling input YAML: %s", err)
		}
		branches = append(branches, branch)
	}
	if len(branches) == 0 {
		return nil, errors.New("The file is empty.")
	}

	// Like SOPS, read the metadata from the first document and strip the
	// metadata key from every document.
	var metadata TreeBranch
	for i, branch := range branches {
		kept := make(TreeBranch, 0, len(branch))
		for _, item := range branch {
			if item.Key == MetadataKey {
				if i == 0 {
					if m, ok := item.Value.(TreeBranch); ok {
						metadata = m
					}
				}
				continue
			}
			kept = append(kept, item)
		}
		branches[i] = kept
	}
	if metadata == nil {
		return nil, errors.New("No SOPS metadata found. Is this a SOPS-encrypted YAML file?")
	}

	settings, err := settingsFromMetadata(metadata)
	if err != nil {
		return nil, err
	}

	ids, err := age.ParseIdentities(strings.NewReader(identities))
	if err != nil {
		return nil, fmt.Errorf("Could not read the age keys: %s", err)
	}

	groups, recipients := ageKeyGroups(metadata)
	markMine(recipients, ids)
	dataKey, err := recoverDataKey(metadata, groups, ids)
	if err != nil {
		return nil, err
	}

	cipher := NewCipher()
	tree := Tree{Metadata: settings, Branches: branches}
	computedMac, err := tree.Decrypt(dataKey, cipher)
	if err != nil {
		return nil, fmt.Errorf("Error decrypting tree: %s", err)
	}
	lastModified, err := lastModifiedFromMetadata(metadata)
	if err != nil && !ignoreMAC {
		return nil, err
	}
	fileMac, err := cipher.Decrypt(stringField(metadata, "mac"), dataKey, lastModified.Format(time.RFC3339))
	if err != nil && !ignoreMAC {
		return nil, fmt.Errorf("Cannot decrypt MAC: %s", err)
	}
	if !ignoreMAC && fileMac != computedMac {
		if fileMac == "" {
			fileMac = "no MAC"
		}
		return nil, fmt.Errorf("Failed to verify data integrity. expected mac %q, got %q", fileMac, computedMac)
	}

	return &Session{
		Branches:   tree.Branches,
		Settings:   settings,
		Recipients: recipients,
		dataKey:    dataKey,
		cipher:     cipher,
		metadata:   metadata,
	}, nil
}

// Encrypt encrypts the given plaintext branches with the session's data key
// and returns the resulting SOPS YAML file. The recipients and other metadata
// are kept; lastmodified and the MAC are updated. The branches are modified
// in place.
func (s *Session) Encrypt(branches TreeBranches, now time.Time) ([]byte, error) {
	for _, branch := range branches {
		for _, item := range branch {
			if item.Key == MetadataKey {
				return nil, errors.New("The top-level key \"sops\" is reserved for SOPS metadata.")
			}
		}
	}
	tree := Tree{Metadata: s.Settings, Branches: branches}
	mac, err := tree.Encrypt(s.dataKey, s.cipher)
	if err != nil {
		return nil, err
	}
	lastModified := now.UTC().Format(time.RFC3339)
	encryptedMac, err := s.cipher.Encrypt(mac, s.dataKey, lastModified)
	if err != nil {
		return nil, fmt.Errorf("Could not encrypt MAC: %s", err)
	}
	metadata := make(TreeBranch, len(s.metadata))
	copy(metadata, s.metadata)
	metadata = setField(metadata, "lastmodified", lastModified)
	metadata = setField(metadata, "mac", encryptedMac)

	store := Store{}
	var b bytes.Buffer
	e := yaml.NewEncoder(&b)
	e.SetIndent(yamlIndent)
	for _, branch := range tree.Branches {
		var doc = yaml.Node{Kind: yaml.DocumentNode}
		var mapping = yaml.Node{Kind: yaml.MappingNode}
		doc.Content = append(doc.Content, &mapping)
		branch = append(TreeBranch(nil), branch...)
		branch = append(branch, TreeItem{Key: MetadataKey, Value: metadata})
		store.appendTreeBranch(branch, &mapping)
		if err := e.Encode(&doc); err != nil {
			return nil, fmt.Errorf("Error marshaling to yaml: %s", err)
		}
	}
	e.Close()
	return b.Bytes(), nil
}

// LoadPlain parses plaintext YAML into tree branches, like `sops edit` does
// with the edited file.
func LoadPlain(in []byte) (TreeBranches, error) {
	store := Store{}
	var branches TreeBranches
	d := yaml.NewDecoder(bytes.NewReader(in))
	for {
		var data yaml.Node
		err := d.Decode(&data)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("Error unmarshaling input YAML: %s", err)
		}
		branch, err := store.yamlDocumentNodeToTreeBranch(data)
		if err != nil {
			return nil, fmt.Errorf("Error unmarshaling input YAML: %s", err)
		}
		branches = append(branches, branch)
	}
	if len(branches) == 0 {
		branches = TreeBranches{TreeBranch{}}
	}
	return branches, nil
}

// EmitPlain renders tree branches as plaintext YAML, like `sops decrypt`.
func EmitPlain(branches TreeBranches) ([]byte, error) {
	store := Store{}
	var b bytes.Buffer
	e := yaml.NewEncoder(&b)
	e.SetIndent(yamlIndent)
	for _, branch := range branches {
		var doc = yaml.Node{Kind: yaml.DocumentNode}
		var mapping = yaml.Node{Kind: yaml.MappingNode}
		store.appendTreeBranch(branch, &mapping)
		doc.Content = append(doc.Content, &mapping)
		if err := e.Encode(&doc); err != nil {
			return nil, fmt.Errorf("Error marshaling to yaml: %s", err)
		}
	}
	e.Close()
	return b.Bytes(), nil
}

func field(metadata TreeBranch, key string) (interface{}, bool) {
	for _, item := range metadata {
		if item.Key == key {
			return item.Value, true
		}
	}
	return nil, false
}

func stringField(metadata TreeBranch, key string) string {
	v, _ := field(metadata, key)
	switch v := v.(type) {
	case string:
		return v
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

func setField(metadata TreeBranch, key string, value interface{}) TreeBranch {
	for i, item := range metadata {
		if item.Key == key {
			metadata[i].Value = value
			return metadata
		}
	}
	return append(metadata, TreeItem{Key: key, Value: value})
}

func lastModifiedFromMetadata(metadata TreeBranch) (time.Time, error) {
	v, _ := field(metadata, "lastmodified")
	switch v := v.(type) {
	case time.Time:
		return v, nil
	case string:
		return time.Parse(time.RFC3339, v)
	default:
		return time.Time{}, errors.New("The SOPS metadata has no valid lastmodified timestamp.")
	}
}

// settingsFromMetadata mirrors stores.Metadata.ToInternal for the fields
// that influence encryption.
func settingsFromMetadata(metadata TreeBranch) (Metadata, error) {
	m := Metadata{
		UnencryptedSuffix:       stringField(metadata, "unencrypted_suffix"),
		EncryptedSuffix:         stringField(metadata, "encrypted_suffix"),
		UnencryptedRegex:        stringField(metadata, "unencrypted_regex"),
		EncryptedRegex:          stringField(metadata, "encrypted_regex"),
		UnencryptedCommentRegex: stringField(metadata, "unencrypted_comment_regex"),
		EncryptedCommentRegex:   stringField(metadata, "encrypted_comment_regex"),
	}
	if v, ok := field(metadata, "mac_only_encrypted"); ok {
		b, _ := v.(bool)
		m.MACOnlyEncrypted = b
	}
	cryptRuleCount := 0
	for _, rule := range []string{m.UnencryptedSuffix, m.EncryptedSuffix, m.UnencryptedRegex, m.EncryptedRegex, m.UnencryptedCommentRegex, m.EncryptedCommentRegex} {
		if rule != "" {
			cryptRuleCount++
		}
	}
	if cryptRuleCount > 1 {
		return Metadata{}, fmt.Errorf("Cannot use more than one of encrypted_suffix, unencrypted_suffix, encrypted_regex, unencrypted_regex, encrypted_comment_regex, or unencrypted_comment_regex in the same file")
	}
	if cryptRuleCount == 0 {
		m.UnencryptedSuffix = DefaultUnencryptedSuffix
	}
	return m, nil
}

// ageKeyGroups returns, for every key group, the armored age-encrypted data
// keys. Without key_groups, the top-level keys form a single group, like in
// stores.Metadata.internalKeygroups.
func ageKeyGroups(metadata TreeBranch) ([][]string, []Recipient) {
	var groups [][]string
	var recipients []Recipient
	collect := func(group TreeBranch, index int) []string {
		var encs []string
		list, _ := field(group, "age")
		items, _ := list.([]interface{})
		for _, item := range items {
			entry, ok := item.(TreeBranch)
			if !ok {
				continue
			}
			encs = append(encs, stringField(entry, "enc"))
			recipients = append(recipients, Recipient{PublicKey: stringField(entry, "recipient"), Group: index})
		}
		return encs
	}
	if kg, ok := field(metadata, "key_groups"); ok {
		if list, ok := kg.([]interface{}); ok && len(list) > 0 {
			for i, g := range list {
				group, _ := g.(TreeBranch)
				groups = append(groups, collect(group, i))
			}
			return groups, recipients
		}
	}
	return [][]string{collect(metadata, 0)}, recipients
}

func markMine(recipients []Recipient, ids []age.Identity) {
	mine := map[string]bool{}
	for _, id := range ids {
		if x, ok := id.(*age.X25519Identity); ok {
			mine[x.Recipient().String()] = true
		}
	}
	for i := range recipients {
		recipients[i].Mine = mine[recipients[i].PublicKey]
	}
}

// recoverDataKey mirrors Metadata.GetDataKeyWithKeyServices, restricted to
// age master keys.
func recoverDataKey(metadata TreeBranch, groups [][]string, ids []age.Identity) ([]byte, error) {
	var parts [][]byte
	var lastErr error
	for _, group := range groups {
		for _, enc := range group {
			r, err := age.Decrypt(armor.NewReader(strings.NewReader(enc)), ids...)
			if err != nil {
				lastErr = err
				continue
			}
			var b bytes.Buffer
			if _, err := io.Copy(&b, r); err != nil {
				lastErr = err
				continue
			}
			parts = append(parts, b.Bytes())
			break
		}
	}
	total := 0
	for _, g := range groups {
		total += len(g)
	}
	if total == 0 {
		return nil, errors.New("This file has no age recipients, so it can't be decrypted with an age key.")
	}
	if len(groups) > 1 {
		threshold := len(groups)
		if v, ok := field(metadata, "shamir_threshold"); ok {
			if t, ok := v.(int); ok && t > 0 {
				threshold = t
			}
		}
		if len(parts) < threshold {
			return nil, fmt.Errorf("Could not recover the data key: the file needs keys from %d key groups but the given age keys only unlock %d.", threshold, len(parts))
		}
		dataKey, err := shamir.Combine(parts)
		if err != nil {
			return nil, fmt.Errorf("could not get data key from shamir parts: %s", err)
		}
		return dataKey, nil
	}
	if len(parts) != 1 {
		msg := "None of the given age keys can decrypt this file."
		if lastErr != nil && !errors.As(lastErr, new(*age.NoIdentityMatchError)) {
			msg += " (" + lastErr.Error() + ")"
		}
		return nil, errors.New(msg)
	}
	return parts[0], nil
}
