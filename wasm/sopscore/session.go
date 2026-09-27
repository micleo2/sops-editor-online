package sopscore

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/getsops/sops/v3/shamir"
)

// MetadataKey is the top-level key SOPS stores its metadata under.
const MetadataKey = "sops"

// Format is the file format of a SOPS document.
type Format string

const (
	FormatYAML   Format = "yaml"
	FormatDotenv Format = "dotenv"
)

// sopsPrefix prefixes the flattened metadata keys in dotenv files.
const sopsPrefix = MetadataKey + "_"

var dotenvMetadataLine = regexp.MustCompile(`(?m)^sops_[a-z_]+=`)

// DetectFormat picks the format from the file name like the sops CLI does,
// falling back to looking for flattened dotenv metadata keys.
func DetectFormat(fileName string, content []byte) Format {
	name := strings.ToLower(fileName)
	switch {
	case strings.HasSuffix(name, ".env"):
		return FormatDotenv
	case strings.HasSuffix(name, ".yaml"), strings.HasSuffix(name, ".yml"):
		return FormatYAML
	}
	if dotenvMetadataLine.Match(content) {
		return FormatDotenv
	}
	return FormatYAML
}

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
	Format     Format
	Branches   TreeBranches
	Settings   Metadata
	Recipients []Recipient

	dataKey []byte
	cipher  Cipher
	// metadata is the unflattened metadata tree; rawMetadata holds it as it
	// is stored in the file (the nested `sops` mapping for YAML, the
	// flattened `sops_*` entries for dotenv) and is written back on save.
	metadata    TreeBranch
	rawMetadata TreeBranch
}

// Open parses an encrypted SOPS file, recovers the data key using the given
// age identities (the contents of an age keys.txt file) and decrypts the
// document. Unless ignoreMAC is set, the MAC is verified like SOPS does.
func Open(encrypted []byte, identities string, ignoreMAC bool, format Format) (*Session, error) {
	branches, err := LoadPlain(format, encrypted)
	if err != nil {
		return nil, err
	}
	branches, raw, metadata, err := extractMetadata(format, branches)
	if err != nil {
		return nil, err
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
		Format:      format,
		Branches:    tree.Branches,
		Settings:    settings,
		Recipients:  recipients,
		dataKey:     dataKey,
		cipher:      cipher,
		metadata:    metadata,
		rawMetadata: raw,
	}, nil
}

// extractMetadata mirrors stores.ExtractMetadata: it removes the metadata
// from the branches and returns it both as stored and unflattened.
func extractMetadata(format Format, branches TreeBranches) (TreeBranches, TreeBranch, TreeBranch, error) {
	notFound := errors.New("No SOPS metadata found. Is this a SOPS-encrypted file?")
	if len(branches) == 0 {
		return nil, nil, nil, notFound
	}
	if format == FormatDotenv {
		var raw, flat TreeBranch
		kept := TreeBranch{}
		for _, item := range branches[0] {
			if key, ok := item.Key.(string); ok && strings.HasPrefix(key, sopsPrefix) {
				raw = append(raw, item)
				flat = append(flat, TreeItem{Key: key[len(sopsPrefix):], Value: item.Value})
				continue
			}
			kept = append(kept, item)
		}
		if flat == nil {
			return nil, nil, nil, notFound
		}
		metadata, err := unflattenTreeBranch(flat)
		if err != nil {
			return nil, nil, nil, err
		}
		branches[0] = kept
		return branches, raw, metadata, nil
	}

	var metadata TreeBranch
	found := false
	for bi, branch := range branches {
		kept := make(TreeBranch, 0, len(branch))
		for _, item := range branch {
			if item.Key != MetadataKey {
				kept = append(kept, item)
				continue
			}
			if bi == 0 {
				if found {
					return nil, nil, nil, fmt.Errorf("Found duplicate %v entry", MetadataKey)
				}
				found = true
				tree, ok := item.Value.(TreeBranch)
				if !ok {
					return nil, nil, nil, fmt.Errorf("Found %v entry that is not a mapping", MetadataKey)
				}
				metadata = tree
			}
		}
		branches[bi] = kept
	}
	if metadata == nil {
		return nil, nil, nil, notFound
	}
	return branches, metadata, metadata, nil
}

// Encrypt encrypts the given plaintext branches with the session's data key
// and returns the resulting SOPS file. The recipients and other metadata are
// kept; lastmodified and the MAC are updated. The branches are modified in
// place.
func (s *Session) Encrypt(branches TreeBranches, now time.Time) ([]byte, error) {
	if err := checkReservedKeys(s.Format, branches); err != nil {
		return nil, err
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

	metadata := make(TreeBranch, len(s.rawMetadata))
	copy(metadata, s.rawMetadata)
	if s.Format == FormatDotenv {
		metadata = setField(metadata, sopsPrefix+"lastmodified", lastModified)
		metadata = setField(metadata, sopsPrefix+"mac", encryptedMac)
		out := TreeBranches{append(append(TreeBranch(nil), tree.Branches[0]...), metadata...)}
		return EmitPlain(s.Format, out)
	}
	metadata = setField(metadata, "lastmodified", lastModified)
	metadata = setField(metadata, "mac", encryptedMac)
	out := make(TreeBranches, len(tree.Branches))
	for i, branch := range tree.Branches {
		out[i] = append(append(TreeBranch(nil), branch...), TreeItem{Key: MetadataKey, Value: metadata})
	}
	return EmitPlain(s.Format, out)
}

func checkReservedKeys(format Format, branches TreeBranches) error {
	for _, branch := range branches {
		for _, item := range branch {
			key, ok := item.Key.(string)
			if !ok {
				continue
			}
			if format == FormatDotenv {
				if strings.HasPrefix(key, sopsPrefix) {
					return fmt.Errorf("Keys starting with %q are reserved for SOPS metadata: %s", sopsPrefix, key)
				}
			} else if key == MetadataKey {
				return errors.New("The top-level key \"sops\" is reserved for SOPS metadata.")
			}
		}
	}
	return nil
}

// LoadPlain parses a plaintext file into tree branches, like `sops edit`
// does with the edited file.
func LoadPlain(format Format, in []byte) (TreeBranches, error) {
	if format == FormatDotenv {
		return (&DotenvStore{}).LoadPlainFile(in)
	}
	branches, err := (&YAMLStore{}).LoadPlainFile(in)
	if err != nil {
		return nil, err
	}
	if len(branches) == 0 {
		branches = TreeBranches{TreeBranch{}}
	}
	return branches, nil
}

// EmitPlain renders tree branches as a plaintext file, like `sops decrypt`.
func EmitPlain(format Format, branches TreeBranches) ([]byte, error) {
	if format == FormatDotenv {
		if len(branches) != 1 {
			return nil, errors.New("A dotenv file has exactly one document.")
		}
		// The dotenv store writes keys verbatim; refuse keys it could not
		// read back.
		for _, item := range branches[0] {
			if key, ok := item.Key.(string); ok {
				if key == "" || strings.ContainsAny(key, "=\n") || strings.HasPrefix(key, "#") {
					return nil, fmt.Errorf("%q is not a valid dotenv key", key)
				}
			} else if c, ok := item.Key.(Comment); ok && strings.Contains(c.Value, "\n") {
				return nil, errors.New("Comments in dotenv files must be a single line.")
			}
		}
		return (&DotenvStore{}).EmitPlainFile(branches)
	}
	return (&YAMLStore{}).EmitPlainFile(branches)
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
		switch v := v.(type) {
		case bool:
			m.MACOnlyEncrypted = v
		case string:
			m.MACOnlyEncrypted, _ = strconv.ParseBool(v)
		}
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
			t, ok := v.(int)
			if str, isStr := v.(string); isStr {
				t, _ = strconv.Atoi(str)
				ok = true
			}
			if ok && t > 0 {
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
