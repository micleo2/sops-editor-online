// This file is derived from github.com/getsops/sops/v3 (sops.go, v3.9.4),
// licensed under the Mozilla Public License 2.0. The tree walking,
// encryption rules and MAC computation are copied with only logging/audit
// calls removed, so that the editor behaves exactly like SOPS does.

package sopscore

import (
	"crypto/sha512"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// DefaultUnencryptedSuffix is the default suffix a TreeItem key has to end with for SOPS to leave its Value unencrypted
const DefaultUnencryptedSuffix = "_unencrypted"

// MACOnlyEncryptedInitialization is a constant and known sequence of 32 bytes used to initialize
// MAC which is computed only over values which end up encrypted. That assures that a MAC with the
// setting enabled is always different from a MAC with this setting disabled.
var MACOnlyEncryptedInitialization = []byte{0x8a, 0x3f, 0xd2, 0xad, 0x54, 0xce, 0x66, 0x52, 0x7b, 0x10, 0x34, 0xf3, 0xd1, 0x47, 0xbe, 0xb, 0xb, 0x97, 0x5b, 0x3b, 0xf4, 0x4f, 0x72, 0xc6, 0xfd, 0xad, 0xec, 0x81, 0x76, 0xf2, 0x7d, 0x69}

// ValueCipher provides a way to encrypt and decrypt the values of the tree.
type ValueCipher interface {
	Encrypt(plaintext interface{}, key []byte, additionalData string) (ciphertext string, err error)
	Decrypt(ciphertext string, key []byte, additionalData string) (plaintext interface{}, err error)
}

// Comment represents a comment in the sops tree for the file formats that actually support them.
type Comment struct {
	Value string
}

// TreeItem is an item inside sops's tree
type TreeItem struct {
	Key   interface{}
	Value interface{}
}

// TreeBranch is a branch inside sops's tree. It is a slice of TreeItems and is therefore ordered
type TreeBranch []TreeItem

// TreeBranches is a collection of TreeBranch
// Trees usually have more than one branch
type TreeBranches []TreeBranch

// Metadata holds the subset of SOPS metadata that affects how values are
// encrypted and how the MAC is computed.
type Metadata struct {
	UnencryptedSuffix       string
	EncryptedSuffix         string
	UnencryptedRegex        string
	EncryptedRegex          string
	UnencryptedCommentRegex string
	EncryptedCommentRegex   string
	MACOnlyEncrypted        bool
}

// Tree is the data structure used by sops to represent documents internally
type Tree struct {
	Metadata Metadata
	Branches TreeBranches
}

func (branch TreeBranch) walkValue(in interface{}, path []string, commentsStack [][]string, onLeaves func(in interface{}, path []string, commentsStack [][]string) (interface{}, error)) (interface{}, error) {
	switch in := in.(type) {
	case string:
		return onLeaves(in, path, commentsStack)
	case []byte:
		return onLeaves(string(in), path, commentsStack)
	case int:
		return onLeaves(in, path, commentsStack)
	case bool:
		return onLeaves(in, path, commentsStack)
	case float64:
		return onLeaves(in, path, commentsStack)
	case Comment:
		return onLeaves(in, path, commentsStack)
	case TreeBranch:
		return branch.walkBranch(in, path, commentsStack, onLeaves)
	case []interface{}:
		return branch.walkSlice(in, path, commentsStack, onLeaves)
	case nil:
		// the value returned remains the same since it doesn't make
		// sense to encrypt or decrypt a nil value
		return nil, nil
	default:
		return nil, fmt.Errorf("Cannot walk value, unknown type: %T", in)
	}
}

func (branch TreeBranch) walkSlice(in []interface{}, path []string, commentsStack [][]string, onLeaves func(in interface{}, path []string, commentsStack [][]string) (interface{}, error)) ([]interface{}, error) {
	// Because append returns a new slice, the original stack is not changed.
	commentsStack = append(commentsStack, []string{})
	for i, v := range in {
		c, vIsComment := v.(Comment)
		if vIsComment {
			// If v is a comment, we add it to the slice of active comments.
			// This allows us to also encrypt comments themselves by enabling encryption in a prior comment.
			commentsStack[len(commentsStack)-1] = append(commentsStack[len(commentsStack)-1], c.Value)
		}
		newV, err := branch.walkValue(v, path, commentsStack, onLeaves)
		if err != nil {
			return nil, err
		}
		in[i] = newV
		if !vIsComment {
			// If v is not a comment, we clear the slice of active comments.
			commentsStack[len(commentsStack)-1] = []string{}
		}
	}
	return in, nil
}

func (branch TreeBranch) walkBranch(in TreeBranch, path []string, commentsStack [][]string, onLeaves func(in interface{}, path []string, commentsStack [][]string) (interface{}, error)) (TreeBranch, error) {
	// Because append returns a new slice, the original stack is not changed.
	commentsStack = append(commentsStack, []string{})
	for i, item := range in {
		if c, ok := item.Key.(Comment); ok {
			// If key is a comment, we add it to the slice of active comments.
			// This allows us to also encrypt comments themselves by enabling encryption in a prior comment.
			commentsStack[len(commentsStack)-1] = append(commentsStack[len(commentsStack)-1], c.Value)
			enc, err := branch.walkValue(item.Key, path, commentsStack, onLeaves)
			if err != nil {
				return nil, err
			}
			if encComment, ok := enc.(Comment); ok {
				in[i].Key = encComment
				continue
			} else if comment, ok := enc.(string); ok {
				in[i].Key = Comment{Value: comment}
				continue
			} else {
				return nil, fmt.Errorf("walkValue of Comment should be either Comment or string, was %T", enc)
			}
		}
		c, valueIsComment := item.Value.(Comment)
		if valueIsComment {
			// If value is a comment, we add it to the slice of active comments.
			// This allows us to also encrypt comments themselves by enabling encryption in a prior comment.
			commentsStack[len(commentsStack)-1] = append(commentsStack[len(commentsStack)-1], c.Value)
		}
		key, ok := item.Key.(string)
		if !ok {
			return nil, fmt.Errorf("Tree contains a non-string key (type %T): %s. Only string keys are"+
				"supported", item.Key, item.Key)
		}
		newV, err := branch.walkValue(item.Value, append(path, key), commentsStack, onLeaves)
		if err != nil {
			return nil, err
		}
		in[i].Value = newV
		if !valueIsComment {
			// If value is not a comment, we clear the slice of active comments.
			commentsStack[len(commentsStack)-1] = []string{}
		}
	}
	return in, nil
}

func (tree Tree) shouldBeEncrypted(path []string, commentsStack [][]string, isComment bool) bool {
	encrypted := true
	if tree.Metadata.UnencryptedSuffix != "" {
		for _, v := range path {
			if strings.HasSuffix(v, tree.Metadata.UnencryptedSuffix) {
				encrypted = false
				break
			}
		}
	}
	if tree.Metadata.EncryptedSuffix != "" {
		encrypted = false
		for _, v := range path {
			if strings.HasSuffix(v, tree.Metadata.EncryptedSuffix) {
				encrypted = true
				break
			}
		}
	}
	if tree.Metadata.UnencryptedRegex != "" {
		for _, p := range path {
			matched, _ := regexp.Match(tree.Metadata.UnencryptedRegex, []byte(p))
			if matched {
				encrypted = false
				break
			}
		}
	}
	if tree.Metadata.EncryptedRegex != "" {
		encrypted = false
		for _, p := range path {
			matched, _ := regexp.Match(tree.Metadata.EncryptedRegex, []byte(p))
			if matched {
				encrypted = true
				break
			}
		}
	}
	if tree.Metadata.UnencryptedCommentRegex != "" {
	unencryptedComments:
		for _, cs := range commentsStack {
			for _, c := range cs {
				matched, _ := regexp.Match(tree.Metadata.UnencryptedCommentRegex, []byte(c))
				if matched {
					encrypted = false
					break unencryptedComments
				}
			}
		}
	}
	if tree.Metadata.EncryptedCommentRegex != "" {
		lenCommentsStack := len(commentsStack)
		lenLastCommentsStack := len(commentsStack[lenCommentsStack-1])
		encrypted = false
	encryptedComments:
		for i, cs := range commentsStack {
			for j, c := range cs {
				// A special case. We do not encrypt the comment line itself which matches the regex.
				// So we skip the last line of the last set of comments. Only if the matches any previous
				// line, we encrypt this comment. Otherwise we do not.
				if isComment && i == lenCommentsStack-1 && j == lenLastCommentsStack-1 {
					continue
				}
				matched, _ := regexp.Match(tree.Metadata.EncryptedCommentRegex, []byte(c))
				if matched {
					encrypted = true
					break encryptedComments
				}
			}
		}
	}
	return encrypted
}

// Encrypt walks over the tree and encrypts all values with the provided cipher,
// except those whose key ends with the UnencryptedSuffix specified on the
// Metadata struct, those not ending with EncryptedSuffix, if EncryptedSuffix
// is provided (by default it is not), those not matching EncryptedRegex,
// if EncryptedRegex is provided (by default it is not), those matching UnencryptedRegex,
// if UnencryptedRegex is provided (by default it is not), those with their comment
// not matching EncryptedCommentRegex, if EncryptedCommentRegex is provided (by default
// it is not), or those with their comment matching UnencryptedCommentRegex, if
// UnencryptedCommentRegex is provided (by default it is not).
// If encryption is successful, it returns the MAC for the encrypted tree
// (all values if MACOnlyEncrypted is false, or only over values which end
// up encrypted if MACOnlyEncrypted is true).

func (tree Tree) Encrypt(key []byte, cipher ValueCipher) (string, error) {
	hash := sha512.New()
	if tree.Metadata.MACOnlyEncrypted {
		// We initialize with known set of bytes so that a MAC with this setting
		// enabled is always different from a MAC with this setting disabled.
		hash.Write(MACOnlyEncryptedInitialization)
	}
	walk := func(branch TreeBranch) error {
		_, err := branch.walkBranch(branch, make([]string, 0), make([][]string, 0), func(in interface{}, path []string, commentsStack [][]string) (interface{}, error) {
			_, ok := in.(Comment)
			encrypted := tree.shouldBeEncrypted(path, commentsStack, ok)
			if !tree.Metadata.MACOnlyEncrypted || encrypted {
				// Only add to MAC if not a comment
				if !ok {
					bytes, err := ToBytes(in)
					if err != nil {
						return nil, fmt.Errorf("Could not convert %s to bytes: %s", in, err)
					}
					hash.Write(bytes)
				}
			}
			if encrypted {
				var err error
				pathString := strings.Join(path, ":") + ":"
				in, err = cipher.Encrypt(in, key, pathString)
				if err != nil {
					return nil, fmt.Errorf("Could not encrypt value: %s", err)
				}
				if ok && tree.Metadata.UnencryptedCommentRegex != "" {
					// If an encrypted comment matches tree.Metadata.UnencryptedCommentRegex, decryption will fail
					// as the MAC does not match, and the commented value will not be decrypted.
					matched, _ := regexp.Match(tree.Metadata.UnencryptedCommentRegex, []byte(in.(string)))
					if matched {
						return nil, fmt.Errorf("Encrypted comment %q matches UnencryptedCommentRegex! Make sure that UnencryptedCommentRegex cannot match an encrypted comment.", in)
					}
				}
			}
			return in, nil
		})
		return err
	}

	for _, branch := range tree.Branches {
		err := walk(branch)
		if err != nil {
			return "", fmt.Errorf("Error walking tree: %s", err)
		}
	}
	return fmt.Sprintf("%X", hash.Sum(nil)), nil
}

// Decrypt walks over the tree and decrypts all values with the provided cipher,
// except those whose key ends with the UnencryptedSuffix specified on the Metadata struct,
// those not ending with EncryptedSuffix, if EncryptedSuffix is provided (by default it is not),
// those not matching EncryptedRegex, if EncryptedRegex is provided (by default it is not),
// or those matching UnencryptedRegex, if UnencryptedRegex is provided (by default it is not).
// If decryption is successful, it returns the MAC for the decrypted tree
// (all values if MACOnlyEncrypted is false, or only over values which end
// up decrypted if MACOnlyEncrypted is true).
func (tree Tree) Decrypt(key []byte, cipher ValueCipher) (string, error) {
	hash := sha512.New()
	if tree.Metadata.MACOnlyEncrypted {
		// We initialize with known set of bytes so that a MAC with this setting
		// enabled is always different from a MAC with this setting disabled.
		hash.Write(MACOnlyEncryptedInitialization)
	}
	walk := func(branch TreeBranch) error {
		_, err := branch.walkBranch(branch, make([]string, 0), make([][]string, 0), func(in interface{}, path []string, commentsStack [][]string) (interface{}, error) {
			c, ok := in.(Comment)
			encrypted := tree.shouldBeEncrypted(path, commentsStack, ok)
			var v interface{}
			if encrypted {
				var err error
				pathString := strings.Join(path, ":") + ":"
				if ok {
					v, err = cipher.Decrypt(c.Value, key, pathString)
					if err != nil {
						// Assume the comment was not encrypted in the first place
						// (SOPS logs a warning here and keeps the comment as-is.)
						v = c
					}
				} else {
					v, err = cipher.Decrypt(in.(string), key, pathString)
					if err != nil {
						return nil, fmt.Errorf("Could not decrypt value: %s", err)
					}
				}
			} else {
				v = in
			}
			if !tree.Metadata.MACOnlyEncrypted || encrypted {
				// Only add to MAC if not a comment
				if _, ok := v.(Comment); !ok {
					bytes, err := ToBytes(v)
					if err != nil {
						return nil, fmt.Errorf("Could not convert %s to bytes: %s", in, err)
					}
					hash.Write(bytes)
				}
			}
			return v, nil
		})
		return err
	}
	for _, branch := range tree.Branches {
		err := walk(branch)
		if err != nil {
			return "", fmt.Errorf("Error walking tree: %s", err)
		}
	}
	return fmt.Sprintf("%X", hash.Sum(nil)), nil
}

// ToBytes converts a string, int, float or bool to a byte representation.
func ToBytes(in interface{}) ([]byte, error) {
	switch in := in.(type) {
	case string:
		return []byte(in), nil
	case int:
		return []byte(strconv.Itoa(in)), nil
	case float64:
		return []byte(strconv.FormatFloat(in, 'f', -1, 64)), nil
	case bool:
		boolB := []byte("True")
		if !in {
			boolB = []byte("False")
		}
		return boolB, nil
	case []byte:
		return in, nil
	case Comment:
		return ToBytes(in.Value)
	default:
		return nil, fmt.Errorf("Could not convert unknown type %T to bytes", in)
	}
}
