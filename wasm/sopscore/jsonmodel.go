package sopscore

import (
	"fmt"
	"strconv"
	"strings"
)

// Node is the JSON representation of a tree value used by the web UI.
//
// T is one of "map", "seq", "str", "int", "float", "bool" or "null". Scalar
// values are always carried as strings in V so that no precision is lost.
// Enc reports whether SOPS encrypts the value (only set on scalars).
type Node struct {
	T     string `json:"t"`
	V     string `json:"v"`
	Items []Item `json:"items,omitempty"`
	Enc   *bool  `json:"enc,omitempty"`
}

// Item is an entry of a map or sequence: a comment line, a key/value pair
// (maps) or a value (sequences).
type Item struct {
	C   *string `json:"c,omitempty"`
	K   *string `json:"k,omitempty"`
	V   *Node   `json:"v,omitempty"`
	Enc *bool   `json:"enc,omitempty"`
}

// ToJSONModel converts tree branches to the UI model, annotating every leaf
// with whether it will be encrypted under the given settings.
func ToJSONModel(branches TreeBranches, settings Metadata) ([]Node, error) {
	docs := make([]Node, 0, len(branches))
	for _, branch := range branches {
		flags, err := encryptionFlags(branch, settings)
		if err != nil {
			return nil, err
		}
		c := converter{flags: flags}
		n, err := c.branch(branch)
		if err != nil {
			return nil, err
		}
		docs = append(docs, *n)
	}
	return docs, nil
}

// FromJSONModel converts the UI model back to tree branches.
func FromJSONModel(docs []Node) (TreeBranches, error) {
	return fromJSONModel(docs, false)
}

// AnnotateJSONModel recomputes the encryption flags of a UI model. Invalid
// scalar values, empty or duplicate keys are tolerated since the flags only
// depend on the structure, keys and comments.
func AnnotateJSONModel(docs []Node, settings Metadata) ([]Node, error) {
	branches, err := fromJSONModel(docs, true)
	if err != nil {
		return nil, err
	}
	return ToJSONModel(branches, settings)
}

func fromJSONModel(docs []Node, lenient bool) (TreeBranches, error) {
	branches := make(TreeBranches, 0, len(docs))
	for i, doc := range docs {
		if doc.T != "map" {
			return nil, fmt.Errorf("document %d must be a map", i+1)
		}
		v, err := fromNode(&doc, nil, lenient)
		if err != nil {
			return nil, err
		}
		branches = append(branches, v.(TreeBranch))
	}
	if len(branches) == 0 {
		branches = TreeBranches{TreeBranch{}}
	}
	return branches, nil
}

// encryptionFlags walks the branch exactly like Tree.Encrypt does and records,
// in walk order, whether each leaf would be encrypted.
func encryptionFlags(branch TreeBranch, settings Metadata) ([]bool, error) {
	tree := Tree{Metadata: settings}
	var flags []bool
	copied := copyBranch(branch)
	_, err := copied.walkBranch(copied, make([]string, 0), make([][]string, 0), func(in interface{}, path []string, commentsStack [][]string) (interface{}, error) {
		_, isComment := in.(Comment)
		flags = append(flags, tree.shouldBeEncrypted(path, commentsStack, isComment))
		return in, nil
	})
	return flags, err
}

func copyBranch(in TreeBranch) TreeBranch {
	out := make(TreeBranch, len(in))
	for i, item := range in {
		out[i] = TreeItem{Key: item.Key, Value: copyValue(item.Value)}
	}
	return out
}

func copyValue(in interface{}) interface{} {
	switch v := in.(type) {
	case TreeBranch:
		return copyBranch(v)
	case []interface{}:
		out := make([]interface{}, len(v))
		for i, x := range v {
			out[i] = copyValue(x)
		}
		return out
	default:
		return v
	}
}

// converter walks values in the same order as TreeBranch.walkBranch so that
// the recorded encryption flags line up with the leaves.
type converter struct {
	flags []bool
	next  int
}

func (c *converter) flag() *bool {
	if c.next >= len(c.flags) {
		return nil
	}
	f := c.flags[c.next]
	c.next++
	return &f
}

func (c *converter) branch(in TreeBranch) (*Node, error) {
	n := &Node{T: "map", Items: []Item{}}
	for _, item := range in {
		if comment, ok := item.Key.(Comment); ok {
			text := comment.Value
			n.Items = append(n.Items, Item{C: &text, Enc: c.flag()})
			continue
		}
		key, ok := item.Key.(string)
		if !ok {
			return nil, fmt.Errorf("Tree contains a non-string key (type %T): %v. Only string keys are supported", item.Key, item.Key)
		}
		v, err := c.value(item.Value)
		if err != nil {
			return nil, fmt.Errorf("%s: %s", key, err)
		}
		n.Items = append(n.Items, Item{K: &key, V: v})
	}
	return n, nil
}

func (c *converter) value(in interface{}) (*Node, error) {
	switch v := in.(type) {
	case string:
		return &Node{T: "str", V: v, Enc: c.flag()}, nil
	case []byte:
		return &Node{T: "str", V: string(v), Enc: c.flag()}, nil
	case int:
		return &Node{T: "int", V: strconv.Itoa(v), Enc: c.flag()}, nil
	case float64:
		return &Node{T: "float", V: strconv.FormatFloat(v, 'f', -1, 64), Enc: c.flag()}, nil
	case bool:
		return &Node{T: "bool", V: strconv.FormatBool(v), Enc: c.flag()}, nil
	case nil:
		// nil values are not walked by SOPS, so they consume no flag.
		return &Node{T: "null"}, nil
	case TreeBranch:
		return c.branch(v)
	case []interface{}:
		n := &Node{T: "seq", Items: []Item{}}
		for _, x := range v {
			if comment, ok := x.(Comment); ok {
				text := comment.Value
				n.Items = append(n.Items, Item{C: &text, Enc: c.flag()})
				continue
			}
			child, err := c.value(x)
			if err != nil {
				return nil, err
			}
			n.Items = append(n.Items, Item{V: child})
		}
		return n, nil
	default:
		return nil, fmt.Errorf("unsupported value type %T (quote timestamps and other special values)", in)
	}
}

func fromNode(n *Node, path []string, lenient bool) (interface{}, error) {
	where := strings.Join(path, ".")
	if where == "" {
		where = "(top level)"
	}
	switch n.T {
	case "str":
		return n.V, nil
	case "int", "float", "bool":
		v, err := parseScalar(n, where)
		if err != nil && lenient {
			return n.V, nil
		}
		return v, err
	default:
		return fromNodeCollections(n, path, lenient, where)
	}
}

func parseScalar(n *Node, where string) (interface{}, error) {
	switch n.T {
	case "int":
		i, err := strconv.Atoi(strings.TrimSpace(n.V))
		if err != nil {
			return nil, fmt.Errorf("%s: %q is not a valid integer", where, n.V)
		}
		return i, nil
	case "float":
		f, err := strconv.ParseFloat(strings.TrimSpace(n.V), 64)
		if err != nil {
			return nil, fmt.Errorf("%s: %q is not a valid number", where, n.V)
		}
		return f, nil
	case "bool":
		b, err := strconv.ParseBool(strings.TrimSpace(n.V))
		if err != nil {
			return nil, fmt.Errorf("%s: %q is not true or false", where, n.V)
		}
		return b, nil
	}
	return nil, fmt.Errorf("%s: unknown type %q", where, n.T)
}

func fromNodeCollections(n *Node, path []string, lenient bool, where string) (interface{}, error) {
	switch n.T {
	case "null":
		return nil, nil
	case "map":
		branch := make(TreeBranch, 0, len(n.Items))
		seen := map[string]bool{}
		for _, item := range n.Items {
			if item.C != nil {
				branch = append(branch, TreeItem{Key: Comment{Value: *item.C}, Value: nil})
				continue
			}
			if item.K == nil || item.V == nil {
				return nil, fmt.Errorf("%s: incomplete entry", where)
			}
			key := *item.K
			if key == "" && !lenient {
				return nil, fmt.Errorf("%s: a key is empty", where)
			}
			if seen[key] && !lenient {
				return nil, fmt.Errorf("%s: duplicate key %q", where, key)
			}
			seen[key] = true
			v, err := fromNode(item.V, append(append([]string{}, path...), key), lenient)
			if err != nil {
				return nil, err
			}
			branch = append(branch, TreeItem{Key: key, Value: v})
		}
		return branch, nil
	case "seq":
		list := make([]interface{}, 0, len(n.Items))
		for i, item := range n.Items {
			if item.C != nil {
				list = append(list, Comment{Value: *item.C})
				continue
			}
			if item.V == nil {
				return nil, fmt.Errorf("%s: incomplete list item", where)
			}
			v, err := fromNode(item.V, append(append([]string{}, path...), fmt.Sprintf("[%d]", i)), lenient)
			if err != nil {
				return nil, err
			}
			list = append(list, v)
		}
		return list, nil
	default:
		return nil, fmt.Errorf("%s: unknown type %q", where, n.T)
	}
}
