// This file is derived from github.com/getsops/sops/v3 (stores/yaml/store.go, v3.9.4),
// licensed under the Mozilla Public License 2.0. The conversion between YAML
// nodes and the SOPS tree (including comment handling) is copied unchanged;
// metadata handling lives in session.go instead of the stores package.

package sopscore

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

const IndentDefault = 4

// Store handles storage of YAML data
type Store struct{}

func (store Store) appendCommentToList(comment string, list []interface{}) []interface{} {
	if comment != "" {
		for _, commentLine := range strings.Split(comment, "\n") {
			if commentLine != "" {
				list = append(list, Comment{
					Value: commentLine[1:],
				})
			}
		}
	}
	return list
}

func (store Store) appendCommentToMap(comment string, branch TreeBranch) TreeBranch {
	if comment != "" {
		for _, commentLine := range strings.Split(comment, "\n") {
			if commentLine != "" {
				branch = append(branch, TreeItem{
					Key: Comment{
						Value: commentLine[1:],
					},
					Value: nil,
				})
			}
		}
	}
	return branch
}

func (store Store) nodeToTreeValue(node *yaml.Node, commentsWereHandled bool) (interface{}, error) {
	switch node.Kind {
	case yaml.DocumentNode:
		panic("documents should never be passed here")
	case yaml.SequenceNode:
		var result []interface{}
		if !commentsWereHandled {
			result = store.appendCommentToList(node.HeadComment, result)
			result = store.appendCommentToList(node.LineComment, result)
		}
		for _, item := range node.Content {
			result = store.appendCommentToList(item.HeadComment, result)
			result = store.appendCommentToList(item.LineComment, result)
			val, err := store.nodeToTreeValue(item, true)
			if err != nil {
				return nil, err
			}
			result = append(result, val)
			result = store.appendCommentToList(item.FootComment, result)
		}
		if !commentsWereHandled {
			result = store.appendCommentToList(node.FootComment, result)
		}
		return result, nil
	case yaml.MappingNode:
		branch := make(TreeBranch, 0)
		return store.appendYamlNodeToTreeBranch(node, branch, commentsWereHandled)
	case yaml.ScalarNode:
		var result interface{}
		node.Decode(&result)
		return result, nil
	case yaml.AliasNode:
		return store.nodeToTreeValue(node.Alias, false)
	}
	return nil, nil
}

func (store Store) appendYamlNodeToTreeBranch(node *yaml.Node, branch TreeBranch, commentsWereHandled bool) (TreeBranch, error) {
	var err error
	if !commentsWereHandled {
		branch = store.appendCommentToMap(node.HeadComment, branch)
		branch = store.appendCommentToMap(node.LineComment, branch)
	}
	switch node.Kind {
	case yaml.DocumentNode:
		for _, item := range node.Content {
			branch, err = store.appendYamlNodeToTreeBranch(item, branch, false)
			if err != nil {
				return nil, err
			}
		}
	case yaml.SequenceNode:
		return nil, fmt.Errorf("YAML documents that are sequences are not supported")
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			value := node.Content[i+1]
			branch = store.appendCommentToMap(key.HeadComment, branch)
			branch = store.appendCommentToMap(key.LineComment, branch)
			handleValueComments := value.Kind == yaml.ScalarNode || value.Kind == yaml.AliasNode
			if handleValueComments {
				branch = store.appendCommentToMap(value.HeadComment, branch)
				branch = store.appendCommentToMap(value.LineComment, branch)
			}
			var keyValue interface{}
			key.Decode(&keyValue)
			valueTV, err := store.nodeToTreeValue(value, handleValueComments)
			if err != nil {
				return nil, err
			}
			branch = append(branch, TreeItem{
				Key:   keyValue,
				Value: valueTV,
			})
			if handleValueComments {
				branch = store.appendCommentToMap(value.FootComment, branch)
			}
			branch = store.appendCommentToMap(key.FootComment, branch)
		}
	case yaml.ScalarNode:
		// A empty document with a document start marker without comments results in null
		if node.ShortTag() == "!!null" {
			return branch, nil
		}
		return nil, fmt.Errorf("YAML documents that are values are not supported")
	case yaml.AliasNode:
		branch, err = store.appendYamlNodeToTreeBranch(node.Alias, branch, false)
		if err != nil {
			// This should never happen since node.Alias was already successfully decoded before
			return nil, err
		}
	}
	if !commentsWereHandled {
		branch = store.appendCommentToMap(node.FootComment, branch)
	}
	return branch, nil
}

func (store Store) yamlDocumentNodeToTreeBranch(in yaml.Node) (TreeBranch, error) {
	branch := make(TreeBranch, 0)
	return store.appendYamlNodeToTreeBranch(&in, branch, false)
}

func (store *Store) addCommentsHead(node *yaml.Node, comments []string) []string {
	if len(comments) > 0 {
		comment := "#" + strings.Join(comments, "\n#")
		if len(node.HeadComment) > 0 {
			node.HeadComment = comment + "\n" + node.HeadComment
		} else {
			node.HeadComment = comment
		}
	}
	return nil
}

func (store *Store) addCommentsFoot(node *yaml.Node, comments []string) []string {
	if len(comments) > 0 {
		comment := "#" + strings.Join(comments, "\n#")
		if len(node.FootComment) > 0 {
			node.FootComment += "\n" + comment
		} else {
			node.FootComment = comment
		}
	}
	return nil
}

func (store *Store) treeValueToNode(in interface{}) *yaml.Node {
	switch in := in.(type) {
	case TreeBranch:
		var mapping = &yaml.Node{}
		mapping.Kind = yaml.MappingNode
		store.appendTreeBranch(in, mapping)
		return mapping
	case []interface{}:
		var sequence = &yaml.Node{}
		sequence.Kind = yaml.SequenceNode
		store.appendSequence(in, sequence)
		return sequence
	default:
		var valueNode = &yaml.Node{}
		valueNode.Encode(in)
		return valueNode
	}
}

func (store *Store) appendSequence(in []interface{}, sequence *yaml.Node) {
	var comments []string
	var beginning bool = true
	for _, item := range in {
		if comment, ok := item.(Comment); ok {
			comments = append(comments, comment.Value)
		} else {
			if beginning {
				comments = store.addCommentsHead(sequence, comments)
				beginning = false
			}
			itemNode := store.treeValueToNode(item)
			comments = store.addCommentsHead(itemNode, comments)
			sequence.Content = append(sequence.Content, itemNode)
		}
	}
	if len(comments) > 0 {
		if beginning {
			store.addCommentsHead(sequence, comments)
		} else {
			store.addCommentsFoot(sequence.Content[len(sequence.Content)-1], comments)
		}
	}
}

func (store *Store) appendTreeBranch(branch TreeBranch, mapping *yaml.Node) {
	var comments []string
	var beginning bool = true
	for _, item := range branch {
		if comment, ok := item.Key.(Comment); ok {
			comments = append(comments, comment.Value)
		} else {
			if beginning {
				comments = store.addCommentsHead(mapping, comments)
				beginning = false
			}
			var keyNode = &yaml.Node{}
			keyNode.Encode(item.Key)
			comments = store.addCommentsHead(keyNode, comments)
			valueNode := store.treeValueToNode(item.Value)
			mapping.Content = append(mapping.Content, keyNode, valueNode)
		}
	}
	if len(comments) > 0 {
		if beginning {
			store.addCommentsHead(mapping, comments)
		} else {
			store.addCommentsFoot(mapping.Content[len(mapping.Content)-2], comments)
		}
	}
}
