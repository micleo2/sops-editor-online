package sopscore

// Metadata holds the subset of SOPS metadata that affects how values are
// encrypted and how the MAC is computed (see sops.Metadata).
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
// (see sops.Tree).
type Tree struct {
	Metadata Metadata
	Branches TreeBranches
}
