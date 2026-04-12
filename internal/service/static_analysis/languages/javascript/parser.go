package javascript

import (
	"context"
	"os"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/javascript"
)

// JavaScriptAST holds the parsed tree and original source for a JS/TS file.
type JavaScriptAST struct {
	Tree   *sitter.Tree
	Source []byte
	Path   string
}

// ParseJavaScriptFile reads and parses a JavaScript/TypeScript file from disk.
func ParseJavaScriptFile(path string) (*JavaScriptAST, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return ParseJavaScriptSource(path, src)
}

// ParseJavaScriptSource parses JavaScript/TypeScript source code from bytes.
func ParseJavaScriptSource(path string, src []byte) (*JavaScriptAST, error) {
	parser := sitter.NewParser()
	parser.SetLanguage(javascript.GetLanguage())

	tree, err := parser.ParseCtx(context.Background(), nil, src)
	if err != nil {
		return nil, err
	}

	return &JavaScriptAST{
		Tree:   tree,
		Source: src,
		Path:   path,
	}, nil
}
