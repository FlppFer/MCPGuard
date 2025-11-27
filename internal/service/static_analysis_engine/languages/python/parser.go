package python

import (
	"context"
	"os"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/python"
)

type PythonAST struct {
	Tree   *sitter.Tree
	Source []byte
	Path   string
}

// ParsePythonFile reads and parses a Python file from disk
func ParsePythonFile(path string) (*PythonAST, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return ParsePythonSource(path, src)
}

// ParsePythonSource parses Python source code from bytes
func ParsePythonSource(path string, src []byte) (*PythonAST, error) {
	parser := sitter.NewParser()
	parser.SetLanguage(python.GetLanguage())

	tree, err := parser.ParseCtx(context.Background(), nil, src)
	if err != nil {
		return nil, err
	}

	return &PythonAST{
		Tree:   tree,
		Source: src,
		Path:   path,
	}, nil
}
