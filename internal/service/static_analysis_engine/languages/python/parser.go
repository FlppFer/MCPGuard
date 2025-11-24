package python

import (
	"os"

	ts "github.com/smacker/go-tree-sitter"
)

type PythonAST struct {
	Tree   *ts.Tree
	Source []byte
}

func ParsePythonFile(path string) (*PythonAST, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	parser := ts.NewParser()
	parser.SetLanguage(tree_sitter_python.GetLanguage())

	tree := parser.Parse(nil, src)

	return &PythonAST{
		Tree:   tree,
		Source: src,
	}, nil
}
