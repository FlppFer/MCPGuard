package model

// Rule defines the interface that all security analysis rules must implement.
// Each rule is responsible for detecting a specific type of security vulnerability.
type Rule interface {
	ID() string
	Description() string
	AppliesToLanguage() string
	Evaluate(ast interface{}) ([]Finding, error)
}
