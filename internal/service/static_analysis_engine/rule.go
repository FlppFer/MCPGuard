package static_analysis_engine

type Rule interface {
	ID() string
	Description() string
	AppliesToLanguage() string
	Evaluate(ast interface{}) ([]Finding, error)
}