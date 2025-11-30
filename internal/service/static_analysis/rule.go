package static_analysis

type Rule interface {
	ID() string
	Description() string
	AppliesToLanguage() string
	Evaluate(ast interface{}) ([]Finding, error)
}

var registry = map[string][]Rule{}

func RegisterRule(language string, rule Rule) {
	registry[language] = append(registry[language], rule)
}

func GetRules(language string) []Rule {
	return registry[language]
}

// Define supported language constants and a slice for iteration/validation.
const (
	LanguagePython = "python"
)
