package static_analysis_engine

var registry = map[string][]Rule{}

func RegisterRule(language string, rule Rule) {
	registry[language] = append(registry[language], rule)
}

func GetRules(language string) []Rule {
	return registry[language]
}

// Define supported language constants and a slice for iteration/validation.
const (
	LanguagePython     = "python"
)
