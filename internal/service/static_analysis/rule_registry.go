package static_analysis

import "github.com/FlppFer/MCPGuard/internal/service/model"

var registry = map[string][]model.Rule{}

func RegisterRule(language string, rule model.Rule) {
	registry[language] = append(registry[language], rule)
}

func GetRules(language string) []model.Rule {
	return registry[language]
}

// Define supported language constants and a slice for iteration/validation.
const (
	LanguagePython     = "python"
	LanguageJavaScript = "javascript"
)
