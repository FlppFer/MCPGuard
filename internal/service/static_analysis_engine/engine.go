package static_analysis_engine

type Engine struct{}

func NewStaticAnalyzerEngine() *Engine {
	return &Engine{}
}

func (e *Engine) Analyze(language, filePath string, ast interface{}) ([]Finding, error) {
	rules := GetRules(language)

	var findings []Finding

	for _, rule := range rules {
		f, err := rule.Evaluate(ast)
		if err != nil {
			return nil, err
		}
		findings = append(findings, f...)
	}

	return findings, nil
}