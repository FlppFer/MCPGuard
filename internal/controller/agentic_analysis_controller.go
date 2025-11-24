package controller

import "net/http"

type (
	AgenticAnalysisControllerInterface interface {
		RequestAgenticAnalysis() http.HandlerFunc
	}
)
