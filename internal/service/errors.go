package service

import "errors"

var (
	// ErrAnalysisNotFound is returned when an analysis ID does not exist in the database.
	ErrAnalysisNotFound = errors.New("analysis not found")

	// ErrAnalysisNotComplete is returned when results are requested for an analysis
	// that has not yet finished processing.
	ErrAnalysisNotComplete = errors.New("analysis not complete")
)
