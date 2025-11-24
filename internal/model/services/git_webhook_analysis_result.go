package services

import "time"

type GitWebhookAnalysisResultDTO struct {
	AnalysisID string
	Status     string
	Timestamp  time.Time
}
