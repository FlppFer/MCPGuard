package repositories

import "time"

type AnalysisEntity struct {
	ID                string    `gorm:"primaryKey;type:text;column:id"`
	RepoURL           string    `gorm:"type:text;not null;column:repo_url"`
	Branch            string    `gorm:"type:text;default:'main';column:branch"`
	Commit            string    `gorm:"type:text;column:commit_sha"`
	SourceArchivePath string    `gorm:"type:text;column:source_archive_path"`
	StaticResultPath  string    `gorm:"type:text;column:static_result_path"`
	AgentResultPath   string    `gorm:"type:text;column:agent_result_path"`
	Status            string    `gorm:"type:text;not null;default:'created';index;column:status"`
	ErrorMessage      string    `gorm:"type:text;column:error_message"`
	PRNumber          int       `gorm:"column:pr_number"`
	RepoFullName      string    `gorm:"type:text;column:repo_full_name"`
	CreatedAt         time.Time `gorm:"column:created_at"`
	UpdatedAt         time.Time `gorm:"column:updated_at"`
	DeletedAt         time.Time `gorm:"column:deleted_at;index"`
}

func (AnalysisEntity) TableName() string {
	return "analysis"
}

type AnalysisStatus int

const (
	StatusCreated AnalysisStatus = iota
	StatusQueued
	StatusDownloadingRepo
	StatusUploadingSource
	StatusParsingFiles
	StatusStaticAnalysisRunning
	StatusStaticAnalysisDone
	StatusWaitingAgentAnalysis
	StatusAgentAnalysisRunning
	StatusAgentAnalysisDone
	StatusCompleted
	StatusFailed
)

var AnalysisStatusNames = map[AnalysisStatus]string{
	StatusCreated:               "created",
	StatusQueued:                "queued",
	StatusDownloadingRepo:       "downloading_repo",
	StatusUploadingSource:       "uploading_source",
	StatusParsingFiles:          "parsing_files",
	StatusStaticAnalysisRunning: "static_analysis_running",
	StatusStaticAnalysisDone:    "static_analysis_done",
	StatusWaitingAgentAnalysis:  "waiting_agent_analysis",
	StatusAgentAnalysisRunning:  "agent_analysis_running",
	StatusAgentAnalysisDone:     "agent_analysis_done",
	StatusCompleted:             "completed",
	StatusFailed:                "failed",
}

func (s AnalysisStatus) String() string {
	if name, ok := AnalysisStatusNames[s]; ok {
		return name
	}
	return "unknown"
}
