package services

type RepoDownloadResultDTO struct {
	AnalysisID string // UUID linking to the analysis
	RepoURL    string
	Branch     string
	Commit     string

	LocalPath  string // e.g. /tmp/analysisID/repo/
	ZipPath    string // e.g. /tmp/analysisID/repo.zip
}