package service

// S3 key patterns for analysis results.
const (
	S3KeyStaticResult  = "analysis-results/%s_static.json"
	S3KeyAgenticResult = "analysis-results/%s_agentic.json"
	S3KeySourceArchive = "%s.zip"
)

// Worker endpoint paths.
const (
	WorkerAnalyzePath = "%s/analyze"
)

// Temp file name patterns.
const (
	TmpFileStaticResult  = "%s_static.json"
	TmpFileAgenticResult = "%s_agentic.json"
)
