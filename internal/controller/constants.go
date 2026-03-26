package controller

// HTTP error codes used in error responses.
const (
	ErrCodeInvalidRequest   = "invalid_request"
	ErrCodeMissingField     = "missing_field"
	ErrCodeMissingID        = "missing_id"
	ErrCodeNotFound         = "not_found"
	ErrCodeAnalysisFailed   = "analysis_failed"
	ErrCodeAnalysisPending  = "analysis_pending"
	ErrCodeProcessingFailed = "processing_failed"
	ErrCodeInternalError    = "internal_error"
	ErrCodeInvalidPayload   = "invalid_payload"
)

// HTTP response messages.
const (
	MsgAnalysisStarted      = "Analysis started successfully"
	MsgFailedParseBody      = "Failed to parse request body"
	MsgAnalysisIDRequired   = "analysis_id is required"
	MsgIDRequired           = "Analysis ID is required"
	MsgRepoURLRequired      = "repo_url is required"
	MsgCloneURLRequired     = "repository.clone_url is required"
	MsgFailedParsePayload   = "Failed to parse GitHub webhook payload"
	MsgDefaultBranch        = "main"
)

// Content type header value.
const (
	ContentTypeJSON = "application/json; charset=UTF-8"
)
