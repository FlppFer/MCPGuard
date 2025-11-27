package services

type SourceFileDTO struct {
	Path        string            // Full path inside the repository
	Language    string            // e.g., "python", "json", "yaml", "markdown"
	Content     string            // File contents as a raw string
	AST         interface{}       // Parsed AST (Python: *pythonast.Module)
	Metadata    map[string]string // Optional (e.g., size, encoding, etc)
}

