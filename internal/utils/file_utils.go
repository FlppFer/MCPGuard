package utils

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/FlppFer/MCPGuard/internal/model/services"
)

func ParseRepositoryFiles(path string) ([]services.SourceFileDTO, error) {
	var files []services.SourceFileDTO

	err := filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}

		ext := filepath.Ext(p)

		if !isSupportedExt(ext) {
			return nil
		}

		content, err := os.ReadFile(p)
		if err != nil {
			return err
		}

		files = append(files, services.SourceFileDTO{
			Path:     p,
			Language: NormalizeExtension(ext),
			Content:  string(content),
		})

		return nil
	})

	return files, err
}

func zipFolder(srcFolder, destZip string) (retErr error) {
	zipFile, err := os.Create(destZip)
	if err != nil {
		return err
	}

	defer func() {
		if cerr := zipFile.Close(); cerr != nil && retErr == nil {
			retErr = cerr
		}
	}()

	zipWriter := zip.NewWriter(zipFile)

	defer func() {
		if cerr := zipWriter.Close(); cerr != nil && retErr == nil {
			retErr = cerr
		}
	}()

	retErr = filepath.Walk(srcFolder, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(srcFolder, path)
		if err != nil {
			return err
		}

		fileInZip, err := zipWriter.Create(relPath)
		if err != nil {
			return err
		}

		fileOnDisk, err := os.Open(path)
		if err != nil {
			return err
		}

		if _, err := io.Copy(fileInZip, fileOnDisk); err != nil {
			_ = fileOnDisk.Close()
			return err
		}
		if cerr := fileOnDisk.Close(); cerr != nil {
			return cerr
		}

		return nil
	})

	return retErr
}

func CleanupRepo(rd *services.RepoDownloadResultDTO) {
	err := os.RemoveAll(rd.LocalPath)
	if err != nil {
		return
	}
	err = os.Remove(rd.ZipPath)
	if err != nil {
		return
	}
}

func isSupportedExt(ext string) bool {
	ext = strings.ToLower(ext)

	switch ext {
	case ".py",
		".json",
		".yaml",
		".yml",
		".toml",
		".md":
		return true
	default:
		return false
	}
}

func NormalizeExtension(ext string) string {
	ext = strings.ToLower(ext)

	switch ext {
	case ".py":
		return "python"

	case ".json":
		return "json"

	case ".yaml", ".yml":
		return "yaml"

	case ".toml":
		return "toml"

	case ".md":
		return "markdown"

	default:
		return "unknown"
	}
}
