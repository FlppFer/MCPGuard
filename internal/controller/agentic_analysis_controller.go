package controller

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	httpmodel "github.com/FlppFer/MCPGuard/internal/model/http"
	"github.com/FlppFer/MCPGuard/internal/service"
)

type (
	AgenticAnalysisControllerInterface interface {
		ReceiveAgenticResult() http.HandlerFunc
		GetAgenticResult() http.HandlerFunc
	}

	agenticAnalysisController struct {
		agenticService service.AgenticAnalysisService
	}
)

func NewAgenticAnalysisController(agenticService service.AgenticAnalysisService) AgenticAnalysisControllerInterface {
	return &agenticAnalysisController{
		agenticService: agenticService,
	}
}

// ReceiveAgenticResult handles POST /v1/agentic_analysis — callback from the Python worker.
func (c *agenticAnalysisController) ReceiveAgenticResult() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var result httpmodel.AgenticAnalysisResultDTO
		if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
			c.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, MsgFailedParseBody)
			return
		}

		if result.AnalysisID == "" {
			c.writeError(w, http.StatusBadRequest, ErrCodeMissingField, MsgAnalysisIDRequired)
			return
		}

		if err := c.agenticService.ReceiveResult(r.Context(), &result); err != nil {
			slog.Error("Failed to process agentic result", "error", err, "analysis_id", result.AnalysisID)
			if errors.Is(err, service.ErrAnalysisNotFound) {
				c.writeError(w, http.StatusNotFound, ErrCodeNotFound, err.Error())
			} else {
				c.writeError(w, http.StatusInternalServerError, ErrCodeProcessingFailed, err.Error())
			}
			return
		}

		c.writeJSON(w, http.StatusOK, map[string]string{"status": "received"})
	}
}

// GetAgenticResult handles GET /v1/agentic_analysis/{id}/result — retrieves stored agentic findings.
func (c *agenticAnalysisController) GetAgenticResult() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		analysisID := chi.URLParam(r, "id")
		if analysisID == "" {
			c.writeError(w, http.StatusBadRequest, ErrCodeMissingID, MsgIDRequired)
			return
		}

		data, err := c.agenticService.GetResult(r.Context(), analysisID)
		if err != nil {
			slog.Error("Failed to get agentic result", "error", err, "analysis_id", analysisID)
			if errors.Is(err, service.ErrAnalysisNotComplete) {
				c.writeError(w, http.StatusAccepted, ErrCodeAnalysisPending, err.Error())
			} else if errors.Is(err, service.ErrAnalysisNotFound) {
				c.writeError(w, http.StatusNotFound, ErrCodeNotFound, err.Error())
			} else {
				c.writeError(w, http.StatusInternalServerError, ErrCodeInternalError, err.Error())
			}
			return
		}

		w.Header().Set("Content-Type", ContentTypeJSON)
		w.WriteHeader(http.StatusOK)
		w.Write(data)
	}
}

func (c *agenticAnalysisController) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", ContentTypeJSON)
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("Failed to encode response", "error", err)
	}
}

func (c *agenticAnalysisController) writeError(w http.ResponseWriter, status int, errCode, message string) {
	resp := httpmodel.ErrorResponseDTO{
		Error:   errCode,
		Message: message,
	}
	c.writeJSON(w, status, resp)
}
