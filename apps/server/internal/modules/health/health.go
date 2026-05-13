// Package health exposes GET /health for orchestrator liveness checks.
//
// Mirrors apps/server/src/modules/health/routes.ts:
//   200 — every dependency reachable
//   503 — at least one component degraded
package health

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/jmoiron/sqlx"
)

type Status string

const (
	Healthy   Status = "healthy"
	Degraded  Status = "degraded"
	StateUp   string = "up"
	StateDown string = "down"
)

type Response struct {
	Status    Status `json:"status"`
	Timestamp string `json:"timestamp"`
	Checks    Checks `json:"checks"`
}

type Checks struct {
	Database string `json:"database"`
}

type Handler struct {
	DB *sqlx.DB
}

func Register(api huma.API, h *Handler) {
	huma.Register(api, huma.Operation{
		Method:        http.MethodGet,
		Path:          "/health",
		Tags:          []string{"Health"},
		OperationID:   "checkHealth",
		Summary:       "Check API Health",
		DefaultStatus: http.StatusOK,
	}, h.Check)
}

type checkInput struct{}
type checkOutput struct {
	Status int
	Body   Response
}

func (h *Handler) Check(ctx context.Context, _ *checkInput) (*checkOutput, error) {
	out := &checkOutput{
		Body: Response{
			Status:    Healthy,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Checks:    Checks{Database: StateUp},
		},
		Status: http.StatusOK,
	}
	if err := h.DB.PingContext(ctx); err != nil {
		out.Body.Status = Degraded
		out.Body.Checks.Database = StateDown
		out.Status = http.StatusServiceUnavailable
	}
	return out, nil
}
