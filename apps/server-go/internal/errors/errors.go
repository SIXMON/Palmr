// Package errors provides HTTP-aware error types.
//
// Huma understands `huma.Error*` constructors directly; this package
// adds a few project-specific helpers so callers don't need to import
// huma everywhere.
package errors

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

// Status400 / Status401 / ... are thin wrappers around huma.NewError.
// They keep the call sites short:
//
//	return errors.Forbidden("not allowed to do that")
func BadRequest(msg string) huma.StatusError    { return huma.NewError(http.StatusBadRequest, msg) }
func Unauthorized(msg string) huma.StatusError  { return huma.NewError(http.StatusUnauthorized, msg) }
func Forbidden(msg string) huma.StatusError     { return huma.NewError(http.StatusForbidden, msg) }
func NotFound(msg string) huma.StatusError      { return huma.NewError(http.StatusNotFound, msg) }
func Conflict(msg string) huma.StatusError      { return huma.NewError(http.StatusConflict, msg) }
func Gone(msg string) huma.StatusError          { return huma.NewError(http.StatusGone, msg) }
func Internal(msg string) huma.StatusError      { return huma.NewError(http.StatusInternalServerError, msg) }
