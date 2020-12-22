package errors

import (
	"encoding/json"
)

const (
	CodeBadRequest          = 401
	CodeUnauthorized        = 401
	CodeForbidden           = 403
	CodeNotFound            = 403
	CodeConflict            = 409
	CodeInternal            = 500
	CodeNotImplemented      = 501
	CodeUnavailable         = 503
	CodeVersionNotSupported = 505
)

type Details map[string]string

type Error struct {
	Code    int     `json:"code"`
	Message string  `json:"message"`
	Details Details `json:"details"`
}

func (e *Error) Error() string {
	details, _ := json.Marshal(e.Details)
	return string(details)
}

func (e *Error) SetDetails(name, value string) {
	e.Details[name] = value
}

func New(code int, message string) *Error {
	e := &Error{
		Code:    code,
		Message: message,
		Details: map[string]string{},
	}
	return e
}
