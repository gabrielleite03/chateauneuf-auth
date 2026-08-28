package omada

import "fmt"

// Error models an Omada API-level error payload.
type Error struct {
	Code    int
	Message string
	Body    string
}

func (e *Error) Error() string {
	if e == nil {
		return "omada: unknown error"
	}
	if e.Message != "" {
		return fmt.Sprintf("omada: %s", e.Message)
	}
	if e.Body != "" {
		return fmt.Sprintf("omada: %s", e.Body)
	}
	return fmt.Sprintf("omada: status %d", e.Code)
}
