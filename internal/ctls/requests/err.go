package requests

import (
	"errors"
	"fmt"
)

type RequestFailedError struct {
	Err        error
	StatusCode int
	URL        string
}

func (e *RequestFailedError) Error() string {
	if e.Err == nil {
		return "<nil>"
	}

	if e.StatusCode != 0 {
		return fmt.Sprintf(
			"request to %s failed (status=%d): %v",
			e.URL,
			e.StatusCode,
			e.Err,
		)
	}

	return fmt.Sprintf("internal request failure: %v", e.Err)
}

func (e *RequestFailedError) Unwrap() error {
	return e.Err
}

func (e *RequestFailedError) Code() int { return e.StatusCode }

// IsRequestFailedError checks if an error is of type RequestFailedErr.
func IsRequestFailedError(err error) bool {
	var rfe *RequestFailedError
	return errors.As(err, &rfe)
}
