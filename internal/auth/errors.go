package auth

import "errors"

// ErrLogin is the one error for every failed login step; it says nothing about why.
var ErrLogin = errors.New("auth: login failed")

// LoginError is ErrLogin plus a machine-readable reason for the server log. The user never sees the reason
// (it could reveal which accounts exist); operators find it in the logs.
type LoginError struct {
	Reason, Detail string
	Email          string // the Google account that tried to sign in; shown back only to the person who chose it
}

func denyAs(reason, email string) *LoginError { return &LoginError{Reason: reason, Email: email} }

func (e *LoginError) Error() string          { return ErrLogin.Error() }
func (e *LoginError) Is(target error) bool   { return target == ErrLogin }
func deny(reason, detail string) *LoginError { return &LoginError{Reason: reason, Detail: detail} }

// LoginReason returns the reason code and detail of a failed login, if there is one.
func LoginReason(err error) (reason, detail string) {
	var le *LoginError
	if errors.As(err, &le) {
		return le.Reason, le.Detail
	}
	return "", ""
}

// LoginEmail returns the Google account that tried to sign in, when the denial is about that account.
func LoginEmail(err error) string {
	var le *LoginError
	if errors.As(err, &le) {
		return le.Email
	}
	return ""
}
