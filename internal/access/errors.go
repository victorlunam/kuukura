package access

// Error codes shared by the domain packages; the API maps them to problem+json codes.
const (
	CodeNotFound     = "not_found"
	CodeDenied       = "denied"
	CodeAmbiguous    = "ambiguous"
	CodeBlocked      = "blocked"
	CodeClash        = "clash"
	CodeStepUp       = "step_up_required"
	CodeWouldCreate  = "would_create"
	CodeInvalid      = "invalid"
	CodeNeedsOne     = "needs_one"
	CodeKindMismatch = "kind_mismatch"
	CodeLastAdmin    = "last_admin"
	CodeConflict     = "conflict"
	CodeLastFactor   = "last_factor"
	CodeAppExists    = "app_exists"
)

// Error is a domain error. Items lists the things involved ("NAME tag tag"); never values.
type Error struct {
	Code  string
	Msg   string
	Items []string
}

func (e *Error) Error() string { return e.Msg }

func Fail(code, msg string, items ...string) *Error { return &Error{code, msg, items} }
