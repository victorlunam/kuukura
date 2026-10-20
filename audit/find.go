package audit

import "context"

// Find returns the successful rows with this action and target type, newest first. It is for the few host-level
// events that have no secret behind them, such as a master key being shown.
func (l *Log) Find(ctx context.Context, action, targetType string) ([]Row, error) {
	rows, err := l.p.DB().QueryContext(ctx, l.p.Rebind(`SELECT `+columns+` FROM audit_log a
		WHERE a.action = ? AND a.target_type = ? AND a.result = 'ok' ORDER BY a.at DESC, a.id DESC`), action, targetType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Row
	for rows.Next() {
		r, err := scanRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
