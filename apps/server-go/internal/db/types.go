package db

import (
	"database/sql/driver"
	"fmt"
	"time"
)

// PrismaTime is a time.Time wrapper that knows how to scan from SQLite
// columns Prisma writes: INTEGER (Unix milliseconds) for most rows, plus
// TEXT (ISO 8601) for the seed inserts that landed before Prisma owned
// the column. Without this every query touching `*At` columns fails with
//
//   sql: Scan error: unsupported Scan, storing driver.Value type int64
//   into type *time.Time
//
// Use PrismaTime in struct fields scanned from sqlx; convert to/from
// time.Time on the way in and out.
type PrismaTime struct{ time.Time }

// Scan implements sql.Scanner.
func (t *PrismaTime) Scan(src any) error {
	switch v := src.(type) {
	case nil:
		t.Time = time.Time{}
	case int64:
		// Prisma stores DateTime as Unix milliseconds.
		t.Time = time.UnixMilli(v).UTC()
	case time.Time:
		t.Time = v.UTC()
	case []byte:
		return t.parseString(string(v))
	case string:
		return t.parseString(v)
	default:
		return fmt.Errorf("PrismaTime: unsupported scan type %T", src)
	}
	return nil
}

func (t *PrismaTime) parseString(s string) error {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05.999999999-07:00", "2006-01-02 15:04:05"} {
		if parsed, err := time.Parse(layout, s); err == nil {
			t.Time = parsed.UTC()
			return nil
		}
	}
	return fmt.Errorf("PrismaTime: cannot parse %q", s)
}

// Value implements driver.Valuer — INSERTs write Unix millis so Prisma
// can read them back as DateTime without re-encoding.
func (t PrismaTime) Value() (driver.Value, error) {
	if t.Time.IsZero() {
		return nil, nil
	}
	return t.Time.UnixMilli(), nil
}
