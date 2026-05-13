package db

import (
	"database/sql/driver"
	"fmt"
	"strconv"
	"strings"
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

// BigIntStr is an int64 that serialises to/from JSON as a quoted number,
// matching how Prisma encodes BigInt columns over the wire. Without this
// the web client (which types these fields as `string`) would either
// crash on `someBig.toLocaleString()` or silently lose precision for
// files larger than 2^53 bytes.
type BigIntStr int64

func (b BigIntStr) MarshalJSON() ([]byte, error) {
	// Always emit as a JSON string, even when zero. Matches Prisma's
	// JSON.stringify(BigInt(n)) which produces "0", not 0.
	return []byte(`"` + strconv.FormatInt(int64(b), 10) + `"`), nil
}

func (b *BigIntStr) UnmarshalJSON(data []byte) error {
	s := string(data)
	if s == "null" {
		*b = 0
		return nil
	}
	// Accept both "12345" and 12345 — the legacy frontend sometimes sends a
	// number for newly-uploaded files, so be liberal.
	s = strings.Trim(s, `"`)
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fmt.Errorf("BigIntStr: cannot parse %q: %w", string(data), err)
	}
	*b = BigIntStr(n)
	return nil
}

// Scan implements sql.Scanner so sqlx can read the value from a BIGINT
// column straight into BigIntStr.
func (b *BigIntStr) Scan(src any) error {
	switch v := src.(type) {
	case nil:
		*b = 0
	case int64:
		*b = BigIntStr(v)
	case int:
		*b = BigIntStr(int64(v))
	case []byte:
		n, err := strconv.ParseInt(string(v), 10, 64)
		if err != nil {
			return err
		}
		*b = BigIntStr(n)
	case string:
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return err
		}
		*b = BigIntStr(n)
	default:
		return fmt.Errorf("BigIntStr: unsupported scan type %T", src)
	}
	return nil
}

// Value implements driver.Valuer for INSERTs/UPDATEs.
func (b BigIntStr) Value() (driver.Value, error) { return int64(b), nil }
