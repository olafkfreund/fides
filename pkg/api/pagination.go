package api

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	defaultPageSize = 100
	maxPageSize     = 500
)

type cursorKey struct {
	column string
	kind   string
}

func textKey(column string) cursorKey { return cursorKey{column, "text"} }
func timeKey(column string) cursorKey { return cursorKey{column, "timestamptz"} }
func uuidKey(column string) cursorKey { return cursorKey{column, "uuid"} }

type listCursor struct {
	Version int       `json:"v"`
	Scope   string    `json:"s"`
	Keys    []*string `json:"k"`
}

type listPage struct {
	limit   int
	url     url.URL
	cursor  listCursor
	after   []any
	first   cursorKey
	last    cursorKey
	desc    bool
	hasNext bool
}

func newListPage(w http.ResponseWriter, r *http.Request, orgID uuid.UUID, first, last cursorKey, desc bool) (*listPage, bool) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query["limit"]) > 1 || len(query["cursor"]) > 1 {
		http.Error(w, "invalid pagination query", http.StatusBadRequest)
		return nil, false
	}
	limit := defaultPageSize
	if query.Has("limit") {
		limit, err = strconv.Atoi(query.Get("limit"))
		if err != nil || limit < 1 || limit > maxPageSize {
			http.Error(w, "limit must be an integer from 1 to 500", http.StatusBadRequest)
			return nil, false
		}
	}

	token, hasToken := query["cursor"]
	query.Del("limit")
	query.Del("cursor")
	// The request path includes the parent identifiers. Bind the cursor to
	// those and all filters, while allowing a different limit on the next page.
	scope := sha256.Sum256([]byte(orgID.String() + "\n" + r.URL.EscapedPath() + "\n" + query.Encode()))
	page := &listPage{
		limit: limit, first: first, last: last, desc: desc,
		url:    url.URL{Path: r.URL.Path, RawPath: r.URL.RawPath},
		cursor: listCursor{Version: 1, Scope: hex.EncodeToString(scope[:])},
	}
	if hasToken && !page.parse(token[0]) {
		http.Error(w, "invalid cursor", http.StatusBadRequest)
		return nil, false
	}
	query.Set("limit", strconv.Itoa(limit))
	page.url.RawQuery = query.Encode()
	return page, true
}

func (p *listPage) parse(token string) bool {
	if len(token) > 8192 {
		return false
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(token)
	var cursor listCursor
	if err != nil || json.Unmarshal(data, &cursor) != nil ||
		cursor.Version != p.cursor.Version || cursor.Scope != p.cursor.Scope || len(cursor.Keys) != 2 {
		return false
	}
	for i, key := range []cursorKey{p.first, p.last} {
		value := cursor.Keys[i]
		if value == nil {
			if i != 0 || key.kind != "timestamptz" {
				return false
			}
			p.after = append(p.after, nil)
			continue
		}
		switch key.kind {
		case "uuid":
			id, err := uuid.Parse(*value)
			if err != nil || id.String() != *value {
				return false
			}
			p.after = append(p.after, id)
		case "timestamptz":
			t, err := time.Parse(time.RFC3339Nano, *value)
			if err != nil {
				return false
			}
			p.after = append(p.after, t)
		case "text":
			if !utf8.ValidString(*value) || strings.ContainsRune(*value, 0) {
				return false
			}
			p.after = append(p.after, *value)
		}
	}
	return true
}

// The key columns and SQL types come from handler constants. Values decoded
// from a cursor are only used as bound parameters.
func (p *listPage) query(query string, args ...any) (string, []any) {
	first, last := p.first.column, p.last.column
	direction, op := "ASC", ">"
	if p.desc {
		direction, op = "DESC", "<"
	}
	seek := ""
	if len(p.after) != 0 {
		lastArg := fmt.Sprintf("$%d::%s", len(args)+1, p.last.kind)
		if p.after[0] == nil {
			seek = fmt.Sprintf(" AND (%s IS NULL AND %s %s %s)", first, last, op, lastArg)
			args = append(args, p.after[1])
		} else {
			firstArg := fmt.Sprintf("$%d::%s", len(args)+2, p.first.kind)
			seek = fmt.Sprintf("(%s, %s) %s (%s, %s)", first, last, op, firstArg, lastArg)
			if p.first.kind == "timestamptz" {
				seek += " OR " + first + " IS NULL"
			}
			seek = " AND (" + seek + ")"
			args = append(args, p.after[1], p.after[0])
		}
	}
	query = strings.Replace(query, "/* page keys */", ", "+first+", "+last, 1)
	if strings.Contains(query, "/* page seek */") {
		query = strings.Replace(query, "/* page seek */", seek, 1)
	} else {
		query += seek
	}
	query += fmt.Sprintf(" ORDER BY %s %s NULLS LAST, %s %s LIMIT $%d", first, direction, last, direction, len(args)+1)
	return query, append(args, p.limit+1)
}

func (s *Server) queryPage(r *http.Request, p *listPage, query string, args ...any) (*pageRows, error) {
	query, args = p.query(query, args...)
	rows, err := s.q(r.Context()).QueryContext(r.Context(), query, args...)
	if err != nil {
		return nil, err
	}
	return &pageRows{Rows: rows, page: p}, nil
}

// pageRows scans the key columns separately from the response shape and uses
// the extra row solely to decide whether to emit a next link.
type pageRows struct {
	*sql.Rows
	page     *listPage
	count    int
	closeErr error
}

func (r *pageRows) Next() bool {
	if !r.Rows.Next() {
		return false
	}
	r.count++
	if r.count <= r.page.limit {
		return true
	}
	r.page.hasNext = true
	r.closeErr = r.Close()
	return false
}

func (r *pageRows) Scan(dest ...any) error {
	var first, last any
	if err := r.Rows.Scan(append(dest, &first, &last)...); err != nil {
		return err
	}
	if r.count == r.page.limit {
		r.page.cursor.Keys = []*string{cursorValue(first), cursorValue(last)}
	}
	return nil
}

func (r *pageRows) Err() error {
	if r.closeErr != nil {
		return r.closeErr
	}
	return r.Rows.Err()
}

func cursorValue(value any) *string {
	var key string
	switch value := value.(type) {
	case string:
		key = value
	case []byte:
		key = string(value)
	case time.Time:
		key = value.UTC().Format(time.RFC3339Nano)
	default:
		return nil
	}
	return &key
}

func (p *listPage) write(w http.ResponseWriter, rows any) {
	if p.hasNext {
		// Cursor fields contain only strings and integers.
		data, _ := json.Marshal(p.cursor)
		q := p.url.Query()
		q.Set("cursor", base64.RawURLEncoding.EncodeToString(data))
		p.url.RawQuery = q.Encode()
		w.Header().Set("Link", "<"+p.url.RequestURI()+`>; rel="next"`)
	}
	writeJSON(w, rows)
}
