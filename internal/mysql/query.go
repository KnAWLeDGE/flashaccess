package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// TableInfo summarises a table as returned by information_schema.
type TableInfo struct {
	Name   string
	Engine string
	Rows   int64
	Size   string
}

// ColumnInfo maps a row from SHOW FULL COLUMNS.
type ColumnInfo struct {
	Field   string
	Type    string
	Null    string
	Key     string
	Default sql.NullString
	Extra   string
	Comment string
}

// IndexInfo summarises one index (possibly covering multiple columns).
type IndexInfo struct {
	Name    string
	Columns []string
	Unique  bool
	Type    string
}

// QueryResult holds rows (for SELECT) or affected-row count (for DML).
type QueryResult struct {
	Columns  []string
	Rows     [][]string
	Affected int64
	Elapsed  time.Duration
	IsSelect bool
	Err      string // non-empty on SQL error (not a Go error — callers check this)
}

// ListDatabases returns all schema names visible to the admin user.
func (m *Manager) ListDatabases(ctx context.Context) ([]string, error) {
	rows, err := m.db.QueryContext(ctx, "SHOW DATABASES")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var dbs []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		dbs = append(dbs, name)
	}
	return dbs, rows.Err()
}

// ListTables returns table summaries for a given database.
func (m *Manager) ListTables(ctx context.Context, dbName string) ([]TableInfo, error) {
	rows, err := m.db.QueryContext(ctx, `
		SELECT TABLE_NAME,
		       COALESCE(ENGINE, ''),
		       COALESCE(TABLE_ROWS, 0),
		       COALESCE(CONCAT(ROUND((DATA_LENGTH+INDEX_LENGTH)/1024/1024,2),' MB'),'—')
		FROM information_schema.TABLES
		WHERE TABLE_SCHEMA = ?
		ORDER BY TABLE_NAME`, dbName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tables []TableInfo
	for rows.Next() {
		var t TableInfo
		if err := rows.Scan(&t.Name, &t.Engine, &t.Rows, &t.Size); err != nil {
			return nil, err
		}
		tables = append(tables, t)
	}
	return tables, rows.Err()
}

// ListColumns returns column metadata for a table using SHOW FULL COLUMNS.
func (m *Manager) ListColumns(ctx context.Context, dbName, table string) ([]ColumnInfo, error) {
	q := fmt.Sprintf("SHOW FULL COLUMNS FROM `%s`.`%s`", escIdent(dbName), escIdent(table))
	rows, err := m.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cols []ColumnInfo
	for rows.Next() {
		var c ColumnInfo
		var collation, privileges sql.NullString
		if err := rows.Scan(
			&c.Field, &c.Type, &collation, &c.Null, &c.Key,
			&c.Default, &c.Extra, &privileges, &c.Comment,
		); err != nil {
			return nil, err
		}
		cols = append(cols, c)
	}
	return cols, rows.Err()
}

// ListIndexes returns index definitions for a table.
func (m *Manager) ListIndexes(ctx context.Context, dbName, table string) ([]IndexInfo, error) {
	q := fmt.Sprintf("SHOW INDEX FROM `%s`.`%s`", escIdent(dbName), escIdent(table))
	rows, err := m.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	indexMap := map[string]*IndexInfo{}
	var order []string
	for rows.Next() {
		// SHOW INDEX: Table, Non_unique, Key_name, Seq_in_index, Column_name,
		// Collation, Cardinality, Sub_part, Packed, Null, Index_type,
		// Comment, Index_comment, Visible, Expression
		var tableName, keyName, columnName, indexType string
		var nonUnique int
		var seqInIndex int
		var skip sql.NullString
		if err := rows.Scan(
			&tableName, &nonUnique, &keyName, &seqInIndex, &columnName,
			&skip, &skip, &skip, &skip, &skip,
			&indexType, &skip, &skip, &skip, &skip,
		); err != nil {
			return nil, err
		}
		if _, ok := indexMap[keyName]; !ok {
			indexMap[keyName] = &IndexInfo{
				Name:   keyName,
				Unique: nonUnique == 0,
				Type:   indexType,
			}
			order = append(order, keyName)
		}
		indexMap[keyName].Columns = append(indexMap[keyName].Columns, columnName)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]IndexInfo, 0, len(order))
	for _, name := range order {
		out = append(out, *indexMap[name])
	}
	return out, nil
}

// Count returns the total row count for a table.
func (m *Manager) Count(ctx context.Context, dbName, table string) (int64, error) {
	q := fmt.Sprintf("SELECT COUNT(*) FROM `%s`.`%s`", escIdent(dbName), escIdent(table))
	var n int64
	return n, m.db.QueryRowContext(ctx, q).Scan(&n)
}

// BrowseTable returns a paginated slice of rows from a table.
func (m *Manager) BrowseTable(
	ctx context.Context,
	dbName, table string,
	limit, offset int,
	orderBy, orderDir string,
) (*QueryResult, error) {
	order := ""
	if orderBy != "" {
		dir := "ASC"
		if strings.EqualFold(orderDir, "desc") {
			dir = "DESC"
		}
		order = fmt.Sprintf(" ORDER BY `%s` %s", escIdent(orderBy), dir)
	}
	q := fmt.Sprintf(
		"SELECT * FROM `%s`.`%s`%s LIMIT %d OFFSET %d",
		escIdent(dbName), escIdent(table), order, limit, offset,
	)
	return m.runRawQuery(ctx, q)
}

// RunUserQuery executes arbitrary SQL in the context of a specific database.
// SQL errors are captured in QueryResult.Err rather than returned as Go errors,
// so callers can render them to the user without a 500.
func (m *Manager) RunUserQuery(ctx context.Context, dbName, query string) *QueryResult {
	conn, err := m.db.Conn(ctx)
	if err != nil {
		return &QueryResult{Err: err.Error()}
	}
	defer conn.Close()

	if dbName != "" {
		if _, err := conn.ExecContext(ctx,
			fmt.Sprintf("USE `%s`", escIdent(dbName)),
		); err != nil {
			return &QueryResult{Err: fmt.Sprintf("USE %s: %v", dbName, err)}
		}
	}

	start := time.Now()
	rows, err := conn.QueryContext(ctx, query)
	if err != nil {
		// Might be a DML that doesn't return rows; try ExecContext.
		result, execErr := conn.ExecContext(ctx, query)
		if execErr != nil {
			return &QueryResult{Err: err.Error(), Elapsed: time.Since(start)}
		}
		aff, _ := result.RowsAffected()
		return &QueryResult{Affected: aff, Elapsed: time.Since(start)}
	}
	defer rows.Close()
	return collectRows(rows, start)
}

// runRawQuery executes a pre-built SELECT and returns a QueryResult.
func (m *Manager) runRawQuery(ctx context.Context, q string) (*QueryResult, error) {
	start := time.Now()
	rows, err := m.db.QueryContext(ctx, q)
	if err != nil {
		return &QueryResult{Err: err.Error(), Elapsed: time.Since(start)}, nil
	}
	defer rows.Close()
	return collectRows(rows, start), nil
}

func collectRows(rows *sql.Rows, start time.Time) *QueryResult {
	res := &QueryResult{IsSelect: true}
	cols, err := rows.Columns()
	if err != nil {
		res.Err = err.Error()
		return res
	}
	res.Columns = cols
	for rows.Next() {
		vals := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range ptrs {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			res.Err = err.Error()
			break
		}
		row := make([]string, len(cols))
		for i, v := range vals {
			row[i] = valueStr(v)
		}
		res.Rows = append(res.Rows, row)
	}
	if rows.Err() != nil && res.Err == "" {
		res.Err = rows.Err().Error()
	}
	res.Elapsed = time.Since(start)
	return res
}

func valueStr(v interface{}) string {
	if v == nil {
		return "NULL"
	}
	if b, ok := v.([]byte); ok {
		return string(b)
	}
	return fmt.Sprintf("%v", v)
}

// escIdent sanitises a MySQL identifier to prevent injection via backtick.
func escIdent(s string) string {
	return strings.ReplaceAll(s, "`", "``")
}

// QueryPreview describes an estimated impact of a SQL statement before execution.
type QueryPreview struct {
	Kind          string // "select", "dml", "ddl", "other"
	SQL           string
	EstimatedRows int64  // rows affected/examined (from EXPLAIN, 0 if unknown)
	SampleRows    [][]string
	SampleCols    []string
	Warning       string // e.g. "no WHERE clause — all rows will be affected"
	ErrStr        string
}

// PreviewQuery analyses SQL without executing it and returns a QueryPreview.
// For DML (UPDATE/DELETE) it estimates affected rows via EXPLAIN SELECT.
// For DDL it describes the operation. For SELECT it runs EXPLAIN normally.
func (m *Manager) PreviewQuery(ctx context.Context, dbName, query string) *QueryPreview {
	q := strings.TrimSpace(query)
	upper := strings.ToUpper(q)
	kind := classifySQL(upper)

	conn, err := m.db.Conn(ctx)
	if err != nil {
		return &QueryPreview{Kind: kind, SQL: q, ErrStr: err.Error()}
	}
	defer conn.Close()

	if dbName != "" {
		if _, err := conn.ExecContext(ctx, fmt.Sprintf("USE `%s`", escIdent(dbName))); err != nil {
			return &QueryPreview{Kind: kind, SQL: q, ErrStr: fmt.Sprintf("USE %s: %v", dbName, err)}
		}
	}

	prev := &QueryPreview{Kind: kind, SQL: q}

	switch kind {
	case "select":
		// Run EXPLAIN to get estimated rows.
		rows, err := conn.QueryContext(ctx, "EXPLAIN "+q)
		if err != nil {
			prev.ErrStr = "EXPLAIN: " + err.Error()
			return prev
		}
		defer rows.Close()
		cols, _ := rows.Columns()
		var total int64
		for rows.Next() {
			vals := make([]interface{}, len(cols))
			ptrs := make([]interface{}, len(cols))
			for i := range vals { ptrs[i] = &vals[i] }
			_ = rows.Scan(ptrs...)
			// cols[9] is "rows" in MySQL EXPLAIN output
			for i, col := range cols {
				if strings.EqualFold(col, "rows") {
					if b, ok := vals[i].(int64); ok { total += b }
					if b, ok := vals[i].([]byte); ok {
						var n int64
						fmt.Sscanf(string(b), "%d", &n)
						total += n
					}
				}
			}
		}
		prev.EstimatedRows = total

	case "dml":
		// Convert DML to a COUNT SELECT to estimate impact.
		countSQL := dmlToCountSQL(q)
		if countSQL != "" {
			row := conn.QueryRowContext(ctx, countSQL)
			var n int64
			if err := row.Scan(&n); err == nil {
				prev.EstimatedRows = n
			}
		}
		// Warn if no WHERE clause on UPDATE/DELETE.
		trimmed := strings.ToUpper(strings.TrimSpace(q))
		if (strings.HasPrefix(trimmed, "UPDATE") || strings.HasPrefix(trimmed, "DELETE")) &&
			!strings.Contains(trimmed, " WHERE ") {
			prev.Warning = "No WHERE clause — all rows in the table will be affected."
		}
		// Show a sample of what would be affected (first 5 rows).
		sampleSQL := dmlToSampleSQL(q)
		if sampleSQL != "" {
			srows, err := conn.QueryContext(ctx, sampleSQL)
			if err == nil {
				defer srows.Close()
				prev.SampleCols, _ = srows.Columns()
				for srows.Next() && len(prev.SampleRows) < 5 {
					vals := make([]interface{}, len(prev.SampleCols))
					ptrs := make([]interface{}, len(prev.SampleCols))
					for i := range vals { ptrs[i] = &vals[i] }
					_ = srows.Scan(ptrs...)
					row := make([]string, len(vals))
					for i, v := range vals { row[i] = valueStr(v) }
					prev.SampleRows = append(prev.SampleRows, row)
				}
			}
		}

	case "ddl":
		// For DDL, describe the operation — no safe preview execution.
		prev.Warning = "This is a schema-change (DDL) statement. It cannot be previewed — verify carefully before applying."
	}

	return prev
}

// classifySQL returns a coarse category for a SQL statement.
func classifySQL(upper string) string {
	upper = strings.TrimSpace(upper)
	for _, pfx := range []string{"SELECT", "SHOW", "EXPLAIN", "DESCRIBE", "DESC"} {
		if strings.HasPrefix(upper, pfx) { return "select" }
	}
	for _, pfx := range []string{"INSERT", "UPDATE", "DELETE", "REPLACE"} {
		if strings.HasPrefix(upper, pfx) { return "dml" }
	}
	for _, pfx := range []string{"CREATE", "ALTER", "DROP", "TRUNCATE", "RENAME"} {
		if strings.HasPrefix(upper, pfx) { return "ddl" }
	}
	return "other"
}

// dmlToCountSQL rewrites a DML statement into a SELECT COUNT(*) with the same WHERE clause.
// Returns "" if it can't be converted safely.
func dmlToCountSQL(q string) string {
	up := strings.ToUpper(strings.TrimSpace(q))

	if strings.HasPrefix(up, "DELETE FROM") || strings.HasPrefix(up, "DELETE ") {
		// DELETE FROM t WHERE ... → SELECT COUNT(*) FROM t WHERE ...
		rest := q[len("DELETE "):]
		if strings.HasPrefix(strings.ToUpper(rest), "FROM ") {
			return "SELECT COUNT(*) " + rest
		}
	}
	if strings.HasPrefix(up, "UPDATE ") {
		// UPDATE t SET col=val WHERE ... → SELECT COUNT(*) FROM t WHERE ...
		// Extract table name and WHERE clause.
		tokens := strings.Fields(q)
		if len(tokens) < 2 { return "" }
		table := tokens[1]
		whereIdx := strings.Index(strings.ToUpper(q), " WHERE ")
		if whereIdx >= 0 {
			return fmt.Sprintf("SELECT COUNT(*) FROM `%s` WHERE %s",
				escIdent(table), q[whereIdx+7:])
		}
		return fmt.Sprintf("SELECT COUNT(*) FROM `%s`", escIdent(table))
	}
	return ""
}

// dmlToSampleSQL rewrites a DML into a SELECT * LIMIT 5 to preview affected rows.
func dmlToSampleSQL(q string) string {
	up := strings.ToUpper(strings.TrimSpace(q))

	if strings.HasPrefix(up, "DELETE FROM") || strings.HasPrefix(up, "DELETE ") {
		rest := q[len("DELETE "):]
		if strings.HasPrefix(strings.ToUpper(rest), "FROM ") {
			return "SELECT * " + rest + " LIMIT 5"
		}
	}
	if strings.HasPrefix(up, "UPDATE ") {
		tokens := strings.Fields(q)
		if len(tokens) < 2 { return "" }
		table := tokens[1]
		whereIdx := strings.Index(strings.ToUpper(q), " WHERE ")
		if whereIdx >= 0 {
			return fmt.Sprintf("SELECT * FROM `%s` WHERE %s LIMIT 5",
				escIdent(table), q[whereIdx+7:])
		}
		return fmt.Sprintf("SELECT * FROM `%s` LIMIT 5", escIdent(table))
	}
	return ""
}

// InsertRow inserts a single row into db.table.
func (m *Manager) InsertRow(ctx context.Context, db, table string, cols []string, vals []string) error {
	if len(cols) == 0 {
		return fmt.Errorf("no columns provided")
	}
	escaped := make([]string, len(cols))
	placeholders := make([]string, len(cols))
	args := make([]interface{}, len(vals))
	for i, c := range cols {
		escaped[i] = "`" + escIdent(c) + "`"
		placeholders[i] = "?"
		if i < len(vals) {
			args[i] = vals[i]
		}
	}
	q := fmt.Sprintf("INSERT INTO `%s`.`%s` (%s) VALUES (%s)",
		escIdent(db), escIdent(table),
		strings.Join(escaped, ", "), strings.Join(placeholders, ", "))
	_, err := m.db.ExecContext(ctx, q, args...)
	return err
}

// UpdateRow updates a row identified by pkCol=pkVal.
func (m *Manager) UpdateRow(ctx context.Context, db, table, pkCol, pkVal string, cols []string, vals []string) error {
	if len(cols) == 0 {
		return fmt.Errorf("no columns to update")
	}
	sets := make([]string, len(cols))
	args := make([]interface{}, len(vals)+1)
	for i, c := range cols {
		sets[i] = fmt.Sprintf("`%s` = ?", escIdent(c))
		if i < len(vals) {
			args[i] = vals[i]
		}
	}
	args[len(vals)] = pkVal
	q := fmt.Sprintf("UPDATE `%s`.`%s` SET %s WHERE `%s` = ?",
		escIdent(db), escIdent(table),
		strings.Join(sets, ", "), escIdent(pkCol))
	_, err := m.db.ExecContext(ctx, q, args...)
	return err
}

// DeleteRow deletes a row by PK.
func (m *Manager) DeleteRow(ctx context.Context, db, table, pkCol, pkVal string) error {
	q := fmt.Sprintf("DELETE FROM `%s`.`%s` WHERE `%s` = ? LIMIT 1",
		escIdent(db), escIdent(table), escIdent(pkCol))
	_, err := m.db.ExecContext(ctx, q, pkVal)
	return err
}

// ── SQL script helpers ────────────────────────────────────────────────────

// ScriptResult summarises execution of a multi-statement SQL script.
type ScriptResult struct {
	Total    int
	Executed int
	Skipped  int
	Failed   int
	Errors   []string
	Elapsed  time.Duration
}

// SplitStatements splits a SQL script into individual statements,
// respecting single-quoted strings, double-quoted identifiers, and
// both line (--) and block (/* */) comments.
func SplitStatements(script string) []string {
	var stmts []string
	var cur strings.Builder
	inSingle, inDouble, inLine, inBlock := false, false, false, false

	runes := []rune(script)
	n := len(runes)
	peek := func(i int) rune {
		if i+1 < n {
			return runes[i+1]
		}
		return 0
	}

	for i := 0; i < n; i++ {
		c := runes[i]

		if inLine {
			if c == '\n' {
				inLine = false
				cur.WriteRune(c)
			}
			continue
		}
		if inBlock {
			if c == '*' && peek(i) == '/' {
				inBlock = false
				i++
			}
			continue
		}
		if !inSingle && !inDouble {
			if c == '-' && peek(i) == '-' {
				inLine = true
				i++
				continue
			}
			if c == '/' && peek(i) == '*' {
				inBlock = true
				i++
				continue
			}
		}
		if c == '\'' && !inDouble {
			// Handle escaped '' inside single-quoted strings
			if inSingle && peek(i) == '\'' {
				cur.WriteRune(c)
				i++
				cur.WriteRune(runes[i])
				continue
			}
			inSingle = !inSingle
		} else if c == '"' && !inSingle {
			inDouble = !inDouble
		} else if c == '\\' && (inSingle || inDouble) && i+1 < n {
			cur.WriteRune(c)
			i++
			cur.WriteRune(runes[i])
			continue
		}

		if c == ';' && !inSingle && !inDouble {
			if stmt := strings.TrimSpace(cur.String()); stmt != "" {
				stmts = append(stmts, stmt)
			}
			cur.Reset()
			continue
		}
		cur.WriteRune(c)
	}
	if stmt := strings.TrimSpace(cur.String()); stmt != "" {
		stmts = append(stmts, stmt)
	}
	return stmts
}

// skipStatement returns true for statements that should be silently skipped
// when running an uploaded SQL file (schema-management statements that target
// the server level rather than a specific database).
func skipStatement(sql string) bool {
	u := strings.ToUpper(strings.TrimSpace(sql))
	return strings.HasPrefix(u, "CREATE DATABASE") ||
		strings.HasPrefix(u, "DROP DATABASE") ||
		strings.HasPrefix(u, "USE ")
}

// RunScript splits script into statements, optionally skipping server-level
// statements, and executes each one on dbName. All errors are collected;
// execution continues even after failures.
func (m *Manager) RunScript(ctx context.Context, dbName, script string, skipServerLevel bool) *ScriptResult {
	start := time.Now()
	stmts := SplitStatements(script)
	res := &ScriptResult{Total: len(stmts)}

	conn, err := m.db.Conn(ctx)
	if err != nil {
		res.Errors = append(res.Errors, "connect: "+err.Error())
		res.Failed = len(stmts)
		res.Elapsed = time.Since(start)
		return res
	}
	defer conn.Close()

	if dbName != "" {
		if _, err := conn.ExecContext(ctx,
			fmt.Sprintf("USE `%s`", escIdent(dbName))); err != nil {
			res.Errors = append(res.Errors, "USE "+dbName+": "+err.Error())
			res.Failed = len(stmts)
			res.Elapsed = time.Since(start)
			return res
		}
	}

	for idx, stmt := range stmts {
		if skipServerLevel && skipStatement(stmt) {
			res.Skipped++
			continue
		}
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			res.Failed++
			// Trim long statements in the error message for readability
			preview := stmt
			if len(preview) > 120 {
				preview = preview[:120] + "…"
			}
			res.Errors = append(res.Errors,
				fmt.Sprintf("statement %d: %v\n  ↳ %s", idx+1, err, preview))
		} else {
			res.Executed++
		}
	}
	res.Elapsed = time.Since(start)
	return res
}
