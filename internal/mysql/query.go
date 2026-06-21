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
