package mysql

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const playgroundPrefix = "_fa_playground_"

// IsPlaygroundDB reports whether a database name is a FlashAccess playground.
func IsPlaygroundDB(name string) bool {
	return strings.HasPrefix(name, playgroundPrefix)
}

// PlaygroundDBName returns the canonical playground name for a session ID.
func PlaygroundDBName(sessionID string) string {
	// Keep it short: prefix + first 8 chars of session ID.
	short := sessionID
	if len(short) > 8 {
		short = short[:8]
	}
	return playgroundPrefix + short
}

// CreatePlaygroundDB creates a new empty playground database.
func (m *Manager) CreatePlaygroundDB(ctx context.Context, name string) error {
	if !IsPlaygroundDB(name) {
		return fmt.Errorf("playground database names must start with %q", playgroundPrefix)
	}
	_, err := m.db.ExecContext(ctx,
		fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci", escIdent(name)))
	return err
}

// DropPlaygroundDB drops a playground database. Refuses non-playground names.
func (m *Manager) DropPlaygroundDB(ctx context.Context, name string) error {
	if !IsPlaygroundDB(name) {
		return fmt.Errorf("refusing to drop %q — not a playground database", name)
	}
	_, err := m.db.ExecContext(ctx, fmt.Sprintf("DROP DATABASE IF EXISTS `%s`", escIdent(name)))
	return err
}

// CloneDatabase copies the schema and data from src into dst (which must already exist).
// Tables are copied in definition order using CREATE TABLE … SELECT.
func (m *Manager) CloneDatabase(ctx context.Context, src, dst string) error {
	if !dbNamePattern.MatchString(src) && !IsPlaygroundDB(src) {
		return fmt.Errorf("invalid source database name %q", src)
	}
	if !IsPlaygroundDB(dst) {
		return fmt.Errorf("clone destination must be a playground database (got %q)", dst)
	}

	tables, err := m.ListTables(ctx, src)
	if err != nil {
		return fmt.Errorf("list tables: %w", err)
	}

	for _, t := range tables {
		// 1. Copy table structure.
		createSQL := fmt.Sprintf(
			"CREATE TABLE `%s`.`%s` LIKE `%s`.`%s`",
			escIdent(dst), escIdent(t.Name),
			escIdent(src), escIdent(t.Name),
		)
		if _, err := m.db.ExecContext(ctx, createSQL); err != nil {
			return fmt.Errorf("create table %q in playground: %w", t.Name, err)
		}
		// 2. Copy data (honour a 5-minute per-table budget for very large tables).
		copyCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		_, copyErr := m.db.ExecContext(copyCtx, fmt.Sprintf(
			"INSERT INTO `%s`.`%s` SELECT * FROM `%s`.`%s`",
			escIdent(dst), escIdent(t.Name),
			escIdent(src), escIdent(t.Name),
		))
		cancel()
		if copyErr != nil {
			return fmt.Errorf("copy data for table %q: %w", t.Name, copyErr)
		}
	}
	return nil
}

// GenerateSampleDatabase populates dst with a small e-commerce sample schema.
func (m *Manager) GenerateSampleDatabase(ctx context.Context, dst string) error {
	if !IsPlaygroundDB(dst) {
		return fmt.Errorf("sample target must be a playground database (got %q)", dst)
	}

	db := escIdent(dst)
	stmts := []string{
		// ── Schema ────────────────────────────────────────────────────────
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS `+"`"+`%s`+"`"+`.`+"`"+`customers`+"`"+` (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name        VARCHAR(120) NOT NULL,
  email       VARCHAR(200) NOT NULL UNIQUE,
  country     VARCHAR(60)  NOT NULL DEFAULT 'US',
  created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_country (country)
) ENGINE=InnoDB`, dst),

		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS `+"`"+`%s`+"`"+`.`+"`"+`products`+"`"+` (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  sku         VARCHAR(40)  NOT NULL UNIQUE,
  name        VARCHAR(200) NOT NULL,
  price       DECIMAL(10,2) NOT NULL,
  stock       INT UNSIGNED NOT NULL DEFAULT 0,
  category    VARCHAR(80),
  INDEX idx_category (category)
) ENGINE=InnoDB`, dst),

		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS `+"`"+`%s`+"`"+`.`+"`"+`orders`+"`"+` (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  customer_id INT UNSIGNED NOT NULL,
  status      ENUM('pending','paid','shipped','cancelled') NOT NULL DEFAULT 'pending',
  total       DECIMAL(12,2) NOT NULL,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_orders_customer FOREIGN KEY (customer_id) REFERENCES `+"`"+`customers`+"`"+` (id),
  INDEX idx_status (status),
  INDEX idx_customer (customer_id)
) ENGINE=InnoDB`, dst),

		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS `+"`"+`%s`+"`"+`.`+"`"+`order_items`+"`"+` (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  order_id    INT UNSIGNED NOT NULL,
  product_id  INT UNSIGNED NOT NULL,
  qty         SMALLINT UNSIGNED NOT NULL DEFAULT 1,
  unit_price  DECIMAL(10,2) NOT NULL,
  CONSTRAINT fk_items_order   FOREIGN KEY (order_id)   REFERENCES `+"`"+`orders`+"`"+`   (id),
  CONSTRAINT fk_items_product FOREIGN KEY (product_id) REFERENCES `+"`"+`products`+"`"+` (id),
  INDEX idx_order (order_id)
) ENGINE=InnoDB`, dst),

		// ── Data ──────────────────────────────────────────────────────────
		fmt.Sprintf("INSERT INTO `%s`.`customers` (name, email, country) VALUES"+
			"('Alice Martin','alice@example.com','US'),"+
			"('Bob Tanaka','bob@example.com','JP'),"+
			"('Clara Dupont','clara@example.com','FR'),"+
			"('David Osei','david@example.com','GH'),"+
			"('Eva Rossi','eva@example.com','IT'),"+
			"('Felix Bauer','felix@example.com','DE'),"+
			"('Grace Liu','grace@example.com','CN'),"+
			"('Hiro Yamamoto','hiro@example.com','JP')", dst),

		fmt.Sprintf("INSERT INTO `%s`.`products` (sku, name, price, stock, category) VALUES"+
			"('SKU-001','Wireless Keyboard',49.99,200,'Electronics'),"+
			"('SKU-002','USB-C Hub',29.95,150,'Electronics'),"+
			"('SKU-003','Notebook A5',4.99,500,'Stationery'),"+
			"('SKU-004','Desk Lamp',39.00,80,'Furniture'),"+
			"('SKU-005','Monitor Stand',55.00,60,'Furniture'),"+
			"('SKU-006','Mechanical Pencil Set',12.50,300,'Stationery'),"+
			"('SKU-007','Webcam 1080p',79.99,40,'Electronics'),"+
			"('SKU-008','Noise-Cancelling Headphones',149.00,25,'Electronics')", dst),

		fmt.Sprintf("INSERT INTO `%s`.`orders` (customer_id, status, total, created_at) VALUES"+
			"(1,'paid',79.94,'2024-11-01 09:12:00'),"+
			"(2,'shipped',149.00,'2024-11-03 14:22:00'),"+
			"(3,'pending',4.99,'2024-11-05 08:05:00'),"+
			"(1,'paid',84.99,'2024-11-10 16:30:00'),"+
			"(4,'cancelled',39.00,'2024-11-12 11:00:00'),"+
			"(5,'paid',229.95,'2024-11-15 19:45:00'),"+
			"(6,'shipped',55.00,'2024-11-18 10:00:00'),"+
			"(7,'pending',79.99,'2024-11-20 07:33:00')", dst),

		fmt.Sprintf("INSERT INTO `%s`.`order_items` (order_id, product_id, qty, unit_price) VALUES"+
			"(1,1,1,49.99),(1,2,1,29.95),"+
			"(2,8,1,149.00),"+
			"(3,3,1,4.99),"+
			"(4,7,1,79.99),(4,3,1,4.99),"+
			"(5,4,1,39.00),"+
			"(6,2,3,29.95),(6,5,1,55.00),(6,8,1,149.00),"+
			"(7,5,1,55.00),"+
			"(8,7,1,79.99)", dst),
	}

	for _, s := range stmts {
		if _, err := m.db.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("generate sample: %w", err)
		}
	}
	return nil
}

// ListPlaygroundDBs returns all playground databases visible to the admin user.
func (m *Manager) ListPlaygroundDBs(ctx context.Context) ([]string, error) {
	dbs, err := m.ListDatabases(ctx)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, db := range dbs {
		if IsPlaygroundDB(db) {
			out = append(out, db)
		}
	}
	return out, nil
}
