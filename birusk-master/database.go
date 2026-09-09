package main

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

var DB *sql.DB

func InitDB(filepath string) {
	var err error
	DB, err = sql.Open("sqlite3", filepath)
	if err != nil {
		log.Fatal(err)
	}

	createTables := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		status TEXT DEFAULT 'active',
		data_limit INTEGER DEFAULT 0,
		expire_time INTEGER DEFAULT 0,
		vless_enabled INTEGER DEFAULT 1,
		trojan_enabled INTEGER DEFAULT 1,
		vmess_enabled INTEGER DEFAULT 1,
		custom_remark TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS nodes (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		type TEXT NOT NULL,
		address TEXT NOT NULL,
		clean_ip TEXT DEFAULT '',
		port INTEGER DEFAULT 443,
		transport TEXT DEFAULT 'ws',
		security TEXT DEFAULT 'tls',
		path TEXT DEFAULT '/',
		host TEXT DEFAULT '',
		pbk TEXT DEFAULT '',
		sid TEXT DEFAULT '',
		flow TEXT DEFAULT '',
		token TEXT UNIQUE NOT NULL,
		status TEXT DEFAULT 'active'
	);

	CREATE TABLE IF NOT EXISTS node_usage (
		user_id TEXT,
		node_id TEXT,
		bytes_used INTEGER DEFAULT 0,
		last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (user_id, node_id)
	);

	CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);
	`
	_, err = DB.Exec(createTables)
	if err != nil {
		log.Fatal(err)
	}

	// --- آپدیت‌های قبلی دیتابیس ---
	DB.Exec("ALTER TABLE users ADD COLUMN expire_time INTEGER DEFAULT 0;")
	DB.Exec("ALTER TABLE nodes ADD COLUMN clean_ip TEXT DEFAULT '';")
	DB.Exec("ALTER TABLE users ADD COLUMN vless_enabled INTEGER DEFAULT 1;")
	DB.Exec("ALTER TABLE users ADD COLUMN trojan_enabled INTEGER DEFAULT 1;")
	DB.Exec("ALTER TABLE users ADD COLUMN custom_remark TEXT DEFAULT '';")

	// --- آپدیت‌های فاز 1: ترنسپورت‌ها، پروتکل‌ها و امنیت (بدون حذف دیتا) ---
	DB.Exec("ALTER TABLE users ADD COLUMN vmess_enabled INTEGER DEFAULT 1;")
	
	DB.Exec("ALTER TABLE nodes ADD COLUMN port INTEGER DEFAULT 443;")
	DB.Exec("ALTER TABLE nodes ADD COLUMN transport TEXT DEFAULT 'ws';")
	DB.Exec("ALTER TABLE nodes ADD COLUMN security TEXT DEFAULT 'tls';")
	DB.Exec("ALTER TABLE nodes ADD COLUMN path TEXT DEFAULT '/';")
	DB.Exec("ALTER TABLE nodes ADD COLUMN host TEXT DEFAULT '';")
	DB.Exec("ALTER TABLE nodes ADD COLUMN pbk TEXT DEFAULT '';")
	DB.Exec("ALTER TABLE nodes ADD COLUMN sid TEXT DEFAULT '';")
	DB.Exec("ALTER TABLE nodes ADD COLUMN flow TEXT DEFAULT '';")

	// مقداردهی اولیه تنظیمات پیش‌فرض در صورت عدم وجود
	initDefaultSettings()
}

func initDefaultSettings() {
	defaults := map[string]string{
		"sub_domain":       "",
		"default_clean_ip": "",
		"enable_stats":     "1",
		"mtproto_enabled":  "0",
		"mtproto_port":     "8566",
		"mtproto_secret":   "",
		"mtproto_tag":      "",
	}

	for k, v := range defaults {
		_, _ = DB.Exec("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", k, v)
	}
}

func RecordUsage(userID string, nodeID string, bytes int64) error {
	query := `
	INSERT INTO node_usage (user_id, node_id, bytes_used) 
	VALUES (?, ?, ?)
	ON CONFLICT(user_id, node_id) 
	DO UPDATE SET bytes_used = bytes_used + ?, last_updated = CURRENT_TIMESTAMP;
	`
	_, err := DB.Exec(query, userID, nodeID, bytes, bytes)
	return err
}

func GetTotalUsage(userID string) (int64, error) {
	var total sql.NullInt64
	err := DB.QueryRow("SELECT SUM(bytes_used) FROM node_usage WHERE user_id = ?", userID).Scan(&total)
	if err != nil {
		return 0, err
	}
	if total.Valid {
		return total.Int64, nil
	}
	return 0, nil
}

func ValidateNodeToken(token string) (string, error) {
	var nodeID string
	err := DB.QueryRow("SELECT id FROM nodes WHERE token = ? AND status = 'active'", token).Scan(&nodeID)
	if err != nil {
		return "", err
	}
	return nodeID, nil
}