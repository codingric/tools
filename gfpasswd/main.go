package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/pbkdf2"
	_ "modernc.org/sqlite"
)

func main() {
	db, err := sql.Open("sqlite", "grafana.db")
	if err != nil {
		log.Fatalf("Unable to connect to db: %s", err)
	}
	defer db.Close()

	password := os.Getenv("GF_SECURITY_ADMIN_PASSWORD")

	var salt string
	err = db.QueryRow("SELECT salt FROM user WHERE login = 'admin';").Scan(&salt)
	if err != nil {
		log.Fatalf("Failed to query: %s", err)
	}
	passwd := pbkdf2.Key([]byte(password), []byte(salt), 10000, 50, sha256.New)

	_, err = db.Exec("UPDATE user SET password = ? WHERE login = 'admin'", hex.EncodeToString(passwd))
	if err != nil {
		panic(err.Error())
	}

	fmt.Println("admin password updated")
}
