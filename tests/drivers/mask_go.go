// pgx (Go) against sluice, reading rows that must be hidden (run by tests/drivers.py in a container).
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5"
)

func main() {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, "postgres://postgres@host.docker.internal:"+os.Args[1]+"/postgres?sslmode=disable")
	if err != nil {
		fmt.Println("FATAL", err)
		os.Exit(1)
	}
	defer conn.Close(ctx)
	read := func(tag, sql string, args ...any) {
		rows, err := conn.Query(ctx, sql, args...)
		if err != nil {
			fmt.Println("ERR", tag, err)
			return
		}
		defer rows.Close()
		for rows.Next() {
			var id int
			var email, note *string
			if err := rows.Scan(&id, &email, &note); err != nil {
				fmt.Println("ERR", tag, err)
				return
			}
			e, n := "NULL", "NULL"
			if email != nil {
				e = *email
			}
			if note != nil {
				n = *note
			}
			fmt.Println(tag, id, e, n)
		}
	}
	read("QUERY", "select id, email, note from people where id <= $1 order by id", 3)
	read("AGAIN", "select id, email, note from people where id <= $1 order by id", 3) // statement cache: no Describe
	// a batch: several Executes in one go
	batch := &pgx.Batch{}
	for i := 1; i <= 3; i++ {
		batch.Queue("select id, email, note from people where id = $1", i)
	}
	br := conn.SendBatch(ctx, batch)
	for i := 0; i < 3; i++ {
		var id int
		var email, note *string
		if err := br.QueryRow().Scan(&id, &email, &note); err != nil {
			fmt.Println("ERR BATCH", err)
		} else {
			fmt.Println("BATCH", id, *email, *note)
		}
	}
	br.Close()
}
