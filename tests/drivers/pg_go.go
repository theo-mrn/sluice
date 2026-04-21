// pgx (Go) against sluice (run by tests/drivers.py in a container). Prints what the application saw.
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
	if _, err := conn.Exec(ctx, "delete from t where n <= $1", 20); err != nil {
		fmt.Println("ERR", err)
	} else {
		fmt.Println("NOERROR")
	}
	tag, err := conn.Exec(ctx, os.Args[2])
	if err != nil {
		fmt.Println("ERR2", err)
	} else {
		fmt.Println("ANSWER", tag.String())
	}
	var n int
	if err := conn.QueryRow(ctx, "select count(*) from t").Scan(&n); err != nil {
		fmt.Println("ERR3", err)
	} else {
		fmt.Println("COUNT", n)
	}
}
