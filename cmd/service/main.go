package main

import (
	"log"

	"go.redsock.ru/ruf/cyan-room/internal/app"
)

func main() {
	a, err := app.New()
	if err != nil {
		log.Fatal(err)
	}

	err = a.Start()
	if err != nil {
		log.Fatal(err)
	}
}
