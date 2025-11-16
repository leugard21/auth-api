package main

import (
	"auth-api/cmd/api"
	"auth-api/configs"
	"auth-api/db"
	"log"
)

func main() {
	storage, err := db.NewPostgresStorage(configs.Envs)
	if err != nil {
		log.Fatal(err)
	}

	server := api.NewAPIServer(":"+configs.Envs.Port, storage)

	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}
