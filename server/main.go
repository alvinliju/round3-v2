package main

import (
	"context"
	"log"

	"github.com/alvinliju/round3-v2/server/config"
)

func main(){
	client, err := config.ConnectToMongoDB()
    if err != nil {
        log.Fatal(err)
    }
    defer client.Disconnect(context.TODO())
}
