package config

import (
	"context"
	"fmt"
	"os"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)




func ConnectToMongoDB()(*mongo.Client, error){

	uri := os.Getenv("MONGODB_URI")
	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	opts := options.Client().ApplyURI(uri).SetServerAPIOptions(serverAPI)
	client, err := mongo.Connect(context.TODO(), opts)
	if err != nil {
			panic(err)
		}
		defer func() {
			if err = client.Disconnect(context.TODO()); err != nil {
				panic(err)
			}
		}()
		// Send a ping to confirm a successful connection
		var result bson.M
		if err := client.Database("round3").RunCommand(context.TODO(), bson.D{{"ping", 1}}).Decode(&result); err != nil {
			panic(err)
		}
		fmt.Println("Pinged your deployment. You successfully connected to MongoDB!")

		return client, err
}
