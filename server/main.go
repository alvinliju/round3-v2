package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

// store users locally

var subscriptions []Subscribe

type ContextKey string

const (
	UserContextKey ContextKey = "user"
)

type User struct {
	ID         primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	Username   string             `json:"username" validate:"required"`
	Email      string             `json:"email" validate:"required,email"`
	Password   string             `json:"password" validate:"required, min=8"`
	Role       string             `json:"role" default:"reader"`
	Onboarding bool               `json:"onboarding"`
}

// profile type
type Profile struct {
	UserRef    primitive.ObjectID `bson:"userRef" json:"-"`
	Bio        string             `json:"bio"`
	Website    string             `json:"website"`
	ProfileUrl string             `json:"profileurl"`
	Twitter    string             `json:"twitter"`
}

// update type
type Update struct {
	ID      primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	UserRef primitive.ObjectID `bson:"userRef" json:"-"`
	Title   string             `json:"title"`
	Content string             `json:"content"`
}

// founder type
type Founder struct {
	UserRef       primitive.ObjectID `bson:"userRef" json:"-"`
	Updates       []Update           `json:"updates"`
	WalletAddress string             `json:"wallet_addr"`
}

type Onboarding struct {
	ProfileUrl string `json:"profileUrl"`
	Bio        string `json:"bio"`
	Website    string `json:"website"`
	Twitter    string `json:"twitter"`
}

// subscription type
type Subscribe struct {
	UserRef    string `json:"username"`
	FounderRef string `json:"founder_username"`
	Amount     string `json:"amount"`
	Status     string `json:"status" validate:"oneof=pending success failed"`
}

type Response struct {
	Status  int         `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

var db *mongo.Database
var SECRET []byte

func init() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	SECRET = []byte(os.Getenv("SECRET"))

	MONGO_URI := os.Getenv("MONGO_URI")

	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(MONGO_URI))
	if err != nil {
		log.Fatal("DB connection failed:", err)
	}

	db = client.Database("round3V2")
	fmt.Println("Connected to database")
}

func enableCors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*") // Allow all origins
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func main() {

	r := http.NewServeMux()

	r.HandleFunc("/", homeHandler)
	r.HandleFunc("/register", userRegister)
	r.HandleFunc("/login", userLogin)
	r.HandleFunc("/create/profile", authMiddleware(founderOnlyMiddleware(createProfile)))
	r.HandleFunc("/create/founder", authMiddleware(creteFounder))
	r.HandleFunc("/create/updates", authMiddleware(createUpdates))
	r.HandleFunc("/founder", authMiddleware(fetchFounder))
	// r.HandleFunc("/join/founder", authMijoinUpdates(joinFounder))
	//

	//onboard handler
	r.HandleFunc("/onboarding", authMiddleware(founderOnlyMiddleware(onbaordFounder)))

	handler := enableCors(r)
	fmt.Println("Server started on port 8000")

	if err := http.ListenAndServe(":8000", handler); err != nil {
		fmt.Println("Error starting the server")
	}

}

// middleware
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Auth header not found", http.StatusBadRequest)
			return
		}

		tokenString := strings.Replace(authHeader, "Bearer ", "", 1)

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method %v", token.Header["alg"])
			}
			return SECRET, nil
		})

		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			ctx := context.WithValue(r.Context(), UserContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		} else {
			http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		}
	})
}

func founderOnlyMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(UserContextKey).(jwt.MapClaims)
		if !ok || claims["role"] != "founder" {
			errResponse := Response{
				Status:  http.StatusUnauthorized,
				Message: "Forbidden - Founder access only",
				Data:    nil,
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(errResponse)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// helper function to extract userId from jwt
func extractUserIdFromJwt(r *http.Request) (primitive.ObjectID, error) {
	UserData, ok := r.Context().Value(UserContextKey).(jwt.MapClaims)

	if !ok {
		return primitive.NilObjectID, fmt.Errorf("unauthorized: invalid token")
	}

	userIDStr, ok := UserData["userID"].(string)
	if !ok {
		return primitive.NilObjectID, fmt.Errorf("unauthorized: invalid user ID format")
	}

	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		return primitive.NilObjectID, fmt.Errorf("unauthorized: invalid user ID")
	}

	return userID, nil

}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello world"))
}

// Register Route
func userRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	//create a new user instance
	var user User

	//Decode JSON from request coz go doesnt understand json by default
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid Request body", http.StatusBadRequest)
		return
	}

	collection := db.Collection("users")

	var existingUser User
	err := collection.FindOne(r.Context(), bson.M{"username": user.Username}).Decode(&existingUser)
	if err == nil {
		error := Response{
			Status:  http.StatusConflict,
			Message: "User already exists. Please try logging in or choose another username.",
			Data:    nil,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(error)
		return
	}

	var existingEmailUser User
	err = collection.FindOne(r.Context(), bson.M{"email": user.Email}).Decode(&existingEmailUser)
	if err == nil {
		error := Response{
			Status:  http.StatusConflict,
			Message: "User already exists. Please try logging in or choose another email.",
			Data:    nil,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(error)
		return
	}

	hashed, _ := bcrypt.GenerateFromPassword([]byte(user.Password), 12)
	user.Password = string(hashed)

	if user.Role == "" {
		user.Role = "reader"
	}

	user.Role = strings.ToLower(user.Role)
	user.Onboarding = false

	ctx := r.Context()

	result, err := collection.InsertOne(ctx, user)
	if err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	response := Response{
		Status:  http.StatusCreated,
		Message: "User created",
		Data:    map[string]interface{}{"id": result.InsertedID, "username": user.Username},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// Login Route
type loginUser struct {
	Email    string `json:"email" `
	Password string `json:"password" `
}

func userLogin(w http.ResponseWriter, r *http.Request) {

	collection := db.Collection("users")

	if r.Method != http.MethodPost {
		http.Error(w, "Invalid Method", http.StatusMethodNotAllowed)
		return
	}

	var userCredentials loginUser
	if err := json.NewDecoder(r.Body).Decode(&userCredentials); err != nil {
		http.Error(w, "Invalid Request Body", http.StatusBadRequest)
		return
	}

	if userCredentials.Email == "" || userCredentials.Password == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Status:  http.StatusBadRequest,
			Message: "Email and password are required",
			Data:    nil,
		})
		return
	}

	//find user in db
	var existingUserFromDB User
	ctx := r.Context()
	err := collection.FindOne(ctx, bson.M{"email": userCredentials.Email}).Decode(&existingUserFromDB)

	if err == mongo.ErrNoDocuments {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(Response{
			Status:  http.StatusNotFound,
			Message: "User does not exist",
			Data:    nil,
		})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(existingUserFromDB.Password), []byte(userCredentials.Password))
	if err != nil {
		http.Error(w, "Invalid Password", http.StatusUnauthorized)
		return
	}

	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userID":     existingUserFromDB.ID.Hex(),
		"iss":        "round3dev",
		"role":       existingUserFromDB.Role,
		"onboarding": existingUserFromDB.Onboarding,
		"exp":        time.Now().Add(time.Hour).Unix(),
		"iat":        time.Now().Unix(),
	})

	token, err := claims.SignedString(SECRET)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	type MetadataWithToken struct {
		Token    string
		Username string
	}

	metadata := MetadataWithToken{
		Token:    token,
		Username: existingUserFromDB.Username,
	}

	response := Response{
		Status:  http.StatusAccepted,
		Message: "Login Success",
		Data:    metadata,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(response)
}

// Crete profile route
func createProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid Method", http.StatusBadRequest)
		return
	}

	// userID, err := primitive.ObjectIDFromHex(userIDStr)
	userID, err := extractUserIdFromJwt(r)

	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusUnauthorized)
		return
	}

	var profileData Profile
	if err := json.NewDecoder(r.Body).Decode(&profileData); err != nil {
		http.Error(w, "Invalid Request Body", http.StatusBadRequest)
		return
	}

	profileData.UserRef = userID

	collection := db.Collection("profiles")

	filter := bson.M{"userRef": userID}
	update := bson.M{"$set": profileData}
	opts := options.Update().SetUpsert(true)

	result, err := collection.UpdateOne(r.Context(), filter, update, opts)
	_ = result
	if err != nil {
		http.Error(w, "Failed to save profile", http.StatusNotFound)
		return
	}

	var Updateduser Profile
	collection.FindOne(r.Context(), filter).Decode(&Updateduser)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(Updateduser)

}

// create a founder
func creteFounder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var founderData Founder
	if err := json.NewDecoder(r.Body).Decode(&founderData); err != nil {
		http.Error(w, "Invalid Body requst", http.StatusBadRequest)
		return
	}

	userID, err := extractUserIdFromJwt(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	//see if founder exists then update if not create a new one
	founderData.UserRef = userID

	filter := bson.M{"userRef": userID}
	update := bson.M{"$set": founderData}
	opts := options.Update().SetUpsert(true)

	collections := db.Collection("founders")

	result, err := collections.UpdateOne(r.Context(), filter, update, opts)
	_ = result
	if err != nil {
		http.Error(w, "Error Creating Founder Profile", http.StatusNotModified)
		return
	}

	var updatedFounder Founder
	err = collections.FindOne(r.Context(), filter).Decode(&updatedFounder)
	if err != nil {
		http.Error(w, "Error fetching updated founder", http.StatusInternalServerError)
		return
	}

	response := Response{
		Status:  http.StatusCreated,
		Message: "Founder profile created",
		Data:    updatedFounder,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)

}

// create Updates
func createUpdates(w http.ResponseWriter, r *http.Request) {
	collection := db.Collection("updates")

	userID, err := extractUserIdFromJwt(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var updateData Update
	if err := json.NewDecoder(r.Body).Decode(&updateData); err != nil {
		http.Error(w, "Invalid Body", http.StatusBadRequest)
		return
	}

	updateData.UserRef = userID

	result, err := collection.InsertOne(r.Context(), updateData)
	if err != nil {
		http.Error(w, "Error creating updates in database", http.StatusInternalServerError)
		return
	}

	var addedUpdate Update
	fmt.Println(result.InsertedID)
	findNewUpdateFilter := bson.M{"_id": result.InsertedID}
	err = collection.FindOne(r.Context(), findNewUpdateFilter).Decode(&addedUpdate)
	if err != nil {
		http.Error(w, "Error fetching new update", http.StatusInternalServerError)
		return
	}

	//TODO: embed the newly create update ID to founder document
	filter := bson.M{"userRef": userID}
	update := bson.M{
		"$set": bson.M{
			"updates": []Update{}, // Initialize if doesn't exist
		},
		"$push": bson.M{
			"updates": addedUpdate.ID,
		},
	}

	_, err = db.Collection("founders").UpdateOne(r.Context(), filter, update)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(addedUpdate)

}

// fetch founder profile

func fetchFounder(w http.ResponseWriter, r *http.Request) {

	collection := db.Collection("founders")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.URL.Query().Get("username")

	var fetchedFounder Founder

	collection.FindOne(r.Context(), bson.M{"username": username}).Decode(&fetchedFounder)

	response := Response{
		Status:  http.StatusFound,
		Message: "Fetched founder success",
		Data:    fetchedFounder,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

func onbaordFounder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var onbardingData Onboarding
	if err := json.NewDecoder(r.Body).Decode(&onbardingData); err != nil {
		http.Error(w, "Invalid Body requst", http.StatusBadRequest)
		return
	}

	userID, err := extractUserIdFromJwt(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	userFilter := bson.M{"_id": userID}
	userUpdate := bson.M{"$set": bson.M{"onboarding": true}}
	userOpts := options.Update().SetUpsert(true)

	usersCollection := db.Collection("users")

	result, err := usersCollection.UpdateOne(r.Context(), userFilter, userUpdate, userOpts)
	_ = result
	if err != nil {
		http.Error(w, "Error Creating Founder Profile", http.StatusNotModified)
		return
	}

	//founder table update
	founderData := Founder{
		UserRef:       userID,
		Updates:       nil,
		WalletAddress: "",
	}

	founderUpdate := bson.M{"$set": founderData}
	opts := options.Update().SetUpsert(true)

	_, err = db.Collection("founders").UpdateOne(r.Context(), userFilter, founderUpdate, opts)
	if err != nil {
		errResponse := Response{
			Status:  http.StatusInternalServerError,
			Message: "Failed to update founder information",
			Data:    nil,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errResponse)

	}

	//profile update
	profileData := Profile{
		UserRef:    userID,
		ProfileUrl: onbardingData.ProfileUrl,
		Bio:        onbardingData.Bio,
		Website:    onbardingData.Website,
		Twitter:    onbardingData.Twitter,
	}

	profileUpdate := bson.M{"$set": profileData}
	profileOpts := options.Update().SetUpsert(true)

	_, err = db.Collection("profiles").UpdateOne(r.Context(), userFilter, profileUpdate, profileOpts)
	if err != nil {
		errResponse := Response{
			Status:  http.StatusInternalServerError,
			Message: "Failed to update profile information",
			Data:    nil,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errResponse)

	}

	response := Response{
		Status:  http.StatusCreated,
		Message: "Founder profile created",
		Data:    nil,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)

}

// // create a subscription
// func joinFounder(w http.ResponseWriter, r *http.Request) {
// 	userID, err := extractUserIdFromJwt(r)
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// 	if r.Method != http.MethodPost {
// 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 		return
// 	}

// 	var subscriptionData Subscribe
// 	if err := json.NewDecoder(r.Body).Decode(&subscriptionData); err != nil {
// 		http.Error(w, "Invalid Body type", http.StatusBadRequest)
// 		return
// 	}

// 	if err := validate.Struct(subscriptionData); err != nil {
// 		http.Error(w, err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	if subscriptionData.Status != "success" {
// 		http.Error(w, "Subscription failed contact at round3adim@gmail.com to resolve", http.StatusBadRequest)
// 		return
// 	}

// 	subscriptions = append(subscriptions, subscriptionData)

// 	response := Response{
// 		Status:  http.StatusCreated,
// 		Message: "Subscibed succesfully",
// 		Data:    subscriptionData,
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(http.StatusCreated)
// 	json.NewEncoder(w).Encode(response)

// }
