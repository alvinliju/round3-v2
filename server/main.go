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

	"github.com/joho/godotenv"

	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

// store users locally
var profiles []Profile
var founders []Founder
var updates []Update
var subscriptions []Subscribe

type ContextKey string

const (
	UserContextKey ContextKey = "user"
)

type User struct {
	ID       primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	Username string             `json:"username"`
	Password string             `json:"password"`
	Role     string             `json:"role" default:"reader"`
}

// profile type
type Profile struct {
	UserRef primitive.ObjectID `bson:"userRef" json:"-"`
	Bio     string             `json:"bio"`
	Website string             `json:"website"`
}

// update type
type Update struct {
	ID      string `json:"id"`
	UserRef string `json:"username"`
	Title   string `json:"title"`
	Content string `json:"content"`
}

// founder type
type Founder struct {
	UserRef  string   `json:"username"`
	Updates  []Update `json:"updates"`
	StripeId string   `json:"stripe_id"`
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

func main() {

	r := http.NewServeMux()

	r.HandleFunc("/", homeHandler)
	r.HandleFunc("/register", userRegister)
	r.HandleFunc("/login", userLogin)
	r.HandleFunc("/create/profile", authMiddleware(createProfile))
	r.HandleFunc("/create/founder", creteFounder)
	r.HandleFunc("/create/updates", createUpdates)
	r.HandleFunc("/founder", fetchFounder)
	r.HandleFunc("/join/founder", joinUpdates)

	fmt.Println("Server started on port 8000")

	if err := http.ListenAndServe(":8000", r); err != nil {
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
				return nil, fmt.Errorf("Unexpected signing method", token.Header["alg"])
			}
			return SECRET, nil
		})

		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			ctx := context.WithValue(r.Context(), UserContextKey, claims)
			fmt.Println(ctx)
			fmt.Println(claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		} else {
			http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		}
	})
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
	err := collection.FindOne(context.TODO(), bson.M{"username": user.Username}).Decode(&existingUser)
	if err == nil {
		http.Error(w, "User already exists", http.StatusInternalServerError)
		return
	}

	if err != mongo.ErrNoDocuments {
		http.Error(w, "Error checking username", http.StatusInternalServerError)
		return
	}

	hashed, _ := bcrypt.GenerateFromPassword([]byte(user.Password), 12)
	user.Password = string(hashed)

	user.ID = primitive.NewObjectID()

	user.Role = "Reader"

	ctx := context.TODO()

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
	Username string `json:"username" `
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

	//find user in db
	var existingUserFromDB User
	ctx := context.TODO()
	err := collection.FindOne(ctx, bson.M{"username": userCredentials.Username}).Decode(&existingUserFromDB)

	if err == mongo.ErrNoDocuments {
		http.Error(w, "User doesnt exist", http.StatusNotFound)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(existingUserFromDB.Password), []byte(userCredentials.Password))
	if err != nil {
		http.Error(w, "Invalid Password", http.StatusUnauthorized)
		return
	}

	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userID": existingUserFromDB.ID.Hex(),
		"iss":    "round3dev",
		"role":   existingUserFromDB.Role,
		"exp":    time.Now().Add(time.Hour).Unix(),
		"iat":    time.Now().Unix(),
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

	UserData, ok := r.Context().Value(UserContextKey).(jwt.MapClaims)
	fmt.Println("create profile userdata:", UserData)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	userIDStr, ok := UserData["userID"].(string)
	if !ok {
		http.Error(w, "Invalid user ID", http.StatusUnauthorized)
		return
	}

	userID, err := primitive.ObjectIDFromHex(userIDStr)
	fmt.Println("userID:", userID)
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

	collection := db.Collection("profile")

	filter := bson.M{"userRef": userID}
	update := bson.M{"$set": profileData}
	opts := options.Update().SetUpsert(true)

	result, err := collection.UpdateOne(context.TODO(), filter, update, opts)
	_ = result
	if err != nil {
		http.Error(w, "Failed to save profile", http.StatusNotFound)
		return
	}

	var Updateduser Profile
	collection.FindOne(context.TODO(), filter).Decode(&Updateduser)

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

	existingUser, exists, index := findFounder(founders, founderData.UserRef)
	_ = existingUser
	if exists {
		founders[index].StripeId = founderData.StripeId
		founders[index].Updates = founderData.Updates
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(founders)
		return
	}

	founders = append(founders, founderData)

	response := Response{
		Status:  http.StatusCreated,
		Message: "Founder profile created",
		Data:    founders,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)

}

// helper for create founder
func findFounder(founders []Founder, currentUsername string) (*Founder, bool, int) {
	rangeCount := 0
	for _, exisingFounder := range founders {
		if currentUsername == exisingFounder.UserRef {
			return &exisingFounder, true, rangeCount
		}
		rangeCount++
	}

	return nil, false, rangeCount
}

// create Updates
func createUpdates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var updateData Update
	if err := json.NewDecoder(r.Body).Decode(&updateData); err != nil {
		http.Error(w, "Invalid Body", http.StatusBadRequest)
		return
	}

	updateData.ID = uuid.New().String()
	existngFounder, exists, index := findFounder(founders, updateData.UserRef)
	_ = existngFounder
	if exists {
		founders[index].Updates = append(founders[index].Updates, updateData)
	}

	updates = append(updates, updateData)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(updates)

}

// fetch founder profile
func fetchFounder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid Method", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("username")

	exisitngFounder, exists := fetchFounderHelper(id)

	if !exists {
		http.Error(w, "Founder doesnt exist", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/jso")
	w.WriteHeader(http.StatusFound)
	json.NewEncoder(w).Encode(exisitngFounder)
}

func fetchFounderHelper(founderId string) (*Founder, bool) {
	for _, founder := range founders {
		if founder.UserRef == founderId {
			return &founder, true
		}
	}

	return nil, false
}

// create a subscription
func joinUpdates(w http.ResponseWriter, r *http.Request) {
	var validate = validator.New()
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var subscriptionData Subscribe
	if err := json.NewDecoder(r.Body).Decode(&subscriptionData); err != nil {
		http.Error(w, "Invalid Body type", http.StatusBadRequest)
		return
	}

	if err := validate.Struct(subscriptionData); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if subscriptionData.Status != "success" {
		http.Error(w, "Subscription failed contact at round3adim@gmail.com to resolve", http.StatusBadRequest)
		return
	}

	subscriptions = append(subscriptions, subscriptionData)

	response := Response{
		Status:  http.StatusCreated,
		Message: "Subscibed succesfully",
		Data:    subscriptionData,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)

}
