package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// store users locally
var users []User
var profiles []Profile
var founders []Founder
var updates []Update
var subscriptions []Subscribe

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role" default:"user"`
}

// profile type
type Profile struct {
	UserRef string `json:"username"`
	Bio     string `json:"bio"`
	Website string `json:"website"`
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

func init() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}

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
	r.HandleFunc("/create/profile", createProfile)
	r.HandleFunc("/create/founder", creteFounder)
	r.HandleFunc("/create/updates", createUpdates)
	r.HandleFunc("/founder", fetchFounder)
	r.HandleFunc("/join/founder", joinUpdates)

	fmt.Println("Server started on port 8000")

	if err := http.ListenAndServe(":8000", r); err != nil {
		fmt.Println("Error starting the server")
	}

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

	//add user to local db
	users = append(users, user)
	_ = users

	response := Response{
		Status:  http.StatusCreated,
		Message: "User created",
		Data:    user.Username,
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
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid Method", http.StatusMethodNotAllowed)
		return
	}

	var userCredentials loginUser
	if err := json.NewDecoder(r.Body).Decode(&userCredentials); err != nil {
		http.Error(w, "Invalid Request Body", http.StatusBadRequest)
		return
	}

	existingUser, exists := findUser(users, userCredentials.Username)
	if !exists {
		http.Error(w, "Invalid Username", http.StatusUnauthorized)
		return
	}

	if userCredentials.Password != existingUser.Password {
		http.Error(w, "Invalid Password", http.StatusUnauthorized)
		return
	}

	response := Response{
		Status:  http.StatusAccepted,
		Message: "Login Success",
		Data:    userCredentials.Username,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(response)
}

// helper for login
func findUser(users []User, targetUsername string) (*User, bool) {
	for _, user := range users {
		if user.Username == targetUsername {
			return &user, true
		}

	}
	return nil, false
}

// Crete profile route
func createProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid Method", http.StatusBadRequest)
		return
	}

	//no need to do validation will verify userinfo via jwt since no we are not in prod we can get username from body

	var profileData Profile
	if err := json.NewDecoder(r.Body).Decode(&profileData); err != nil {
		http.Error(w, "Invalid Request Body", http.StatusBadRequest)
		return
	}

	existingProfile, exists, rangeCount := findProfiles(profiles, profileData.UserRef)
	_ = existingProfile

	if exists {
		profiles[rangeCount].Bio = profileData.Bio
		profiles[rangeCount].Website = profileData.Website

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(profiles)

		return
	}

	profiles = append(profiles, profileData)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(profiles)

}

// helper for createProfile
func findProfiles(profiles []Profile, currentUsername string) (*Profile, bool, int) {
	rangeCount := 0
	for _, existingProfile := range profiles {
		if currentUsername == existingProfile.UserRef {
			return &existingProfile, true, rangeCount
		}
		rangeCount++
	}

	return nil, false, rangeCount
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
