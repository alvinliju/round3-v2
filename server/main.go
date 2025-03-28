package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func main() {

	r := http.NewServeMux()

	r.HandleFunc("/", homeHandler)
	r.HandleFunc("/register", userRegister)
	r.HandleFunc("/login", userLogin)

	fmt.Println("Server started on port 8000")

	if err := http.ListenAndServe(":8000", r); err != nil {
		fmt.Println("Error starting the server")
	}

}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello world"))
}

// Register Route
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Response struct {
	Status  int         `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

// store users locally
var users []User

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

	// response := Response{
	// 	Status:  http.StatusCreated,
	// 	Message: "User created",
	// 	Data:    user.Username,
	// }

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(users)
}

// Login Route
type loginUser struct {
	Username string `json:"username" `
	Password string `json:"password" `
}

func findUser(users []User, targetUsername string) (*User, bool) {
	for _, user := range users {
		if user.Username == targetUsername {
			return &user, true
		}

	}
	return nil, false
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
