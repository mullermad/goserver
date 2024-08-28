// package main

// import (
// 	"bytes"
// 	"encoding/json"
// 	"errors"
// 	"fmt"
// 	"io/ioutil"
// 	"log"
// 	"net/http"
// 	"time"

// 	"github.com/dgrijalva/jwt-go"
// 	"github.com/gorilla/mux"
// 	"golang.org/x/crypto/bcrypt"
// )

// var jwtSecret = []byte("your_secret_key_here") // Replace with your own secret key

// type ActionPayload struct {
// 	SessionVariables map[string]interface{} `json:"session_variables"`
// 	Input            signupArgs             `json:"input"`
// }

// type GraphQLError struct {
// 	Message string `json:"message"`
// }

// type GraphQLRequest struct {
// 	Query     string      `json:"query"`
// 	Variables interface{} `json:"variables"`
// }

// type GraphQLData struct {
// 	Insert_user_one signupOutput `json:"insert_user_one"`
// 	User            []userOutput `json:"user"` // Changed to array
// }

// type GraphQLResponse struct {
// 	Data   GraphQLData    `json:"data,omitempty"`
// 	Errors []GraphQLError `json:"errors,omitempty"`
// }

// type signupArgs struct {
// 	Username string `json:"username"`
// 	Email    string `json:"email"`
// 	Password string `json:"password"`
// }

// type loginArgs struct {
// 	Email    string `json:"email"`
// 	Password string `json:"password"`
// }

// type signupOutput struct {
// 	UserID string `json:"user_id"`
// }

// type userOutput struct {
// 	UserID   string `json:"user_id"`
// 	Password string `json:"password"`
// 	Role     string `json:"role"` // Add role here
// }

// type JWTClaims struct {
// 	UserID string `json:"user_id"`
// 	jwt.StandardClaims
// }

// func helloHandler(w http.ResponseWriter, r *http.Request) {
// 	fmt.Fprint(w, "Hello Muller, welcome to Go!")
// }

// func signupHandler(w http.ResponseWriter, r *http.Request) {
// 	w.Header().Set("Content-Type", "application/json")

// 	reqBody, err := ioutil.ReadAll(r.Body)
// 	if err != nil {
// 		http.Error(w, "invalid payload", http.StatusBadRequest)
// 		return
// 	}

// 	var actionPayload ActionPayload
// 	err = json.Unmarshal(reqBody, &actionPayload)
// 	if err != nil {
// 		http.Error(w, "invalid payload", http.StatusBadRequest)
// 		return
// 	}

// 	result, err := signup(actionPayload.Input)
// 	if err != nil {
// 		errorObject := GraphQLError{
// 			Message: err.Error(),
// 		}
// 		errorBody, _ := json.Marshal(errorObject)
// 		w.WriteHeader(http.StatusBadRequest)
// 		w.Write(errorBody)
// 		return
// 	}

// 	data, _ := json.Marshal(result)
// 	w.Write(data)
// }

// func loginHandler(w http.ResponseWriter, r *http.Request) {
// 	w.Header().Set("Content-Type", "application/json")

// 	reqBody, err := ioutil.ReadAll(r.Body)
// 	if err != nil {
// 		http.Error(w, "invalid payload", http.StatusBadRequest)
// 		return
// 	}

// 	var actionPayload struct {
// 		Input struct {
// 			Object loginArgs `json:"object"`
// 		} `json:"input"`
// 	}

// 	err = json.Unmarshal(reqBody, &actionPayload)
// 	if err != nil {
// 		http.Error(w, "invalid payload", http.StatusBadRequest)
// 		return
// 	}

// 	loginPayload := actionPayload.Input.Object

// 	result, err := login(loginPayload)
// 	if err != nil {
// 		errorObject := GraphQLError{
// 			Message: err.Error(),
// 		}
// 		errorBody, _ := json.Marshal(errorObject)
// 		w.WriteHeader(http.StatusUnauthorized)
// 		w.Write(errorBody)
// 		return
// 	}

// 	token, err := generateJWT(result.UserID)
// 	if err != nil {
// 		http.Error(w, "failed to generate token", http.StatusInternalServerError)
// 		return
// 	}

// 	// Log the role to the console
// 	fmt.Printf("User Role: %s\n", result.Role)

// 	response := struct {
// 		UserID string `json:"user_id"`
// 		Token  string `json:"token"`
// 		Role   string `json:"role"` // Include role here
// 	}{
// 		UserID: result.UserID,
// 		Token:  token,
// 		Role:   result.Role, // Include role here
// 	}

// 	data, _ := json.Marshal(response)
// 	w.Write(data)
// }

// func signup(args signupArgs) (response signupOutput, err error) {
// 	// Hash the password before sending it to Hasura
// 	hashedPassword, err := hashPassword(args.Password)
// 	if err != nil {
// 		return
// 	}

// 	// Prepare variables for GraphQL mutation
// 	variables := map[string]interface{}{
// 		"username": args.Username,
// 		"email":    args.Email,
// 		"password": hashedPassword,
// 	}

// 	hasuraResponse, err := executeSignup(variables)
// 	if err != nil {
// 		return
// 	}

// 	if len(hasuraResponse.Errors) != 0 {
// 		err = errors.New(hasuraResponse.Errors[0].Message)
// 		return
// 	}

// 	response = hasuraResponse.Data.Insert_user_one
// 	return
// }

// func login(args loginArgs) (response userOutput, err error) {
// 	// Query the user by email
// 	hasuraResponse, err := executeLogin(map[string]interface{}{
// 		"email": args.Email,
// 	})
// 	if err != nil {
// 		return
// 	}

// 	if len(hasuraResponse.Errors) != 0 {
// 		err = errors.New(hasuraResponse.Errors[0].Message)
// 		return
// 	}
// 	if len(hasuraResponse.Data.User) == 0 {
// 		err = errors.New("invalid credentials")
// 		return
// 	}

// 	user := hasuraResponse.Data.User[0] // Assuming we only need the first match

// 	// Compare provided password with the stored hashed password
// 	isValid := checkPasswordHash(args.Password, user.Password)
// 	if !isValid {
// 		err = errors.New("invalid credentials")
// 		return
// 	}

// 	response = user
// 	return
// }

// func hashPassword(password string) (string, error) {
// 	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
// 	if err != nil {
// 		return "", err
// 	}
// 	return string(hashedPassword), nil
// }

// func checkPasswordHash(password, hash string) bool {
// 	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
// 	return err == nil
// }

// func generateJWT(userID string) (string, error) {
// 	claims := JWTClaims{
// 		UserID: userID,
// 		StandardClaims: jwt.StandardClaims{
// 			ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
// 			Issuer:    "cinema_app", // Replace with your app name
// 		},
// 	}

// 	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
// 	tokenString, err := token.SignedString(jwtSecret)
// 	fmt.Printf("Generated Token: %v\n", tokenString) // Log token for debugging
// 	if err != nil {
// 		return "", err
// 	}
// 	return tokenString, nil
// }

// func executeSignup(variables map[string]interface{}) (response GraphQLResponse, err error) {
// 	query := `mutation ($username: String!, $email: String!, $password: String!) {
// 		insert_user_one(object: {username: $username, email: $email, password: $password}) {
// 			user_id
// 		}
// 	}`

// 	reqBody := GraphQLRequest{
// 		Query:     query,
// 		Variables: variables,
// 	}
// 	reqBytes, err := json.Marshal(reqBody)
// 	if err != nil {
// 		return
// 	}

// 	resp, err := http.Post("http://localhost:8080/v1/graphql", "application/json", bytes.NewBuffer(reqBytes))
// 	if err != nil {
// 		return
// 	}
// 	defer resp.Body.Close()

// 	respBytes, err := ioutil.ReadAll(resp.Body)
// 	if err != nil {
// 		return
// 	}

// 	if resp.StatusCode != http.StatusOK {
// 		err = fmt.Errorf("failed to execute GraphQL query: %s", string(respBytes))
// 		return
// 	}

// 	err = json.Unmarshal(respBytes, &response)
// 	if err != nil {
// 		return
// 	}

// 	return
// }

// func executeLogin(variables map[string]interface{}) (response GraphQLResponse, err error) {
// 	query := `query ($email: String!) {
// 		user(where: {email: {_eq: $email}}) {
// 			user_id
// 			password
// 			role
// 		}
// 	}`

// 	reqBody := GraphQLRequest{
// 		Query:     query,
// 		Variables: variables,
// 	}
// 	reqBytes, err := json.Marshal(reqBody)
// 	if err != nil {
// 		return
// 	}

// 	resp, err := http.Post("http://localhost:8080/v1/graphql", "application/json", bytes.NewBuffer(reqBytes))
// 	if err != nil {
// 		return
// 	}
// 	defer resp.Body.Close()

// 	respBytes, err := ioutil.ReadAll(resp.Body)
// 	if err != nil {
// 		return
// 	}

// 	if resp.StatusCode != http.StatusOK {
// 		err = fmt.Errorf("failed to execute GraphQL query: %s", string(respBytes))
// 		return
// 	}

// 	err = json.Unmarshal(respBytes, &response)
// 	if err != nil {
// 		return
// 	}

// 	return
// }

// func main() {
// 	router := mux.NewRouter()

// 	router.HandleFunc("/", helloHandler)
// 	router.HandleFunc("/signup", signupHandler).Methods("POST")
// 	router.HandleFunc("/login", loginHandler).Methods("POST")

// 	fmt.Println("Server is listening on port 5000...")
// 	log.Fatal(http.ListenAndServe(":5000", router))
// }


