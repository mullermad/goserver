package main

import (
    "bytes"
    "encoding/json"
    "errors"
    "fmt"
	"context"
	"encoding/base64"
    
    "strings"

    // "io"
    "io/ioutil"
    "log"
    "net/http"
    "time"

    "github.com/dgrijalva/jwt-go"
    "github.com/gorilla/mux"
    "github.com/cloudinary/cloudinary-go/v2"
    "github.com/cloudinary/cloudinary-go/v2/api/uploader"
    "golang.org/x/crypto/bcrypt"
)

var jwtSecret = []byte("your_secret_key_here") // Replace with your own secret key

var cloudinaryClient *cloudinary.Cloudinary

func init() {
    // Initialize Cloudinary client
    var err error
    cloudinaryClient, err = cloudinary.NewFromParams("dtyywkiyq", "362127989821936", "hh1PZ_hYj5kS2cAIhsKhUgZPD7w")
    if err != nil {
        log.Fatalf("Error initializing Cloudinary client: %v", err)
    }
}

type ActionPayload struct {
    SessionVariables map[string]interface{} `json:"session_variables"`
    Input            signupArgs             `json:"input"`
}

type GraphQLError struct {
    Message string `json:"message"`
}

type GraphQLRequest struct {
    Query     string      `json:"query"`
    Variables interface{} `json:"variables"`
}

type GraphQLData struct {
    Insert_user_one signupOutput `json:"insert_user_one"`
    User            []userOutput `json:"user"` // Changed to array
}

type GraphQLResponse struct {
    Data   GraphQLData    `json:"data,omitempty"`
    Errors []GraphQLError `json:"errors,omitempty"`
}

type signupArgs struct {
    Username string `json:"username"`
    Email    string `json:"email"`
    Password string `json:"password"`
}

type loginArgs struct {
    Email    string `json:"email"`
    Password string `json:"password"`
}

type signupOutput struct {
    UserID string `json:"user_id"`
}

type userOutput struct {
    UserID   string `json:"user_id"`
    Password string `json:"password"`
    Role     string `json:"role"` // Add role here
}

type JWTClaims struct {
    UserID string `json:"user_id"`
    jwt.StandardClaims
}

func helloHandler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprint(w, "Hello Muller, welcome to Go!")
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    reqBody, err := ioutil.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "invalid payload", http.StatusBadRequest)
        return
    }

    var actionPayload ActionPayload
    err = json.Unmarshal(reqBody, &actionPayload)
    if err != nil {
        http.Error(w, "invalid payload", http.StatusBadRequest)
        return
    }

    result, err := signup(actionPayload.Input)
    if err != nil {
        errorObject := GraphQLError{
            Message: err.Error(),
        }
        errorBody, _ := json.Marshal(errorObject)
        w.WriteHeader(http.StatusBadRequest)
        w.Write(errorBody)
        return
    }

    data, _ := json.Marshal(result)
    w.Write(data)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    reqBody, err := ioutil.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "invalid payload", http.StatusBadRequest)
        return
    }

    var actionPayload struct {
        Input struct {
            Object loginArgs `json:"object"`
        } `json:"input"`
    }

    err = json.Unmarshal(reqBody, &actionPayload)
    if err != nil {
        http.Error(w, "invalid payload", http.StatusBadRequest)
        return
    }

    loginPayload := actionPayload.Input.Object

    result, err := login(loginPayload)
    if err != nil {
        errorObject := GraphQLError{
            Message: err.Error(),
        }
        errorBody, _ := json.Marshal(errorObject)
        w.WriteHeader(http.StatusUnauthorized)
        w.Write(errorBody)
        return
    }

    token, err := generateJWT(result.UserID)
    if err != nil {
        http.Error(w, "failed to generate token", http.StatusInternalServerError)
        return
    }
    response := struct {
        UserID string `json:"user_id"`
        Token  string `json:"token"`
        Role   string `json:"role"` // Include role here
    }{
        UserID: result.UserID,
        Token:  token,
        Role:   result.Role, // Include role here
    }
      fmt.Printf("token is %v",token)
            fmt.Printf("role is %v",result.Role)

            


    data, _ := json.Marshal(response)
    w.Write(data)
}

func signup(args signupArgs) (response signupOutput, err error) {
    hashedPassword, err := hashPassword(args.Password)
    if err != nil {
        return
    }

    variables := map[string]interface{}{
        "username": args.Username,
        "email":    args.Email,
        "password": hashedPassword,
    }

    hasuraResponse, err := executeSignup(variables)
    if err != nil {
        return
    }

    if len(hasuraResponse.Errors) != 0 {
        err = errors.New(hasuraResponse.Errors[0].Message)
        return
    }

    response = hasuraResponse.Data.Insert_user_one
    return
}

func login(args loginArgs) (response userOutput, err error) {
    hasuraResponse, err := executeLogin(map[string]interface{}{
        "email": args.Email,
    })
    if err != nil {
        return
    }

    if len(hasuraResponse.Errors) != 0 {
        err = errors.New(hasuraResponse.Errors[0].Message)
        return
    }
    if len(hasuraResponse.Data.User) == 0 {
        err = errors.New("invalid credentials")
        return
    }

    user := hasuraResponse.Data.User[0] // Assuming we only need the first match

    isValid := checkPasswordHash(args.Password, user.Password)
    if !isValid {
        err = errors.New("invalid credentials")
        return
    }

    response = user
    return
}

func hashPassword(password string) (string, error) {
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        return "", err
    }
    return string(hashedPassword), nil
}

func checkPasswordHash(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}

func generateJWT(userID string) (string, error) {
    claims := JWTClaims{
        UserID: userID,
        StandardClaims: jwt.StandardClaims{
            ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
            Issuer:    "cinema_app", // Replace with your app name
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString(jwtSecret)
    if err != nil {
        return "", err
    }
    return tokenString, nil
}

func executeSignup(variables map[string]interface{}) (response GraphQLResponse, err error) {
    query := `mutation ($username: String!, $email: String!, $password: String!) {
        insert_user_one(object: {username: $username, email: $email, password: $password}) {
            user_id
        }
    }`

    reqBody := GraphQLRequest{
        Query:     query,
        Variables: variables,
    }
    reqBytes, err := json.Marshal(reqBody)
    if err != nil {
        return
    }

    resp, err := http.Post("http://localhost:8080/v1/graphql", "application/json", bytes.NewBuffer(reqBytes))
    if err != nil {
        return
    }
    defer resp.Body.Close()

    respBytes, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return
    }

    if resp.StatusCode != http.StatusOK {
        err = fmt.Errorf("failed to execute GraphQL query: %s", string(respBytes))
        return
    }

    err = json.Unmarshal(respBytes, &response)
    if err != nil {
        return
    }

    return
}

func executeLogin(variables map[string]interface{}) (response GraphQLResponse, err error) {
    query := `query ($email: String!) {
        user(where: {email: {_eq: $email}}) {
            user_id
            password
            role
        }
    }`

    reqBody := GraphQLRequest{
        Query:     query,
        Variables: variables,
    }
    reqBytes, err := json.Marshal(reqBody)
    if err != nil {
        return
    }

    resp, err := http.Post("http://localhost:8080/v1/graphql", "application/json", bytes.NewBuffer(reqBytes))
    if err != nil {
        return
    }
    defer resp.Body.Close()

    respBytes, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return
    }

    if resp.StatusCode != http.StatusOK {
        err = fmt.Errorf("failed to execute GraphQL query: %s", string(respBytes))
        return
    }

    err = json.Unmarshal(respBytes, &response)
    if err != nil {
        return
    }

    return
}

func uploadFileHandler(w http.ResponseWriter, r *http.Request) {
   
    w.Header().Set("Content-Type", "application/json")

    // Parse the JSON body
    var requestBody map[string]string
    if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
        http.Error(w, "Unable to parse JSON body", http.StatusBadRequest)
        return
    }

    // Get the base64 encoded file from the JSON body
    base64File, ok := requestBody["file"]
    if !ok || base64File == "" {
        http.Error(w, "No file data provided", http.StatusBadRequest)
        return
    }

    // Decode the base64 string
    data, err := base64.StdEncoding.DecodeString(base64File)
    if err != nil {
        http.Error(w, "Error decoding base64 data", http.StatusBadRequest)
        return
    }


// postgres://postgres:postgrespassword@postgres:5432/postgres
// postgres://postgres:postgrespassword@postgres:5432/postgres

    // Create an io.Reader from the decoded data
    fileReader := strings.NewReader(string(data))

    // Upload the file to Cloudinary
    uploadResponse, err := cloudinaryClient.Upload.Upload(context.Background(), fileReader, uploader.UploadParams{Folder: "assets/img"})
    if err != nil {
        http.Error(w, "Error uploading file", http.StatusInternalServerError)
        return
    }
    // Send response
    response := map[string]string{
        "url": uploadResponse.SecureURL,
    }
    	fmt.Printf("Uploaded the file to Cloudinary kkkkkk: %v\n", response)

    data, err = json.Marshal(response)
    if err != nil {
        http.Error(w, "Error encoding JSON response", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    w.Write(data)

}

func main() {
    router := mux.NewRouter()
    router.HandleFunc("/", helloHandler)
    router.HandleFunc("/signup", signupHandler).Methods("POST")
    router.HandleFunc("/login", loginHandler).Methods("POST")
    router.HandleFunc("/upload", uploadFileHandler).Methods("POST")
	fmt.Println("Server is listening on port 5000...")
	log.Fatal(http.ListenAndServe(":5000", router))
    
}

// func main() {
// 	router := mux.NewRouter()
// 	router.HandleFunc("/", helloHandler)
// 	router.HandleFunc("/signup", signupHandler).Methods("POST")
// 	router.HandleFunc("/login", loginHandler).Methods("POST")
// 	router.HandleFunc("/upload", uploadFileHandler).Methods("POST")

	
	// fmt.Println("Server is listening on port 5000...")
	// log.Fatal(http.ListenAndServe(":5000", router))
// }




