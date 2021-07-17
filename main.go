package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"github.com/gorilla/mux"
)

var secretKey = []byte(os.Getenv("SESSION_SECRET"))
var users = map[string]string{
	"aybjax": "aybjax",
	"admin": "password",
}
type Response struct {
	Token string `json:"token"`
	Status string `json:"status"`	
}

func HealthcheckHandler(w http.ResponseWriter, r *http.Request) {
	tokenString, err := request.HeaderExtractor{"access_token"}.ExtractToken(r)

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing methodL %v",
									token.Header["alg"])
		}

		return secretKey, nil
	})

	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Access Denied; Please check the access token"))

		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		response := make(map[string]string)
		response["time"] = time.Now().String()
		response["user"] = claims["username"].(string)

		responseJson,_ := json.Marshal(response)
		w.Write(responseJson)
	} else {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(err.Error()))
	}
}

func getTokenHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()

	if err != nil {
		http.Error(w, "Please pass the dataas URL form encoded", http.StatusBadRequest)
	}

	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")

	if originalPassword, ok := users[username]; ok {
		if password == originalPassword {
			claims := jwt.MapClaims{
				"username": username,
				"ExpiresAt": 15000,
				"IssuedAt": time.Now().String(),
			}

			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

			tokenString, err := token.SignedString(secretKey)
			
			if err != nil {
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte(err.Error()))

				return
			}

			response := Response{Token: tokenString, Status: "success"}
			responseJson, _ := json.Marshal(response)
			
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/json")
			w.Write(responseJson)
		} else {
			http.Error(w, "Invalid Credentials", http.StatusUnauthorized)

			return
		}
	} else {
		http.Error(w, "User not found", http.StatusNotFound)

		return
	}
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/gettoken", getTokenHandler)
	r.HandleFunc("/healthcheck", HealthcheckHandler)

	http.Handle("/", r)
	srv := &http.Server {
		Handler: r,
		Addr: "127.0.0.1:8080",
	}

	log.Fatal(srv.ListenAndServe())
}

func init() {
	os.Setenv("JWT_SECRET", "MY_JWT_SECRET")
}