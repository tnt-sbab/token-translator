package token_translator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

type Config struct {
	LookupPath string
}

func CreateConfig() *Config {
	return &Config{
		LookupPath: "",
	}
}

type TokenTranslator struct {
	next       http.Handler
	lookupPath string
	name       string
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.LookupPath) == 0 {
		return nil, errors.New("LookupPath cannot be empty")
	}
	log.SetOutput(os.Stdout)
	return &TokenTranslator{
		next:       next,
		lookupPath: config.LookupPath,
		name:       name,
	}, nil
}

func (t *TokenTranslator) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	authorization, err := extractAuthorization(req)
	if err != nil {
		log.Println("could not extract authorization from request", err)
	}
	if len(authorization) == 36 {
		req.Header.Set("accessToken", authorization)
		jwt, err := fetchUserToken(t.lookupPath, authorization)
		if err != nil {
			log.Println("failed fetching jwt token:", err)
			http.Error(rw, "Not allowed", http.StatusForbidden)
			return
		}
		req.Header.Set("Authorization", "Bearer "+jwt)
	}
	t.next.ServeHTTP(rw, req)
}

func extractAuthorization(req *http.Request) (string, error) {
	var authorization string
	authorization = req.Header.Get("Authorization")
	if len(authorization) == 0 {
		gwTokenCookie, err := req.Cookie("GWTOKEN")
		if err != nil {
			return authorization, err
		}
		if gwTokenCookie != nil {
			authorization = gwTokenCookie.Value
		}
	}
	authorization = strings.TrimPrefix(authorization, "Bearer")
	authorization = strings.TrimSpace(authorization)
	return authorization, nil
}

func fetchUserToken(lookupPath string, accessToken string) (string, error) {
	var jwt string
	url := fmt.Sprintf(lookupPath, accessToken)
	res, err := http.Get(url)
	if err != nil {
		return jwt, err
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return jwt, err
	}
	var userTokenResponse UserTokenResponse
	err = json.Unmarshal(body, &userTokenResponse)
	if err != nil {
		return jwt, err
	}
	if len(userTokenResponse.Message) > 0 {
		return jwt, errors.New(userTokenResponse.Message)
	}
	return userTokenResponse.Token, nil
}

type UserTokenResponse struct {
	Token   string `json:"token,omitempty"`
	Message string `json:"message,omitempty"`
}
