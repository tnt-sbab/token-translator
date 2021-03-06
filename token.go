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
	"time"
)

var (
	ErrEmptyTokenUrl      = errors.New("TokenUrl cannot be empty")
	ErrInvalidTokenUrl    = errors.New("TokenUrl must contain '%s'")
	ErrInvalidAccessToken = errors.New("invalid access token format")
)

type Config struct {
	TokenUrl       string
	AllowOnlyToken bool
}

type UserTokenResponse struct {
	Token   string `json:"token,omitempty"`
	Message string `json:"message,omitempty"`
}

type TokenTranslator struct {
	name           string
	next           http.Handler
	tokenUrl       string
	allowOnlyToken bool
	client         http.Client
}

func CreateConfig() *Config {
	return &Config{
		TokenUrl:       "",
		AllowOnlyToken: false, // If auth info is present, it must be a 36 char UUID access token
	}
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.TokenUrl) == 0 {
		return nil, ErrEmptyTokenUrl
	} else if !strings.Contains(config.TokenUrl, "%s") {
		return nil, ErrInvalidTokenUrl
	}
	log.SetOutput(os.Stdout)
	return &TokenTranslator{
		name:           name,
		next:           next,
		tokenUrl:       config.TokenUrl,
		allowOnlyToken: config.AllowOnlyToken,
		client:         httpClient(),
	}, nil
}

func httpClient() http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = 100
	transport.MaxConnsPerHost = 100 // Defaults to only 2, but all connections in this service use the same host
	transport.MaxIdleConnsPerHost = 100

	client := http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}
	return client
}

func (t *TokenTranslator) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	authorization, err := ExtractAuthorization(req)
	if err != nil {
		log.Println("could not extract authorization from request", err)
	}
	if len(authorization) == 36 {
		req.Header.Set("accessToken", authorization)
		jwt, err := fetchUserToken(t.client, t.tokenUrl, authorization)
		if err != nil {
			log.Println("failed fetching jwt token:", err)
			http.Error(rw, "Not allowed", http.StatusForbidden)
			return
		}
		req.Header.Set("Authorization", "Bearer "+jwt)
	} else if t.allowOnlyToken && len(authorization) > 0 {
		log.Println("access token must be a uuid")
		http.Error(rw, "Not allowed", http.StatusForbidden)
		return
	}
	t.next.ServeHTTP(rw, req)
}

func ExtractAuthorization(req *http.Request) (string, error) {
	var authorization string
	authorization = req.Header.Get("Authorization")
	if len(authorization) == 0 {
		gwTokenCookie, err := req.Cookie("GWTOKEN")
		if err != nil && err == http.ErrNoCookie {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		if gwTokenCookie != nil {
			authorization = gwTokenCookie.Value
		}
	}
	authorization = strings.TrimPrefix(authorization, "Bearer")
	authorization = strings.TrimSpace(authorization)
	return authorization, nil
}

func fetchUserToken(client http.Client, lookupUrl string, accessToken string) (string, error) {
	if !IsValidUUID(accessToken) {
		return "", ErrInvalidAccessToken
	}
	tokenUrl := fmt.Sprintf(lookupUrl, accessToken)
	res, err := client.Get(tokenUrl)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	return ParseTokenResponse(body)
}

func ParseTokenResponse(body []byte) (string, error) {
	var userTokenResponse UserTokenResponse
	err := json.Unmarshal(body, &userTokenResponse)
	if err != nil {
		return "", err
	}
	if len(userTokenResponse.Message) > 0 {
		return "", errors.New(userTokenResponse.Message)
	} else if len(userTokenResponse.Token) == 0 {
		return "", errors.New("empty token response")
	} else {
		return userTokenResponse.Token, nil
	}
}

func IsValidUUID(s string) bool {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	for _, c := range strings.ToLower(s[:8] + s[9:13] + s[14:18] + s[19:23] + s[24:]) {
		if c < '0' || (c > '9' && c < 'a') || c > 'f' {
			return false
		}
	}
	return true
}
