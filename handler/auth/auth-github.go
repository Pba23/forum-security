package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"forum/data/models"
	"io"
	"log"
	"net/http"
	"os"
)

func getGithubClientID() string {

	githubClientID, exists := os.LookupEnv("GITHUB_CLIENT_ID")
	if !exists {
		log.Fatal("Github Client ID not defined in .env file")
	}

	return githubClientID
}

func getGithubClientSecret() string {

	githubClientSecret, exists := os.LookupEnv("GITHUB_CLIENT_SECRET")
	if !exists {
		log.Fatal("Github Client ID not defined in .env file")
	}

	return githubClientSecret
}

func HandleGithubLoginHandler(w http.ResponseWriter, r *http.Request) {
	// Get the environment variable
	githubClientID := getGithubClientID()

	// Create the dynamic redirect URL for login
	redirectURL := fmt.Sprintf(
		"https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s",
		githubClientID,
		"https://localhost:8080/github-callback")

	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

func getGithubAccessToken(w http.ResponseWriter, r *http.Request, code string) string {
	clientID := getGithubClientID()
	clientSecret := getGithubClientSecret()
	// Set us the request body as JSON
	requestBodyMap := map[string]string{
		"client_id":     clientID,
		"client_secret": clientSecret,
		"code":          code,
	}
	requestJSON, _ := json.Marshal(requestBodyMap)
	// POST request to set URL
	req, reqerr := http.NewRequest(
		"POST",
		"https://github.com/login/oauth/access_token",
		bytes.NewBuffer(requestJSON))
	if reqerr != nil {
		log.Panic("Request creation failed")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	// Get the response
	resp, resperr := http.DefaultClient.Do(req)
	if resperr != nil {
		log.Panic("Request failed")
	}
	// Response body converted to stringified JSON
	respbody, _ := io.ReadAll(resp.Body)
	// Represents the response received from Github
	type githubAccessTokenResponse struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
	}
	// Convert stringified JSON to a struct object of type githubAccessTokenResponse
	var ghresp githubAccessTokenResponse
	json.Unmarshal(respbody, &ghresp)
	// Return the access token (as the rest of the
	// details are relatively unnecessary for us)
	return ghresp.AccessToken
}

func HandleGithubCallback(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")

	githubAccessToken := getGithubAccessToken(w, r, code)

	// Get request to a set URL
	req, reqerr := http.NewRequest(
		"GET",
		"https://api.github.com/user",
		nil)

	if reqerr != nil {
		log.Panic("API Request creation failed")
	}

	// Set the Authorization header before sending the request
	// Authorization: token XXXXXXXXXXXXXXXXXXXXXXXXXXX
	authorizationHeaderValue := fmt.Sprintf("token %s", githubAccessToken)
	req.Header.Set("Authorization", authorizationHeaderValue)

	// Make the request
	resp, resperr := http.DefaultClient.Do(req)
	if resperr != nil {
		log.Panic("Request failed")
	}

	// Read the response as a byte slice
	respbody, _ := io.ReadAll(resp.Body)

	var GithubUser GithubUser

	json.Unmarshal(respbody, &GithubUser)

	//////////////////////////////

	client2 := &http.Client{}

	req2, err := http.NewRequest("GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		return
	}

	req2.Header.Add("Authorization", "Bearer "+githubAccessToken)
	resp2, err := client2.Do(req2)
	if err != nil {
		return
	}
	defer resp2.Body.Close()

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&emails); err != nil {
		return
	}

	var userPrimaryEmail string
	for _, email := range emails {
		if email.Primary {
			userPrimaryEmail = email.Email
			break
		}
	}

	/////////////////

	user := models.User{}

	user.ID = GithubUser.ID
	user.Username = GithubUser.Name
	user.AvatarURL = GithubUser.AvatarURL
	user.Email = userPrimaryEmail
	user.Role = models.RoleUser

	if _, exist := models.UserRepo.IsExistedSignIn(user.Username); !exist {
		err := models.UserRepo.CreateUser(&user)
		if err != nil {
			log.Fatalf("❌ Failed to created account %v", err)
		}

		models.NewSessionToken(w, user.ID, user.Username)

		http.Redirect(w, r, "/", http.StatusSeeOther)
		log.Println("✅ Account created with success")
	} else {
		models.NewSessionToken(w, user.ID, user.Username)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		fmt.Println("❌ User already exist")
	}
}

type GithubUser struct {
	Login      string `json:"login"`
	ID         string `json:"node_id"`
	AvatarURL  string `json:"avatar_url"`
	GravatarID string `json:"gravatar_id"`
	URL        string `json:"url"`
	Name       string `json:"name"`
	Email      string `json:"email"`
}
