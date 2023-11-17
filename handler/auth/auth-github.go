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
	"strings"
)

// getGithubClientSecret retrieves the GitHub client secret from the environment variable.
func getGithubClientSecret() string {
	clientSecret, exists := os.LookupEnv("GITHUB_CLIENT_SECRET")
	if !exists {
		log.Fatal("GitHub Client Secret not defined in .env file")
	}
	return clientSecret
}

// getGithubClientID retrieves the GitHub client ID from the environment variable.
func getGithubClientID() string {
	clientID, exists := os.LookupEnv("GITHUB_CLIENT_ID")
	if !exists {
		log.Fatal("GitHub Client ID not defined in .env file")
	}
	return clientID
}

// HandleGithubLoginHandler handles the GitHub login redirect.
func HandleGithubLoginHandler(w http.ResponseWriter, r *http.Request) {
	clientID := getGithubClientID()
	redirectURL := fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s", clientID, "http://localhost:8080/github-callback")
	log.Printf("Redirection to %s", redirectURL)
	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

// getGithubAccessToken retrieves the GitHub access token using the provided code.
func getGithubAccessToken(w http.ResponseWriter, r *http.Request, code string) (string, error) {
	clientID := getGithubClientID()
	clientSecret := getGithubClientSecret()

	// Prepare request body as JSON
	requestBody := map[string]string{
		"client_id":     clientID,
		"client_secret": clientSecret,
		"code":          code,
	}
	requestJSON, _ := json.Marshal(requestBody)

	// Make a POST request to obtain the access token
	resp, err := http.Post("https://github.com/login/oauth/access_token", "application/json", bytes.NewBuffer(requestJSON))
	if err != nil {
		log.Printf("Request failed: %v", resp)
		return "", err
	}
	defer resp.Body.Close()

	// Read the response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read response body: %v", respBody)
		return "", err
	}

	// Parse the GitHub access token from the response
	accessToken := parseAccessToken(string(respBody))
	if accessToken == "" {
		log.Printf("Failed to parse response body: %s", string(respBody))
		return "", err
	}

	return accessToken, nil
}

// parseAccessToken parses the access token from the GitHub response.
func parseAccessToken(response string) string {
	// Split the response string by '&' to get key-value pairs
	pairs := strings.Split(response, "&")

	// Iterate through key-value pairs to find the access token
	for _, pair := range pairs {
		if strings.HasPrefix(pair, "access_token=") {
			// Extract the access token value
			return strings.TrimPrefix(pair, "access_token=")
		}
	}

	// Access token not found
	return ""
}

// HandleGithubCallback handles the callback from GitHub after authentication.
func HandleGithubCallback(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	if code == "" {
		log.Printf("No code provided")
	}

	// Obtain the GitHub access token
	githubAccessToken, err := getGithubAccessToken(w, r, code)
	if err != nil {
		log.Printf("Failed to obtain GitHub access token: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Make a request to get user information from GitHub
	githubUser, err := getGithubUser(githubAccessToken)
	if err != nil {
		log.Printf("Failed to get GitHub user information: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Make a request to get user emails from GitHub
	emails, err := getGithubUserEmails(githubAccessToken)
	if err != nil {
		log.Printf("Failed to get GitHub user emails: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Process GitHub user information and emails
	user := processGithubUserInfo(githubUser, emails)

	// Create a new user account
	err = models.UserRepo.CreateGithubUser(&user)
	if err != nil {
		log.Fatalf("🚨 Failed to create account: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Create a new session token
	models.NewSessionToken(w, user.ID, user.Username)

	// Redirect to the home page
	http.Redirect(w, r, "/", http.StatusSeeOther)
	log.Println("✅ Account created successfully")
}

// getGithubUser retrieves user information from GitHub.
func getGithubUser(accessToken string) (GithubUser, error) {
	client := &http.Client{}

	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return GithubUser{}, err
	}

	// Set the Authorization header with the access token
	req.Header.Add("Authorization", "Bearer "+accessToken)

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		return GithubUser{}, err
	}
	defer resp.Body.Close()

	// Read the response as a byte slice
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return GithubUser{}, err
	}

	// Parse the GitHub user information response
	var githubUser GithubUser
	err = json.Unmarshal(respBody, &githubUser)
	if err != nil {
		return GithubUser{}, err
	}

	return githubUser, nil
}

// getGithubUserEmails retrieves user emails from GitHub.
func getGithubUserEmails(accessToken string) ([]struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}, error) {
	client := &http.Client{}

	req, err := http.NewRequest("GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		return nil, err
	}

	// Set the Authorization header with the access token
	req.Header.Add("Authorization", "Bearer "+accessToken)

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read the response as a byte slice
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse the GitHub user emails response
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	err = json.Unmarshal(respBody, &emails)
	if err != nil {
		return nil, err
	}

	return emails, nil
}

// processGithubUserInfo processes GitHub user information and returns a User struct.
func processGithubUserInfo(githubUser GithubUser, emails []struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}) models.User {
	user := models.User{
		Username:  githubUser.Name,
		AvatarURL: githubUser.AvatarURL,
		Role:      models.RoleUser,
	}

	// Extract the primary email (if available)
	for _, email := range emails {
		if email.Primary {
			user.Email = email.Email
			break
		}
	}

	return user
}

// GithubUser represents the GitHub user structure.
type GithubUser struct {
	Login      string `json:"login"`
	ID         string `json:"node_id"`
	AvatarURL  string `json:"avatar_url"`
	GravatarID string `json:"gravatar_id"`
	URL        string `json:"url"`
	Name       string `json:"name"`
	Email      string `json:"email"`
}
