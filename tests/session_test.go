package tests

import (
	"forum/data/models"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestValidSession_Valid(t *testing.T) {
	// Create a valid session
	sessionToken := "valid_token"
	models.AllSessions.Store(sessionToken, models.Session{
		UserID:   "user123",
		Username: "testuser",
		ExpireAt: time.Now().Add(1 * time.Hour),
	})

	// Create a request with a valid session cookie
	req, _ := http.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "auth_session",
		Value: sessionToken,
	})

	valid := models.ValidSession(req)
	if !valid {
		t.Errorf("Expected session to be valid, but it wasn't")
	}
}

func TestValidSession_Expired(t *testing.T) {
	// Create an expired session
	sessionToken := "expired_token"
	models.AllSessions.Store(sessionToken, models.Session{
		UserID:   "user123",
		Username: "testuser",
		ExpireAt: time.Now().Add(-1 * time.Hour), // Expired
	})

	// Create a request with an expired session cookie
	req, _ := http.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "auth_session",
		Value: sessionToken,
	})

	valid := models.ValidSession(req)
	if valid {
		t.Errorf("Expected session to be expired, but it wasn't")
	}
}

func TestNewSessionToken(t *testing.T) {
	res := httptest.NewRecorder()
	UserID := "user123"
	Username := "testuser"

	models.NewSessionToken(res, UserID, Username)

	// Get the set cookie from the response recorder
	setCookie := res.Header().Get("Set-Cookie")

	// Check if the cookie was set correctly
	if setCookie == "" {
		t.Errorf("Expected Set-Cookie header, but it was not set")
	}

	// Parse the set cookie to verify details (e.g., Name, Value, Expires)
	// Implement your own cookie parsing logic and assertions
}

func TestDeleteSession(t *testing.T) {
	// Create a session
	sessionToken := "session_to_delete"
	models.AllSessions.Store(sessionToken, models.Session{
		UserID:   "user123",
		Username: "testuser",
		ExpireAt: time.Now().Add(1 * time.Hour),
	})

	// Create a request with a session cookie to delete
	req, _ := http.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "auth_session",
		Value: sessionToken,
	})

	deleted := models.DeleteSession(req)
	if !deleted {
		t.Errorf("Expected session to be deleted, but it wasn't")
	}

	// Ensure the session was removed from the sessions map
	_, exists := models.AllSessions.Load(sessionToken)
	if exists {
		t.Errorf("Expected session to be deleted from sessions map, but it still exists")
	}
}

func TestDeleteExpiredSessions(t *testing.T) {
	// Create an expired session
	expiredSessionToken := "expired_session"
	models.AllSessions.Store(expiredSessionToken, models.Session{
		UserID:   "user123",
		Username: "testuser",
		ExpireAt: time.Now().Add(-1 * time.Hour), // Expired
	})

	// Create a valid session
	validSessionToken := "valid_session"
	models.AllSessions.Store(validSessionToken, models.Session{
		UserID:   "user456",
		Username: "anotheruser",
		ExpireAt: time.Now().Add(1 * time.Second),
	})

	// Run the DeleteExpiredSessions function
	go models.DeleteExpiredSessions()

	// Sleep for a short while to allow the goroutine to run
	time.Sleep(2 * time.Second)

	// Ensure the expired session was deleted
	_, exists := models.AllSessions.Load(expiredSessionToken)
	if exists {
		t.Errorf("Expected expired session to be deleted, but it still exists")
	}

	// Ensure the valid session is retained
	_, exists = models.AllSessions.Load(validSessionToken)
	if !exists {
		t.Errorf("Expected valid session to be retained, but it was deleted")
	}
}
