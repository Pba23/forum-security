package models

import (
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gofrs/uuid"
)

var AllSessions sync.Map

type Session struct {
	UserID   string    `json:"user_id"`
	Username string    `json:"username"`
	ExpireAt time.Time `json:"exp"`
}

func (s Session) isExpired() bool {
	return s.ExpireAt.Before(time.Now())
}

func ValidSession(req *http.Request) bool {
	cookie, err := req.Cookie("auth_session")
	if err == nil {
		if _, ok := AllSessions.Load(cookie.Value); ok {
			return ok
		}
	}
	return false
}

func GetUserFromSession(req *http.Request) *User {
	user := User{}
	cookie, err := req.Cookie("auth_session")
	if err == nil {
		if session, ok := AllSessions.Load(cookie.Value); ok {
			_user, err := UserRepo.GetUserByID(session.(Session).UserID)
			if err != nil {
				log.Println("❌ ", err)
			}
			user = *_user
		}
	}
	return &user
}

func NewSessionToken(res http.ResponseWriter, UserID, Username string) {
	sessionToken, err := uuid.NewV4()
	if err != nil {
		log.Fatalf("❌ Failed to generate UUID: %v", err)
	}
	deleteSessionIfExist(Username)
	ExpireAt := time.Now().Add(2 * time.Hour)
	AllSessions.Store(sessionToken.String(), Session{UserID, Username, ExpireAt})
	http.SetCookie(res, &http.Cookie{
		Name:     "auth_session",
		Value:    sessionToken.String(),
		HttpOnly: true,
		Expires:  ExpireAt,
	})
}

func deleteSessionIfExist(username string) {
	AllSessions.Range(func(key, value interface{}) bool {
		if username == value.(Session).Username {
			AllSessions.Delete(key)
		}
		return true
	})
}

func CheckIfSessionExist(username string) bool {
	exist := false
	AllSessions.Range(func(key, value interface{}) bool {
		if username == value.(Session).Username {
			exist = true
		}
		return true
	})
	return exist
}

func DeleteExpiredSessions() {
	for {
		AllSessions.Range(func(key, value interface{}) bool {
			if value.(Session).isExpired() {
				AllSessions.Delete(key)
			}
			return true
		})
		time.Sleep(10 * time.Second)
	}
}

func DeleteSession(req *http.Request) bool {
	cookie, err := req.Cookie("auth_session")
	if err != nil {
		return false
	}
	AllSessions.Delete(cookie.Value)
	return true
}
