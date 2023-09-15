package models

import (
	"database/sql"
	"log"

	uuid "github.com/gofrs/uuid"
	_ "github.com/mattn/go-sqlite3"
)

type Request struct {
	ID       string
	AuthorID string
	Time     string
	Username string
	ImageURL string
	Role     ROLE
}

type RequestRepository struct {
	db *sql.DB
}

func NewRequestRepository(db *sql.DB) *RequestRepository {
	return &RequestRepository{
		db: db,
	}
}

// Create a new report in the database
func (rr *RequestRepository) CreateRequest(request *Request) error {
	ID, err := uuid.NewV4()
	if err != nil {
		log.Fatalf("❌ Failed to generate UUID: %v", err)
	}
	request.ID = ID.String()
	_, err = rr.db.Exec("INSERT INTO request (id, authorID, time, username, imageurl, role) VALUES (?, ?, ?, ?, ?, ?)",
		request.ID, request.AuthorID, request.Time, request.Username, request.ImageURL, request.Role)
	return err
}

// Get a report by ID from the database
func (rr *RequestRepository) GetRequestByID(requestID string) (*Request, error) {
	var request Request
	row := rr.db.QueryRow("SELECT id, authorID, time, username, imageurl, role FROM request WHERE id = ?", requestID)
	err := row.Scan(&request.ID, &request.AuthorID, &request.Time, &request.Username, &request.ImageURL, &request.Role)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Report not found
		}
		return nil, err
	}
	return &request, nil
}

// Get a report by ID from the database
func (rr *RequestRepository) GetRequestByUser(userID string) (*Request, error) {
	var request Request
	row := rr.db.QueryRow("SELECT id, authorID, time, username, imageurl, role FROM request WHERE authorID = ?", userID)
	err := row.Scan(&request.ID, &request.AuthorID, &request.Time, &request.Username, &request.ImageURL, &request.Role)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Report not found
		}
		return nil, err
	}
	return &request, nil
}

// Select All Requestss
func (rr *RequestRepository) GetAllRequest() ([]Request, error) {
	var request []Request
	row, err := rr.db.Query("SELECT * FROM request")
	if err != nil {
		log.Fatal(err)
	}
	for row.Next() {
		var ID string
		var AuthorID string
		var Time string
		var Username string
		var ImageURL string
		var Role ROLE

		err = row.Scan(&ID, &AuthorID, &Time, &Username, &ImageURL, &Role)
		if err != nil {
			log.Fatal(err)
		}

		var tab = Request{
			ID:       ID,
			AuthorID: AuthorID,
			Time:     Time,
			Username: Username,
			ImageURL: ImageURL,
			Role:     Role,
		}

		request = append(request, tab)
	}
	return request, nil
}

// Delete a report from the database
func (rr *RequestRepository) DeleteRequest(requestID string) error {
	_, err := rr.db.Exec("DELETE FROM request WHERE id = ?", requestID)
	return err
}
func (rr *RequestRepository) UpdateRequest(request *Request) error {
	_, err := rr.db.Exec("UPDATE request SET authorID = ?, time = ?, username = ?, imageurl = ?, role = ? WHERE id = ?",
		request.AuthorID, request.Time, request.Username, request.ImageURL, request.Role, request.ID)
	return err
}
