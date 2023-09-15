package models

import (
	"database/sql"
	"log"

	uuid "github.com/gofrs/uuid"
	_ "github.com/mattn/go-sqlite3"
)

type Response struct {
	ID           string
	AuthorID     string
	ReportID     string
	Text         string
	CreateDate   string
	ModifiedDate string
}

type ResponseRepository struct {
	db *sql.DB
}

func NewResponseRepository(db *sql.DB) *ResponseRepository {
	return &ResponseRepository{
		db: db,
	}
}

// Create a new response in the database
func (rr *ResponseRepository) CreateResponse(response *Response) error {
	ID, err := uuid.NewV4()
	if err != nil {
		log.Fatalf("❌ Failed to generate UUID: %v", err)
	}
	response.ID = ID.String()
	_, err = rr.db.Exec("INSERT INTO response (id, authorID, reportID, content, createDate, modifiedDate) VALUES (?, ?, ?, ?, ?, ?)",
		response.ID, response.AuthorID, response.ReportID, response.Text, response.CreateDate, response.ModifiedDate)
	return err
}

func (rr *ResponseRepository) GetAllResponse() ([]Response, error) {
	var Responsetab []Response
	rows, err := rr.db.Query("SELECT id, authorID, reportID, content, createDate, modifiedDate FROM response ORDER BY modifiedDate DESC")

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var response Response
		err := rows.Scan(&response.ID, &response.AuthorID, &response.ReportID, &response.Text, &response.CreateDate, &response.ModifiedDate)

		if err != nil {
			return nil, err
		}

		Responsetab = append(Responsetab, response)
	}

	return Responsetab, nil

}

// Get a response by ID from the database
func (rr *ResponseRepository) GetResponseByID(responseID string) (*Response, error) {
	var response Response
	row := rr.db.QueryRow("SELECT id, authorID, reportID, content, createDate, modifiedDate FROM response WHERE id = ?", responseID)
	err := row.Scan(&response.ID, &response.AuthorID, &response.ReportID, &response.Text, &response.CreateDate, &response.ModifiedDate)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Response not found
		}
		return nil, err
	}
	return &response, nil
}

// Update a response in the database
func (rr *ResponseRepository) UpdateResponse(response *Response) error {
	_, err := rr.db.Exec("UPDATE response SET authorID = ?, reportID = ?, text = ?, createDate = ?, modifiedDate = ? WHERE id = ?",
		response.AuthorID, response.ReportID, response.Text, response.CreateDate, response.ModifiedDate, response.ID)
	return err
}

// Delete a response from the database
func (rr *ResponseRepository) DeleteResponse(responseID string) error {
	_, err := rr.db.Exec("DELETE FROM response WHERE id = ?", responseID)
	return err
}
