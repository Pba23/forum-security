package models

import (
	"database/sql"
	"log"

	uuid "github.com/gofrs/uuid"
	_ "github.com/mattn/go-sqlite3"
)

type CommentRate struct {
	ID        string
	Rate      RATE
	AuthorID  string
	CommentID string
	Notifications []*Notification
}

type CommentRateRepository struct {
	db *sql.DB
}

func NewCommentRateRepository(db *sql.DB) *CommentRateRepository {
	return &CommentRateRepository{
		db: db,
	}
}

// Create a new rate in the database
func (vr *CommentRateRepository) CreateCommentRate(Comment_Rate *CommentRate) error {
	ID, err := uuid.NewV4()
	if err != nil {
		log.Fatalf("❌ Failed to generate UUID: %v", err)
	}
	Comment_Rate.ID = ID.String()
	_, err = vr.db.Exec("INSERT INTO comment_rate (id, rate, authorID, commentID) VALUES (?, ?, ?, ?)",
		Comment_Rate.ID, Comment_Rate.Rate, Comment_Rate.AuthorID, Comment_Rate.CommentID)
	return err
}

// Get a rate by ID from the database
func (vr *CommentRateRepository) GetCommentRateByID(Comment_RateID string) (*CommentRate, error) {
	var Comment_Rate CommentRate
	row := vr.db.QueryRow("SELECT id, rate, authorID, commentID FROM comment_rate WHERE id = ?", Comment_RateID)
	err := row.Scan(&Comment_Rate.ID, &Comment_Rate.Rate, &Comment_Rate.AuthorID, &Comment_Rate.CommentID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Comment_Rate not found
		}
		return nil, err
	}
	return &Comment_Rate, nil
}

// Get a number of disrate by post
func (vr *CommentRateRepository) GetLikesByComment(commentID string) (int, error) {
	var nbrRate int
	row := vr.db.QueryRow("SELECT COUNT(*) FROM comment_rate WHERE commentID = ? AND rate=1", commentID)
	err := row.Scan(&nbrRate)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil // Rate not found
		}
		return 0, err
	}
	return nbrRate, nil
}

func (vr *CommentRateRepository) GetDislikesByComment(commentID string) (int, error) {
	var nbrRate int
	row := vr.db.QueryRow("SELECT COUNT(*) FROM comment_rate WHERE commentID = ? AND rate=2", commentID)
	err := row.Scan(&nbrRate)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil // Rate not found
		}
		return 0, err
	}
	return nbrRate, nil
}

// Get a rate by ID from the database
func (vr *CommentRateRepository) GetRateByAuthorIDandCommentID(authorID string, commentID string) (*CommentRate, error) {
	var comment_rate CommentRate
	row := vr.db.QueryRow("SELECT id, rate, authorID, commentID FROM comment_rate WHERE authorid = ? AND commentid = ?", authorID, commentID)
	err := row.Scan(&comment_rate.ID, &comment_rate.Rate, &comment_rate.AuthorID, &comment_rate.CommentID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // comment_rate not found
		}
		return nil, err
	}
	return &comment_rate, nil
}

// Update a rate in the database
func (vr *CommentRateRepository) UpdateRate(comment_rate *CommentRate) error {
	_, err := vr.db.Exec("UPDATE comment_rate SET rate = ?, authorID = ?, commentID = ? WHERE id = ?",
		comment_rate.Rate, comment_rate.AuthorID, comment_rate.CommentID, comment_rate.ID)
	return err
}

// Delete a rate from the database
func (vr *CommentRateRepository) DeleteCommentRate(comment_rateID string) error {
	_, err := vr.db.Exec("DELETE FROM comment_rate WHERE id = ?", comment_rateID)
	return err
}
