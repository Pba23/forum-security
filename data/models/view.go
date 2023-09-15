package models

import (
	"database/sql"
	"log"

	uuid "github.com/gofrs/uuid"
	_ "github.com/mattn/go-sqlite3"
)

type View struct {
	ID           string
	IsBookmarked bool
	Rate         RATE
	AuthorID     string
	PostID       string
}

type RATE int

const (
	Neutral ROLE = 0
	Like    ROLE = 1
	Dislike ROLE = 2
)

type ViewRepository struct {
	db *sql.DB
}

func NewViewRepository(db *sql.DB) *ViewRepository {
	return &ViewRepository{
		db: db,
	}
}

// Create a new view in the database
func (vr *ViewRepository) CreateView(view *View) error {
	ID, err := uuid.NewV4()
	if err != nil {
		log.Fatalf("❌ Failed to generate UUID: %v", err)
	}
	view.ID = ID.String()
	_, err = vr.db.Exec("INSERT INTO view (id, isBookmarked, rate, authorID, postID) VALUES (?, ?, ?, ?, ?)",
		view.ID, view.IsBookmarked, view.Rate, view.AuthorID, view.PostID)
	return err
}

// Get a view by ID from the database
func (vr *ViewRepository) GetViewByID(viewID string) (*View, error) {
	var view View
	row := vr.db.QueryRow("SELECT id, isBookmarked, rate, authorID, postID FROM view WHERE id = ?", viewID)
	err := row.Scan(&view.ID, &view.IsBookmarked, &view.Rate, &view.AuthorID, &view.PostID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // View not found
		}
		return nil, err
	}
	return &view, nil
}

// Get a number of dislike by post
func (vr *ViewRepository) GetLikesByPost(postID string) (int, error) {
	var nbrLike int
	row := vr.db.QueryRow("SELECT COUNT(*) FROM view WHERE postid = ? AND rate=1", postID)
	err := row.Scan(&nbrLike)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil // View not found
		}
		return 0, err
	}
	return nbrLike, nil
}

func (vr *ViewRepository) GetDislikesByPost(postID string) (int, error) {
	var nbrDislike int
	row := vr.db.QueryRow("SELECT COUNT(*) FROM view WHERE postid = ? AND rate=2", postID)
	err := row.Scan(&nbrDislike)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil // View not found
		}
		return 0, err
	}
	return nbrDislike, nil
}

func (vr *ViewRepository) GetNbrOfBookmarks(postID string) (int, error) {
	var NbrOfBookmarks int
	row := vr.db.QueryRow("SELECT COUNT(*) FROM view WHERE isbookmarked = true AND postid = ? ", postID)
	err := row.Scan(&NbrOfBookmarks)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil // View not found
		}
		return 0, err
	}
	return NbrOfBookmarks, nil
}

func (vr *ViewRepository) GetNbrOfUnBookmarks(postID string) (int, error) {
	var NbrOfUnBookmarks int
	row := vr.db.QueryRow("SELECT COUNT(*) FROM view WHERE isBookmarked = false")
	err := row.Scan(&NbrOfUnBookmarks)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil // View not found
		}
		return 0, err
	}
	return NbrOfUnBookmarks, nil
}

// Get a view by ID from the database
func (vr *ViewRepository) GetViewByAuthorIDandPostID(authorID string, postID string) (*View, error) {
	var view View
	row := vr.db.QueryRow("SELECT id, isBookmarked, rate, authorID, postID FROM view WHERE authorid = ? AND postid = ?", authorID, postID)
	err := row.Scan(&view.ID, &view.IsBookmarked, &view.Rate, &view.AuthorID, &view.PostID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // View not found
		}
		return nil, err
	}
	return &view, nil
}

// Update a view in the database
func (vr *ViewRepository) UpdateView(view *View) error {
	_, err := vr.db.Exec("UPDATE view SET isBookmarked = ?, rate = ?, authorID = ?, postID = ? WHERE id = ?",
		view.IsBookmarked, view.Rate, view.AuthorID, view.PostID, view.ID)
	return err
}

// Delete a view from the database
func (vr *ViewRepository) DeleteView(viewID string) error {
	_, err := vr.db.Exec("DELETE FROM view WHERE id = ?", viewID)
	return err
}
