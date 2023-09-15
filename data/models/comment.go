package models

import (
	"database/sql"
	"forum/lib"
	"log"
	"strconv"
	"strings"

	uuid "github.com/gofrs/uuid"
	_ "github.com/mattn/go-sqlite3"
)

type Comment struct {
	ID           string
	Text         string
	AuthorID     string
	PostID       string
	ParentID     string
	CreateDate   string
	ModifiedDate string
	Notifications      []*Notification
}

type CommentItem struct {
	ID                 string
	Index              int
	Depth              string
	Text               string
	AuthorID           string
	AuthorName         string
	AuthorAvatar       string
	ParentID           string
	LastModifiedDate   string
	NbrLikesComment    int
	NbrDislikesComment int
	
}

type CommentRepository struct {
	db *sql.DB
}

func NewCommentRepository(db *sql.DB) *CommentRepository {
	return &CommentRepository{
		db: db,
	}
}

// Create a new comment in the database
func (cr *CommentRepository) CreateComment(comment *Comment) error {
	ID, err := uuid.NewV4()
	if err != nil {
		log.Fatalf("❌ Failed to generate UUID: %v", err)
	}
	comment.ID = ID.String()
	_, err = cr.db.Exec("INSERT INTO comment (id, text, authorID, postID, parentID, createDate, modifiedDate) VALUES (?, ?, ?, ?, ?, ?, ?)",
		comment.ID, comment.Text, comment.AuthorID, comment.PostID, comment.ParentID, comment.CreateDate, comment.ModifiedDate)
	return err
}

// Get a comment by ID from the database
func (cr *CommentRepository) GetCommentByID(commentID string) (*Comment, error) {
	var comment Comment
	row := cr.db.QueryRow("SELECT id, text, authorID, postID, parentID, createDate, modifiedDate FROM comment WHERE id = ?", commentID)
	err := row.Scan(&comment.ID, &comment.Text, &comment.AuthorID, &comment.PostID, &comment.ParentID, &comment.CreateDate, &comment.ModifiedDate)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Comment not found
		}
		return nil, err
	}
	return &comment, nil
}

func (cr *CommentRepository) GetCommentsOfPost(postID, limit string) ([]*CommentItem, error) {
	moreComment, err := strconv.Atoi(limit)
	if err != nil {
		return nil, err
	}

	var comments []*CommentItem

	rows, err := cr.db.Query("SELECT c.id, c.text, c.authorID, c.parentID, c.modifiedDate, u.userName, u.avatarURL FROM comment c LEFT JOIN user u ON c.authorID = u.ID WHERE c.PostID = ? LIMIT ?", postID, moreComment)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var comment CommentItem
		err := rows.Scan(&comment.ID, &comment.Text, &comment.AuthorID, &comment.ParentID, &comment.LastModifiedDate, &comment.AuthorName, &comment.AuthorAvatar)
		if err != nil {
			return nil, err
		}
		comment.LastModifiedDate = strings.ReplaceAll(comment.LastModifiedDate, "T", " ")
		comment.LastModifiedDate = strings.ReplaceAll(comment.LastModifiedDate, "Z", "")
		comment.LastModifiedDate = lib.TimeSinceCreation(comment.LastModifiedDate)
		comment.NbrLikesComment, err = CommentRateRepo.GetLikesByComment(comment.ID)
		if err != nil {
			return nil, err
		}
		comment.NbrDislikesComment, err = CommentRateRepo.GetDislikesByComment(comment.ID)
		if err != nil {
			return nil, err
		}
		comments = append(comments, &comment)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return comments, nil
}

// Update a comment in the database
func (cr *CommentRepository) UpdateComment(comment *Comment) error {
	_, err := cr.db.Exec("UPDATE comment SET text = ?, authorID = ?, postID = ?, parentID = ?, createDate = ?, modifiedDate = ? WHERE id = ?",
		comment.Text, comment.AuthorID, comment.PostID, comment.ParentID, comment.CreateDate, comment.ModifiedDate, comment.ID)
	return err
}

// Delete a comment from the database
func (cr *CommentRepository) DeleteComment(commentID string) error {
	_, err := cr.db.Exec("DELETE FROM comment WHERE id = ?", commentID)
	return err
}
