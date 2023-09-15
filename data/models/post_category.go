package models

import (
	"database/sql"
	"forum/lib"
	"log"
	"strings"

	uuid "github.com/gofrs/uuid"
	_ "github.com/mattn/go-sqlite3"
)

type PostCategory struct {
	ID         string
	CategoryID string
	PostID     string
}

type PostCategoryRepository struct {
	db *sql.DB
}

func NewPostCategoryRepository(db *sql.DB) *PostCategoryRepository {
	return &PostCategoryRepository{
		db: db,
	}
}

// Create a new post-category relationship in the database
func (pcr *PostCategoryRepository) CreatePostCategory(categoryID, postID string) error {
	ID, err := uuid.NewV4()
	if err != nil {
		log.Fatalf("❌ Failed to generate UUID: %v", err)
	}
	postCategory := PostCategory{
		ID:         ID.String(),
		CategoryID: categoryID,
		PostID:     postID,
	}
	_, err = pcr.db.Exec("INSERT INTO post_category (id, categoryID, postID) VALUES (?, ?, ?)",
		postCategory.ID, postCategory.CategoryID, postCategory.PostID)
	return err
}

// Get categories of a post from the database
func (pcr *PostCategoryRepository) GetCategoriesOfPost(postID string) ([]Category, error) {
	rows, err := pcr.db.Query(`
		SELECT c.id, c.name, c.createDate, c.modifiedDate
		FROM category c
		INNER JOIN post_category pc ON c.id = pc.categoryID
		WHERE pc.postID = ?
	`, postID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var categories []Category
	for rows.Next() {
		var category Category
		err := rows.Scan(&category.ID, &category.Name, &category.CreateDate, &category.ModifiedDate)
		if err != nil {
			return nil, err
		}
		categories = append(categories, category)
	}

	return categories, nil
}

// Get posts of a category from the database
func (pcr *PostCategoryRepository) GetPostsOfCategory(categoryName string) ([]PostItem, error) {
	rows, err := pcr.db.Query(`
SELECT
    p.id AS ID,
    p.title AS Title,
    p.slug AS Slug,
    u.username AS AuthorName,
    p.imageURL AS ImageURL,
    p.modifiedDate AS LastEditionDate,
    COALESCE(cmt.comment_count, 0) AS NumberOfComments,
    COALESCE(cmt.commentators, '') AS ListOfCommentator
FROM
    post p
JOIN
    post_category pc ON p.id = pc.postID
JOIN
    category cat ON pc.categoryID = cat.id
LEFT JOIN (
    SELECT
        c.postID,
        COUNT(c.id) AS comment_count,
        GROUP_CONCAT(u.avatarURL) AS commentators
    FROM "comment" c
    JOIN "user" u ON c.authorID = u.id
    GROUP BY c.postID
) cmt ON p.id = cmt.postID
LEFT JOIN
    user u ON p.authorID = u.id
WHERE
    cat.name = ?
GROUP BY
    p.id, p.title, p.slug, u.avatarURL, p.imageURL, p.modifiedDate, comment_count
ORDER BY
    p.modifiedDate DESC
	`, categoryName)
	if err != nil {
		log.Println("❌ SQL ERROR ", err.Error())
		return nil, err
	}
	defer rows.Close()

	var posts []PostItem
	for rows.Next() {
		_listOfCommentator := ""
		var post PostItem
		err := rows.Scan(
			&post.ID, &post.Title, &post.Slug, &post.AuthorName, &post.ImageURL, &post.LastEditionDate, &post.NumberOfComments, &_listOfCommentator,
		)
		if err != nil {
			log.Println("❌ SQL ERROR ", err.Error())
			return nil, err
		}
		post.ListOfCommentator = strings.Split(_listOfCommentator, ",")
		post.LastEditionDate = strings.ReplaceAll(post.LastEditionDate, "T", " ")
		post.LastEditionDate = strings.ReplaceAll(post.LastEditionDate, "Z", "")
		post.LastEditionDate = lib.TimeSinceCreation(post.LastEditionDate)
		posts = append(posts, post)
	}

	return posts, nil
}

// Delete a category from the database
func (cr *PostCategoryRepository) DeletePostCategory(categoryID, userID string) error {
	_, err := cr.db.Exec("DELETE FROM post_category WHERE categoryID = ? AND postID = ?", categoryID, userID)
	return err
}
