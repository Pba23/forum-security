package models

import (
	"database/sql"
	"log"
	"strings"

	uuid "github.com/gofrs/uuid"
	_ "github.com/mattn/go-sqlite3"
)

type User struct {
	ID         string
	Username   string
	IsLoggedIn string
	Email      string
	Password   string
	AvatarURL  string
	Role       ROLE
}

type TopUser struct {
	ID               string
	Username         string
	AvatarURL        string
	NumberOfReaction int
}

var DEFAULT_AVATAR = "/uploads/avatar.1.jpeg"

type ROLE int

const (
	RoleAdmin     ROLE = 0
	RoleModerator ROLE = 1
	RoleUser      ROLE = 2
)

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{
		db: db,
	}
}

// Create a new user in the database
func (ur *UserRepository) CreateUser(user *User) error {
	ID, err := uuid.NewV4()
	if err != nil {
		log.Fatalf("❌ Failed to generate UUID: %v", err)
	}
	user.ID = ID.String()
	_, err = ur.db.Exec("INSERT INTO user (id, username, email, password, avatarURL, role) VALUES (?, ?, ?, ?, ?, ?)",
		user.ID, user.Username, user.Email, user.Password, user.AvatarURL, user.Role)
	return err
}

// Get a user by ID from the database
func (ur *UserRepository) GetUserByID(userID string) (*User, error) {
	var user User
	row := ur.db.QueryRow("SELECT id, username, email, password, avatarURL, role FROM user WHERE id = ?", userID)
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.AvatarURL, &user.Role)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // User not found
		}
		return nil, err
	}
	return &user, nil
}

// Get a user by email from the database
func (ur *UserRepository) GetUserByEmail(email string) (*User, error) {
	var user User
	row := ur.db.QueryRow("SELECT id, username, email, password, avatarURL, role FROM user WHERE email = ?", email)
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.AvatarURL, &user.Role)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // User not found
		}
		return nil, err
	}
	return &user, nil
}

// Get a user by email from the database
func (ur *UserRepository) GetUserByUsername(username string) (*User, error) {
	var user User
	row := ur.db.QueryRow("SELECT id, username, email, password, avatarURL, role FROM user WHERE username = ?", username)
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.AvatarURL, &user.Role)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // User not found
		}
		return nil, err
	}
	return &user, nil
}

// Select All users
func (ur *UserRepository) SelectAllUsers() ([]User, error) {
	var user []User
	row, err := ur.db.Query("SELECT * FROM user")
	if err != nil {
		log.Fatal(err)
	}
	for row.Next() {
		var ID string
		var Email string
		var Username string
		var Password string
		var AvatarUrl string
		var Role ROLE

		err = row.Scan(&ID, &Username, &Email, &Password, &AvatarUrl, &Role)
		if err != nil {
			log.Fatal(err)
		}

		var tab = User{
			ID:        ID,
			Email:     Email,
			Username:  Username,
			Password:  Password,
			AvatarURL: AvatarUrl,
			Role:      Role,
		}

		user = append(user, tab)
	}
	return user, nil
}

// Select All users
func (ur *UserRepository) SelectAllUsersByPost(postID string) ([]User, error) {
	var user []User
	row, err := ur.db.Query("SELECT u.id AS user_id, u.avatarURL AS user_avatar, u.username FROM \"comment\" c INNER JOIN \"user\" u ON c.authorID = u.id WHERE c.postID = ?;", postID)
	if err != nil {
		log.Fatal(err)
	}
	for row.Next() {
		var ID string
		var AvatarUrl string
		var Username string

		err = row.Scan(&ID, &AvatarUrl, &Username)

		if err != nil {
			log.Fatal(err)
		}

		var tab = User{
			ID:        ID,
			AvatarURL: AvatarUrl,
			Username:  Username,
		}

		user = append(user, tab)
	}
	return user, nil
}

// Select 17 random users from the database
func (ur *UserRepository) SelectRandomUsers(count int) ([]User, error) {
	var users []User
	query := "SELECT * FROM user ORDER BY RANDOM() LIMIT ?"
	rows, err := ur.db.Query(query, count)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var user User
		err := rows.Scan(
			&user.ID,
			&user.Username,
			&user.Email,
			&user.Password,
			&user.AvatarURL,
			&user.Role,
		)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	if len(users) < count {
		rest := count - len(users)
		for i := 0; i < rest; i++ {
			users = append(users, User{
				AvatarURL: DEFAULT_AVATAR,
			})
		}
	}

	return users, nil
}

// Update a user in the database
func (ur *UserRepository) UpdateUser(user *User) error {
	_, err := ur.db.Exec("UPDATE user SET username = ?, email = ?, password = ?, avatarURL = ?, role = ? WHERE id = ?",
		user.Username, user.Email, user.Password, user.AvatarURL, user.Role, user.ID)
	return err
}

// Delete a user from the database
func (ur *UserRepository) DeleteUser(userID string) error {
	_, err := ur.db.Exec("DELETE FROM user WHERE id = ?", userID)
	return err
}

// Check if user exists
func (ur *UserRepository) IsExisted(email, username string) (*User, bool) {
	var user User
	email = strings.ToLower(email)
	username = strings.ToLower(username)
	row := ur.db.QueryRow("SELECT password FROM user WHERE email = ? OR username = ?", email, username)
	err := row.Scan(&user.Password)
	if err != nil {
		log.Println("❌ ", err)
		if err == sql.ErrNoRows {
			return nil, false
		}
		return nil, false
	}
	return &user, true
}

func (ur *UserRepository) IsExistedSignIn(email string) (*User, bool) {
	var user User
	email = strings.ToLower(email)
	row := ur.db.QueryRow("SELECT password FROM user WHERE email = ?", email)
	err := row.Scan(&user.Password)
	if err != nil {
		log.Println("❌1 ", err)
		if err == sql.ErrNoRows {
			return nil, false
		}
		return nil, false
	}
	return &user, true
}

// Check if user exists
func (ur *UserRepository) IsExistedByID(ID string) (*User, bool) {
	var user User
	row := ur.db.QueryRow("SELECT id FROM user WHERE id = ?", ID)
	err := row.Scan(&user.ID)
	if err != nil {
		log.Println("❌ ", err)
		if err == sql.ErrNoRows {
			return nil, false
		}
		return nil, false
	}
	return &user, true
}

func (ur *UserRepository) TopUsers() ([]TopUser, error) {
	var user []TopUser
	row, err := ur.db.Query(`SELECT u.id AS user_id,
									u.username AS user_username,
									u.avatarurl AS avatarurl,
									COALESCE(COUNT(DISTINCT c.id),0) + COALESCE(COUNT(DISTINCT v.id),0) AS number_of_reactions
							FROM "user" u
							LEFT JOIN "post" p ON u.id = p.authorID
							LEFT JOIN "comment" c ON p.id = c.postID
							LEFT JOIN "view" v ON p.id = v.postID
							GROUP BY u.id , u.email
							ORDER BY (number_of_reactions) DESC
							LIMIT 3`)
	if err != nil {
		log.Fatal(err)
	}
	for row.Next() {
		var ID string
		var Username string
		var AvatarUrl string
		var NumberOfReaction int
		err = row.Scan(&ID, &Username, &AvatarUrl, &NumberOfReaction)

		if err != nil {
			log.Fatal(err)
		}

		var tab = TopUser{
			ID:               ID,
			Username:         Username,
			AvatarURL:        AvatarUrl,
			NumberOfReaction: NumberOfReaction,
		}

		user = append(user, tab)
	}
	return user, nil
}
func (ur *UserRepository) GetUserByPostID(PostID string) (*User, error) {
	post, err := PostRepo.GetPostByID(PostID)
	if err == nil {
		user, err := ur.GetUserByID(post.AuthorID)
		if err != nil {
			return nil, err
		} else {
			return user, nil
		}
	} else {
		return nil, err
	}
}
