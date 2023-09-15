package models

import (
	"database/sql"
	"forum/lib"
	"log"
	"os"
)

var (
	db               *sql.DB
	ViewRepo         *ViewRepository
	CommentRateRepo  *CommentRateRepository
	UserRepo         *UserRepository
	PostRepo         *PostRepository
	CommentRepo      *CommentRepository
	CategoryRepo     *CategoryRepository
	PostCategoryRepo *PostCategoryRepository
	NotifRepo        *NotificationRepository
	RequestRepo      *RequestRepository
	ReportRepo       *ReportRepository
	ResponseRepo     *ResponseRepository
)

func init() {
	lib.LoadEnv(".env")
	d, err := sql.Open("sqlite3", os.Getenv("DATABASE"))
	if err != nil {
		log.Fatal("❌ Couldn't open the database")
	}
	db = d

	if err = db.Ping(); err != nil {
		log.Fatal("❌ Connection to the database is dead")
	}

	query, err := os.ReadFile("./data/sql/init.sql")
	if err != nil {
		log.Fatal("couldn't read setup.sql")
	}
	if _, err = db.Exec(string(query)); err != nil {
		log.Fatal("database setup wasn't successful", err)
	}

	UserRepo = NewUserRepository(db)
	CommentRateRepo = NewCommentRateRepository(db)
	NotifRepo = NewNotificationRepository(db)
	ViewRepo = NewViewRepository(db)
	PostRepo = NewPostRepository(db)
	CommentRepo = NewCommentRepository(db)
	CategoryRepo = NewCategoryRepository(db)
	PostCategoryRepo = NewPostCategoryRepository(db)
	RequestRepo = NewRequestRepository(db)
	ReportRepo = NewReportRepository(db)
	ResponseRepo = NewResponseRepository(db)

	log.Println("✅ Database init with success")
}
