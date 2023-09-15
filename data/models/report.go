package models

import (
	"database/sql"
	"errors"
	"log"

	uuid "github.com/gofrs/uuid"
	_ "github.com/mattn/go-sqlite3"
)

type Report struct {
	ID           string
	AuthorID     string
	ReportedID   string
	ReportedName string
	Cause        string
	Type         string
	CreateDate   string
	ModifiedDate string
	Reported     bool
	ImageURL     string
}

type ReportRepository struct {
	db *sql.DB
}

func NewReportRepository(db *sql.DB) *ReportRepository {
	return &ReportRepository{
		db: db,
	}
}

func (rr *ReportRepository) GetAllReports() ([]Report, error) {
	var reports []Report
	rows, err := rr.db.Query("SELECT id, authorID, reportedID, ReportedName, cause, type, createDate, modifiedDate, reported, ImageURL FROM report ORDER BY createDate")

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var report Report
		err := rows.Scan(&report.ID, &report.AuthorID, &report.ReportedID, &report.ReportedName, &report.Cause, &report.Type, &report.CreateDate, &report.ModifiedDate, &report.Reported, &report.ImageURL)

		if err != nil {
			return nil, err
		}

		reports = append(reports, report)
	}

	return reports, nil

}

// Create a new report in the database
func (rr *ReportRepository) CreateReport(report *Report) error {
	ID, err := uuid.NewV4()
	if err != nil {
		log.Fatalf("❌ Failed to generate UUID: %v", err)
	}
	report.ID = ID.String()
	_, err = rr.db.Exec("INSERT INTO report (id, authorID, reportedID, ReportedName, cause, type, createDate, modifiedDate, reported, ImageURL ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		report.ID, report.AuthorID, report.ReportedID, report.ReportedName, report.Cause, report.Type, report.CreateDate, report.ModifiedDate, report.Reported, report.ImageURL)
	return err
}

// Get a report by ID from the database
func (rr *ReportRepository) GetReportByID(reportID string) (*Report, error) {
	var report Report
	row := rr.db.QueryRow("SELECT id, authorID, reportedID, ReportedName, cause, type, createDate, modifiedDate, reported, ImageURL FROM report WHERE id = ?", reportID)
	err := row.Scan(&report.ID, &report.AuthorID, &report.ReportedID, &report.ReportedName, &report.Cause, &report.Type, &report.CreateDate, &report.ModifiedDate, &report.Reported, &report.ImageURL)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Report not found
		}
		return nil, err
	}
	return &report, nil
}

func (rr *ReportRepository) GetReportByIDPost(idPost string) (*Report, error) {
	var report Report
	row := rr.db.QueryRow("SELECT id, authorID, reportedID, ReportedName, cause, type, createDate, modifiedDate, reported, ImageURL FROM report WHERE reportedID = ?", idPost)
	err := row.Scan(&report.ID, &report.AuthorID, &report.ReportedID, &report.ReportedName, &report.Cause, &report.Type, &report.CreateDate, &report.ModifiedDate, &report.Reported, &report.ImageURL)
	if err == nil {
		if err != sql.ErrNoRows {
			return &report, errors.New("already reported")
		}
		return &report, nil
	}
	return &report, nil
}

func (rr *ReportRepository) GetReportByIDPostExist(idPost string) (*Report, error) {
	var report Report
	row := rr.db.QueryRow("SELECT id, authorID, reportedID, ReportedName, cause, type, createDate, modifiedDate, reported, ImageURL FROM report WHERE reportedID = ?", idPost)
	err := row.Scan(&report.ID, &report.AuthorID, &report.ReportedID, &report.ReportedName, &report.Cause, &report.Type, &report.CreateDate, &report.ModifiedDate, &report.Reported, &report.ImageURL)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Report not found
		}
		return nil, err
	}
	return &report, nil
}

// Update a report in the database
func (rr *ReportRepository) UpdateReport(report *Report) error {
	_, err := rr.db.Exec("UPDATE report SET authorID = ?, reportedID = ?, ReportedName = ? , cause = ?, type = ?, createDate = ?, modifiedDate = ?, reported = ?, ImageURL = ? WHERE id = ?",
		report.AuthorID, report.ReportedID, &report.ReportedName, report.Cause, report.Type, report.CreateDate, report.ModifiedDate, report.Reported, report.ImageURL, report.ID)
	return err
}

// Delete a report from the database
func (rr *ReportRepository) DeleteReport(reportID string) error {
	_, err := rr.db.Exec("DELETE FROM report WHERE id = ?", reportID)
	return err
}
