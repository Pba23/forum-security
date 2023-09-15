package handler

import (
	"forum/data/models"
	"forum/lib"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gofrs/uuid"
)

type RequestPostPageData struct {
	IsLoggedIn  bool
	CurrentUser models.User
	PostsList   []models.PostItem
	AllPosts    []*models.Post
}

func SeePosts(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/posts", http.MethodGet) {
		basePath := "base"
		pagePath := "admin/posts"
		isSessionOpen := models.ValidSession(req)
		currentuser := models.GetUserFromSession(req)
		if !isSessionOpen || currentuser.Role != 1 {
			res.WriteHeader(http.StatusNotFound)
			lib.RenderPage("base", "", nil, res)
			log.Println("404 ❌ - Page not found ", req.URL.Path)
			return
		}
		tabPostItems, err := models.PostRepo.GetAllNoValidedPosts()
		if err != nil {
			log.Println("Error getting no valided posts ", req.URL.Path)
			return
		}
		allPost, err := models.PostRepo.GetAllPosts("")
		if err != nil {
			return
		}
		PostPage := RequestPostPageData{
			IsLoggedIn:  isSessionOpen,
			CurrentUser: *currentuser,
			PostsList:   tabPostItems,
			AllPosts:    allPost,
		}
		lib.RenderPage(basePath, pagePath, PostPage, res)
		log.Println("✅ success")
	} else {
		res.WriteHeader(http.StatusNotFound)
		lib.RenderPage("base", "", nil, res)
		log.Println("404 ❌ - Page not found ", req.URL.Path)
		return
	}
}

func Publish(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/publish/*", http.MethodGet) {
		isSessionOpen := models.ValidSession(req)
		currentuser := models.GetUserFromSession(req)
		if !isSessionOpen || currentuser.Role != 1 {
			res.WriteHeader(http.StatusNotFound)
			lib.RenderPage("base", "", nil, res)
			log.Println("404 ❌ - Page not found ", req.URL.Path)
			return
		}
		path := req.URL.Path
		pathPart := strings.Split(path, "/")
		if len(pathPart) == 3 && pathPart[1] == "publish" && pathPart[2] != "" {
			slug := pathPart[2]
			post, err := models.PostRepo.GetPostBySlug(slug)
			if post == nil {
				res.WriteHeader(http.StatusNotFound)
				lib.RenderPage("base", "", nil, res)
				log.Println("404 ❌ - Page not found ", req.URL.Path)
				return
			}
			if err != nil {
				return
			}
			UpdatePost := models.Post{
				ID:           post.ID,
				Title:        post.Title,
				Slug:         post.Slug,
				Description:  post.Description,
				ImageURL:     post.ImageURL,
				AuthorID:     post.AuthorID,
				IsEdited:     post.IsEdited,
				CreateDate:   post.CreateDate,
				ModifiedDate: post.ModifiedDate,
				Validate:     true,
			}
			err = models.PostRepo.UpdatePost(&UpdatePost)
			if err != nil {
				return
			}
			lib.RedirectToPreviousURL(res, req)
		}
		log.Println("✅ publish success")
	} else {
		res.WriteHeader(http.StatusNotFound)
		lib.RenderPage("base", "", nil, res)
		log.Println("404 ❌ - Page not found ", req.URL.Path)
		return
	}
}

func Response(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/response/*", http.MethodPost) {
		isSessionOpen := models.ValidSession(req)
		currentuser := models.GetUserFromSession(req)
		if !isSessionOpen || currentuser.Role != 0 {
			res.WriteHeader(http.StatusNotFound)
			lib.RenderPage("base", "", nil, res)
			log.Println("404 ❌ - Page not found ", req.URL.Path)
			return
		}
		path := req.URL.Path
		pathPart := strings.Split(path, "/")
		if len(pathPart) == 3 && pathPart[1] == "response" && pathPart[2] != "" {
			id := pathPart[2]
			Response := models.Response{
				AuthorID:     currentuser.ID,
				ReportID:     id,
				Text:         req.FormValue("text"),
				CreateDate:   time.Now().Format("2006-01-02 15:04:05"),
				ModifiedDate: time.Now().Format("2006-01-02 15:04:05"),
			}
			err := models.ResponseRepo.CreateResponse(&Response)
			if err != nil {
				return
			}

			u, err := uuid.NewV4()
			if err != nil {
				log.Fatalf("❌ Failed to generate UUID: %v", err)
			}
			Report, err := models.ReportRepo.GetReportByID(id)
			if err != nil {
				return
			}
			user := models.GetUserFromSession(req)
			post, err := models.PostRepo.GetPostByID(Report.ReportedID)
			if err != nil {
				return
			}
			time := time.Now().Format("2006-01-02 15:04:05")
			notif := models.Notification{
				ID:         u.String(),
				AuthorID:   currentuser.ID,
				AuthorName: user.Username,
				PostID:     post.ID,
				OwnerID:    Report.AuthorID,
				Notif_type: "ResponseAdmin",
				Slug:       post.Slug,
				Time:       lib.FormatDate(time),
			}

			err = models.NotifRepo.CreateNotification(&notif)
			if err != nil {
				res.WriteHeader(http.StatusInternalServerError)
				log.Println("❌ error Insert Notification")
				return
			}
			report, err1 := models.ReportRepo.GetReportByID(id)
			if err1 != nil {
				return
			}
			UpdateReport := models.Report{
				ID:           report.ID,
				AuthorID:     report.AuthorID,
				ReportedID:   report.ReportedID,
				ReportedName: report.ReportedName,
				Cause:        report.Cause,
				Type:         report.Type,
				CreateDate:   report.CreateDate,
				ModifiedDate: report.ModifiedDate,
				Reported:     false,
				ImageURL:     report.ImageURL,
			}
			err2 := models.ReportRepo.UpdateReport(&UpdateReport)
			if err2 != nil {
				return
			}
			lib.RedirectToPreviousURL(res, req)
		}
		log.Println("✅ response success")
	} else {
		res.WriteHeader(http.StatusNotFound)
		lib.RenderPage("base", "", nil, res)
		log.Println("404 ❌ - Page1 not found ", req.URL.Path)
		return
	}
}

func DeleteReport(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/delete-report/*", http.MethodGet) {
		isSessionOpen := models.ValidSession(req)
		currentuser := models.GetUserFromSession(req)
		if !isSessionOpen || currentuser.Role != 0 {
			res.WriteHeader(http.StatusNotFound)
			lib.RenderPage("base", "", nil, res)
			log.Println("404 ❌ - Page not found ", req.URL.Path)
			return
		}
		path := req.URL.Path
		pathPart := strings.Split(path, "/")
		if len(pathPart) == 3 && pathPart[1] == "delete-report" && pathPart[2] != "" {
			id := pathPart[2]
			err1 := models.ReportRepo.DeleteReport(id)
			if err1 != nil {
				res.WriteHeader(http.StatusNotFound)
				lib.RenderPage("base", "404", nil, res)
				log.Println("404 ❌ - Page not found ", req.URL.Path)
				return
			}
			lib.RedirectToPreviousURL(res, req)
		}
	} else {
		res.WriteHeader(http.StatusNotFound)
		lib.RenderPage("base", "", nil, res)
		log.Println("404 ❌ - Page1 not found ", req.URL.Path)
		return
	}
}
