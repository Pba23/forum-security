package handler

import (
	"forum/data/models"
	"forum/lib"
	"log"
	"net/http"
	"strings"
	"text/template"
	"time"

	"github.com/gofrs/uuid"
)

type RequestPageData struct {
	IsLoggedIn  bool
	CurrentUser models.User
	Requests    []models.Request
	AllPosts    []*models.Post
}

func SeeRequests(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/requests", http.MethodGet) {
		basePath := "base"
		pagePath := "admin/request"
		isSessionOpen := models.ValidSession(req)
		currentuser := models.GetUserFromSession(req)
		if !isSessionOpen || currentuser.Role != 0 {
			res.WriteHeader(http.StatusNotFound)
			lib.RenderPage("base", "", nil, res)
			log.Println("404 ❌ - Page not found ", req.URL.Path)
			return
		}
		requests, err := models.RequestRepo.GetAllRequest()
		if err != nil {
			return
		}
		allPosts, err := models.PostRepo.GetAllPosts("")
		if err != nil {
			return
		}

		requestPageData := RequestPageData{
			IsLoggedIn:  isSessionOpen,
			CurrentUser: *currentuser,
			Requests:    requests,
			AllPosts:    allPosts,
		}

		lib.RenderPage(basePath, pagePath, requestPageData, res)
		log.Println("✅ Request page get with success")
	}
}

func ReportPost(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/reportpost/*", http.MethodPost) {
		base := "base"
		PagePath := "post"
		isSessionOpen := models.ValidSession(req)
		currentuser := models.GetUserFromSession(req)
		if !isSessionOpen || currentuser.Role == 0 || currentuser.Role == 2 {
			res.WriteHeader(http.StatusNotFound)
			lib.RenderPage("base", "", nil, res)
			log.Println("404 ❌ - Page not found ", req.URL.Path)
			return
		}
		path := req.URL.Path
		pathPart := strings.Split(path, "/")
		if len(pathPart) == 3 && pathPart[1] == "reportpost" && pathPart[2] != "" {
			idPost := pathPart[2]
			post, err := models.PostRepo.GetPostByID(idPost)
			if post == nil {
				res.WriteHeader(http.StatusNotFound)
				lib.RenderPage("base", "404", nil, res)
				log.Println("404 ❌ - Page not found ", req.URL.Path)
				return
			}

			if err != nil {
				log.Println("❌ error DB", err.Error())
				return
			}
			user, err := models.UserRepo.GetUserByPostID(idPost)
			if err != nil {
				log.Fatal("Can't get user by postID")
			}
			if user == nil {
				res.WriteHeader(http.StatusNotFound)
				lib.RenderPage("base", "", nil, res)
				log.Println("404 ❌ - Page not found ", req.URL.Path)
				return
			}

			IDreport, err := uuid.NewV4()

			if err != nil {
				log.Println("❌ Failed to generate uuid")
			}

			creationDate := time.Now().Format("2006-01-02 15:04:05")
			modificationDate := time.Now().Format("2006-01-02 15:04:05")

			cause := req.FormValue("cause")
			typeReport := req.FormValue("type")

			if cause == "" || typeReport == "" {
				res.WriteHeader(http.StatusBadRequest)
				lib.RenderPage("base", "", nil, res)
				log.Println("404 ❌ - Page not found ", req.URL.Path)
				return
			}

			report := models.Report{
				ID:           IDreport.String(),
				AuthorID:     currentuser.ID,
				ReportedID:   idPost,
				ReportedName: post.Slug,
				Cause:        cause,
				Type:         typeReport,
				CreateDate:   creationDate,
				ModifiedDate: modificationDate,
				Reported:     true,
				ImageURL:     post.ImageURL,
			}

			_, err = models.ReportRepo.GetReportByIDPost(idPost)

			if err != nil {
				lib.RedirectToPreviousURL(res, req)
				log.Fatal("❌ Report Already done")
				return
			}

			err = models.ReportRepo.CreateReport(&report)

			if err != nil {
				log.Println("❌ Failed to create report")
			}

			PostComments, err := models.CommentRepo.GetCommentsOfPost(post.ID, "15")
			if err != nil {
				res.WriteHeader(http.StatusInternalServerError)
				log.Println("❌ error DB", err.Error())
				return
			}
			PostComments = SortComments(PostComments)
			post.ModifiedDate = strings.ReplaceAll(post.ModifiedDate, "T", " ")
			post.ModifiedDate = strings.ReplaceAll(post.ModifiedDate, "Z", "")
			post.ModifiedDate = lib.TimeSinceCreation(post.ModifiedDate)
			userPost, err := models.UserRepo.GetUserByID(post.AuthorID)
			if err != nil {
				res.WriteHeader(http.StatusInternalServerError)
				log.Println("❌ error reading from user", err.Error())
				return
			}
			postCategories, err := models.PostCategoryRepo.GetCategoriesOfPost(post.ID)
			if err != nil {
				res.WriteHeader(http.StatusInternalServerError)
				log.Println("❌ error reading from category", err.Error())
				return
			}
			nbrLike, err := models.ViewRepo.GetLikesByPost(post.ID)
			if err != nil {
				res.WriteHeader(http.StatusInternalServerError)
				log.Println("❌ error reading from View", err.Error())
				return
			}
			nbrDislike, err := models.ViewRepo.GetDislikesByPost(post.ID)
			if err != nil {
				res.WriteHeader(http.StatusInternalServerError)
				log.Println("❌ error reading from View", err.Error())
				return
			}
			post.Description = template.HTMLEscapeString(post.Description)
			post.Title = template.HTMLEscapeString(post.Title)
			if postCategories != nil {
				for k := 0; k < len(postCategories); k++ {
					postCategories[k].Name = template.HTMLEscapeString(postCategories[k].Name)
				}
			}

			if PostComments != nil {
				for j := 0; j < len(PostComments); j++ {
					PostComments[j].Text = template.HTMLEscapeString(PostComments[j].Text)
				}
			}
			userPost.IsLoggedIn = "Offline"
			if models.CheckIfSessionExist(userPost.Username) {
				userPost.IsLoggedIn = "Online"
			}
			cat, err := models.CategoryRepo.GetAllCategory()
			if err != nil {
				return
			}
			allPost, err := models.PostRepo.GetAllPosts("")
			if err != nil {
				return
			}

			notifications, err := models.NotifRepo.GetAllNotifs()

			if err != nil {
				return
			}

			NbrOfBookmarks, err := models.ViewRepo.GetNbrOfBookmarks(post.ID)

			if err != nil {
				return
			}

			PostPageData := PostPageData{
				IsLoggedIn:     isSessionOpen,
				Post:           *post,
				CurrentUser:    *(models.GetUserFromSession(req)),
				UserPoster:     userPost,
				Comments:       PostComments,
				NbrComment:     len(PostComments),
				CategoriesPost: postCategories,
				NbrLike:        nbrLike,
				NbrDislike:     nbrDislike,
				Categories:     cat,
				AllPosts:       allPost,
				NbrBookmarks:   NbrOfBookmarks,
				AllNotifs:      notifications,
				Reported:       true,
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
				Validate:     false,
			}
			err = models.PostRepo.UpdatePost(&UpdatePost)
			if err != nil {
				return
			}

			log.Println("Report Created")
			lib.RenderPage(base, PagePath, PostPageData, res)
			log.Println("✅ Post page get with success")
		}
	}
}

type ReportPageData struct {
	IsLoggedIn  bool
	CurrentUser models.User
	Reports     []models.Report
	AllPosts    []*models.Post
}

func SeeReports(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/seeReports", http.MethodGet) {
		base := "base"
		PagePath := "admin/reports"
		isSessionOpen := models.ValidSession(req)
		currentuser := models.GetUserFromSession(req)
		if !isSessionOpen || currentuser.Role != 0 {
			res.WriteHeader(http.StatusNotFound)
			lib.RenderPage("base", "", nil, res)
			log.Println("404 ❌ - Page not found ", req.URL.Path)
			return
		}
		AllReports, err := models.ReportRepo.GetAllReports()

		if err != nil {
			log.Fatal("No Reports")
		}

		allPosts, err := models.PostRepo.GetAllPosts("")
		if err != nil {
			log.Fatal("Cannot Get Posts")
			return
		}

		ReportPageData := ReportPageData{
			IsLoggedIn:  isSessionOpen,
			CurrentUser: *currentuser,
			Reports:     AllReports,
			AllPosts:    allPosts,
		}
		lib.RenderPage(base, PagePath, ReportPageData, res)
		log.Println("✅ Home page get with success")
	}
}

func Validate(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/validate/*", http.MethodGet) {
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
		if len(pathPart) == 3 && pathPart[1] == "validate" && pathPart[2] != "" {
			id := pathPart[2]
			user, err := models.UserRepo.GetUserByID(id)
			if user == nil {
				res.WriteHeader(http.StatusNotFound)
				lib.RenderPage("base", "", nil, res)
				log.Println("404 ❌ - Page not found ", req.URL.Path)
				return
			}
			if err != nil {
				return
			}
			UpdateUser := models.User{
				ID:        user.ID,
				Username:  user.Username,
				Email:     user.Email,
				Password:  user.Password,
				AvatarURL: user.AvatarURL,
				Role:      models.RoleModerator,
			}
			err = models.UserRepo.UpdateUser(&UpdateUser)
			if err != nil {
				res.WriteHeader(http.StatusInternalServerError)
				log.Println("❌ error Update user")
				return
			}
			request, err := models.RequestRepo.GetRequestByUser(user.ID)
			if err != nil {
				return
			}
			UpdateRequest := models.Request{
				ID:       request.ID,
				AuthorID: request.AuthorID,
				Time:     request.Time,
				Username: request.Username,
				ImageURL: request.ImageURL,
				Role:     models.RoleModerator,
			}
			err = models.RequestRepo.UpdateRequest(&UpdateRequest)
			if err != nil {
				res.WriteHeader(http.StatusInternalServerError)
				log.Println("❌ error Update user")
				return
			}
			lib.RedirectToPreviousURL(res, req)
		} else {
			res.WriteHeader(http.StatusNotFound)
			lib.RenderPage("base", "", nil, res)
			log.Println("404 ❌ - Page not found ", req.URL.Path)
			return
		}
	} else {
		res.WriteHeader(http.StatusNotFound)
		lib.RenderPage("base", "", nil, res)
		log.Println("404 ❌ - Page not found ", req.URL.Path)
		return
	}
}

func Invalidate(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/invalidate/*", http.MethodGet) {
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
		if len(pathPart) == 3 && pathPart[1] == "invalidate" && pathPart[2] != "" {
			id := pathPart[2]
			user, err := models.UserRepo.GetUserByID(id)
			if user == nil {
				res.WriteHeader(http.StatusNotFound)
				lib.RenderPage("base", "", nil, res)
				log.Println("404 ❌ - Page not found ", req.URL.Path)
				return
			}
			if err != nil {
				return
			}
			request, err := models.RequestRepo.GetRequestByUser(user.ID)
			if request == nil {
				res.WriteHeader(http.StatusNotFound)
				lib.RenderPage("base", "", nil, res)
				log.Println("404 ❌ - Page not found ", req.URL.Path)
				return
			}
			if err != nil {
				return
			}
			models.RequestRepo.DeleteRequest(request.ID)
			lib.RedirectToPreviousURL(res, req)
		} else {
			res.WriteHeader(http.StatusNotFound)
			lib.RenderPage("base", "", nil, res)
			log.Println("404 ❌ - Page not found ", req.URL.Path)
			return
		}
	} else {
		res.WriteHeader(http.StatusNotFound)
		lib.RenderPage("base", "", nil, res)
		log.Println("404 ❌ - Page not found ", req.URL.Path)
		return
	}
}
