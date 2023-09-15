package handler

import (
	"forum/data/models"
	"forum/lib"
	"log"
	"net/http"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/gofrs/uuid"
)

func SortComments(comments []*models.CommentItem) []*models.CommentItem {
	commentMap := make(map[string][]*models.CommentItem)

	for _, comment := range comments {
		commentMap[comment.ParentID] = append(commentMap[comment.ParentID], comment)
	}

	var sortedComments []*models.CommentItem
	var dfs func(string, int)
	dfs = func(parentID string, depth int) {
		children := commentMap[parentID]
		sort.SliceStable(children, func(i, j int) bool {
			return children[i].Index < children[j].Index
		})
		for _, child := range children {
			child.Index = depth
			child.Depth = strings.Repeat(`<span class="ml-1"></span>`, child.Index)
			sortedComments = append(sortedComments, child)
			dfs(child.ID, depth+1)
		}
	}

	dfs("", 0)
	return sortedComments
}

func Comment(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/comment/*", http.MethodPost) {
		err := req.ParseForm()
		if err != nil {
			http.Error(res, err.Error(), http.StatusBadRequest)
			return
		}
		text := strings.TrimSpace(req.FormValue("text"))
		parentID := strings.TrimSpace(req.FormValue("parentID"))
		path := req.URL.Path
		pathPart := strings.Split(path, "/")
		if text != "" {
			if len(pathPart) == 3 && pathPart[1] == "comment" {
				creationDate := time.Now().Format("2006-01-02 15:04:05")
				modifDate := time.Now().Format("2006-01-02 15:04:05")

				authorID := models.GetUserFromSession(req).ID
				postID := pathPart[2]

				commentStruct := models.Comment{
					Text:         text,
					AuthorID:     authorID,
					PostID:       postID,
					ParentID:     parentID,
					CreateDate:   creationDate,
					ModifiedDate: modifDate,
				}

				models.CommentRepo.CreateComment(&commentStruct)
				lib.RedirectToPreviousURL(res, req)
				u, err := uuid.NewV4()
				if err != nil {
					log.Fatalf("❌ Failed to generate UUID: %v", err)
				}
				post, err := models.PostRepo.GetPostByCommentID(commentStruct.ID)
				if err != nil {
					res.WriteHeader(http.StatusInternalServerError)
					log.Println("❌ error Finding the Post")
					return
				}
				postOwner, _ := models.UserRepo.GetUserByPostID(post.ID)
				time := creationDate
				Author, _ := models.UserRepo.GetUserByID(commentStruct.AuthorID)
				notif := models.Notification{
					ID:         u.String(),
					AuthorID:   Author.ID,
					AuthorName: Author.Username,
					PostID:     post.ID,
					OwnerID:    postOwner.ID,
					Notif_type: "have commented (" + commentStruct.Text + ") your post",
					Slug:       post.Slug,
					Time:       lib.FormatDate(time),
				}
				err = models.NotifRepo.CreateNotification(&notif)
				if err != nil {
					res.WriteHeader(http.StatusInternalServerError)
					log.Println("❌ error Insert Notification")
					return
				}
				notifications, err := models.NotifRepo.GetAllNotifs()
				Update := models.Comment{
					ID:            commentStruct.ID,
					Text:          text,
					AuthorID:      commentStruct.AuthorID,
					PostID:        postID,
					ParentID:      parentID,
					CreateDate:    creationDate,
					ModifiedDate:  modifDate,
					Notifications: notifications,
				}
				if err != nil {
					res.WriteHeader(http.StatusInternalServerError)
					log.Println("❌ no notifications")
					return
				}
				err = models.CommentRepo.UpdateComment(&Update)
				if err != nil {
					res.WriteHeader(http.StatusInternalServerError)
					log.Println("❌ error Update comment rate")
					return
				}
				lib.RedirectToPreviousURL(res, req)

			}
		} else {
			lib.RedirectToPreviousURL(res, req)
		}

	}
}

func EditCommentPage(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/edit-comment-page/*", http.MethodGet) {
		basePath := "base"
		pagePath := "edit-comment"
		isSessionOpen := models.ValidSession(req)
		user := models.GetUserFromSession(req)

		path := req.URL.Path
		pathPart := strings.Split(path, "/")
		if len(pathPart) == 3 && pathPart[1] == "edit-comment-page" && pathPart[2] != "" {
			id := pathPart[2]
			comment, err := models.CommentRepo.GetCommentByID(id)
			if comment == nil || err != nil {
				return
			}
			post, err := models.PostRepo.GetPostByID(comment.PostID)
			nbrLike, err1 := models.ViewRepo.GetLikesByPost(post.ID)
			nbrDislike, err2 := models.ViewRepo.GetDislikesByPost(post.ID)
			if err != nil || err1 != nil || err2 != nil {
				return
			}
			postCategories, err := models.PostCategoryRepo.GetCategoriesOfPost(post.ID)
			post.Description = template.HTMLEscapeString(post.Description)
			post.Title = template.HTMLEscapeString(post.Title)
			post.ModifiedDate = lib.FormatDateDB(post.ModifiedDate)
			post.ModifiedDate = lib.TimeSinceCreation(post.ModifiedDate)
			if postCategories != nil {
				for k := 0; k < len(postCategories); k++ {
					postCategories[k].Name = template.HTMLEscapeString(postCategories[k].Name)
				}
			}
			if err != nil {
				res.WriteHeader(http.StatusInternalServerError)
				log.Println("❌ error DB")
				return
			}

			notifications, err := models.NotifRepo.GetAllNotifs()

			if err != nil {
				return
			}

			userPageData := PostPageData{
				IsLoggedIn:     isSessionOpen,
				CurrentUser:    *user,
				Comment:        *comment,
				Post:           *post,
				NbrLike:        nbrLike,
				NbrDislike:     nbrDislike,
				CategoriesPost: postCategories,
				AllNotifs:      notifications,
			}

			lib.RenderPage(basePath, pagePath, userPageData, res)
			log.Println("✅ " + pagePath + " page get with success")
		} else {
			res.WriteHeader(http.StatusNotFound)
			lib.RenderPage("base", "404", nil, res)
			log.Println("404 ❌ - Page not found ", req.URL.Path)
			return
		}
	} else {
		res.WriteHeader(http.StatusNotFound)
		lib.RenderPage("base", "404", nil, res)
		log.Println("404 ❌ - Page not found ", req.URL.Path)
		return
	}
}

func EditComment(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/edit-comment/*", http.MethodPost) {
		path := req.URL.Path
		pathPart := strings.Split(path, "/")
		if len(pathPart) == 3 && pathPart[1] == "edit-comment" && pathPart[2] != "" {
			id := pathPart[2]
			comment, err := models.CommentRepo.GetCommentByID(id)
			if comment == nil {
				return
			}
			if err != nil {
				res.WriteHeader(http.StatusInternalServerError)
				log.Println("❌ error DB")
				return
			}
			comment.Text = req.FormValue("text")
			comment.ModifiedDate = time.Now().Format("2006-01-02 15:04:05")
			models.CommentRepo.UpdateComment(comment)
			http.Redirect(res, req, "/profile?index=4", http.StatusSeeOther)
		} else {
			res.WriteHeader(http.StatusNotFound)
			lib.RenderPage("base", "404", nil, res)
			log.Println("404 ❌ - Page not found ", req.URL.Path)
			return
		}
	} else {
		res.WriteHeader(http.StatusNotFound)
		lib.RenderPage("base", "404", nil, res)
		log.Println("404 ❌ - Page not found ", req.URL.Path)
		return
	}
}

func DeleteComment(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/delete-comment/*", http.MethodGet) {
		isSessionOpen := models.ValidSession(req)
		if isSessionOpen {
			path := req.URL.Path
			pathPart := strings.Split(path, "/")
			if len(pathPart) == 3 && pathPart[1] == "delete-comment" && pathPart[2] != "" {
				id := pathPart[2]
				models.CommentRepo.DeleteComment(id)

				log.Println("✅ comment deleted with success")
				http.Redirect(res, req, "/profile?index=4", http.StatusSeeOther)
			}
		} else {
			res.WriteHeader(http.StatusNotFound)
			lib.RenderPage("base", "404", nil, res)
			log.Println("404 ❌ - Page not found ", req.URL.Path)
			return
		}
	} else {
		res.WriteHeader(http.StatusNotFound)
		lib.RenderPage("base", "404", nil, res)
		log.Println("404 ❌ - Page not found ", req.URL.Path)
		return
	}
}
