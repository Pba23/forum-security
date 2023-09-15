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

func LikeComment(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/like-comment/*", http.MethodGet) {
		err := req.ParseForm()
		if err != nil {
			http.Error(res, err.Error(), http.StatusBadRequest)
			return
		}
		path := req.URL.Path
		pathPart := strings.Split(path, "/")
		if len(pathPart) == 3 && pathPart[1] == "like-comment" && pathPart[2] != "" {
			commentID := pathPart[2]
			comment, err := models.CommentRepo.GetCommentByID(commentID)
			if comment == nil {
				res.WriteHeader(http.StatusNotFound)
				lib.RenderPage("base", "404", nil, res)
				log.Println("404 ❌ - Page not found ", req.URL.Path)
				return
			}
			if err != nil {
				res.WriteHeader(http.StatusInternalServerError)
				log.Println("❌ error DB")
				return
			}
			user := models.GetUserFromSession(req)
			if user == nil {
				return
			}
			commentRate, err := models.CommentRateRepo.GetRateByAuthorIDandCommentID(user.ID, comment.ID)
			if err != nil {
				res.WriteHeader(http.StatusInternalServerError)
				log.Println("❌ error Reading from Rate")
				return
			}
			if commentRate == nil {
				NewRate := models.CommentRate{
					Rate:      1,
					AuthorID:  user.ID,
					CommentID: comment.ID,
				}
				err = models.CommentRateRepo.CreateCommentRate(&NewRate)
				if err != nil {
					res.WriteHeader(http.StatusInternalServerError)
					log.Println("❌ error Creating comment rate")
					return
				}
				lib.RedirectToPreviousURL(res, req)
			} else {
				if commentRate.Rate == 0 || commentRate.Rate == 2 {
					u, err := uuid.NewV4()
					if err != nil {
						log.Fatalf("❌ Failed to generate UUID: %v", err)
					}
					post, err := models.PostRepo.GetPostByCommentID(commentRate.CommentID)
					if err != nil {
						res.WriteHeader(http.StatusInternalServerError)
						log.Println("❌ error Finding the Post")
						return
					}
					postOwner, _ := models.UserRepo.GetUserByPostID(post.ID)
					time := time.Now().Format("2006-01-02 15:04:05")
					notif := models.Notification{
						ID:         u.String(),
						AuthorID:   user.ID,
						AuthorName: user.Username,
						PostID:     post.ID,
						OwnerID:    postOwner.ID,
						Notif_type: "has liked ❤️ your comment",
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
					if err != nil {
						res.WriteHeader(http.StatusInternalServerError)
						log.Println("❌ no notifications")
						return
					}
					UpdateRate := models.CommentRate{
						ID:            commentRate.ID,
						Rate:          1,
						AuthorID:      user.ID,
						CommentID:     comment.ID,
						Notifications: notifications,
					}
					err = models.CommentRateRepo.UpdateRate(&UpdateRate)
					if err != nil {
						res.WriteHeader(http.StatusInternalServerError)
						log.Println("❌ error Update comment rate")
						return
					}
					lib.RedirectToPreviousURL(res, req)
				} else if commentRate.Rate == 1 {
					UpdateRate := models.CommentRate{
						ID:        commentRate.ID,
						Rate:      0,
						AuthorID:  user.ID,
						CommentID: comment.ID,
					}
					err = models.CommentRateRepo.UpdateRate(&UpdateRate)
					if err != nil {
						res.WriteHeader(http.StatusInternalServerError)
						log.Println("❌ error Update comment rate")
						return
					}
					lib.RedirectToPreviousURL(res, req)
				}
			}
		} else {
			res.WriteHeader(http.StatusNotFound)
			lib.RenderPage("base", "404", nil, res)
			log.Println("404 ❌ - Page not found ", req.URL.Path)
		}
	}
}

func DislikeComment(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/dislike-comment/*", http.MethodGet) {
		err := req.ParseForm()
		if err != nil {
			http.Error(res, err.Error(), http.StatusBadRequest)
			return
		}
		path := req.URL.Path
		pathPart := strings.Split(path, "/")
		if len(pathPart) == 3 && pathPart[1] == "dislike-comment" && pathPart[2] != "" {
			commentID := pathPart[2]
			comment, err := models.CommentRepo.GetCommentByID(commentID)
			if comment == nil {
				res.WriteHeader(http.StatusNotFound)
				lib.RenderPage("base", "404", nil, res)
				log.Println("404 ❌ - Page not found ", req.URL.Path)
				return
			}
			if err != nil {
				res.WriteHeader(http.StatusInternalServerError)
				log.Println("❌ error DB")
				return
			}
			user := models.GetUserFromSession(req)
			if user == nil {
				return
			}
			commentRate, err := models.CommentRateRepo.GetRateByAuthorIDandCommentID(user.ID, comment.ID)
			if err != nil {
				res.WriteHeader(http.StatusInternalServerError)
				log.Println("❌ error Reading from Rate")
				return
			}
			if commentRate == nil {
				NewRate := models.CommentRate{
					Rate:      2,
					AuthorID:  user.ID,
					CommentID: comment.ID,
				}
				err = models.CommentRateRepo.CreateCommentRate(&NewRate)
				if err != nil {
					res.WriteHeader(http.StatusInternalServerError)
					log.Println("❌ error Creating comment rate")
					return
				}
				lib.RedirectToPreviousURL(res, req)
			} else {
				if commentRate.Rate == 0 || commentRate.Rate == 1 {
					u, err := uuid.NewV4()
					if err != nil {
						log.Fatalf("❌ Failed to generate UUID: %v", err)
					}
					post, err := models.PostRepo.GetPostByCommentID(commentRate.CommentID)
					if err != nil {
						res.WriteHeader(http.StatusInternalServerError)
						log.Println("❌ error Finding the Post")
						return
					}
					postOwner, _ := models.UserRepo.GetUserByPostID(post.ID)
					time := time.Now().Format("2006-01-02 15:04:05")
					notif := models.Notification{
						ID:         u.String(),
						AuthorID:   user.ID,
						AuthorName: user.Username,
						PostID:     post.ID,
						OwnerID:    postOwner.ID,
						Notif_type: "has disliked 👎 your comment",
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
					if err != nil {
						res.WriteHeader(http.StatusInternalServerError)
						log.Println("❌ no notifications")
						return
					}

					UpdateRate := models.CommentRate{
						ID:            commentRate.ID,
						Rate:          2,
						AuthorID:      user.ID,
						CommentID:     comment.ID,
						Notifications: notifications,
					}
					err = models.CommentRateRepo.UpdateRate(&UpdateRate)
					if err != nil {
						res.WriteHeader(http.StatusInternalServerError)
						log.Println("❌ error Update comment rate")
						return
					}
					lib.RedirectToPreviousURL(res, req)
				} else if commentRate.Rate == 2 {
					UpdateRate := models.CommentRate{
						ID:        commentRate.ID,
						Rate:      0,
						AuthorID:  user.ID,
						CommentID: comment.ID,
					}
					err = models.CommentRateRepo.UpdateRate(&UpdateRate)
					if err != nil {
						res.WriteHeader(http.StatusInternalServerError)
						log.Println("❌ error Update comment rate")
						return
					}
					lib.RedirectToPreviousURL(res, req)
				}
			}
		} else {
			res.WriteHeader(http.StatusNotFound)
			lib.RenderPage("base", "404", nil, res)
			log.Println("404 ❌ - Page not found ", req.URL.Path)
		}
	}
}
