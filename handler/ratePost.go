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

func LikePost(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/like/*", http.MethodGet) {
		err := req.ParseForm()
		if err != nil {
			http.Error(res, err.Error(), http.StatusBadRequest)
			return
		}
		path := req.URL.Path
		pathPart := strings.Split(path, "/")
		if len(pathPart) == 3 && pathPart[1] == "like" && pathPart[2] != "" {
			slug := pathPart[2]
			post, err := models.PostRepo.GetPostBySlug(slug)
			if post == nil {
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
			view, err := models.ViewRepo.GetViewByAuthorIDandPostID(user.ID, post.ID)
			if err != nil {
				res.WriteHeader(http.StatusInternalServerError)
				log.Println("❌ error Reading from View")
				return
			}
			if view == nil {
				NewView := models.View{
					IsBookmarked: false,
					Rate:         1,
					AuthorID:     user.ID,
					PostID:       post.ID,
				}
				err = models.ViewRepo.CreateView(&NewView)
				if err != nil {
					res.WriteHeader(http.StatusInternalServerError)
					log.Println("❌ error Create view")
					return
				}
				u, err := uuid.NewV4()
				if err != nil {
					log.Fatalf("❌ Failed to generate UUID: %v", err)
				}
				postOwner, _ := models.UserRepo.GetUserByPostID(post.ID)
				time := time.Now().Format("2006-01-02 15:04:05")
				notif := models.Notification{
					ID:         u.String(),
					AuthorID:   user.ID,
					AuthorName: user.Username,
					PostID:     post.ID,
					OwnerID:    postOwner.ID,
					Notif_type: "has liked ❤️ your post",
					Slug:       post.Slug,
					Time:       lib.FormatDate(time),
				}
				err = models.NotifRepo.CreateNotification(&notif)
				if err != nil {
					res.WriteHeader(http.StatusInternalServerError)
					log.Println("❌ error Insert Notification")
					return
				}
				lib.RedirectToPreviousURL(res, req)
			} else {
				if view.Rate == 0 || view.Rate == 2 {
					u, err := uuid.NewV4()
					if err != nil {
						log.Fatalf("❌ Failed to generate UUID: %v", err)
					}
					postOwner, _ := models.UserRepo.GetUserByPostID(post.ID)
					time := time.Now().Format("2006-01-02 15:04:05")
					notif := models.Notification{
						ID:         u.String(),
						AuthorID:   user.ID,
						AuthorName: user.Username,
						PostID:     post.ID,
						OwnerID:    postOwner.ID,
						Notif_type: "has liked ❤️ your post",
						Slug:       post.Slug,
						Time:       lib.FormatDate(time),
					}
					err = models.NotifRepo.CreateNotification(&notif)
					if err != nil {
						res.WriteHeader(http.StatusInternalServerError)
						log.Println("❌ error Insert Notification")
						return
					}
					UpdateView := models.View{
						ID:           view.ID,
						IsBookmarked: view.IsBookmarked,
						Rate:         1,
						AuthorID:     user.ID,
						PostID:       post.ID,
					}
					err = models.ViewRepo.UpdateView(&UpdateView)
					if err != nil {
						res.WriteHeader(http.StatusInternalServerError)
						log.Println("❌ error Update view")
						return
					}
					lib.RedirectToPreviousURL(res, req)

				} else if view.Rate == 1 {
					UpdateView := models.View{
						ID:           view.ID,
						IsBookmarked: view.IsBookmarked,
						Rate:         0,
						AuthorID:     user.ID,
						PostID:       post.ID,
					}
					err = models.ViewRepo.UpdateView(&UpdateView)
					if err != nil {
						res.WriteHeader(http.StatusInternalServerError)
						log.Println("❌ error Update view")
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

func DislikePost(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/dislike/*", http.MethodGet) {
		err := req.ParseForm()
		if err != nil {
			http.Error(res, err.Error(), http.StatusBadRequest)
			return
		}
		path := req.URL.Path
		pathPart := strings.Split(path, "/")
		if len(pathPart) == 3 && pathPart[1] == "dislike" && pathPart[2] != "" {
			slug := pathPart[2]
			post, err := models.PostRepo.GetPostBySlug(slug)
			if post == nil {
				res.WriteHeader(http.StatusNotFound)
				lib.RenderPage("base", "", nil, res)
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
				res.WriteHeader(http.StatusNotFound)
				lib.RenderPage("base", "", nil, res)
				log.Println("404 ❌ - Page not found ", req.URL.Path)
				return
			}
			view, err := models.ViewRepo.GetViewByAuthorIDandPostID(user.ID, post.ID)
			if err != nil {
				res.WriteHeader(http.StatusInternalServerError)
				log.Println("❌ error Reading from View")
				return
			}
			if view == nil {
				NewView := models.View{
					IsBookmarked: false,
					Rate:         2,
					AuthorID:     user.ID,
					PostID:       post.ID,
				}
				err = models.ViewRepo.CreateView(&NewView)
				if err != nil {
					res.WriteHeader(http.StatusInternalServerError)
					log.Println("❌ error Create view")
					return
				}
				u, err := uuid.NewV4()
				if err != nil {
					log.Fatalf("❌ Failed to generate UUID: %v", err)
				}
				postOwner, _ := models.UserRepo.GetUserByPostID(post.ID)
				time := time.Now().Format("2006-01-02 15:04:05")
				notif := models.Notification{
					ID:         u.String(),
					AuthorID:   user.ID,
					AuthorName: user.Username,
					PostID:     post.ID,
					OwnerID:    postOwner.ID,
					Notif_type: "has disliked 👎 your post",
					Slug:       post.Slug,
					Time:       lib.FormatDate(time),
				}
				err = models.NotifRepo.CreateNotification(&notif)
				if err != nil {
					res.WriteHeader(http.StatusInternalServerError)
					log.Println("❌ error Insert Notification")
					return
				}
				lib.RedirectToPreviousURL(res, req)
			} else {
				if view.Rate == 0 || view.Rate == 1 {
					u, err := uuid.NewV4()
					if err != nil {
						log.Fatalf("❌ Failed to generate UUID: %v", err)
					}
					postOwner, _ := models.UserRepo.GetUserByPostID(post.ID)
					time := time.Now().Format("2006-01-02 15:04:05")
					notif := models.Notification{
						ID:         u.String(),
						AuthorID:   user.ID,
						AuthorName: user.Username,
						PostID:     post.ID,
						OwnerID:    postOwner.ID,
						Notif_type: "has disliked 👎 your post",
						Slug:       post.Slug,
						Time:       lib.FormatDate(time),
					}
					err = models.NotifRepo.CreateNotification(&notif)
					if err != nil {
						res.WriteHeader(http.StatusInternalServerError)
						log.Println("❌ error Insert Notification")
						return
					}
					UpdateView := models.View{
						ID:           view.ID,
						IsBookmarked: view.IsBookmarked,
						Rate:         2,
						AuthorID:     user.ID,
						PostID:       post.ID,
					}
					err = models.ViewRepo.UpdateView(&UpdateView)
					if err != nil {
						res.WriteHeader(http.StatusInternalServerError)
						log.Println("❌ error Update view")
						return
					}
					lib.RedirectToPreviousURL(res, req)
				} else if view.Rate == 2 {
					UpdateView := models.View{
						ID:           view.ID,
						IsBookmarked: view.IsBookmarked,
						Rate:         0,
						AuthorID:     user.ID,
						PostID:       post.ID,
					}
					err = models.ViewRepo.UpdateView(&UpdateView)
					if err != nil {
						res.WriteHeader(http.StatusInternalServerError)
						log.Println("❌ error Update view")
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
