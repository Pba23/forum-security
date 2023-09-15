package handler

import (
	"forum/data/models"
	"forum/lib"
	"log"
	"net/http"
	"strings"

	"github.com/gofrs/uuid"
)

func Bookmark(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/bookmark/*", http.MethodGet) {
		err := req.ParseForm()
		if err != nil {
			http.Error(res, err.Error(), http.StatusBadRequest)
			return
		}
		path := req.URL.Path
		pathPart := strings.Split(path, "/")
		if len(pathPart) == 3 && pathPart[1] == "bookmark" && pathPart[2] != "" {
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
				log.Println("❌ error DB...")
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
				u, _ := uuid.NewV4()
				NewView := models.View{
					ID:           u.String(),
					IsBookmarked: true,
					Rate:         0,
					AuthorID:     user.ID,
					PostID:       post.ID,
				}
				err = models.ViewRepo.CreateView(&NewView)
				if err != nil {
					res.WriteHeader(http.StatusInternalServerError)
					log.Println("❌ error Create view")
					return
				}
			} else {
				if view.IsBookmarked {
					UpdateView := models.View{
						ID:           view.ID,
						IsBookmarked: false,
						Rate:         view.Rate,
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
				} else {
					UpdateView := models.View{
						ID:           view.ID,
						IsBookmarked: true,
						Rate:         view.Rate,
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
		}
		lib.RedirectToPreviousURL(res, req)
	}
}
