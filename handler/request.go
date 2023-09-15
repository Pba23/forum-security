package handler

import (
	"forum/data/models"
	"forum/lib"
	"log"
	"net/http"
	"strings"
	"time"
)

func CreateRequest(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/request/*", http.MethodGet) {
		path := req.URL.Path
		pathPart := strings.Split(path, "/")
		if len(pathPart) == 3 && pathPart[1] == "request" && pathPart[2] != "" {
			id := pathPart[2]
			user, err := models.UserRepo.GetUserByID(id)
			if user == nil {
				res.WriteHeader(http.StatusNotFound)
				lib.RenderPage("base", "404", nil, res)
				log.Println("404 ❌ - Page not found ", req.URL.Path)
				return
			}
			if err != nil {
				return
			}
			request := models.Request{
				AuthorID: id,
				Time:     time.Now().Format("2006-01-02 15:04:05"),
				Username: user.Username,
				ImageURL: user.AvatarURL,
				Role:     user.Role,
			}
			models.RequestRepo.CreateRequest(&request)
			log.Println("✅ Request success")
			lib.RedirectToPreviousURL(res, req)
		}
	}

}
