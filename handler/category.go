package handler

import (
	"forum/data/models"
	"forum/lib"
	"log"
	"net/http"
	"strings"
	"text/template"
)

func GetPostOfCategory(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/category/*", http.MethodGet) {
		basePath := "base"
		pagePath := "list-post"

		isSessionOpen := models.ValidSession(req)
		user := models.GetUserFromSession(req)
		limit := 10

		path := req.URL.Path
		pathPart := strings.Split(path, "/")
		if len(pathPart) == 3 && pathPart[1] == "category" && pathPart[2] != "" {
			name := pathPart[2]
			posts, _ := models.PostCategoryRepo.GetPostsOfCategory(name)
			if posts == nil {
				res.WriteHeader(http.StatusNotFound)
				lib.RenderPage("base", "404", nil, res)
				log.Println("404 ❌ - Page not found ", req.URL.Path)
				return
			}
			TopUsers, err := models.UserRepo.TopUsers()
			if err != nil {
				res.WriteHeader(http.StatusInternalServerError)
				log.Println("❌ Can't get top users")
				return
			}
			if posts != nil {
				for j := 0; j < len(posts); j++ {
					posts[j].Title = template.HTMLEscapeString(posts[j].Title)
				}
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

			homePageData := ListPostsPageData{
				Title:       "Category: " + name,
				IsLoggedIn:  isSessionOpen,
				CurrentUser: *user,
				Post:        posts,
				TopUsers:    TopUsers,
				Limit:       limit,
				Categories:  cat,
				AllPosts:    allPost,
				AllNotifs:   notifications,
			}

			lib.RenderPage(basePath, pagePath, homePageData, res)
			log.Println("✅ Home page get with success")
		}
	}
}
