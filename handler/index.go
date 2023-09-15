package handler

import (
	"forum/data/models"
	"forum/lib"
	"log"
	"net/http"
	"strconv"
	"text/template"
)

type HomePageData struct {
	IsLoggedIn    bool
	RandomUsers   []models.User
	CurrentUser   models.User
	Post          []models.PostItem
	NumberOfPosts int
	Limit         int
	TopUsers      []models.TopUser
	Categories    []*models.Category
	AllPosts      []*models.Post
	AllNotifs     []*models.Notification
}

func Index(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/", http.MethodGet) {
		basePath := "base"
		pagePath := "index"

		isSessionOpen := models.ValidSession(req)
		user := models.GetUserFromSession(req)
		queryParams := req.URL.Query()
		limit := 5
		numberOfPosts := models.PostRepo.GetNumberOfPosts()

		if len(queryParams["limit"]) != 0 {
			_limit, err := strconv.Atoi(queryParams.Get("limit"))
			if limit <= 0 || err != nil {
				res.WriteHeader(http.StatusBadRequest)
				log.Println("❌ Can't convert index to int")
				return
			} else {
				if _limit == numberOfPosts {
					limit = -1
				} else {
					limit = _limit
				}
			}
		}
		randomUsers, err := models.UserRepo.SelectRandomUsers(17)
		if err != nil {
			res.WriteHeader(http.StatusInternalServerError)
			log.Println("❌ Can't get 17 random users in the database")
			return
		}

		posts, _ := models.PostRepo.GetAllPostsItems(limit)

		TopUsers, err := models.UserRepo.TopUsers()
		if err != nil {
			res.WriteHeader(http.StatusInternalServerError)
			log.Println("❌ Can't get top users")
			return
		}

		if limit != -1 {
			if limit+5 > numberOfPosts {
				limit = numberOfPosts
			} else {
				limit += 5
			}
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
		homePageData := HomePageData{
			IsLoggedIn:    isSessionOpen,
			CurrentUser:   *user,
			RandomUsers:   randomUsers,
			Post:          posts,
			NumberOfPosts: numberOfPosts,
			TopUsers:      TopUsers,
			Limit:         limit,
			Categories:    cat,
			AllPosts:      allPost,
			AllNotifs:     notifications,
		}

		lib.RenderPage(basePath, pagePath, homePageData, res)
		log.Println("✅ Home page get with success")
	}
}
