package handler

import (
	"forum/data/models"
	"forum/lib"
	"log"
	"net/http"
	"strconv"
	"strings"
	"text/template"
)

type UserPageData struct {
	IsLoggedIn     bool
	CurrentUser    models.User
	Author         models.User
	TabIndex       int
	PostsList      []models.PostItem
	Categories     []*models.Category
	AllPosts       []*models.Post
	PostsCommented map[models.Post][]models.Comment
	AllNotifs      []*models.Notification
	Error          string
}

func ProfilePage(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/profile", http.MethodGet) {
		basePath := "base"
		pagePath := "user/profile"
		postsList := []models.PostItem{}
		queryParams := req.URL.Query()
		TabIndex := 1
		if len(queryParams["index"]) != 0 {
			_tabIndex, err := strconv.Atoi(queryParams.Get("index"))
			if err != nil {
				res.WriteHeader(http.StatusBadRequest)
				log.Println("❌ Can't convert index to int")
			} else {
				TabIndex = _tabIndex
			}
		}
		isSessionOpen := models.ValidSession(req)
		user := models.GetUserFromSession(req)
		// posts := []models.Post{}
		// comments := []models.Comment{}
		commentMap := make(map[models.Post][]models.Comment)
		switch TabIndex {
		case 1:
			_postListed, err := models.PostRepo.GetUserOwnPosts(user.ID, user.Username)
			if err != nil {
				res.WriteHeader(http.StatusInternalServerError)
				log.Println("❌ Can't get users created post")
				return
			}
			postsList = _postListed
		case 2:
			_postListed, err := models.PostRepo.GetUserLikedPosts(user.ID)
			if err != nil {
				res.WriteHeader(http.StatusInternalServerError)
				log.Println("❌ Can't get users liked post")
				return
			}
			postsList = _postListed
		case 4:
			_postListed, err := models.PostRepo.GetUserBookmarkedPosts(user.ID)
			if err != nil {
				res.WriteHeader(http.StatusInternalServerError)
				log.Println("❌ Can't get users bookmarked post")
				return
			}
			postsList = _postListed
		case 5:
			Map, err := models.PostRepo.GetUserReaction(user.ID)
			if err != nil {
				res.WriteHeader(http.StatusInternalServerError)
				log.Println("❌ Can't get")
				return
			}
			commentMap = Map
		case 3:
			_postListed, err := models.PostRepo.GetUserDislikedPosts(user.ID)
			if err != nil {
				res.WriteHeader(http.StatusInternalServerError)
				log.Println("❌ Can't get users bookmarked post")
				return
			}
			postsList = _postListed
		}
		if postsList != nil {
			for j := 0; j < len(postsList); j++ {
				postsList[j].Title = template.HTMLEscapeString(postsList[j].Title)
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
		userPageData := UserPageData{
			IsLoggedIn:     isSessionOpen,
			CurrentUser:    *user,
			TabIndex:       TabIndex,
			PostsList:      postsList,
			Categories:     cat,
			AllPosts:       allPost,
			PostsCommented: commentMap,
			AllNotifs:      notifications,
		}

		lib.RenderPage(basePath, pagePath, userPageData, res)
		log.Println("✅ Login page get with success")
	}
}

func UserProfilePage(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/user/*", http.MethodGet) {
		basePath := "base"
		pagePath := "profile"
		path := req.URL.Path
		pathPart := strings.Split(path, "/")
		if len(pathPart) == 3 && pathPart[1] == "user" && pathPart[2] != "" {
			username := pathPart[2]
			isSessionOpen := models.ValidSession(req)
			user := models.GetUserFromSession(req)
			_user, err := models.UserRepo.GetUserByUsername(username)
			if err != nil {
				res.WriteHeader(http.StatusInternalServerError)
				log.Println("❌ Can't post author")
				return
			}
			postsList, err := models.PostRepo.GetUserOwnPosts(_user.ID, _user.Username)
			if err != nil {
				res.WriteHeader(http.StatusInternalServerError)
				log.Println("❌ Can't get users created post")
				return
			}

			if postsList != nil {
				for j := 0; j < len(postsList); j++ {
					postsList[j].Title = template.HTMLEscapeString(postsList[j].Title)
				}
			}
			notifications, err := models.NotifRepo.GetAllNotifs()

			if err != nil {
				return
			}
			userPageData := UserPageData{
				IsLoggedIn:  isSessionOpen,
				CurrentUser: *user,
				Author:      *_user,
				PostsList:   postsList,
				AllNotifs:   notifications,
			}

			lib.RenderPage(basePath, pagePath, userPageData, res)
			log.Println("✅ Login page get with success")
		}
	}
}

func EditUser(res http.ResponseWriter, req *http.Request) {
	//TODO: Return http error
	if lib.ValidateRequest(req, res, "/edit-user", http.MethodPost) {
		// Check if the user is logged in
		currentUser := models.GetUserFromSession(req)
		if currentUser == nil || currentUser.ID == "" {
			http.Redirect(res, req, "/", http.StatusSeeOther)
			return
		}

		// Parse form data
		err := req.ParseMultipartForm(32 << 20) // 32 MB limit
		if err != nil {
			res.WriteHeader(http.StatusBadRequest)
			log.Println("❌ Failed to parse form data", err.Error())
			return
		}

		// Update user information
		username := req.Form.Get("username")
		username = strings.TrimSpace(username)
		email := req.Form.Get("email")
		email = strings.TrimSpace(email)
		newPassword := req.Form.Get("new_password")
		confirmPassword := req.Form.Get("confirm_password")
		oldPassword := req.Form.Get("old_password")

		if username != "" && strings.TrimSpace(currentUser.Username) != username {
			currentUser.Username = username
			log.Println("✅ Username changed successfully")
		}
		if email != "" && strings.TrimSpace(currentUser.Email) != email {
			currentUser.Email = email
			log.Println("✅ Email changed successfully")
		}
		if newPassword != "" {
			if lib.IsPasswordsMatch(currentUser.Password, oldPassword) {
				if !lib.IsPasswordsMatch(currentUser.Password, newPassword) {
					if newPassword == confirmPassword {
						newPassword, err = lib.HashPassword(newPassword)
						if err != nil {
							res.WriteHeader(http.StatusInternalServerError)
							log.Println("❌ Failed to hash password", err.Error())
							return
						}
						currentUser.Password = newPassword
						log.Println("✅ Password changed successfully")
					} else {
						res.WriteHeader(http.StatusBadRequest)
						log.Println("❌ The password is different with the confirmation")
					}
				} else {
					res.WriteHeader(http.StatusBadRequest)
					log.Println("❌ The password is the same")
					http.Redirect(res, req, "/edit-user-page", http.StatusSeeOther)
					return
				}
			} else {

				log.Println("❌ Password is wrong")
				http.Redirect(res, req, "/edit-user-page", http.StatusSeeOther)
				res.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		avatarURL := lib.UploadImage(req)
		if avatarURL != "" {
			currentUser.AvatarURL = avatarURL
			log.Println("✅ Avatar changed successfully")
		}

		// Update user information in the database
		err = models.UserRepo.UpdateUser(currentUser)
		if err != nil {
			res.WriteHeader(http.StatusInternalServerError)
			log.Println("❌ Failed to update user information ", err.Error())
			return
		}

		// Redirect to the user's profile page
		http.Redirect(res, req, "/edit-user-page", http.StatusSeeOther)
		return
	}
}

func EditUserPage(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/edit-user-page", http.MethodGet) {
		basePath := "base"
		pagePath := "user/edit-user"
		queryParams := req.URL.Query()
		TabIndex := 1
		if len(queryParams["index"]) != 0 {
			_tabIndex, err := strconv.Atoi(queryParams.Get("index"))
			if err != nil {
				res.WriteHeader(http.StatusBadRequest)
				log.Println("❌ Can't convert index to int")
			} else {
				TabIndex = _tabIndex
			}
		}
		isSessionOpen := models.ValidSession(req)
		user := models.GetUserFromSession(req)
		cat, err := models.CategoryRepo.GetAllCategory()
		if err != nil {
			return
		}

		notifications, err := models.NotifRepo.GetAllNotifs()

		if err != nil {
			return
		}

		userPageData := UserPageData{
			IsLoggedIn:  isSessionOpen,
			CurrentUser: *user,
			TabIndex:    TabIndex,
			Categories:  cat,
			AllNotifs:   notifications,
		}

		lib.RenderPage(basePath, pagePath, userPageData, res)
		log.Println("✅ Login page get with success")
	}
}
