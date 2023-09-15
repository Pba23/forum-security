package handler

import (
	"forum/data/models"
	"forum/lib"
	"log"
	"net/http"
	"strings"
	"text/template"
	"time"
)

type PostPageData struct {
	IsLoggedIn       bool
	CurrentUser      models.User
	Post             models.Post
	Comment          models.Comment
	Comments         []*models.CommentItem
	UserPoster       *models.User
	NbrComment       int
	CategoriesPost   []models.Category
	CategoriesString string
	NbrLike          int
	NbrDislike       int
	Categories       []*models.Category
	AllPosts         []*models.Post
	NbrBookmarks     int
	IsBookmarked     bool
	AllNotifs        []*models.Notification
	Reported         bool
}

func CreatePost(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/post", http.MethodPost) {
		isSessionOpen := models.ValidSession(req)
		if isSessionOpen {
			// Parse form data
			err := req.ParseMultipartForm(32 << 20) // 32 MB limit
			if err != nil {
				log.Println("❌ Failed to parse form data", err.Error())
				return
			}
			creationDate := time.Now().Format("2006-01-02 15:04:05")
			modificationDate := time.Now().Format("2006-01-02 15:04:05")
			title := req.FormValue("title")
			posts, err := models.PostRepo.GetAllPosts("")
			if err != nil {
				return
			}
			if posts != nil {
				for j := 0; j < len(posts); j++ {
					if strings.EqualFold(posts[j].Title, title) {
						lib.RedirectToPreviousURL(res, req)
						return
					}
				}
			}
			slug := lib.Slugify(title)
			description := req.FormValue("description")
			_categories := req.FormValue("categories")

			imageUrl := lib.UploadImage(req)
			authorID := models.GetUserFromSession(req).ID
			categories := strings.Split(_categories, "#")

			post := models.Post{
				Title:        title,
				Slug:         slug,
				Description:  description,
				ImageURL:     imageUrl,
				AuthorID:     authorID,
				IsEdited:     false,
				CreateDate:   creationDate,
				ModifiedDate: modificationDate,
				Validate:     true,
			}

			err = models.PostRepo.CreatePost(&post)
			if err != nil {
				res.WriteHeader(http.StatusInternalServerError)
				log.Println("❌ Can't create post")
				return
			}

			for i := 1; i < len(categories); i++ {
				name := strings.TrimSpace(categories[i])
				category, _ := models.CategoryRepo.GetCategoryByName(name)
				if category == nil {
					category = &models.Category{
						Name:         name,
						CreateDate:   creationDate,
						ModifiedDate: modificationDate,
					}
					models.CategoryRepo.CreateCategory(category)
				}
				models.PostCategoryRepo.CreatePostCategory(category.ID, post.ID)
			}

			log.Println("✅ Post created with success")
			lib.RedirectToPreviousURL(res, req)
		}
	}
}

func EditPost(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/edit-post/*", http.MethodPost) {
		// Check if the user is logged in
		currentUser := models.GetUserFromSession(req)
		if currentUser == nil || currentUser.ID == "" {
			http.Redirect(res, req, "/", http.StatusSeeOther)
			return
		}

		err := req.ParseMultipartForm(32 << 20) // 32 MB limit
		if err != nil {
			log.Println("❌ Failed to parse form data", err.Error())
			return
		}

		path := req.URL.Path
		pathPart := strings.Split(path, "/")
		if len(pathPart) == 3 && pathPart[1] == "edit-post" && pathPart[2] != "" {
			idPost := pathPart[2]
			post, err := models.PostRepo.GetPostByID(idPost)
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

			// Update user information
			title := req.FormValue("title")
			posts, err := models.PostRepo.GetAllPosts("")
			if err != nil {
				return
			}
			if posts != nil {
				for j := 0; j < len(posts); j++ {
					if strings.EqualFold(posts[j].Title, title) {
						lib.RedirectToPreviousURL(res, req)
						return
					}
				}
			}
			description := req.FormValue("description")
			_categories := req.FormValue("categories")
			categories := strings.Split(_categories, "#")
			isEdited := false
			if title != "" && post.Title != title {
				isEdited = true
				post.Title = title
				post.Slug = lib.Slugify(title)
				post.ModifiedDate = time.Now().Format("2006-01-02 15:04:05")
				log.Println("✅ Title changed successfully")
			}
			if description != "" && post.Description != description {
				isEdited = true
				post.Description = description
				log.Println("✅ Description changed successfully")
			}
			imageURL := lib.UploadImage(req)
			if imageURL != "" {
				isEdited = true
				post.ImageURL = imageURL
				log.Println("✅ Image changed successfully")
			}

			// Update user information in the database

			categoriesOfPost, err := models.PostCategoryRepo.GetCategoriesOfPost(idPost)
			if err != nil {
				log.Println("❌ Failed to update post information ", err.Error())
				return
			}

			for i := 1; i < len(categories); i++ {
				categories[i] = strings.TrimSpace(categories[i])
				found := false
				for _, cat := range categoriesOfPost {
					if cat.Name == categories[i] {
						found = true
						break
					}
				}
				if !found {
					creationDate := time.Now().Format("2006-01-02 15:04:05")
					modificationDate := time.Now().Format("2006-01-02 15:04:05")
					category := &models.Category{
						Name:         categories[i],
						CreateDate:   creationDate,
						ModifiedDate: modificationDate,
					}
					isEdited = true
					models.CategoryRepo.CreateCategory(category)
					models.PostCategoryRepo.CreatePostCategory(category.ID, post.ID)
				}
			}

			for _, category := range categoriesOfPost {
				found := false
				for _, cat := range categories {
					if category.Name == cat {
						found = true
						break
					}
				}
				if !found {
					isEdited = true
					err = models.PostCategoryRepo.DeletePostCategory(category.ID, currentUser.ID)
					if err != nil {
						log.Println("❌ Failed to delete category post information ", err.Error())
						return
					}
				}
			}

			if isEdited {
				post.IsEdited = true
				post.ModifiedDate = time.Now().Format("2006-01-02 15:04:05")
				err = models.PostRepo.UpdatePost(post)
				if err != nil {
					log.Println("❌ Failed to update post information ", err.Error())
					return
				}
			}

			// Redirect to the user's profile page
			http.Redirect(res, req, "/profile", http.StatusSeeOther)
		}
	}
}

func EditPostPage(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/edit-post-page/*", http.MethodGet) {
		basePath := "base"
		pagePath := "edit-post"
		isSessionOpen := models.ValidSession(req)
		user := models.GetUserFromSession(req)

		path := req.URL.Path
		pathPart := strings.Split(path, "/")
		if len(pathPart) == 3 && pathPart[1] == "edit-post-page" && pathPart[2] != "" {
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
			categories, err := models.PostCategoryRepo.GetCategoriesOfPost(post.ID)
			if err != nil {
				res.WriteHeader(http.StatusInternalServerError)
				log.Println("❌ error DB")
				return
			}
			_categories := ""
			for _, category := range categories {
				_categories += "#" + category.Name + " "
			}
			allPost, err := models.PostRepo.GetAllPosts("")
			if err != nil {
				return
			}
			notifications, err := models.NotifRepo.GetAllNotifs()

			if err != nil {
				return
			}
			userPageData := PostPageData{
				IsLoggedIn:       isSessionOpen,
				CurrentUser:      *user,
				Post:             *post,
				CategoriesString: _categories,
				AllPosts:         allPost,
				AllNotifs:        notifications,
			}

			lib.RenderPage(basePath, pagePath, userPageData, res)
			log.Println("✅ Login page get with success")
		}

	}
}

func DeletePost(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/delete-post/*", http.MethodGet) {
		isSessionOpen := models.ValidSession(req)
		if isSessionOpen {
			path := req.URL.Path
			pathPart := strings.Split(path, "/")
			if len(pathPart) == 3 && pathPart[1] == "delete-post" && pathPart[2] != "" {
				id := pathPart[2]
				err := models.PostRepo.DeletePost(id)
				if err != nil {
					res.WriteHeader(http.StatusNotFound)
					lib.RenderPage("base", "404", nil, res)
					log.Println("404 ❌ - Page not found ", req.URL.Path)
					return
				}

				log.Println("✅ Post created with success")
				lib.RedirectToPreviousURL(res, req)
			}
		}
	}
}

func DeletePostAdmin(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/delete-Postt/*", http.MethodGet) {

		isSessionOpen := models.ValidSession(req)
		if isSessionOpen {
			path := req.URL.Path
			pathPart := strings.Split(path, "/")
			if len(pathPart) == 3 && pathPart[1] == "delete-Postt" && pathPart[2] != "" {
				id := pathPart[2]
				err := models.PostRepo.DeletePost(id)
				if err != nil {
					res.WriteHeader(http.StatusNotFound)
					lib.RenderPage("base", "404", nil, res)
					log.Println("404 ❌ - Page not found ", req.URL.Path)
					return
				}

				log.Println("✅ Post deleted with success")
				http.Redirect(res, req, "/", http.StatusSeeOther)
			}
		}
	}
}

func GetPost(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/posts/*", http.MethodGet) {
		basePath := "base"
		pagePath := "post"

		isSessionOpen := models.ValidSession(req)

		err := req.ParseForm()
		if err != nil {
			http.Error(res, err.Error(), http.StatusBadRequest)
			return
		}

		path := req.URL.Path
		pathPart := strings.Split(path, "/")
		if len(pathPart) == 3 && pathPart[1] == "posts" && pathPart[2] != "" {
			slug := pathPart[2]
			post, err := models.PostRepo.GetPostBySlug(slug)
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
			}
			lib.RenderPage(basePath, pagePath, PostPageData, res)
			log.Println("✅ Post page get with success")
		} else {
			res.WriteHeader(http.StatusNotFound)
			lib.RenderPage("base", "404", nil, res)
			log.Println("404 ❌ - Page not found ", req.URL.Path)
		}
	}
}
