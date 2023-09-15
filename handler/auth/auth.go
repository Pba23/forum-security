package auth

import (
	"fmt"
	"forum/data/models"
	"forum/lib"
	"log"
	"net/http"
	"strings"
)

type SignPageData struct {
	IsLoggedIn  bool
	RandomUsers []models.User
	Err         string
	Categories  []*models.Category
}

func SignUp(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/sign-up", http.MethodPost) {
		if err := req.ParseForm(); err != nil {
			fmt.Fprintf(res, "❌ On Signing Up %v", err)
			return
		}
		user := models.User{}

		if strings.TrimSpace(req.FormValue("email")) == "" || strings.TrimSpace(req.FormValue("username")) == "" || strings.TrimSpace(req.FormValue("password")) == "" || !strings.Contains(req.FormValue("email"), "@") || strings.Count(req.FormValue("email"), "@") != 1 {
			res.WriteHeader(http.StatusBadRequest)
			randomUsers, err := models.UserRepo.SelectRandomUsers(15)
			if err != nil {
				log.Println("❌ Can't get 15 random users in the database")
			}

			signPageData := SignPageData{
				IsLoggedIn:  false,
				RandomUsers: randomUsers,
				Err:         "Email or password invalid",
			}
			lib.RenderPage("base", "sign-up", signPageData, res)
			fmt.Println("❌ Bad Credentials")
			return
		}
		user.Email = strings.ToLower(req.FormValue("email"))
		user.Username = strings.ToLower(req.FormValue("username"))
		_password, err := lib.HashPassword(req.FormValue("password"))

		if err != nil {
			log.Fatalf("❌ Failed to generate UUID: %v", err)
		}
		user.Password = _password

		user.AvatarURL = models.DEFAULT_AVATAR
		if user.Email == "ggueye294@gmail.com" {
			user.Role = models.RoleAdmin
		} else {
			user.Role = models.RoleUser
		}

		if _, exist := models.UserRepo.IsExisted(user.Email, user.Username); !exist {
			err := models.UserRepo.CreateUser(&user)
			if err != nil {
				log.Fatalf("❌ Failed to created account %v", err)
			}

			models.NewSessionToken(res, user.ID, user.Username)

			http.Redirect(res, req, "/", http.StatusSeeOther)
			log.Println("✅ Account created with success")
		} else {
			res.WriteHeader(http.StatusBadRequest)
			randomUsers, err := models.UserRepo.SelectRandomUsers(15)
			if err != nil {
				log.Println("❌ Can't get 15 random users in the database")
			}

			signPageData := SignPageData{
				IsLoggedIn:  false,
				RandomUsers: randomUsers,
				Err:         "Email or password invalid",
			}
			lib.RenderPage("base", "sign-up", signPageData, res)
			fmt.Println("❌ User already exists")
			return
		}
	} else {
		res.WriteHeader(http.StatusNotFound)
		lib.RenderPage("base", "404", nil, res)
		log.Println("404 ❌ - Page not found ", req.URL)
		return
	}
}

func SignUpPage(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/sign-up-page", http.MethodGet) {
		basePath := "base"
		pagePath := "sign-up"

		randomUsers, err := models.UserRepo.SelectRandomUsers(15)
		if err != nil {
			log.Println("❌ Can't get 15 random users in the database")
		}
		cat, err := models.CategoryRepo.GetAllCategory()
		if err != nil {
			return
		}
		signPageData := SignPageData{
			IsLoggedIn:  false,
			RandomUsers: randomUsers,
			Err:         "",
			Categories:  cat,
		}

		lib.RenderPage(basePath, pagePath, signPageData, res)
		log.Println("✅ Register page get with success")
	} else {
		res.WriteHeader(http.StatusNotFound)
		lib.RenderPage("base", "404", nil, res)
		log.Println("404 ❌ - Page not found ", req.URL)
		return
	}
}

func SignIn(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/sign-in", http.MethodPost) {
		if err := req.ParseForm(); err != nil {
			fmt.Fprintf(res, "❌ On Signing In %v", err)
			return
		}
		user := models.User{}
		email := req.FormValue("email")
		password := req.FormValue("password")

		if _user, exist := models.UserRepo.IsExistedSignIn(email); exist {
			if !lib.IsPasswordsMatch(_user.Password, password) {
				res.WriteHeader(http.StatusNotFound)
				randomUsers, err := models.UserRepo.SelectRandomUsers(15)
				if err != nil {
					log.Println("❌ Can't get 15 random users in the database")
				}

				signPageData := SignPageData{
					IsLoggedIn:  false,
					RandomUsers: randomUsers,
					Err:         "Email or Password Wrong ",
				}

				lib.RenderPage("base", "sign-in", signPageData, res)
				log.Println("❌ User with the given email don't exist")
				return
			} else {
				_user, err := models.UserRepo.GetUserByEmail(email)
				if err != nil {
					log.Println("❌ ", err)
				}
				user = *_user

				models.NewSessionToken(res, user.ID, user.Username)

				http.Redirect(res, req, "/", http.StatusSeeOther)
				log.Println("✅ Sign in with success")
			}
		} else {
			res.WriteHeader(http.StatusNotFound)
			randomUsers, err := models.UserRepo.SelectRandomUsers(15)
			if err != nil {
				log.Println("❌ Can't get 15 random users in the database")
			}
			signPageData := SignPageData{
				IsLoggedIn:  false,
				RandomUsers: randomUsers,
				Err:         "Email or password Invalid",
			}
			lib.RenderPage("base", "sign-in", signPageData, res)
			log.Println("❌ User with the given email don't exist")
			return
		}
	}
}

func SignInPage(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/sign-in-page", http.MethodGet) {
		basePath := "base"
		pagePath := "sign-in"

		randomUsers, err := models.UserRepo.SelectRandomUsers(15)
		if err != nil {
			log.Println("❌ Can't get 15 random users in the database")
		}
		cat, err := models.CategoryRepo.GetAllCategory()
		if err != nil {
			return
		}
		signPageData := SignPageData{
			IsLoggedIn:  false,
			RandomUsers: randomUsers,
			Err:         "",
			Categories:  cat,
		}

		lib.RenderPage(basePath, pagePath, signPageData, res)
		log.Println("✅ Login page get with success")
	} else {
		res.WriteHeader(http.StatusNotFound)
		lib.RenderPage("base", "404", nil, res)
		log.Println("404 ❌ - Page not found ", req.URL)
		return
	}
}

func Logout(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/logout", http.MethodGet) {
		if ok := models.DeleteSession(req); ok {
			http.Redirect(res, req, "/", http.StatusSeeOther)
			log.Println("✅ Logout done with success")
		} else {
			log.Println("❌ Logout failure")
		}
	} else {
		res.WriteHeader(http.StatusNotFound)
		lib.RenderPage("base", "404", nil, res)
		log.Println("404 ❌ - Page not found ", req.URL)
		return
	}
}
