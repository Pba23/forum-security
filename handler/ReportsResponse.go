package handler

import (
	"forum/data/models"
	"forum/lib"
	"log"
	"net/http"
)

type ResponseReportPage struct {
	IsLoggedIn  bool
	CurrentUser models.User
	AllResponse []models.Response
	AllNotifs   []*models.Notification
	AllPosts    []*models.Post
	ImageUrl    string
	AllSlug     []string
}

func SeeReportsResponse(res http.ResponseWriter, req *http.Request) {
	if lib.ValidateRequest(req, res, "/seeReportsResponse", http.MethodGet) {
		isSessionOpen := models.ValidSession(req)
		currentUser := models.GetUserFromSession(req)
		AllResponse, err := models.ResponseRepo.GetAllResponse()
		imageurl := ""
		tabSlug := []string{}

		if err != nil {
			log.Println("1")
			return
		}
		notifications, err := models.NotifRepo.GetAllNotifs()

		if err != nil {
			log.Println("2")
			return
		}

		allPosts, err := models.PostRepo.GetAllPosts("")
		if err != nil {
			log.Println("3")
			return
		}
		if len(AllResponse) > 0 {
			report, err := models.ReportRepo.GetReportByID(AllResponse[0].ReportID)
			if report == nil {
				return
			}
			if err != nil {
				return
			}
			adminUser, err := models.UserRepo.GetUserByPostID(report.ReportedID)
			if err != nil {
				return
			}
			imageurl = adminUser.AvatarURL
			for i := 0; i < len(AllResponse); i++ {
				reporti, _ := models.ReportRepo.GetReportByID(AllResponse[i].ReportID)
				post, err := models.PostRepo.GetPostByID(reporti.ReportedID)
				if err != nil {
					return
				}
				tabSlug = append(tabSlug, post.Slug)
				AllResponse[i].ModifiedDate = lib.FormatDateDB(AllResponse[i].ModifiedDate)
			}
		}
		ResponseReportPage := ResponseReportPage{
			IsLoggedIn:  isSessionOpen,
			CurrentUser: *currentUser,
			AllResponse: AllResponse,
			AllNotifs:   notifications,
			AllPosts:    allPosts,
			ImageUrl:    imageurl,
			AllSlug:     tabSlug,
		}

		log.Println("Response Page get with success")
		lib.RenderPage("base", "admin/adminResponse", ResponseReportPage, res)
	}
}
