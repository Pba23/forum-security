package main

import (
	"forum/data/models"
	"forum/handler"
	"forum/handler/auth"
	"forum/lib"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	PORT := ":" + os.Getenv("PORT")
	ADDRESS := os.Getenv("ADDRESS")

	rateLimiter := lib.NewRateLimiter(time.Minute)

	http.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("./assets/styles/"))))
	http.Handle("/img/", http.StripPrefix("/img/", http.FileServer(http.Dir("./assets/img/"))))
	http.Handle("/uploads/", http.StripPrefix("/uploads/", http.FileServer(http.Dir("./uploads/"))))

	// Login/authentication rate limiting
	http.Handle("/sign-up", rateLimiter.Wrap("auth", auth.SignUp))
	http.Handle("/sign-up-page", rateLimiter.Wrap("auth", auth.SignUpPage))
	http.Handle("/google-sign-in", rateLimiter.Wrap("auth", auth.HandleGoogleLogin))
	http.Handle("/github-sign-in", rateLimiter.Wrap("auth", auth.HandleGithubLoginHandler))
	http.Handle("/callback", rateLimiter.Wrap("auth", auth.HandleCallback))
	http.Handle("/github-callback", rateLimiter.Wrap("auth", auth.HandleGithubCallback))
	http.Handle("/sign-in", rateLimiter.Wrap("auth", auth.SignIn))
	http.Handle("/sign-in-page", rateLimiter.Wrap("auth", auth.SignInPage))
	http.Handle("/logout", rateLimiter.Wrap("auth", auth.Logout))

	// API endpoint rate limiting
	http.Handle("/", rateLimiter.Wrap("api", handler.Index))
	http.Handle("/bookmark/", rateLimiter.Wrap("api", handler.Bookmark))
	http.Handle("/profile", rateLimiter.Wrap("api", handler.ProfilePage))
	http.Handle("/request/", rateLimiter.Wrap("api", handler.CreateRequest))
	http.Handle("/edit-user", rateLimiter.Wrap("api", handler.EditUser))
	http.Handle("/edit-user-page", rateLimiter.Wrap("api", handler.EditUserPage))

	http.Handle("/trending", rateLimiter.Wrap("api", handler.ListPost))
	http.Handle("/post", rateLimiter.Wrap("api", handler.CreatePost))
	http.Handle("/delete-post/", rateLimiter.Wrap("api", handler.DeletePost))
	http.Handle("/delete-Postt/", rateLimiter.Wrap("api", handler.DeletePostAdmin))
	http.Handle("/delete-comment/", rateLimiter.Wrap("api", handler.DeleteComment))
	http.Handle("/edit-post-page/", rateLimiter.Wrap("api", handler.EditPostPage))
	http.Handle("/edit-post/", rateLimiter.Wrap("api", handler.EditPost))
	http.Handle("/edit-comment-page/", rateLimiter.Wrap("api", handler.EditCommentPage))
	http.Handle("/edit-comment/", rateLimiter.Wrap("api", handler.EditComment))
	http.Handle("/comment/", rateLimiter.Wrap("api", handler.Comment))
	http.Handle("/posts/", rateLimiter.Wrap("api", handler.GetPost))
	http.Handle("/user/", rateLimiter.Wrap("api", handler.UserProfilePage))
	http.Handle("/like/", rateLimiter.Wrap("api", handler.LikePost))
	http.Handle("/dislike/", rateLimiter.Wrap("api", handler.DislikePost))
	http.Handle("/like-comment/", rateLimiter.Wrap("api", handler.LikeComment))
	http.Handle("/dislike-comment/", rateLimiter.Wrap("api", handler.DislikeComment))
	http.Handle("/category/", rateLimiter.Wrap("api", handler.GetPostOfCategory))
	http.Handle("/notification/", rateLimiter.Wrap("api", handler.GetNotifs))
	http.Handle("/validate/", rateLimiter.Wrap("api", handler.Validate))
	http.Handle("/invalidate/", rateLimiter.Wrap("api", handler.Invalidate))
	http.Handle("/requests", rateLimiter.Wrap("api", handler.SeeRequests))
	http.Handle("/posts", rateLimiter.Wrap("api", handler.SeePosts))
	http.Handle("/publish/", rateLimiter.Wrap("api", handler.Publish))
	http.Handle("/reportpost/", rateLimiter.Wrap("api", handler.ReportPost))
	http.Handle("/seeReports", rateLimiter.Wrap("api", handler.SeeReports))
	http.Handle("/seeReportsResponse", rateLimiter.Wrap("api", handler.SeeReportsResponse))
	http.Handle("/response/", rateLimiter.Wrap("api", handler.Response))
	http.Handle("/delete-report/", rateLimiter.Wrap("api", handler.DeleteReport))

	/* httpsServer := http.Server{
		Addr: PORT,
		TLSConfig: &tls.Config{
			MinVersion:               tls.VersionTLS12, // Minimum TLS version supported
			PreferServerCipherSuites: true,             // Prefer the server's cipher suite order
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				// Add more cipher suites as needed
			},
		},
	} */

	go models.DeleteExpiredSessions()

	log.Print("Server started and running on ")
	log.Println(ADDRESS + PORT)
	if err := http.ListenAndServe(PORT, nil); err != nil {
		log.Fatal(err)
	}
}
