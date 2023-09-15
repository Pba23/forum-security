package lib

import (
	"bufio"
	"fmt"
	"unicode"

	//"forum/data/models"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/gofrs/uuid"
)

var maxSize int64 = 20 * 1024 * 1024 // 20 MB

func Slugify(input string) string {
	input = strings.ToLower(input)
	re := regexp.MustCompile("[^a-z0-9]+")
	input = re.ReplaceAllString(input, "-")
	input = strings.Trim(input, "-")

	return input
}

func FormatDateDB(str string) string {
	str = strings.ReplaceAll(str, "T", " ")
	str = strings.ReplaceAll(str, "Z", "")
	str = TimeSinceCreation(str)

	return str
}

func RedirectToPreviousURL(res http.ResponseWriter, req *http.Request) {
	// Get the Referer header from the request
	previousPage := req.Header.Get("Referer")

	// Perform the redirection
	http.Redirect(res, req, previousPage, http.StatusSeeOther)
}

func LoadEnv(path string) error {
	file, err := os.Open(path)
	if err != nil {
		log.Println("🚨 " + err.Error())
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			log.Println("🚨 Your env file must be set")
		}
		key := parts[0]
		value := parts[1]
		os.Setenv(key, value)
	}
	return scanner.Err()
}

func RedirectToHTTPS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-Proto") != "https" {
			http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusPermanentRedirect)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func ValidateRequest(req *http.Request, res http.ResponseWriter, url, method string) bool {
	if strings.Contains(url, "*") {
		_urlSplit := strings.Split(req.URL.Path, "/")
		url = url[:len(url)-1]
		url += _urlSplit[len(_urlSplit)-1]
	}
	if req.URL.Path != url {
		res.WriteHeader(http.StatusNotFound)
		RenderPage("base", "404", nil, res)
		log.Println("404 ❌ - Page not found ", url)
		return false
	}

	if req.Method != method {
		res.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(res, "%s", "Error - Method not allowed")
		log.Printf("405 ❌ - Method not allowed %s - %s on URL : %s\n", req.Method, method, url)
		return false
	}
	return true
}

func RenderPage(basePath, pagePath string, data any, res http.ResponseWriter) {
	files := []string{"templates/common/" + basePath + ".html", "templates/" + pagePath + ".html"}
	tpl, err := template.ParseFiles(files...)
	if err != nil {
		res.WriteHeader(http.StatusInternalServerError)
		log.Println("🚨 " + err.Error())
	} else {
		tpl.Execute(res, data)
	}
}

func UploadImage(req *http.Request) string {
	image, header, err := req.FormFile("image")
	if err != nil {
		log.Println("❌ Request doesn't contain image", err)
		return ""
	}
	defer image.Close()

	if header.Size > maxSize {
		log.Println("❌ File size exceeds limit")
		return ""
	}

	if !isValidFileType(header.Header.Get("Content-Type")) {
		log.Println("❌ Invalid file type")
		return ""
	}

	uploads := "/uploads" // Use "uploads" without the leading slash
	imageURL := filepath.Join(uploads, generateUniqueFilename(header.Filename))
	filePath := filepath.Join(".", imageURL) // Use "." to denote the current directory
	// if filePath[0] != '/' {
	// 	filePath = "" + filePath
	// }
	file, err := os.Create(filePath)
	if err != nil {
		fmt.Println("❌ Error when creating the file", err)
		return ""
	}
	defer file.Close()
	_, err = io.Copy(file, image)
	if err != nil {
		fmt.Println("❌ Error when copying data", err)
		return ""
	}

	return imageURL
}

func generateUniqueFilename(filename string) string {
	ext := filepath.Ext(filename)
	randomName, err := uuid.NewV4()
	if err != nil {
		log.Fatalf("❌ Failed to generate UUID: %v", err)
	}
	newFilename := randomName.String() + ext
	return newFilename
}

func isValidFileType(contentType string) bool {
	switch contentType {
	case "image/jpeg", "image/png", "image/gif":
		return true
	}
	return false
}

func TimeSinceCreation(creationDate string) string {
	layout := "2006-01-02 15:04:05" // Date format layout

	creationTime, err := time.Parse(layout, creationDate)
	if err != nil {
		return "Invalid date format"
	}

	currentTime := time.Now()
	elapsedTime := currentTime.Sub(creationTime)

	if elapsedTime < time.Hour/60 {
		seconds := int(elapsedTime.Hours() * 60 * 60)
		return fmt.Sprintf("%d second%s ago", seconds, pluralize(seconds))
	} else if elapsedTime < time.Hour {
		minutes := int(elapsedTime.Hours() * 60)
		return fmt.Sprintf("%d minute%s ago", minutes, pluralize(minutes))
	} else if elapsedTime < 24*time.Hour {
		hours := int(elapsedTime.Hours())
		return fmt.Sprintf("%d hour%s ago", hours, pluralize(hours))
	} else if elapsedTime < 30*24*time.Hour {
		days := int(elapsedTime.Hours() / 24)
		return fmt.Sprintf("%d day%s ago", days, pluralize(days))
	} else if elapsedTime < 12*30*24*time.Hour {
		months := int(elapsedTime.Hours() / (24 * 30))
		return fmt.Sprintf("%d month%s ago", months, pluralize(months))
	} else {
		years := int(elapsedTime.Hours() / (24 * 30 * 12))
		return fmt.Sprintf("%d year%s ago", years, pluralize(years))
	}
}

func pluralize(count int) string {
	if count > 1 {
		return "s"
	}
	return ""
}

func FormatDate(DateAndTime string) string {
	tab := strings.Split(DateAndTime, " ")
	if len(tab) != 2 {
		return DateAndTime
	}
	Date, Time := tab[0], tab[1]
	tabDate := strings.Split(Date, "-")
	year, month, day := tabDate[0], tabDate[1], tabDate[2]
	MonthInt := map[string]string{
		"01": "January",
		"02": "February",
		"03": "March",
		"04": "April",
		"05": "May",
		"06": "June",
		"07": "July",
		"08": "August",
		"09": "September",
		"10": "October",
		"11": "November",
		"12": "December"}
	month = MonthInt[month]
	tabTime := strings.Split(Time, ":")
	hour, minute := tabTime[0], tabTime[1]
	inthour, _ := strconv.Atoi(hour)
	suf := ""
	if inthour > 12 {
		inthour -= 12
		suf = "pm"
	} else {
		suf = "am"
	}
	hour = strconv.Itoa(inthour)
	minute += suf
	TimeFormatted := strings.Join([]string{hour, minute}, ":")
	TheDate := fmt.Sprintf("%s, %sth, %s, at %s time", month, day, year, TimeFormatted)
	return TheDate
}

func VerifyPassword(password string) bool {
	var num int
	for _, val := range password {
		if !unicode.IsSpace(val) {
			num++
		}
	}
	return num >= 8
}
