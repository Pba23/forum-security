package tests

import (
	"forum/lib"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestLoadEnv(t *testing.T) {
	err := lib.LoadEnv(".env")
	if err != nil {
		t.Errorf("Error loading .env file: %v", err)
	}

	expectedValues := map[string]string{
		"KEY1": "VALUE1",
		"KEY2": "VALUE2",
		// Add more key-value pairs
	}

	for key, expectedValue := range expectedValues {
		actualValue := os.Getenv(key)
		if actualValue != expectedValue {
			t.Errorf("Expected %s=%s, but got %s", key, expectedValue, actualValue)
		}
	}
}

func TestValidateRequest(t *testing.T) {
	req, _ := http.NewRequest("GET", "/path/to/page", nil)
	res := httptest.NewRecorder()

	valid := lib.ValidateRequest(req, res, "/path/to/page", "GET")
	if !valid {
		t.Errorf("Expected request to be valid, but it wasn't")
	}
}

func TestRenderPage(t *testing.T) {
	res := httptest.NewRecorder()
	data := struct {
		Title string
	}{
		Title: "Test Page",
	}

	lib.RenderPage("common", "base", data, res)

	// Check response status code, content type, etc.
	if res.Code != http.StatusOK {
		t.Errorf("Expected status code %d, but got %d", http.StatusOK, res.Code)
	}

	// Check if the rendered content contains the expected data
	expectedContent := "Test Page"
	if !strings.Contains(res.Body.String(), expectedContent) {
		t.Errorf("Expected response body to contain '%s', but it didn't", expectedContent)
	}
}
