package auth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gosom/google-maps-scraper/runner/auth"
)

func TestBearerTokenMiddleware(t *testing.T) {
	const testAPIKey = "test-api-key-123"

	// Create a test handler that should only be reached with valid auth
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("authenticated"))
	})

	tests := []struct {
		name           string
		apiKey         string
		authHeader     string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "valid bearer token",
			apiKey:         testAPIKey,
			authHeader:     "Bearer " + testAPIKey,
			expectedStatus: http.StatusOK,
			expectedBody:   "authenticated",
		},
		{
			name:           "missing authorization header",
			apiKey:         testAPIKey,
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   `{"code":401,"message":"Missing authentication token"}`,
		},
		{
			name:           "invalid token format - missing Bearer prefix",
			apiKey:         testAPIKey,
			authHeader:     testAPIKey,
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   `{"code":401,"message":"Invalid authentication token format"}`,
		},
		{
			name:           "invalid token format - wrong prefix",
			apiKey:         testAPIKey,
			authHeader:     "Basic " + testAPIKey,
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   `{"code":401,"message":"Invalid authentication token format"}`,
		},
		{
			name:           "incorrect API key",
			apiKey:         testAPIKey,
			authHeader:     "Bearer wrong-key",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   `{"code":401,"message":"Invalid authentication token"}`,
		},
		{
			name:           "empty API key disables auth",
			apiKey:         "",
			authHeader:     "",
			expectedStatus: http.StatusOK,
			expectedBody:   "authenticated",
		},
		{
			name:           "empty API key allows any request",
			apiKey:         "",
			authHeader:     "Bearer some-token",
			expectedStatus: http.StatusOK,
			expectedBody:   "authenticated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create middleware with test API key
			middleware := auth.BearerTokenMiddleware(tt.apiKey)
			handler := middleware(testHandler)

			// Create test request
			req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			// Record response
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)

			// Check status code
			if recorder.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, recorder.Code)
			}

			// Check response body
			body := recorder.Body.String()

			if tt.expectedStatus == http.StatusUnauthorized {
				// For error responses, check that it's valid JSON with expected structure
				var errorResp auth.ErrorResponse
				if err := json.Unmarshal([]byte(body), &errorResp); err != nil {
					t.Errorf("expected valid JSON error response, got: %s", body)
				}

				// Verify the error structure matches expected
				expectedErrorResp := auth.ErrorResponse{}
				if err := json.Unmarshal([]byte(tt.expectedBody), &expectedErrorResp); err != nil {
					t.Fatalf("test setup error: invalid expected JSON: %s", tt.expectedBody)
				}

				if errorResp.Code != expectedErrorResp.Code {
					t.Errorf("expected error code %d, got %d", expectedErrorResp.Code, errorResp.Code)
				}

				if errorResp.Message != expectedErrorResp.Message {
					t.Errorf("expected error message %q, got %q", expectedErrorResp.Message, errorResp.Message)
				}
			} else if body != tt.expectedBody {
				// For success responses, check exact body match
				t.Errorf("expected body %q, got %q", tt.expectedBody, body)
			}

			// Check Content-Type header for error responses
			if tt.expectedStatus == http.StatusUnauthorized {
				contentType := recorder.Header().Get("Content-Type")
				if contentType != "application/json" {
					t.Errorf("expected Content-Type application/json, got %s", contentType)
				}
			}
		})
	}
}

func TestSendUnauthorized(t *testing.T) {
	const expectedContentType = "application/json"

	recorder := httptest.NewRecorder()
	auth.SendUnauthorized(recorder, "test message")

	// Check status code
	if recorder.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, recorder.Code)
	}

	// Check Content-Type header
	contentType := recorder.Header().Get("Content-Type")
	if contentType != expectedContentType {
		t.Errorf("expected Content-Type %s, got %s", expectedContentType, contentType)
	}

	// Check response body
	var errorResp auth.ErrorResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &errorResp); err != nil {
		t.Errorf("expected valid JSON response, got error: %v", err)
	}

	if errorResp.Code != http.StatusUnauthorized {
		t.Errorf("expected error code %d, got %d", http.StatusUnauthorized, errorResp.Code)
	}

	if errorResp.Message != "test message" {
		t.Errorf("expected message %q, got %q", "test message", errorResp.Message)
	}
}

// TestRateLimiting tests the rate limiting functionality
func TestRateLimiting(t *testing.T) {
	const testAPIKey = "test-api-key-123"

	// Create middleware with authentication
	middleware := auth.BearerTokenMiddleware(testAPIKey)

	// Create a test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	})

	handler := middleware(testHandler)

	t.Run("multiple failed attempts trigger rate limiting", func(t *testing.T) {
		// Create requests with invalid auth from same IP
		for i := 0; i < 12; i++ { // Exceed burst limit of 10
			req := httptest.NewRequest("GET", "/test", http.NoBody)
			req.RemoteAddr = "192.168.1.100:12345" // Same IP
			req.Header.Set("Authorization", "Bearer wrong-token")

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)

			if i < 10 {
				// First 10 requests should get 401 (within burst limit)
				if recorder.Code != http.StatusUnauthorized {
					t.Errorf("request %d: expected status %d, got %d", i+1, http.StatusUnauthorized, recorder.Code)
				}
			} else {
				// After burst limit, should get 429 (rate limited)
				if recorder.Code != http.StatusTooManyRequests {
					t.Errorf("request %d: expected status %d, got %d", i+1, http.StatusTooManyRequests, recorder.Code)
				}

				// Check Retry-After header
				retryAfter := recorder.Header().Get("Retry-After")
				if retryAfter != "60" {
					t.Errorf("expected Retry-After header 60, got %s", retryAfter)
				}
			}
		}
	})

	t.Run("different IPs have separate rate limits", func(t *testing.T) {
		// First IP - exceed rate limit
		for i := 0; i < 11; i++ {
			req := httptest.NewRequest("GET", "/test", http.NoBody)
			req.RemoteAddr = "192.168.1.200:12345"
			req.Header.Set("Authorization", "Bearer wrong-token")

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
		}

		// Second IP - should still be allowed
		req := httptest.NewRequest("GET", "/test", http.NoBody)
		req.RemoteAddr = "192.168.1.201:12345" // Different IP
		req.Header.Set("Authorization", "Bearer wrong-token")

		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)

		// Should get 401 (not rate limited) because it's a different IP
		if recorder.Code != http.StatusUnauthorized {
			t.Errorf("expected status %d for different IP, got %d", http.StatusUnauthorized, recorder.Code)
		}
	})

	t.Run("valid authentication bypasses rate limiting check", func(t *testing.T) {
		// Valid request should succeed regardless of previous failures
		req := httptest.NewRequest("GET", "/test", http.NoBody)
		req.RemoteAddr = "192.168.1.100:12345" // Same IP that was rate limited
		req.Header.Set("Authorization", "Bearer "+testAPIKey)

		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)

		// Should succeed with valid auth
		if recorder.Code != http.StatusOK {
			t.Errorf("expected status %d for valid auth, got %d", http.StatusOK, recorder.Code)
		}
	})
}

// TestSendRateLimited tests the rate limited response function
func TestSendRateLimited(t *testing.T) {
	const expectedContentType = "application/json"

	recorder := httptest.NewRecorder()
	auth.SendRateLimited(recorder, "rate limit exceeded")

	// Check status code
	if recorder.Code != http.StatusTooManyRequests {
		t.Errorf("expected status %d, got %d", http.StatusTooManyRequests, recorder.Code)
	}

	// Check Content-Type header
	contentType := recorder.Header().Get("Content-Type")
	if contentType != expectedContentType {
		t.Errorf("expected Content-Type %s, got %s", expectedContentType, contentType)
	}

	// Check Retry-After header
	retryAfter := recorder.Header().Get("Retry-After")
	if retryAfter != "60" {
		t.Errorf("expected Retry-After header 60, got %s", retryAfter)
	}

	// Check response body
	var errorResp auth.ErrorResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &errorResp); err != nil {
		t.Errorf("expected valid JSON response, got error: %v", err)
	}

	if errorResp.Code != http.StatusTooManyRequests {
		t.Errorf("expected error code %d, got %d", http.StatusTooManyRequests, errorResp.Code)
	}

	if errorResp.Message != "rate limit exceeded" {
		t.Errorf("expected message %q, got %q", "rate limit exceeded", errorResp.Message)
	}
}
