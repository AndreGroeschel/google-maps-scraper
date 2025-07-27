// Package auth provides authentication middleware for the API.
package auth

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// ErrorResponse represents an API error response.
type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// IPRateLimiter manages rate limiters per IP address
type IPRateLimiter struct {
	limiters sync.Map
	rate     rate.Limit
	burst    int
}

// NewIPRateLimiter creates a new IP-based rate limiter
func NewIPRateLimiter(r rate.Limit, b int) *IPRateLimiter {
	return &IPRateLimiter{
		rate:  r,
		burst: b,
	}
}

// Allow checks if the IP is allowed to make a request
func (rl *IPRateLimiter) Allow(ip string) bool {
	limiter := rl.getLimiter(ip)
	return limiter.Allow()
}

// getLimiter returns the rate limiter for the given IP
func (rl *IPRateLimiter) getLimiter(ip string) *rate.Limiter {
	if limiter, exists := rl.limiters.Load(ip); exists {
		if typedLimiter, ok := limiter.(*rate.Limiter); ok {
			return typedLimiter
		}
	}

	limiter := rate.NewLimiter(rl.rate, rl.burst)
	rl.limiters.Store(ip, limiter)

	return limiter
}

// getClientIP extracts the real client IP from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (most common for proxies)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		if ip := strings.Split(xff, ",")[0]; ip != "" {
			return strings.TrimSpace(ip)
		}
	}

	// Check X-Real-IP header (nginx proxy)
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return ip
}

// BearerTokenMiddleware creates a middleware that validates bearer tokens with rate limiting.
// If apiKey is empty, authentication is disabled and all requests pass through.
func BearerTokenMiddleware(apiKey string) func(http.Handler) http.Handler {
	// Create rate limiter: 5 failed attempts per minute per IP, burst of 10
	rateLimiter := NewIPRateLimiter(rate.Every(12*time.Second), 10)

	// Log authentication status on startup
	if apiKey == "" {
		log.Println("🔓 Authentication DISABLED - API key not configured")
	} else {
		log.Println("🔐 Authentication ENABLED - API key configured with rate limiting")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// If no API key is configured, skip authentication
			if apiKey == "" {
				next.ServeHTTP(w, r)
				return
			}

			clientIP := getClientIP(r)

			// Extract Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				// Check rate limit for this IP
				if !rateLimiter.Allow(clientIP) {
					log.Printf("🚨 RATE LIMITED - Too many auth failures from IP: %s", clientIP)
					SendRateLimited(w, "Too many authentication attempts")

					return
				}

				log.Printf("❌ AUTH FAILED - Missing token: %s %s from %s", r.Method, r.URL.Path, clientIP)
				SendUnauthorized(w, "Missing authentication token")

				return
			}

			// Validate Bearer token format
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				// Check rate limit for this IP
				if !rateLimiter.Allow(clientIP) {
					log.Printf("🚨 RATE LIMITED - Too many auth failures from IP: %s", clientIP)
					SendRateLimited(w, "Too many authentication attempts")

					return
				}

				log.Printf("❌ AUTH FAILED - Invalid format: %s %s from %s", r.Method, r.URL.Path, clientIP)
				SendUnauthorized(w, "Invalid authentication token format")

				return
			}

			// Compare token with configured API key using constant-time comparison
			token := parts[1]
			if subtle.ConstantTimeCompare([]byte(token), []byte(apiKey)) != 1 {
				// Check rate limit for this IP
				if !rateLimiter.Allow(clientIP) {
					log.Printf("🚨 RATE LIMITED - Too many auth failures from IP: %s", clientIP)
					SendRateLimited(w, "Too many authentication attempts")

					return
				}

				log.Printf("❌ AUTH FAILED - Invalid token: %s %s from %s", r.Method, r.URL.Path, clientIP)
				SendUnauthorized(w, "Invalid authentication token")

				return
			}

			// Authentication successful, proceed to next handler
			log.Printf("✅ AUTH SUCCESS: %s %s from %s", r.Method, r.URL.Path, clientIP)
			next.ServeHTTP(w, r)
		})
	}
}

// SendUnauthorized sends a 401 Unauthorized response with JSON error.
func SendUnauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)

	errResp := ErrorResponse{
		Code:    http.StatusUnauthorized,
		Message: message,
	}

	_ = json.NewEncoder(w).Encode(errResp)
}

// SendRateLimited sends a 429 Too Many Requests response with JSON error.
func SendRateLimited(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", "60") // Suggest retry after 60 seconds
	w.WriteHeader(http.StatusTooManyRequests)

	errResp := ErrorResponse{
		Code:    http.StatusTooManyRequests,
		Message: message,
	}

	_ = json.NewEncoder(w).Encode(errResp)
}
