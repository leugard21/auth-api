package utils_test

import (
	"auth-api/configs"
	"auth-api/utils"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthMiddleware_AllowsValidAccessToken(t *testing.T) {
	configs.Envs.JWTSecret = "test-secret"

	token, err := utils.GenerateAccessToken(999)
	if err != nil {
		t.Fatalf("GenerateAccessToken error: %v", err)
	}

	var called bool
	var gotUserID int

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		id, ok := utils.GetUserIDFromContext(r.Context())
		if !ok {
			t.Fatalf("userID not found in context")
		}
		gotUserID = id
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler := utils.AuthMiddleware(nextHandler)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
	if !called {
		t.Fatalf("expected next handler to be called")
	}
	if gotUserID != 999 {
		t.Fatalf("expected userID 999 in context, got %d", gotUserID)
	}
}

func TestAuthMiddleware_RejectsMissingToken(t *testing.T) {
	configs.Envs.JWTSecret = "test-secret"

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("next handler should not be called on missing token")
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rr := httptest.NewRecorder()

	handler := utils.AuthMiddleware(nextHandler)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rr.Code)
	}
}

func TestAuthMiddleware_RejectsRefreshToken(t *testing.T) {
	configs.Envs.JWTSecret = "test-secret"

	refreshToken, err := utils.GenerateRefreshToken(1)
	if err != nil {
		t.Fatalf("GenerateRefreshToken error: %v", err)
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("next handler should not be called for refresh token")
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+refreshToken)
	rr := httptest.NewRecorder()

	handler := utils.AuthMiddleware(nextHandler)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401 for refresh token, got %d", rr.Code)
	}
}
