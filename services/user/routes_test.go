package user

import (
	"auth-api/configs"
	"auth-api/types"
	"auth-api/utils"
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type MockUserStore struct {
	CreateUserFn                    func(types.User) (int, error)
	GetUserByEmailFn                func(email string) (*types.User, error)
	GetUserByUsernameFn             func(username string) (*types.User, error)
	GetUserByIDFn                   func(id int) (*types.User, error)
	SaveRefreshTokenFn              func(userID int, token string, expiresAt time.Time) error
	RevokeRefreshTokenFn            func(token string) error
	IsRefreshTokenValidFn           func(token string) (bool, error)
	UpdatePasswordFn                func(userID int, newPasswordHash string) error
	RevokeAllRefreshTokensForUserFn func(userID int) error
}

func (m *MockUserStore) CreateUser(u types.User) (int, error) {
	if m.CreateUserFn == nil {
		return 0, nil
	}
	return m.CreateUserFn(u)
}

func (m *MockUserStore) GetUserByEmail(email string) (*types.User, error) {
	if m.GetUserByEmailFn == nil {
		return nil, sql.ErrNoRows
	}
	return m.GetUserByEmailFn(email)
}

func (m *MockUserStore) GetUserByUsername(username string) (*types.User, error) {
	if m.GetUserByUsernameFn == nil {
		return nil, sql.ErrNoRows
	}
	return m.GetUserByUsernameFn(username)
}

func (m *MockUserStore) GetUserByID(id int) (*types.User, error) {
	if m.GetUserByIDFn == nil {
		return nil, sql.ErrNoRows
	}
	return m.GetUserByIDFn(id)
}

func (m *MockUserStore) SaveRefreshToken(userID int, token string, expiresAt time.Time) error {
	if m.SaveRefreshTokenFn == nil {
		return nil
	}
	return m.SaveRefreshTokenFn(userID, token, expiresAt)
}

func (m *MockUserStore) RevokeRefreshToken(token string) error {
	if m.RevokeRefreshTokenFn == nil {
		return nil
	}
	return m.RevokeRefreshTokenFn(token)
}

func (m *MockUserStore) IsRefreshTokenValid(token string) (bool, error) {
	if m.IsRefreshTokenValidFn == nil {
		return false, nil
	}
	return m.IsRefreshTokenValidFn(token)
}

func (m *MockUserStore) UpdatePassword(userID int, newPasswordHash string) error {
	if m.UpdatePasswordFn == nil {
		return nil
	}
	return m.UpdatePasswordFn(userID, newPasswordHash)
}

func (m *MockUserStore) RevokeAllRefreshTokensForUser(userID int) error {
	if m.RevokeAllRefreshTokensForUserFn == nil {
		return nil
	}
	return m.RevokeAllRefreshTokensForUserFn(userID)
}

func TestHandleRegister_Success(t *testing.T) {
	configs.Envs.JWTSecret = "test-secret"

	mockStore := &MockUserStore{
		GetUserByEmailFn: func(email string) (*types.User, error) {
			return nil, sql.ErrNoRows
		},
		GetUserByUsernameFn: func(username string) (*types.User, error) {
			return nil, sql.ErrNoRows
		},
		CreateUserFn: func(u types.User) (int, error) {
			if u.Username != "testuser" {
				t.Fatalf("expected username 'testuser', got %q", u.Username)
			}
			if u.Email != "test@example.com" {
				t.Fatalf("expected email 'test@example.com', got %q", u.Email)
			}
			return 1, nil
		},
		SaveRefreshTokenFn: func(userID int, token string, expiresAt time.Time) error {
			if userID != 1 {
				t.Fatalf("expected userID 1, got %d", userID)
			}
			if token == "" {
				t.Fatalf("expected non-empty refresh token")
			}
			if expiresAt.IsZero() {
				t.Fatalf("expected non-zero expiresAt")
			}
			return nil
		},
	}

	h := NewHandler(mockStore)

	payload := types.RegisterUserPayload{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "verystrongpassword",
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	http.HandlerFunc(h.handleRegister).ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", rr.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["accessToken"] == nil || resp["refreshToken"] == nil {
		t.Fatalf("expected accessToken and refreshToken in response")
	}
}

func TestHandleLogin_InvalidCredentials(t *testing.T) {
	configs.Envs.JWTSecret = "test-secret"

	mockStore := &MockUserStore{
		GetUserByEmailFn: func(email string) (*types.User, error) {
			return nil, sql.ErrNoRows
		},
		GetUserByUsernameFn: func(username string) (*types.User, error) {
			return nil, sql.ErrNoRows
		},
	}

	h := NewHandler(mockStore)

	payload := types.LoginPayload{
		Identifier: "unknown",
		Password:   "whatever",
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	http.HandlerFunc(h.handleLogin).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rr.Code)
	}
}

func TestHandleMe_Success(t *testing.T) {
	configs.Envs.JWTSecret = "test-secret"

	mockStore := &MockUserStore{
		GetUserByIDFn: func(id int) (*types.User, error) {
			if id != 42 {
				t.Fatalf("expected userID 42, got %d", id)
			}
			return &types.User{
				ID:        42,
				Username:  "meuser",
				Email:     "me@example.com",
				CreatedAt: time.Now(),
			}, nil
		},
	}

	h := NewHandler(mockStore)

	accessToken, err := utils.GenerateAccessToken(42)
	if err != nil {
		t.Fatalf("GenerateAccessToken error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rr := httptest.NewRecorder()

	handler := utils.AuthMiddleware(http.HandlerFunc(h.handleMe))
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["id"] == nil || resp["username"] == nil || resp["email"] == nil {
		t.Fatalf("expected id, username, email in /me response")
	}
}
