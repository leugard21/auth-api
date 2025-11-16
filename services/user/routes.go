package user

import (
	"auth-api/types"
	"auth-api/utils"
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
)

type Handler struct {
	store types.UserStore
}

func NewHandler(store types.UserStore) *Handler {
	return &Handler{store: store}
}

func (h *Handler) RegisterRoutes(router *mux.Router) {
	router.Handle("/register", utils.RateLimit(5, 1*time.Minute)(http.HandlerFunc(h.handleRegister))).Methods("POST")

	router.Handle("/login", utils.RateLimit(10, 1*time.Minute)(http.HandlerFunc(h.handleLogin))).Methods("POST")

	router.HandleFunc("/refresh", h.handleRefresh).Methods("POST")
	router.HandleFunc("/logout", h.handleLogout).Methods("POST")

	router.Handle("/me", utils.AuthMiddleware(http.HandlerFunc(h.handleMe))).Methods("GET")

	router.Handle("/change-password", utils.AuthMiddleware(http.HandlerFunc(h.handleChangePassword))).Methods("POST")
}

func (h *Handler) handleRegister(w http.ResponseWriter, r *http.Request) {
	var payload types.RegisterUserPayload
	if err := utils.ParseJSON(r, &payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err)
		return
	}
	if err := utils.Validate.Struct(payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err)
		return
	}

	if existing, err := h.store.GetUserByEmail(payload.Email); err == nil && existing != nil {
		utils.WriteError(w, http.StatusBadRequest, errors.New("email already exists"))
		return
	}

	if existing, err := h.store.GetUserByUsername(payload.Username); err == nil && existing != nil {
		utils.WriteError(w, http.StatusBadRequest, errors.New("username already exists"))
		return
	}

	hashed, err := utils.HashPassword(payload.Password)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	user := types.User{
		Username: payload.Username,
		Email:    payload.Email,
		Password: hashed,
	}

	userID, err := h.store.CreateUser(user)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	accessToken, err := utils.GenerateAccessToken(userID)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	refreshToken, err := utils.GenerateRefreshToken(userID)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	claims, err := utils.ParseToken(refreshToken)
	if err != nil || claims.TokenType != "refresh" || claims.ExpiresAt == nil {
		utils.WriteError(w, http.StatusInternalServerError, errors.New("failed to persist refresh token"))
		return
	}

	if err := h.store.SaveRefreshToken(userID, refreshToken, claims.ExpiresAt.Time); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	utils.WriteJSON(w, http.StatusCreated, map[string]any{
		"message":      "registered successfully",
		"accessToken":  accessToken,
		"refreshToken": refreshToken,
	})
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	var payload types.LoginPayload
	if err := utils.ParseJSON(r, &payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err)
		return
	}
	if err := utils.Validate.Struct(payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err)
		return
	}

	u, err := h.store.GetUserByEmail(payload.Identifier)
	if errors.Is(err, sql.ErrNoRows) {
		u, err = h.store.GetUserByUsername(payload.Identifier)
	}

	if err != nil {
		utils.WriteError(w, http.StatusUnauthorized, errors.New("invalid credentials"))
		return
	}

	if !utils.CheckPassword(u.Password, payload.Password) {
		utils.WriteError(w, http.StatusUnauthorized, errors.New("invalid credentials"))
		return
	}

	accessToken, err := utils.GenerateAccessToken(u.ID)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	refreshToken, err := utils.GenerateRefreshToken(u.ID)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	claims, err := utils.ParseToken(refreshToken)
	if err != nil || claims.TokenType != "refresh" || claims.ExpiresAt == nil {
		utils.WriteError(w, http.StatusInternalServerError, errors.New("failed to persist refresh token"))
		return
	}

	if err := h.store.SaveRefreshToken(u.ID, refreshToken, claims.ExpiresAt.Time); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]any{
		"message":      "login successfully",
		"accessToken":  accessToken,
		"refreshToken": refreshToken,
		"user": map[string]any{
			"id":        u.ID,
			"username":  u.Username,
			"email":     u.Email,
			"createdAt": u.CreatedAt,
		},
	})
}

func (h *Handler) handleMe(w http.ResponseWriter, r *http.Request) {
	userID, ok := utils.GetUserIDFromContext(r.Context())
	if !ok {
		utils.WriteError(w, http.StatusUnauthorized, errors.New("unauthorized"))
		return
	}

	u, err := h.store.GetUserByID(userID)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]any{
		"id":        u.ID,
		"username":  u.Username,
		"email":     u.Email,
		"createdAt": u.CreatedAt,
	})
}

func (h *Handler) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var payload types.RefreshPayload
	if err := utils.ParseJSON(r, &payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err)
		return
	}
	if err := utils.Validate.Struct(payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err)
		return
	}

	claims, err := utils.ParseToken(payload.RefreshToken)
	if err != nil {
		utils.WriteError(w, http.StatusUnauthorized, errors.New("invalid token"))
		return
	}

	if claims.TokenType != "refresh" {
		utils.WriteError(w, http.StatusUnauthorized, errors.New("invalid token"))
		return
	}

	valid, err := h.store.IsRefreshTokenValid(payload.RefreshToken)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	if !valid {
		utils.WriteError(w, http.StatusUnauthorized, errors.New("invalid token"))
		return
	}

	userID, err := strconv.Atoi(claims.Subject)
	if err != nil || userID <= 0 {
		utils.WriteError(w, http.StatusUnauthorized, errors.New("invalid token"))
		return
	}

	newAccessToken, err := utils.GenerateAccessToken(userID)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	newRefreshToken, err := utils.GenerateRefreshToken(userID)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	newClaims, err := utils.ParseToken(newRefreshToken)
	if err != nil || newClaims.TokenType != "refresh" || newClaims.ExpiresAt == nil {
		utils.WriteError(w, http.StatusInternalServerError, errors.New("failed to persist refresh token"))
		return
	}

	_ = h.store.RevokeRefreshToken(payload.RefreshToken)
	if err := h.store.SaveRefreshToken(userID, newRefreshToken, newClaims.ExpiresAt.Time); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]any{
		"accessToken":  newAccessToken,
		"refreshToken": newRefreshToken,
	})
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	var payload types.RefreshPayload
	if err := utils.ParseJSON(r, &payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err)
		return
	}
	if err := utils.Validate.Struct(payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err)
		return
	}

	_ = h.store.RevokeRefreshToken(payload.RefreshToken)

	utils.WriteJSON(w, http.StatusOK, map[string]any{
		"message": "logged out",
	})
}

func (h *Handler) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	userID, ok := utils.GetUserIDFromContext(r.Context())
	if !ok {
		utils.WriteError(w, http.StatusUnauthorized, errors.New("unauthorized"))
		return
	}

	var payload types.ChangePasswordPayload
	if err := utils.ParseJSON(r, &payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err)
		return
	}
	if err := utils.Validate.Struct(payload); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err)
		return
	}

	u, err := h.store.GetUserByID(userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			utils.WriteError(w, http.StatusUnauthorized, errors.New("unauthorized"))
			return
		}
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	if !utils.CheckPassword(u.Password, payload.CurrentPassword) {
		utils.WriteError(w, http.StatusUnauthorized, errors.New("invalid current password"))
		return
	}

	newHash, err := utils.HashPassword(payload.NewPassword)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	if err := h.store.UpdatePassword(userID, newHash); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	if err := h.store.RevokeAllRefreshTokensForUser(userID); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]any{
		"message": "password changed successfully, all sessions have been logged out",
	})
}
