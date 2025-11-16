package user

import (
	"auth-api/types"
	"auth-api/utils"
	"database/sql"
	"errors"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	store types.UserStore
}

func NewHandler(store types.UserStore) *Handler {
	return &Handler{store: store}
}

func (h *Handler) RegisterRoutes(router *mux.Router) {
	router.HandleFunc("/register", h.handleRegister).Methods("POST")
	router.HandleFunc("/login", h.handleLogin).Methods("POST")
	router.HandleFunc("/refresh", h.handleRefresh).Methods("POST")

	router.Handle("/me", utils.AuthMiddleware(http.HandlerFunc(h.handleMe))).Methods("GET")
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

	hashed, err := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	user := types.User{
		Username: payload.Username,
		Email:    payload.Email,
		Password: string(hashed),
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
		utils.WriteError(w, http.StatusUnauthorized, errors.New("invalid username or email"))
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(payload.Password)) != nil {
		utils.WriteError(w, http.StatusUnauthorized, errors.New("invalid password"))
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

	utils.WriteJSON(w, http.StatusOK, map[string]any{
		"message":      "login successfully",
		"accessToken":  accessToken,
		"refreshToken": refreshToken,
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
		utils.WriteError(w, http.StatusUnauthorized, errors.New("invalid or expired token"))
		return
	}

	if claims.TokenType != "refresh" {
		utils.WriteError(w, http.StatusUnauthorized, errors.New("invalid token type"))
		return
	}

	userID, err := strconv.Atoi(claims.Subject)
	if err != nil || userID <= 0 {
		utils.WriteError(w, http.StatusUnauthorized, errors.New("invalid token subject"))
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

	utils.WriteJSON(w, http.StatusOK, map[string]any{
		"accessToken":  newAccessToken,
		"refreshToken": newRefreshToken,
	})
}
