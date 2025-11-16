package utils

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
)

type contextKey string

const contextKeyUserID contextKey = "userID"

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			WriteError(w, http.StatusUnauthorized, errors.New("missing or invalid authorization header"))
			return
		}

		rawToken := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))

		claims, err := ParseToken(rawToken)
		if err != nil {
			WriteError(w, http.StatusUnauthorized, errors.New("invalid or expired token"))
			return
		}

		if claims.TokenType != "access" {
			WriteError(w, http.StatusUnauthorized, errors.New("invalid token type"))
			return
		}

		userID, err := strconv.Atoi(claims.Subject)
		if err != nil || userID <= 0 {
			WriteError(w, http.StatusUnauthorized, errors.New("invalid token subject"))
			return
		}

		ctx := context.WithValue(r.Context(), contextKeyUserID, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func GetUserIDFromContext(ctx context.Context) (int, bool) {
	v := ctx.Value(contextKeyUserID)
	if v == nil {
		return 0, false
	}

	userID, ok := v.(int)
	if !ok {
		return 0, false
	}

	return userID, true
}
