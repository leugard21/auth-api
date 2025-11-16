package utils

import (
	"auth-api/configs"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func GenerateAccessToken(userID int) (string, error) {
	return generateToken(userID, time.Duration(12)*time.Hour)
}

func GenerateRefreshToken(userID int) (string, error) {
	return generateToken(userID, time.Duration(43200)*time.Minute)
}

func generateToken(userID int, ttl time.Duration) (string, error) {
	now := time.Now().UTC()

	claims := jwt.RegisteredClaims{
		Subject:   strconv.Itoa(userID),
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	secret := configs.Envs.JWTSecret
	if secret == "" {
		return "", fmt.Errorf("JWT_SECRET is not configured")
	}

	return token.SignedString([]byte(secret))
}

func ParseToken(tokenStr string) (*jwt.RegisteredClaims, error) {
	secret := configs.Envs.JWTSecret
	if secret == "" {
		return nil, errors.New("JWT_SECRET is not configured")
	}

	token, err := jwt.ParseWithClaims(tokenStr, &jwt.RegisteredClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("invalid token")
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}
