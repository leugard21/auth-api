package utils_test

import (
	"auth-api/configs"
	"auth-api/utils"
	"testing"
)

func TestGenerateAndParseAccessToken(t *testing.T) {
	configs.Envs.JWTSecret = "test-secret"

	token, err := utils.GenerateAccessToken(123)
	if err != nil {
		t.Fatalf("GenerateAccessToken error: %v", err)
	}
	if token == "" {
		t.Fatalf("expected non-empty access token")
	}

	claims, err := utils.ParseToken(token)
	if err != nil {
		t.Fatalf("ParseToken error: %v", err)
	}

	if claims.TokenType != "access" {
		t.Fatalf("expected token type 'access', got %q", claims.TokenType)
	}

	if claims.Subject != "123" {
		t.Fatalf("expected subject '123', got %q", claims.Subject)
	}

	if claims.ExpiresAt == nil {
		t.Fatalf("expected ExpiresAt to be set")
	}
}

func TestGenerateAndParseRefreshToken(t *testing.T) {
	configs.Envs.JWTSecret = "test-secret"

	token, err := utils.GenerateRefreshToken(456)
	if err != nil {
		t.Fatalf("GenerateRefreshToken error: %v", err)
	}
	if token == "" {
		t.Fatalf("expected non-empty refresh token")
	}

	claims, err := utils.ParseToken(token)
	if err != nil {
		t.Fatalf("ParseToken error: %v", err)
	}

	if claims.TokenType != "refresh" {
		t.Fatalf("expected token type 'refresh', got %q", claims.TokenType)
	}

	if claims.Subject != "456" {
		t.Fatalf("expected subject '456', got %q", claims.Subject)
	}

	if claims.ExpiresAt == nil {
		t.Fatalf("expected ExpiresAt to be set")
	}
}
