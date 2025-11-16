package types

import "time"

type User struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Password  string    `json:"-"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"createdAt"`
}

type UserStore interface {
	CreateUser(User) (int, error)
	GetUserByEmail(email string) (*User, error)
	GetUserByUsername(username string) (*User, error)
	GetUserByID(id int) (*User, error)
	ListUsers() ([]User, error)

	SaveRefreshToken(userID int, token string, expiresAt time.Time) error
	RevokeRefreshToken(token string) error
	IsRefreshTokenValid(token string) (bool, error)

	UpdatePassword(userID int, newPasswordHash string) error
	RevokeAllRefreshTokensForUser(userID int) error
}

type RegisterUserPayload struct {
	Username string `json:"username" validate:"required,min=3,max=30"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8,max=130"`
}

type LoginPayload struct {
	Identifier string `json:"identifier" validate:"required"`
	Password   string `json:"password" validate:"required"`
}

type RefreshPayload struct {
	RefreshToken string `json:"refreshToken" validate:"required"`
}

type ChangePasswordPayload struct {
	CurrentPassword string `json:"currentPassword" validate:"required"`
	NewPassword     string `json:"newPassword" validate:"required,min=8,max=130"`
}
