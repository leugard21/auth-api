package user

import (
	"auth-api/types"
	"database/sql"
	"time"
)

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) CreateUser(user types.User) (int, error) {
	var userID int

	err := s.db.QueryRow(
		"INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id",
		user.Username,
		user.Email,
		user.Password,
	).Scan(&userID)

	if err != nil {
		return 0, err
	}

	return userID, nil
}

func (s *Store) GetUserByEmail(email string) (*types.User, error) {
	row := s.db.QueryRow(
		`SELECT id, username, email, password, created_at
         FROM users
         WHERE email = $1
         LIMIT 1`,
		email,
	)

	var u types.User
	err := row.Scan(
		&u.ID,
		&u.Username,
		&u.Email,
		&u.Password,
		&u.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &u, nil
}

func (s *Store) GetUserByUsername(username string) (*types.User, error) {
	row := s.db.QueryRow(
		`SELECT id, username, email, password, created_at
         FROM users
         WHERE username = $1
         LIMIT 1`,
		username,
	)

	var u types.User
	err := row.Scan(
		&u.ID,
		&u.Username,
		&u.Email,
		&u.Password,
		&u.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &u, nil
}

func (s *Store) GetUserByID(id int) (*types.User, error) {
	row := s.db.QueryRow(
		`SELECT id, username, email, password, created_at
         FROM users
         WHERE id = $1
         LIMIT 1`,
		id,
	)

	var u types.User
	err := row.Scan(
		&u.ID,
		&u.Username,
		&u.Email,
		&u.Password,
		&u.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &u, nil
}

func (s *Store) UpdatePassword(userID int, newPasswordHash string) error {
	_, err := s.db.Exec(
		`UPDATE users
           SET password = $1
         WHERE id = $2`,
		newPasswordHash,
		userID,
	)
	return err
}

func (s *Store) SaveRefreshToken(userID int, token string, expiresAt time.Time) error {
	_, err := s.db.Exec(
		`INSERT INTO refresh (user_id, token, expires_at)
         VALUES ($1, $2, $3)`,
		userID,
		token,
		expiresAt,
	)
	return err
}

func (s *Store) RevokeRefreshToken(token string) error {
	_, err := s.db.Exec(
		`UPDATE refresh
           SET revoked = TRUE
         WHERE token = $1`,
		token,
	)
	return err
}

func (s *Store) IsRefreshTokenValid(token string) (bool, error) {
	var revoked bool
	var expiresAt time.Time

	err := s.db.QueryRow(
		`SELECT revoked, expires_at
           FROM refresh
          WHERE token = $1`,
		token,
	).Scan(&revoked, &expiresAt)

	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	if revoked || time.Now().UTC().After(expiresAt) {
		return false, nil
	}

	return true, nil
}

func (s *Store) RevokeAllRefreshTokensForUser(userID int) error {
	_, err := s.db.Exec(
		`UPDATE refresh
           SET revoked = TRUE
         WHERE user_id = $1
           AND revoked = FALSE`,
		userID,
	)
	return err
}
