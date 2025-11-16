package user

import (
	"auth-api/types"
	"database/sql"
)

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) CreateUser(user types.User) error {
	_, err := s.db.Exec(
		"INSERT INTO users (username, email, password) VALUES ($1, $2, $3)",
		user.Username,
		user.Email,
		user.Password,
	)
	return err
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
