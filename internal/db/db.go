package db

import (
	"time"

	"gorm.io/gorm"
)

type DB struct {
	*gorm.DB
}

type AuthRequest struct {
	ID                  uint           `gorm:"primaryKey"`
	Code                string         `gorm:"uniqueIndex;not null"`
	ClientId            string         `gorm:"not null"`
	RedirectUri         string         `gorm:"not null"`
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Sub                 string
	PreferredUsername   string
	Email               string
	ExpiresAt           time.Time
	CreatedAt           time.Time
}
