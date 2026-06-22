package db

import (
	"time"

	"gorm.io/gorm"
)

type DB struct {
	*gorm.DB
}

type OidcAuthCode struct {
	ID                  uint           `gorm:"primaryKey"`
	Code                string         `gorm:"index"`
	AccessToken         string         `gorm:"index"`
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
