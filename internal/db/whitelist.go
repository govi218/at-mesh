package db

import "time"

// WhitelistEntry represents an authorized DID that can join the mesh.
// An empty whitelist means all DIDs are allowed (bootstrap mode).
type WhitelistEntry struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	DID       string    `gorm:"uniqueIndex;not null" json:"did"`
	Handle    string    `json:"handle"`
	MaxNodes  int       `gorm:"default:0" json:"max_nodes"` // 0 = unlimited
	Notes     string    `json:"notes"`
	CreatedAt time.Time `json:"created_at"`
}
