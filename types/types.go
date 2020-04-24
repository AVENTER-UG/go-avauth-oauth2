package types

import (
	"github.com/dgrijalva/jwt-go"
)

type CheckAuth struct {
	Method string `json:"method"`
	Client struct {
		Username        string `json:"username"`
		EMail           string `json:"email"`
		Type            string `json:"type"`
		ClientID        string `json:"client_id"`
		Language        string `json:"language"`
		Country         string `json:"country"`
		GroupMaster     string `json:"group_master"`
		GroupAdditional string `json:"group_additional"`
		Notes           string `json:"notes"`
	} `json:"client"`
	Token string `json:"token"`
	Auth  bool   `json:"auth"`
}

type CustomClaims struct {
	Type            string `json:"type"`
	ClientID        string `json:"client_id"`
	GroupMaster     string `json:"group_master"`
	GroupAdditional string `json:"group_additional"`
	Notes           string `json:"notes"`
	jwt.StandardClaims
}
