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
	} `json:"client"`
	Token string `json:"token"`
	Auth  bool   `json:"auth"`
}

type CustomClaims struct {
	Type            string `json:"type"`
	ClientID        string `json:"client_id"`
	GroupMaster     string `json:"group_master"`
	GroupAdditional string `json:"group_additional"`
	jwt.StandardClaims
}

type UserInfo struct {
	UserID      string `json:"user_id"`
	UserName    string `json:"user_name"`
	EMail       string `json:"email"`
	ConnectorID string `json:"connector_id"`
	Sub         string `json:"sub"`
	Name        string `json:"name"`
	Auth        string `json:"auth"`
	ClientID    string `json:"client_id"`
	Type        string `json:"type"`
}
