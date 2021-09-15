package main

import (
	jwt "github.com/golang-jwt/jwt"
	"github.com/sirupsen/logrus"
	"gopkg.in/oauth2.v3"

	cfg "github.com/AVENTER-UG/go-avauth-oauth2/types"
)

type JWTGenerator struct {
	SignedKey []byte
}

func (a *JWTGenerator) Token(data *oauth2.GenerateBasic, isGenRefresh bool) (access, refresh string, err error) {
	logrus.Debug("Token: LoggedIn: ", data)
	signingKey := []byte(JwtSignKey)

	// Create the Claims
	myClaims := &cfg.CustomClaims{
		ClientID: data.UserID,
		Type:     "user",
		StandardClaims: jwt.StandardClaims{
			Audience:  data.Client.GetID(),
			Subject:   data.UserID,
			ExpiresAt: data.TokenInfo.GetAccessCreateAt().Add(data.TokenInfo.GetAccessExpiresIn()).Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, myClaims)
	access, err = token.SignedString(signingKey)

	if err != nil {
		logrus.Debug("newToken = ", err)
	}

	return
}

// Check if the token is valid
// return true and false and if its true then also the clientID of the token
func validToken(token string) (bool, *cfg.CustomClaims) {
	newToken, err := jwt.ParseWithClaims(token, &cfg.CustomClaims{}, func(newToken *jwt.Token) (interface{}, error) {
		return []byte(JwtSignKey), nil
	})

	if err != nil {
		logrus.Error("validToken: ", err)
		return false, nil
	}

	if claims, ok := newToken.Claims.(*cfg.CustomClaims); ok && newToken.Valid {
		return true, claims
	} else {
		return false, nil
	}
}
