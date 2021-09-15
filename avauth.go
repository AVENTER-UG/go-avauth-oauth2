package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"

	cfg "github.com/AVENTER-UG/go-avauth-oauth2/types"
)

// AuthUser Function to authenticate a user against the ispconfig backend system
//	curl -X GET -u <customeruser>:<password>  http://127.0.0.1:10777/api/v0/authUser
//

func AuthUser(username, password string) cfg.CheckAuth {
	// check user auth
	client := &http.Client{}
	req, err := http.NewRequest("GET", AuthServer+"/checkAuth.php", nil)

	var user cfg.CheckAuth

	// User authorization not correct
	if err != nil {
		logrus.Error("authUser 1: ", err)
		user.Auth = false
		return user
	}
	req.SetBasicAuth(username, password)
	res, err := client.Do(req)

	if err != nil {
		logrus.Error("authUser 2: ", err)
		user.Auth = false
	} else {
		json.NewDecoder(res.Body).Decode(&user)
	}

	logrus.Debug("AuthUser: user: ", user)

	ug := strings.Split(user.Client.GroupAdditional, ":")

	// if the server was started with UserGroup then check if the user in in that group
	if UserGroup != "" {
		if len(ug) >= 2 {
			if !strings.Contains(ug[1], UserGroup) {
				user.Auth = false
			}
		} else {
			user.Auth = false
		}
	}

	logrus.Debug("AuthUser: ug: ", ug, " UserGroup: ", UserGroup)

	return user
}
