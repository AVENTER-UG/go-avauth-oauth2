package main

import (
	"encoding/json"
	"net/http"

	"github.com/sirupsen/logrus"

	cfg "./types"
)

// AuthUser Function to authenticate a user against the ispconfig backend system
//	curl -X GET -u <customeruser>:<password>  http://127.0.0.1:10777/api/v0/authUser
//
func AuthUser(username, password string) cfg.CheckAuth {

	client := &http.Client{}
	req, err := http.NewRequest("GET", AuthServer+"/api/v0/authUser", nil)

	if err != nil {
		logrus.Println(err)
	}

	req.SetBasicAuth(username, password)
	res, err := client.Do(req)

	if err != nil {
		logrus.Println(err)
	}

	var user cfg.CheckAuth

	json.NewDecoder(res.Body).Decode(&user)

	return user

}
