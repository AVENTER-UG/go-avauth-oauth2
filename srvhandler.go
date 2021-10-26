package main

import (
	"github.com/sirupsen/logrus"
	"gopkg.in/oauth2.v4/errors"
)

func srvPasswordAuthorizationHandler(username, password string) (userID string, err error) {
	ispUser := AuthUser(username, password)
	logrus.Debug("SetPasswordAuthorizationHandler:", ispUser)

	if ispUser.Auth == false {
		logrus.Debug("SetPasswordAuthorizationHandler: Auth False")
		return "", err
	}

	return ispUser.Client.ClientID, nil
}

func srvInternalErrorHandler(err error) (re *errors.Response) {
	logrus.Error("SetInternalErrorHandler: Internal Error:", err.Error())
	return
}

func srvResponseErrorHandler(re *errors.Response) {
	logrus.Error("SetResponseErrorHandler: Response Error:", re.Error.Error())
}
