package main

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/go-session/session"
	"github.com/sirupsen/logrus"
)

func tokenHandler(w http.ResponseWriter, r *http.Request) {
	logrus.Debug("/token")
	err := Srv.HandleTokenRequest(w, r)
	if err != nil {
		logrus.Error("/token: Error ", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func authorizeHandler(w http.ResponseWriter, r *http.Request) {
	logrus.Debug("/authorize")
	store, err := session.Start(nil, w, r)
	if err != nil {
		logrus.Error("/authorize: Error ", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var form url.Values
	if v, ok := store.Get("ReturnUri"); ok {
		logrus.Debug("/authorize: ReturnUri: ", v, ok)
		form = v.(url.Values)
	}
	r.Form = form

	store.Delete("ReturnUri")
	store.Save()

	err = Srv.HandleAuthorizeRequest(w, r)
	if err != nil {
		logrus.Error("/authorize: Error1 ", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

func userInfoHandler(w http.ResponseWriter, r *http.Request) {
	logrus.Debug("/userinfo")
	token, err := Srv.ValidationBearerToken(r)
	if err != nil {
		logrus.Error("/userinfo: Error ", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	//var info []byte

	info, err := json.Marshal(token)

	if err != nil {
		logrus.Error("userInfoHandler: Error Create JSON")
		return
	}

	sendJSON(info, w)
}

func userAuthorizeHandler(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	logrus.Debug("userAuthorizeHandler")
	store, err := session.Start(nil, w, r)
	if err != nil {
		logrus.Error("userAuthorizeHandler: Error ", err)
		return
	}

	uid, ok := store.Get("LoggedInUserID")
	if !ok {
		logrus.Debug("userAuthorizeHandler: Not LoggedIn")
		if r.Form == nil {
			r.ParseForm()
		}

		store.Set("ReturnUri", r.Form)
		store.Save()

		w.Header().Set("Location", "/oauth/login")
		w.WriteHeader(http.StatusFound)
		return
	}

	logrus.Debug("userAuthorizeHandler: LoggedIn: ", uid)
	userID = uid.(string)
	store.Delete("LoggedInUserID")
	store.Save()
	return
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	logrus.Debug("loginHandler")
	store, err := session.Start(nil, w, r)
	if err != nil {
		logrus.Error("loginHandler: Error ", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if r.Method == "POST" {

		username := r.FormValue("username")
		userPassword := r.FormValue("password")
		ispUser := AuthUser(username, userPassword)
		logrus.Debug("loginHandler: ispUser: ", ispUser)

		if ispUser.Auth == true {

			logrus.Debug("loginHandler: Auth True")
			store.Set("LoggedInUserID", ispUser.Client.ClientID)

			store.Save()

			w.Header().Set("Location", "/oauth/auth")
			w.WriteHeader(http.StatusFound)
			return

		}

	}
	outputHTML(w, r, "static/login.html")
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	logrus.Debug("authHandler")
	store, err := session.Start(nil, w, r)
	if err != nil {
		logrus.Error("authHandler: Error ", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if _, ok := store.Get("LoggedInUserID"); !ok {
		logrus.Debug("authHandler: Not LoggedIn")
		w.Header().Set("Location", "/oauth/login")
		w.WriteHeader(http.StatusFound)
		return
	}

	outputHTML(w, r, "static/auth.html")
}
