package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-session/session"
	"github.com/sirupsen/logrus"
	"gopkg.in/oauth2.v3/errors"
	"gopkg.in/oauth2.v3/generates"
	"gopkg.in/oauth2.v3/manage"
	"gopkg.in/oauth2.v3/models"
	"gopkg.in/oauth2.v3/server"
	"gopkg.in/oauth2.v3/store"
)

var (
	globalSessions *session.Manager
	AuthServer     string
	ClientDomain   string
	ClientID       string
	ClientSecret   string
	User           UserInfo
	LogLevel       string
	AppName        string
	EnableSyslog   bool
	UserGroup      string
	Identifier     string
)

type UserInfo struct {
	UserID      string `json:"user_id"`
	UserName    string `json:"user_name"`
	EMail       string `json:"email"`
	ConnectorID string `json:"connector_id"`
	Sub         string `json:"sub"`
	Name        string `json:"name"`
}

func main() {
	AuthServer = os.Getenv("AUTH_SERVER")
	ClientDomain = os.Getenv("CLIENTDOMAIN")
	ClientID = os.Getenv("CLIENTID")
	ClientSecret = os.Getenv("CLIENTSECRET")
	LogLevel = os.Getenv("LOGLEVEL")
	UserGroup = os.Getenv("GROUP")

	fmt.Println("ISPCONFIGServer=", AuthServer)
	fmt.Println("ClientDomain=", ClientDomain)
	fmt.Println("ClientSecret=", ClientSecret)
	fmt.Println("ClientID=", ClientID)

	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)

	// token store
	manager.MustTokenStorage(store.NewMemoryTokenStore())

	// generate jwt access token
	manager.MapAccessGenerate(generates.NewAccessGenerate())

	clientStore := store.NewClientStore()
	clientStore.Set(ClientID, &models.Client{
		ID:     ClientID,
		Secret: ClientSecret,
		Domain: ClientDomain,
	})
	manager.MapClientStorage(clientStore)

	srv := server.NewServer(server.NewConfig(), manager)

	srv.SetPasswordAuthorizationHandler(func(username, password string) (userID string, err error) {
		ispUser := AuthUser(username, password)

		ug := strings.Split(ispUser.Client.GroupAdditional, ":")

		if ispUser.Auth == true && strings.Contains(ug[1], UserGroup) {
			return ispUser.Client.Username, nil
		}
		return
	})

	srv.SetUserAuthorizationHandler(userAuthorizeHandler)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		logrus.Println("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		logrus.Println("Response Error:", re.Error.Error())
	})

	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/auth", authHandler)
	http.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		token, err := srv.ValidationBearerToken(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var user UserInfo

		user.UserID = token.GetUserID()
		user.ConnectorID = token.GetUserID()

		//var info []byte
		info, err := json.Marshal(user)

		if err != nil {
			logrus.Println("userInfoHandler: Error Create JSON")
			return
		}

		sendJSON(info, w)
	})

	http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		store, err := session.Start(nil, w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var form url.Values
		if v, ok := store.Get("ReturnUri"); ok {
			form = v.(url.Values)
		}
		r.Form = form

		store.Delete("ReturnUri")
		store.Save()

		err = srv.HandleAuthorizeRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})

	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		err := srv.HandleTokenRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		token, err := srv.ValidationBearerToken(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		data := map[string]interface{}{
			"expires_in": int64(token.GetAccessCreateAt().Add(token.GetAccessExpiresIn()).Sub(time.Now()).Seconds()),
			"client_id":  token.GetClientID(),
			"user_id":    token.GetUserID(),
		}
		e := json.NewEncoder(w)
		e.SetIndent("", "  ")
		e.Encode(data)
	})

	logrus.Println("Server is running at 9096 port.")
	logrus.Fatal(http.ListenAndServe(":9096", nil))
}

func userAuthorizeHandler(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	store, err := session.Start(nil, w, r)
	if err != nil {
		return
	}

	uid, ok := store.Get("LoggedInUserID")
	if !ok {
		if r.Form == nil {
			r.ParseForm()
		}

		store.Set("ReturnUri", r.Form)
		store.Save()

		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
		return
	}

	userID = uid.(string)
	store.Delete("LoggedInUserID")
	store.Save()
	return
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	store, err := session.Start(nil, w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if r.Method == "POST" {

		username := r.FormValue("username")
		userPassword := r.FormValue("password")
		ispUser := AuthUser(username, userPassword)

		ug := strings.Split(ispUser.Client.GroupAdditional, ":")

		if ispUser.Auth == true && strings.Contains(ug[1], UserGroup) {
			store.Set("LoggedInUserID", ispUser.Client.Username)
			store.Set("EMail", ispUser.Client.EMail)
			store.Set("UserName", ispUser.Client.Username)

			store.Save()

			w.Header().Set("Location", "/auth")
			w.WriteHeader(http.StatusFound)
			return

		}

	}
	outputHTML(w, r, "static/login.html")
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	store, err := session.Start(nil, w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if _, ok := store.Get("LoggedInUserID"); !ok {
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
		return
	}

	outputHTML(w, r, "static/auth.html")
}

func outputHTML(w http.ResponseWriter, req *http.Request, filename string) {
	file, err := os.Open(filename)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer file.Close()
	fi, _ := file.Stat()
	http.ServeContent(w, req, file.Name(), fi.ModTime(), file)
}

func sendJSON(js []byte, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write(js)
}
