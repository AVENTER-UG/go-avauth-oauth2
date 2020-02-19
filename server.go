package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"

	"git.aventer.biz/AVENTER/util"
	"github.com/go-session/session"
	"github.com/sirupsen/logrus"
	"gopkg.in/oauth2.v3/errors"
	"gopkg.in/oauth2.v3/manage"
	"gopkg.in/oauth2.v3/models"
	"gopkg.in/oauth2.v3/server"
	"gopkg.in/oauth2.v3/store"
)

var (
	globalSessions *session.Manager
	JwtSignKey     string
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
	Auth        string `json:"auth"`
	ClientID    string `json:"client_id"`
	Type        string `json:"type"`
}

func main() {
	AuthServer = os.Getenv("AUTH_SERVER")
	ClientDomain = os.Getenv("CLIENTDOMAIN")
	ClientID = os.Getenv("CLIENTID")
	ClientSecret = os.Getenv("CLIENTSECRET")
	LogLevel = os.Getenv("LOGLEVEL")
	UserGroup = os.Getenv("GROUP")
	JwtSignKey = os.Getenv("JWT_SIGNKEY")

	util.SetLogging(LogLevel, EnableSyslog, AppName)

	logrus.Info("ISPCONFIGServer=", AuthServer)
	logrus.Info("ClientDomain=", ClientDomain)
	logrus.Info("ClientSecret=", ClientSecret)
	logrus.Info("ClientID=", ClientID)

	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)

	// token store
	manager.MustTokenStorage(store.NewMemoryTokenStore())

	// generate jwt access token
	manager.MapAccessGenerate(&JWTGenerator{SignedKey: []byte(JwtSignKey)})
	//	manager.MapAccessGenerate(generates.NewAccessGenerate())

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
		logrus.Debug("SetPasswordAuthorizationHandler:", ispUser)

		if ispUser.Auth == false {
			logrus.Debug("SetPasswordAuthorizationHandler: Auth False")
			return "", err
		}

		return ispUser.Client.ClientID, nil
	})

	srv.SetUserAuthorizationHandler(userAuthorizeHandler)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		logrus.Error("SetInternalErrorHandler: Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		logrus.Error("SetResponseErrorHandler: Response Error:", re.Error.Error())
	})

	http.HandleFunc("/oauth/login", loginHandler)
	http.HandleFunc("/oauth/auth", authHandler)
	http.HandleFunc("/oauth/userinfo", func(w http.ResponseWriter, r *http.Request) {
		logrus.Debug("/userinfo")
		token, err := srv.ValidationBearerToken(r)
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
	})

	http.HandleFunc("/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
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

		err = srv.HandleAuthorizeRequest(w, r)
		if err != nil {
			logrus.Error("/authorize: Error1 ", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})

	http.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		logrus.Debug("/token")
		err := srv.HandleTokenRequest(w, r)
		if err != nil {
			logrus.Error("/token: Error ", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	logrus.Println("Server is running at 9096 port.")
	logrus.Fatal(http.ListenAndServe(":9096", nil))
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
