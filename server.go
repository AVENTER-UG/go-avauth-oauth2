package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	util "git.aventer.biz/AVENTER/util"
	"gopkg.in/oauth2.v3/errors"
	"gopkg.in/oauth2.v3/manage"
	"gopkg.in/oauth2.v3/models"
	"gopkg.in/oauth2.v3/server"
	"gopkg.in/oauth2.v3/store"
	"gopkg.in/session.v1"
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

func init() {

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

	util.SetLogging(LogLevel, EnableSyslog, AppName)

	globalSessions, _ = session.NewManager("memory", `{"cookieName":"gosessionid","gclifetime":3600}`)
	go globalSessions.GC()
}

func main() {
	manager := manage.NewDefaultManager()
	// token store
	manager.MustTokenStorage(store.NewMemoryTokenStore())

	clientStore := store.NewClientStore()
	clientStore.Set(ClientID, &models.Client{
		ID:     ClientID,
		Secret: ClientSecret,
		Domain: ClientDomain,
	})
	manager.MapClientStorage(clientStore)

	srv := server.NewServer(server.NewConfig(), manager)
	srv.SetUserAuthorizationHandler(userAuthorizeHandler)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/auth", authHandler)
	http.HandleFunc("/userinfo", userInfoHandler)

	http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		err := srv.HandleAuthorizeRequest(w, r)
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

	log.Println("Server is running at 9096 port.")
	log.Fatal(http.ListenAndServe(":9096", nil))
}

func userAuthorizeHandler(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	us, err := globalSessions.SessionStart(w, r)
	uid := us.Get("UserID")

	if uid == nil {
		if r.Form == nil {
			r.ParseForm()
		}
		us.Set("Form", r.Form)
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
		return
	}
	userID = uid.(string)
	us.Delete("UserID")
	return
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {

		us, err := globalSessions.SessionStart(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		username := r.FormValue("username")
		userPassword := r.FormValue("password")

		ispUser := AuthUser(username, userPassword)

		ug := strings.Split(ispUser.Client.GroupAdditional, ":")

		if ispUser.Auth == true && strings.Contains(ug[1], UserGroup) {
			us.Set("LoggedInUserID", ispUser.Client.Username)
			us.Set("EMail", ispUser.Client.EMail)
			w.Header().Set("Location", "/auth")
			w.WriteHeader(http.StatusFound)
			return
		}
	}
	outputHTML(w, r, "static/login.html")
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	us, err := globalSessions.SessionStart(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if us.Get("LoggedInUserID") == nil {
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
		return
	}
	if r.Method == "POST" {

		form := us.Get("Form").(url.Values)
		u := new(url.URL)
		u.Path = "/authorize"
		u.RawQuery = form.Encode()
		w.Header().Set("Location", u.String())
		w.WriteHeader(http.StatusFound)
		us.Delete("Form")
		us.Set("UserID", us.Get("LoggedInUserID"))

		User.UserID = us.Get("UserID").(string)
		User.EMail = us.Get("EMail").(string)
		User.Name = us.Get("UserID").(string)
		User.Sub = us.Get("UserID").(string)

		return
	}
	outputHTML(w, r, "static/auth.html")
}

func userInfoHandler(w http.ResponseWriter, r *http.Request) {
	//us, err := globalSessions.SessionStart(w, r)
	//if err != nil {
	//	http.Error(w, err.Error(), http.StatusInternalServerError)
	//	log.Println("userInfoHandler: HTTP Error")
	//	return
	//}

	//var info []byte
	info, err := json.Marshal(User)

	if err != nil {
		log.Println("userInfoHandler: Error Create JSON")
		return
	}

	sendJSON(info, w)
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
