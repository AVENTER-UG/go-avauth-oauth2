package main

import (
	"net/http"
	"os"

	"git.aventer.biz/AVENTER/util"
	"github.com/go-redis/redis"
	"github.com/go-session/session"
	"github.com/sirupsen/logrus"
	oredis "gopkg.in/go-oauth2/redis.v3"
	"gopkg.in/oauth2.v3/manage"
	"gopkg.in/oauth2.v3/models"
	"gopkg.in/oauth2.v3/server"
	"gopkg.in/oauth2.v3/store"

	cfg "./types"
)

var (
	globalSessions *session.Manager
	JwtSignKey     string
	AuthServer     string
	ClientDomain   string
	ClientID       string
	ClientSecret   string
	User           cfg.UserInfo
	LogLevel       string
	AppName        string
	EnableSyslog   bool
	UserGroup      string
	Identifier     string
	RedisServer    string
	RedisDB        string
	Srv            *server.Server
)

func main() {
	AuthServer = os.Getenv("AUTH_SERVER")
	ClientDomain = os.Getenv("CLIENTDOMAIN")
	ClientID = os.Getenv("CLIENTID")
	ClientSecret = os.Getenv("CLIENTSECRET")
	LogLevel = os.Getenv("LOGLEVEL")
	UserGroup = os.Getenv("GROUP")
	RedisServer = os.Getenv("REDIS_SERVER")
	JwtSignKey = os.Getenv("JWT_SIGNKEY")

	util.SetLogging(LogLevel, EnableSyslog, AppName)

	logrus.Info("ISPCONFIGServer=", AuthServer)
	logrus.Info("ClientDomain=", ClientDomain)
	logrus.Info("ClientSecret=", ClientSecret)
	logrus.Info("ClientID=", ClientID)

	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)

	// token store
	manager.MapTokenStorage(oredis.NewRedisStore(&redis.Options{
		Addr: RedisServer,
	}))

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

	Srv = server.NewServer(server.NewConfig(), manager)

	Srv.SetPasswordAuthorizationHandler(srvPasswordAuthorizationHandler)
	Srv.SetUserAuthorizationHandler(userAuthorizeHandler)
	Srv.SetInternalErrorHandler(srvInternalErrorHandler)
	Srv.SetResponseErrorHandler(srvResponseErrorHandler)

	http.HandleFunc("/oauth/login", loginHandler)
	http.HandleFunc("/oauth/auth", authHandler)
	http.HandleFunc("/oauth/userinfo", userInfoHandler)
	http.HandleFunc("/oauth/authorize", authorizeHandler)
	http.HandleFunc("/oauth/token", tokenHandler)

	logrus.Println("Server is running at 9096 port.")
	logrus.Fatal(http.ListenAndServe(":9096", nil))
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