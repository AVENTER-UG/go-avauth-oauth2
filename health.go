package main

import (
	"net/http"

	"github.com/sirupsen/logrus"
)

func apiHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	client := &http.Client{}

	logrus.Debug("Health Check")

	// check auth server connection
	req, _ := http.NewRequest("GET", AuthServer+"/status.php", nil)
	res, err := client.Do(req)

	if err != nil {
		logrus.Error("Health to Auth Server: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if res.StatusCode != 200 {
		logrus.Error("Health to Auth Server: ", res.StatusCode)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	_, err = Cache.Ping().Result()

	if err != nil {
		logrus.Error("Health to Redis Server: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
