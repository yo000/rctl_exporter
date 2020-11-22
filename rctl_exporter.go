// Copyright 2020, johan@nosd.in
// +build freebsd

// Inspired from dovecot_exporter and https://blog.skyrise.tech/custom-prometheus-exporter

package main

import (
	"net/http"
	"os"

	"git.nosd.in/yo/rctl_exporter/collector"
	"git.nosd.in/yo/rctl_exporter/rctl"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	log = logrus.New()
)

// TODO : Dans le fichier de config. processFilter contient des regexp pour identifier les process a collecter
// On surveille le process sshd de l'utilisateur yo
//var processFilter = [1]string{"process:^sshd"}
//var rctlCollect = []string{"process:.*"}

var rctlCollect = []string{"process:.*", "user:^yo$", "jail:ioc-testarp"}

//var rctlCollect = []string{"loginclass:daemon"}
//var rctlCollect = []string{"jail:ioc-testarp"}

func main() {
	var results []rctl.Resource
	var (
		app           = kingpin.New("rctl_exporter", "Prometheus metrics exporter for rctl")
		listenAddress = app.Flag("web.listen-address", "Address to listen on for web interface and telemetry.").Default(":9166").String()
		metricsPath   = app.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
		//debug         = app.Flag("debug", "Enable debug mode").Bool()
	)
	kingpin.MustParse(app.Parse(os.Args[1:]))

	// Do not work. Why?
	/*if *debug == true {
		log.SetLevel(logrus.DebugLevel)
	}*/

	rmgr, err := rctl.NewResourceManager(rctlCollect, log)
	if err != nil {
		log.Error("Error getting resources : %d", err)
	}
	for _, r := range rmgr.Resources {
		results = append(results, r)
	}

	coll := collector.New(rmgr, log)
	prometheus.MustRegister(coll)

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`
			<html>
			<head><title>rctl Exporter</title></head>
			<body>
			<h1>rctl Exporter</h1>
			<p><a href='` + *metricsPath + `'>Metrics</a></p>
			</body>
			</html>`))
	})
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}
