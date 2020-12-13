// Copyright 2020, johan@nosd.in
// +build freebsd

// Inspired from dovecot_exporter and https://blog.skyrise.tech/custom-prometheus-exporter

package main

import (
	"net/http"
	// For profiling, to fix these memory leaks. This is the only required instruction
	//  required to enable profiling on the already included web server !
	_ "net/http/pprof"
	"os"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"github.com/yo000/rctl_exporter/collector"
	"github.com/yo000/rctl_exporter/rctl"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	log = logrus.New()
)

//var rctlCollect = []string{"process:.*", "user:^yo$", "jail:ioc-testarp", "loginclass:.*"}

func main() {
	var results []rctl.Resource
	var (
		app            = kingpin.New("rctl_exporter", "Prometheus metrics exporter for rctl")
		listenAddress  = app.Flag("web.listen-address", "Address to listen on for web interface and telemetry.").Default(":9767").String()
		metricsPath    = app.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
		rctlCollectArg = app.Flag("rctl.filter", "Filter for rctl collection. Ex: \"process:.*java.*,user:git\"").Default("user:.*").String()
		//debug         = app.Flag("debug", "Enable debug mode").Bool()
	)
	kingpin.MustParse(app.Parse(os.Args[1:]))

	// Do not work. Why?
	/*if *debug == true {
		log.SetLevel(logrus.DebugLevel)
	}*/

	rctlCollect := strings.Split(*rctlCollectArg, ",")

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
