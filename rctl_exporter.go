// Copyright 2020, johan@nosd.in
// +build freebsd

// Inspired from dovecot_exporter and https://blog.skyrise.tech/custom-prometheus-exporter

package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"git.nosd.in/yo/rctl_exporter/collector"
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
var rctlCollect = [1]string{"process:.*"}

//var rctlCollect = []string{"user:^yo$"}
//var rctlCollect = []string{"loginclass:daemon"}

// collector.go
//var rctlUpDesc = prometheus.NewDesc(
//	prometheus.BuildFQName("rctl", "", "up"),
//	"Whether scraping rctl's metrics was successful.",
//	[]string{"scope"},
//	nil)

// CollectFromReader converts the output of Dovecot's EXPORT command to metrics.
func CollectFromReader(file io.Reader, scope string, ch chan<- prometheus.Metric) error {
	if scope == "global" {
		return collectGlobalMetricsFromReader(file, scope, ch)
	}
	return collectDetailMetricsFromReader(file, scope, ch)
}

// CollectFromExec collects rctl statistics from the execution of rctl binary
func CollectFromExec(path string, scope string, ch chan<- prometheus.Metric) error {
	var conn io.Reader
	cmd := exec.Command(path)
	conn, cmd.Stdout = io.Pipe()
	err := cmd.Run()
	if err != nil {
		return err
	}

	return CollectFromReader(conn, scope, ch)
}

// CollectFromFile collects rctl statistics from the given file
func CollectFromFile(path string, scope string, ch chan<- prometheus.Metric) error {
	conn, err := os.Open(path)
	if err != nil {
		return err
	}
	return CollectFromReader(conn, scope, ch)
}

// CollectFromSocket collects statistics from dovecot's stats socket.
func CollectFromSocket(path string, scope string, ch chan<- prometheus.Metric) error {
	conn, err := net.Dial("unix", path)
	if err != nil {
		return err
	}
	_, err = conn.Write([]byte("EXPORT\t" + scope + "\n"))
	if err != nil {
		return err
	}
	return CollectFromReader(conn, scope, ch)
}

// collectGlobalMetricsFromReader collects dovecot "global" scope metrics from
// the supplied reader.
func collectGlobalMetricsFromReader(reader io.Reader, scope string, ch chan<- prometheus.Metric) error {
	scanner := bufio.NewScanner(reader)
	scanner.Split(bufio.ScanLines)

	// Read first line of input, containing the aggregation and column names.
	if !scanner.Scan() {
		return fmt.Errorf("Failed to extract columns from input")
	}
	columnNames := strings.Fields(scanner.Text())
	if len(columnNames) < 1 {
		return fmt.Errorf("Input does not provide any columns")
	}

	columns := []*prometheus.Desc{}
	for _, columnName := range columnNames {
		columns = append(columns, prometheus.NewDesc(
			prometheus.BuildFQName("dovecot", scope, columnName),
			"Help text not provided by this exporter.",
			[]string{},
			nil))
	}

	// Global metrics only have a single row containing values following the
	// line with column names
	if !scanner.Scan() {
		return scanner.Err()
	}
	values := strings.Fields(scanner.Text())

	if len(values) != len(columns) {
		return fmt.Errorf("error while parsing row: value count does not match column count")
	}

	for i, value := range values {
		f, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return err
		}
		ch <- prometheus.MustNewConstMetric(
			columns[i],
			prometheus.UntypedValue,
			f,
		)
	}
	return scanner.Err()
}

// collectGlobalMetricsFromReader collects dovecot "non-global" scope metrics
// from the supplied reader.
func collectDetailMetricsFromReader(reader io.Reader, scope string, ch chan<- prometheus.Metric) error {
	scanner := bufio.NewScanner(reader)
	scanner.Split(bufio.ScanLines)

	// Read first line of input, containing the aggregation and column names.
	if !scanner.Scan() {
		return fmt.Errorf("Failed to extract columns from input")
	}
	columnNames := strings.Split(scanner.Text(), "\t")
	if len(columnNames) < 2 {
		return fmt.Errorf("Input does not provide any columns")
	}

	columns := []*prometheus.Desc{}
	for _, columnName := range columnNames[1:] {
		columns = append(columns, prometheus.NewDesc(
			prometheus.BuildFQName("dovecot", columnNames[0], columnName),
			"Help text not provided by this exporter.",
			[]string{columnNames[0]},
			nil))
	}

	// Read successive lines, containing the values.
	for scanner.Scan() {
		row := scanner.Text()
		if strings.TrimSpace(row) == "" {
			break
		}

		values := strings.Split(row, "\t")
		if len(values) != len(columns)+1 {
			return fmt.Errorf("error while parsing rows: value count does not match column count")
		}
		if values[0] == "" {
			values[0] = "empty_user"
		}

		for i, value := range values[1:] {
			f, err := strconv.ParseFloat(value, 64)
			if err != nil {
				return err
			}
			ch <- prometheus.MustNewConstMetric(
				columns[i],
				prometheus.UntypedValue,
				f,
				values[0])
		}
	}
	return scanner.Err()
}

type DovecotExporter struct {
	scopes     []string
	socketPath string
}

func NewDovecotExporter(socketPath string, scopes []string) *DovecotExporter {
	return &DovecotExporter{
		scopes:     scopes,
		socketPath: socketPath,
	}
}

// collector.go
//func (e *DovecotExporter) Describe(ch chan<- *prometheus.Desc) {
//	ch <- rctlUpDesc
//}

// collector.go
//func (e *DovecotExporter) Collect(ch chan<- prometheus.Metric) {
//		err := CollectFromSocket(e.socketPath, scope, ch)
//		if err == nil {
//			ch <- prometheus.MustNewConstMetric(
//				rctlUpDesc,
//				prometheus.GaugeValue,
//				1.0,
//				scope)
//		} else {
//			log.Printf("Failed to scrape socket: %s", err)
//			ch <- prometheus.MustNewConstMetric(
//				rctlUpDesc,
//				prometheus.GaugeValue,
//				0.0,
//				scope)
//		}
//	}
//}

func main() {
	var (
		app           = kingpin.New("rctl_exporter", "Prometheus metrics exporter for rctl")
		listenAddress = app.Flag("web.listen-address", "Address to listen on for web interface and telemetry.").Default(":9166").String()
		metricsPath   = app.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
		//		socketPath    = app.Flag("dovecot.socket-path", "Path under which to expose metrics.").Default("/var/run/dovecot/stats").String()
		//		dovecotScopes = app.Flag("dovecot.scopes", "Stats scopes to query (comma separated)").Default("user").String()
	)
	kingpin.MustParse(app.Parse(os.Args[1:]))

	var results []Resource

	// Boucle principale : On collecte les métriques ciblées
	for i := range rctlCollect {
		//		s := strings.SplitN(rctlCollect[i], ":", 2)
		//		subject, filter := s[0], s[1]
		//
		//		if subject == "process" {
		//			getProcessesResources(subject, filter)
		//			// getProcessesResources prints values itself
		//		} else if subject == "user" {
		//			resrc, err := getUsersResources(subject, filter)
		//			if err == nil {
		//				log.Printf("%s\n", resrc)
		//			}
		//		} else if subject == "loginclass" {
		//			resrc, err := getLoginClassResources(subject, filter)
		//			if err == nil {
		//				log.Printf("%s\n", resrc)
		//			}
		//		}
		results = append(results, NewResourceManager(rctlCollect[i], log))
	}
	// FIN Boucle principale
	coll := collector.New(results)
	prometheus.MustRegister(coll)
	//exporter := NewDovecotExporter(*socketPath, strings.Split(*dovecotScopes, ","))
	//prometheus.MustRegister(exporter)

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
