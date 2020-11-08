// Copyright 2020, johan@nosd.in
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build freebsd

package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	ps "github.com/yo000/go-ps"
	"golang.org/x/sys/unix"
	"gopkg.in/alecthomas/kingpin.v2"
)

// TODO : Dans le fichier de config. processFilter contient des regexp pour identifier les process a collecter
// On surveille le process sshd de l'utilisateur yo
var processFilter = [1]string{"^sshd"}

// copied from sys/sysctl.h
const (
	CTL_KERN         = 1  // "high kernel": proc, limits
	KERN_PROC        = 14 // struct: process entries
	KERN_PROC_RLIMIT = 37 // process resource limits
)

// copied from sys/syscall.h
const (
	SYS_RCTL_GET_RACCT = 525
)

//type Resource struct {
//	restype   string
//	proc      Process
//	resrcList string
//}

var rctlUpDesc = prometheus.NewDesc(
	prometheus.BuildFQName("rctl", "", "up"),
	"Whether scraping rctl's metrics was successful.",
	[]string{"scope"},
	nil)

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

func (e *DovecotExporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- rctlUpDesc
}

func (e *DovecotExporter) Collect(ch chan<- prometheus.Metric) {
	for _, scope := range e.scopes {
		err := CollectFromSocket(e.socketPath, scope, ch)
		if err == nil {
			ch <- prometheus.MustNewConstMetric(
				rctlUpDesc,
				prometheus.GaugeValue,
				1.0,
				scope)
		} else {
			log.Printf("Failed to scrape socket: %s", err)
			ch <- prometheus.MustNewConstMetric(
				rctlUpDesc,
				prometheus.GaugeValue,
				0.0,
				scope)
		}
	}
}

func call_syscall(mib []int32) ([]byte, uint64, error) {
	miblen := uint64(len(mib))

	// get required buffer size
	length := uint64(0)
	_, _, err := syscall.RawSyscall6(
		syscall.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])),
		uintptr(miblen),
		0,
		uintptr(unsafe.Pointer(&length)),
		0,
		0)
	if err != 0 {
		b := make([]byte, 0)
		return b, length, err
	}
	if length == 0 {
		b := make([]byte, 0)
		return b, length, err
	}
	// get proc info itself
	buf := make([]byte, length)
	_, _, err = syscall.RawSyscall6(
		syscall.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])),
		uintptr(miblen),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&length)),
		0,
		0)
	if err != 0 {
		return buf, length, err
	}

	return buf, length, nil
}

// Appel du syscall sys_rctl_get_racct implémenté dans sys/kern/kern_rctl.c:1609
// Le corps de fonction est copié de https://go.googlesource.com/go/+/refs/tags/go1.15.3/src/syscall/zsyscall_freebsd_amd64.go
func rctlGetRacct(rule string) (string, error) {
	var result string

	_rule, err := unix.BytePtrFromString(rule)
	if err != nil {
		return result, err
	}

	// FIXME: 256bytes should be enough for anybody
	_out := make([]byte, 256)

	_, _, e1 := syscall.Syscall6(SYS_RCTL_GET_RACCT, uintptr(unsafe.Pointer(_rule)), uintptr(len(rule)+1), uintptr(unsafe.Pointer(&_out[0])), uintptr(len(_out)), 0, 0)
	if e1 != 0 {
		// 78 = "RACCT/RCTL present, but disabled; enable using kern.racct.enable=1 tunable"
		return string(_out), e1
	}

	result = string(_out)
	return result, nil
}

func getProcessResources(pid int) string {
	var cmdline string
	var byt []byte

	//	var len uint64

	// parse buf to command line by replacing \0 with space
	//	for i := uint64(0); i < len; i++ {
	//		if buf[i] != 0 {
	//			byt = append(byt, buf[i])
	//		} else {
	//			byt = append(byt, ' ')
	//		}
	//	}
	cmdline = string(byt)

	return cmdline
}

func main() {
	var (
		app           = kingpin.New("rctl_exporter", "Prometheus metrics exporter for rctl")
		listenAddress = app.Flag("web.listen-address", "Address to listen on for web interface and telemetry.").Default(":9166").String()
		metricsPath   = app.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
		socketPath    = app.Flag("dovecot.socket-path", "Path under which to expose metrics.").Default("/var/run/dovecot/stats").String()
		dovecotScopes = app.Flag("dovecot.scopes", "Stats scopes to query (comma separated)").Default("user").String()
	)
	kingpin.MustParse(app.Parse(os.Args[1:]))

	// Boucle principale : On collecte les porcessus ciblés
	processList, err := ps.Processes()
	if err != nil {
		log.Println("ps.Processes() Failed, are you using windows?")
		return
	}
	// map ages
	for x := range processList {
		var process ps.Process
		process = processList[x]

		for i := range processFilter {
			re, err := regexp.Compile(processFilter[i])
			if err != nil {
				log.Printf("processFilter %s do not compile\n", processFilter[i])
				log.Fatal(err)
			}
			if len(re.FindString(process.CommandLine())) > 0 {
				log.Printf("%d\t%d\t%s\n", process.PPid(), process.Pid(), process.CommandLine())
				rule := fmt.Sprintf("process:%d:", process.Pid())
				resrc, err := rctlGetRacct(rule)
				if err == nil {
					log.Printf("%s\n", resrc)
				}
			}

		}
		//log.Printf("%d\t%d\t%s\n", process.PPid(), process.Pid(), process.CommandLine())

		// do os.* stuff on the pid
	}

	// FIN Boucle principale

	exporter := NewDovecotExporter(*socketPath, strings.Split(*dovecotScopes, ","))
	prometheus.MustRegister(exporter)

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
