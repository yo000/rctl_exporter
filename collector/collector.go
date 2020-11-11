// Copyright 2020, johan@nosd.in
// Implementation of Prometheus Collector Interface for rctl_exporter
// https://godoc.org/github.com/prometheus/client_golang/prometheus#Collector

// +build freebsd

package collector

import (
	//	"fmt"
	//	"strings"

	"strconv"
	"strings"

	"git.nosd.in/yo/rctl_exporter/rctl"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
	"github.com/sirupsen/logrus"
)

type Collector struct {
	resrces []rctl.Resource
	log     *logrus.Logger
	up      *prometheus.Desc
	// ... declare some more descriptors here ...
}

// instantiate a collector object
func New(resrc []rctl.Resource, log *logrus.Logger) *Collector {
	return &Collector{

		//up: prometheus.NewDesc("rctl_up", "Whether scraping rctl's metrics was successful", []string{"collectFilter"}, nil),
		up:      prometheus.NewDesc("rctl_up", "Whether scraping rctl's metrics was successful", []string{"pid", "cmdline"}, nil),
		log:     log,
		resrces: resrc,

		// ... initialize rest of the descriptors ...
		// ... do other initialization ...
	}
}

// Describe - called to get descriptors of the metrics provided by the collector.
// A descriptor contains metadata about the metric, but not the actual value.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.up
	// ... describe other metrics ...
}

func (c *Collector) collectFromResourceStruct(ch chan<- prometheus.Metric) {
	// 1. Describe metrics by
	//		- building names with prometheus.BuildFQName
	//		- Declare them with prometheus.NewDesc(fqname, help, variablelabels, constlabels)
	// 2. Send metrics value with MustNewConstMetric(desc, type, value, labels, labels,...)

	// Example of metric names :
	// rctl_usage_process_cputime{pid="713", cmdline="/usr/local/sbin/libvirtd --daemon --pid-file=/var/run/libvirtd.pid"}
	// rctl_usage_user_cputime{user="yo"}
	// rctl_usage_loginclass{class="daemon"}
	// rctl_usage_jail{jid="120", name="dovecot"}

	//log.Info("Inside CollectFromResourceStruct, got " + strconv.Itoa(len(c.resrces)) + " elements in c.resrces")

	for _, resrcObj := range c.resrces {
		if resrcObj.GetResourceType() == rctl.RESRC_PROCESS {
			log.Info("Collecting resources for PID " + resrcObj.GetID())
			rawresrces := resrcObj.GetRawResources()
			log.Info("Longueur de la chaine provenant de GetRawResources() " + strconv.Itoa(len(rawresrces)))
			rawresrc := strings.Split(rawresrces, ",")
			for _, resrc := range rawresrc {
				// Last resource is not correctly terminated (len ~ 860char); it cause float conversion to crash so ensure we
				// got a string with only the printable chars
				var i int
				for i, _ = range resrc {
					if resrc[i] == 0 {
						break
					}
				}
				tmpstr := resrc[0:i]

				s := strings.SplitN(tmpstr, "=", 2)
				d := prometheus.NewDesc("rctl_usage_process_"+s[0], "man rctl", []string{"pid", "cmdline"}, nil)
				if len(s[1]) > 0 && s[1] != "0" {
					//v, err := strconv.ParseFloat(s[1], 64)
					v, err := strconv.ParseInt(s[1], 10, 64)
					if err != nil {
						log.Error("Error parsing " + s[1] + ", value of " + s[0] + " into int : " + err.Error())
						return
					}
					ch <- prometheus.MustNewConstMetric(d, prometheus.UntypedValue, float64(v), resrcObj.GetID(), resrcObj.GetProcessCommandLine())
				} else {
					ch <- prometheus.MustNewConstMetric(d, prometheus.UntypedValue, 0, resrcObj.GetID(), resrcObj.GetProcessCommandLine())
				}

			}
		} else if resrcObj.GetResourceType() == rctl.RESRC_USER {
		}
	}
}

// Collect - called to get the metric values
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	//if stats, err := c.client.GetServiceBusStats(); err != nil {
	//	// client call failed, set the up metric value to 0
	//	ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 0)
	//
	//	} else {
	//		// client call succeeded, set the up metric value to 1
	ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 1, "pidnull", "cmdlinenull")

	c.collectFromResourceStruct(ch)

	// ... collect other metrics ...
	//	}

	//	for _, scope := range e.scopes {
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
}
