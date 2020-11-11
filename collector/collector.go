// Copyright 2020, johan@nosd.in
// Implementation of Prometheus Collector Interface for rctl_exporter
// https://godoc.org/github.com/prometheus/client_golang/prometheus#Collector

// +build freebsd

package collector

import (
	//	"fmt"
	//	"strings"

	"strings"

	// local import, see go.mod
	"github.com/prometheus/client_golang/prometheus"
)

type Collector struct {
	resrces []*Resource
	log     *logrus.Logger
	up      *prometheus.Desc
	// ... declare some more descriptors here ...
}

// instantiate a collector object
func New(resrc []*Resource, log *logrus.Logger) *Collector {
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

func collectFromResourceStruct(resrces []*Resource) {
	// 1. Describe metrics by
	//		- building names with prometheus.BuildFQName
	//		- Declare them with prometheus.NewDesc(fqname, help, variablelabels, constlabels)
	// 2. Send metrics value with MustNewConstMetric(desc, type, value, labels, labels,...)

	// Example of metric names :
	// rctl_usage_process_cputime{pid="713", cmdline="/usr/local/sbin/libvirtd --daemon --pid-file=/var/run/libvirtd.pid"}
	// rctl_usage_user_cputime{user="yo"}
	// rctl_usage_loginclass{class="daemon"}
	// rctl_usage_jail{jid="120", name="dovecot"}

	for _, resrcObj := range resrces {
		if resrcObj.resrctype == "process" {
			for _, resrc := range resrcObj.rawresources {
				s := strings.Split(resrc, "=")
				d := prometheus.NewDesc("rctl_usage_process_"+s[0], "man rctl", []string{"pid", "cmdline"}, nil)
				ch <- prometheus.MustNewConstMetric(d, prometheus.UntypedValue, s[1], []string{resrc.GetResourceID(), resrc.GetProcessCommandLine()})
			}
		} else if resrcObj.resrctype == "user" {
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
	ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 1, "collectFilterGoesHere")

	collectFromResourceStruct(resrces)

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
