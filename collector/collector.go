// Copyright 2020, johan@nosd.in
// Implementation of Prometheus Collector Interface for rctl_exporter
// https://godoc.org/github.com/prometheus/client_golang/prometheus#Collector

// +build freebsd

package collector

import (
	"fmt"
	"strconv"
	"strings"

	"git.nosd.in/yo/rctl_exporter/rctl"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
	"github.com/sirupsen/logrus"
)

type Collector struct {
	resmgr rctl.ResourceMgr
	log    *logrus.Logger
	up     *prometheus.Desc
	// ... declare some more descriptors here ...
}

// instantiate a collector object
func New(resmgr rctl.ResourceMgr, log *logrus.Logger) *Collector {
	return &Collector{

		//up: prometheus.NewDesc("rctl_up", "Whether scraping rctl's metrics was successful", []string{"collectFilter"}, nil),
		up:     prometheus.NewDesc("rctl_up", "Whether scraping rctl's metrics was successful", []string{"pid", "cmdline"}, nil),
		log:    log,
		resmgr: resmgr,

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

func (c *Collector) collectFromResourceStruct(ch chan<- prometheus.Metric) error {
	// 1. Describe metrics by
	//		- building names with prometheus.BuildFQName
	//		- Declare them with prometheus.NewDesc(fqname, help, variablelabels, constlabels)
	// 2. Send metrics value with MustNewConstMetric(desc, type, value, labels, labels,...)

	// Example of metric names :
	// rctl_usage_process_cputime{pid="713", cmdline="/usr/local/sbin/libvirtd --daemon --pid-file=/var/run/libvirtd.pid"}
	// rctl_usage_user_cputime{user="yo"}
	// rctl_usage_loginclass{class="daemon"}
	// rctl_usage_jail{jid="120", name="dovecot"}

	c.resmgr.Refresh()

	for _, resrcObj := range c.resmgr.GetResources() {
		if resrcObj.GetResourceType() == rctl.RESRC_PROCESS {
			rawresrces := resrcObj.GetRawResources()
			rawresrc := strings.Split(rawresrces, ",")
			for _, resrc := range rawresrc {
				s := strings.SplitN(resrc, "=", 2)
				if len(s) == 2 {
					d := prometheus.NewDesc("rctl_usage_process_"+s[0], "man rctl", []string{"pid", "cmdline"}, nil)
					if len(s[1]) > 0 && s[1] != "0" {
						v, err := strconv.ParseFloat(s[1], 64)
						//v, err := strconv.ParseInt(s[1], 10, 64)
						if err != nil {
							log.Error("Error parsing " + s[1] + ", value of " + s[0] + " into int : " + err.Error())
							return err
						}
						ch <- prometheus.MustNewConstMetric(d, prometheus.UntypedValue, v, resrcObj.GetID(), resrcObj.GetProcessCommandLine())
					} else {
						ch <- prometheus.MustNewConstMetric(d, prometheus.UntypedValue, 0, resrcObj.GetID(), resrcObj.GetProcessCommandLine())
					}
				} else {
					log.Error("resource format is incorrect : " + resrc)
					return fmt.Errorf("Resource incorrect format : %s", resrc)
				}

			}
		} else if resrcObj.GetResourceType() == rctl.RESRC_USER {
		}
	}

	return nil
}

// Collect - called to get the metric values
func (c *Collector) Collect(ch chan<- prometheus.Metric) {

	err := c.collectFromResourceStruct(ch)
	if err != nil {
		ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 0, "pidnull", "cmdlinenull")
	} else {
		ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 1, "pidnull", "cmdlinenull")
	}
}
