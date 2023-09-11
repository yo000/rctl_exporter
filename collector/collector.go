// Copyright 2020, johan@nosd.in
// Implementation of Prometheus Collector Interface for rctl_exporter
// https://godoc.org/github.com/prometheus/client_golang/prometheus#Collector

// +build freebsd

package collector

import (
	"os"
	"fmt"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/yo000/rctl_exporter/rctl"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	gVersion = "0.6.0"
)

type Collector struct {
	resmgr rctl.ResourceMgr
	log    *logrus.Logger
	up     *prometheus.Desc
	// ... declare some more descriptors here ...
}

// instantiate a collector object
func New(resmgr rctl.ResourceMgr, log *logrus.Logger) *Collector {
	pid := strconv.Itoa(os.Getpid())
	return &Collector{
		up:     prometheus.NewDesc("rctl_up", "Whether scraping rctl's metrics was successful", nil,
				prometheus.Labels{"version": gVersion,"pid": pid}),
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

	for _, resrcObj := range c.resmgr.Resources {
		if resrcObj.ResourceType == rctl.RESRC_PROCESS {
			rawresrces := resrcObj.RawResources
			rawresrc := strings.Split(rawresrces, ",")
			for _, resrc := range rawresrc {
				s := strings.SplitN(resrc, "=", 2)
				if len(s) == 2 {
					d := prometheus.NewDesc("rctl_usage_process_"+s[0], "man rctl", []string{"pid", "name", "cmdline"}, nil)
					if len(s[1]) > 0 && s[1] != "0" {
						v, err := strconv.ParseFloat(s[1], 64)
						//v, err := strconv.ParseInt(s[1], 10, 64)
						if err != nil {
							c.log.Error("Error parsing " + s[1] + ", value of " + s[0] + " into int : " + err.Error())
							return err
						}
						ch <- prometheus.MustNewConstMetric(d, prometheus.UntypedValue, v, resrcObj.ResourceID, resrcObj.ProcessName, resrcObj.ProcessCmdLine)
					} else {
						ch <- prometheus.MustNewConstMetric(d, prometheus.UntypedValue, 0, resrcObj.ResourceID, resrcObj.ProcessName, resrcObj.ProcessCmdLine)
					}
				} else {
					c.log.Error("resource format is incorrect : " + resrc)
					return fmt.Errorf("Resource incorrect format : %s", resrc)
				}

			}
		} else if resrcObj.ResourceType == rctl.RESRC_USER {
			rawresrces := resrcObj.RawResources
			rawresrc := strings.Split(rawresrces, ",")
			for _, resrc := range rawresrc {
				s := strings.SplitN(resrc, "=", 2)
				if len(s) == 2 {
					d := prometheus.NewDesc("rctl_usage_user_"+s[0], "man rctl", []string{"uid", "username"}, nil)
					if len(s[1]) > 0 && s[1] != "0" {
						v, err := strconv.ParseFloat(s[1], 64)
						//v, err := strconv.ParseInt(s[1], 10, 64)
						if err != nil {
							c.log.Error("Error parsing " + s[1] + ", value of " + s[0] + " into int : " + err.Error())
							return err
						}
						ch <- prometheus.MustNewConstMetric(d, prometheus.UntypedValue, v, resrcObj.ResourceID, resrcObj.UserName)
					} else {
						ch <- prometheus.MustNewConstMetric(d, prometheus.UntypedValue, 0, resrcObj.ResourceID, resrcObj.UserName)
					}
				} else {
					c.log.Error("resource format is incorrect : " + resrc)
					return fmt.Errorf("Resource incorrect format : %s", resrc)
				}
			}
		} else if resrcObj.ResourceType == rctl.RESRC_JAIL {
			rawresrces := resrcObj.RawResources
			rawresrc := strings.Split(rawresrces, ",")
			for _, resrc := range rawresrc {
				s := strings.SplitN(resrc, "=", 2)
				if len(s) == 2 {
					d := prometheus.NewDesc("rctl_usage_jail_"+s[0], "man rctl", []string{"jid", "name"}, nil)
					if len(s[1]) > 0 && s[1] != "0" {
						v, err := strconv.ParseFloat(s[1], 64)
						//v, err := strconv.ParseInt(s[1], 10, 64)
						if err != nil {
							c.log.Error("Error parsing " + s[1] + ", value of " + s[0] + " into int : " + err.Error())
							return err
						}
						ch <- prometheus.MustNewConstMetric(d, prometheus.UntypedValue, v, resrcObj.ResourceID, resrcObj.JailName)
					} else {
						ch <- prometheus.MustNewConstMetric(d, prometheus.UntypedValue, 0, resrcObj.ResourceID, resrcObj.JailName)
					}
				} else {
					c.log.Error("resource format is incorrect : " + resrc)
					return fmt.Errorf("Resource incorrect format : %s", resrc)
				}
			}
		} else if resrcObj.ResourceType == rctl.RESRC_LOGINCLASS {
			rawresrces := resrcObj.RawResources
			rawresrc := strings.Split(rawresrces, ",")
			for _, resrc := range rawresrc {
				s := strings.SplitN(resrc, "=", 2)
				if len(s) == 2 {
					d := prometheus.NewDesc("rctl_usage_loginclass_"+s[0], "man rctl", []string{"name"}, nil)
					if len(s[1]) > 0 && s[1] != "0" {
						v, err := strconv.ParseFloat(s[1], 64)
						//v, err := strconv.ParseInt(s[1], 10, 64)
						if err != nil {
							c.log.Error("Error parsing " + s[1] + ", value of " + s[0] + " into int : " + err.Error())
							return err
						}
						ch <- prometheus.MustNewConstMetric(d, prometheus.UntypedValue, v, resrcObj.LoginClassName)
					} else {
						ch <- prometheus.MustNewConstMetric(d, prometheus.UntypedValue, 0, resrcObj.LoginClassName)
					}
				} else {
					c.log.Error("resource format is incorrect : " + resrc)
					return fmt.Errorf("Resource incorrect format : %s", resrc)
				}
			}
		}
	}

	return nil
}

// Collect - called to get the metric values
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	err := c.collectFromResourceStruct(ch)
	if err != nil {
		ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 0)
	} else {
		ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 1)
	}
}
