// Copyright 2020, johan@nosd.in
// Implementation of Prometheus Collector Interface for rctl_exporter
// https://godoc.org/github.com/prometheus/client_golang/prometheus#Collector

// +build freebsd

package collector

import (
	//	"fmt"
	//	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

type Collector struct {
	up *prometheus.Desc
	// ... declare some more descriptors here ...
}

// instantiate a collector object
func New() *Collector {
	return &Collector{

		up: prometheus.NewDesc("rctl_up", "Whether scraping rctl's metrics was successful", []string{"collectFilter"}, nil),

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

// Collect - called to get the metric values
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	//if stats, err := c.client.GetServiceBusStats(); err != nil {
	//	// client call failed, set the up metric value to 0
	//	ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 0)
	//
	//	} else {
	//		// client call succeeded, set the up metric value to 1
	ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 1, "collectFilterGoesHere")

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
