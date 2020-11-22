# rctl_exporter

rctl_exporter is a Prometheus exporter for FreeBSD RCTL/RACCT metrics. It can collect metrics of all items, or specific ones targeted in the config.  

It support following items :
  - process
  - user
  - jail

loginclass metrics is on the TODO list.

- - - -

# Prerequesites

RACCT/RCTL should be enabled on the host. Enable with tunable "kern.racct.enable=1" in /boot/loader.conf, then reboot.

- - - -

# Build instructions

```
go get
go build
```

- - - -

# Usage

Resources to monitor are specified in the "rctl.filter" argument. There is 4 resources types (see man page of rctl).
Each resource can be specified using regexp :
```
  - 'process:^java.*'
  - 'user:yo$'
  - 'jail:mongo'
```
Different resource types can be monitored, separated by comma :
```
rctl_exporter --rctl.filter="process:^java.*,user:^yo$,jail:mongo"
```

Avoid monitoring all processes, as it would create lots of time series and impact prometheus

