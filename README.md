# rctl_exporter

rctl_exporter is a Prometheus exporter for FreeBSD RCTL/RACCT metrics. It can collect metrics of all items, or specific ones targeted in the config.  

It support all items rctl supports :
  - process
  - user
  - jail
  - loginclass

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
  - 'jail:ioc-mongo'
```

Jail are identified by name as reported by "jls -N" in first column (JID). For example with iocage, they are prefixed with "ioc-".  
Different resource types can be monitored, separated by comma :
```
rctl_exporter --rctl.filter="process:^java.*,user:^yo$,jail:ioc-.*"
```

Avoid monitoring all processes, as it would create lots of time series and impact prometheus

