# rctl_exporter

rctl_exporter is a Prometheus exporter for FreeBSD RCTL/RACCT metrics. It can collect metrics of all processes, or specific ones targeted in the config.

Jail, user and loginclass metrics are on the TODO list.

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

Resources to monitor are specified in the configuration file. There is 4 resources types (see man page of rctl).
Each resource can be specified using regexp :
```
rctl_collect:
  - 'process:^java.*'
  - 'user:yo$'
  - 'jail:mongo'
```

