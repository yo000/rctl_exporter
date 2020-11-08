# rctl_exporter

rctl_exporter is a Prometheus exporter for FreeBSD RCTL/RACCT metrics.\\ 
It can collect metrics of all processes, or specific ones targeted in the config.

Jail, user and loginclass metrics are on the TODO list.

- - - -

# Prerequesites

RACCT/RCTL should be enabled on the host.\\ 
Enable with tunable "kern.racct.enable=1"

- - - -

# Build instructions

```
go get
go build
```


