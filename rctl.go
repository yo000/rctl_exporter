// Copyright 2020, johan@nosd.in
// +build freebsd

package main

import (
	"errors"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Supported rctl subjects
var SUPPORTED_SUBJECTS = []string{"process", "user", "loginclass"}

// copied from sys/syscall.h
const (
	SYS_RCTL_GET_RACCT = 525
)

type Resource struct {
	resrctype       int    // Resource type : process, jail, loginclass or user
	resrcid         string // Resource identifier : PID, jail name, loginclass from login.conf, or user name
	cputime         int    // CPU time, in seconds
	datasize        int    // data size, in bytes
	stacksize       int    // stack size, in bytes
	coredumpsize    int    // core dump size, in bytes
	memoryuse       int    // resident set size, in bytes
	memorylocked    int    // locked memory, in bytes
	maxproc         int    // number of processes
	openfiles       int    // file descriptor table size
	vmemoryuse      int    // address space limit, in bytes
	pseudoterminals int    // number of PTYs
	swapuse         int    // swap space that may be reserved or used, in bytes
	nthr            int    // number of threads
	msgqqueued      int    // number of queued SysV messages
	msgqsize        int    // SysV message queue size, in bytes
	nmsgq           int    // number of SysV message queues
	nsem            int    // number of SysV semaphores
	nsemop          int    // number of SysV semaphores modified in a single semop(2) call
	nshm            int    // number of SysV shared memory segments
	shmsize         int    // SysV shared memory size, in bytes
	wallclock       int    // wallclock time, in seconds
	pcpu            int    // %CPU, in percents of a single CPU core
	readbps         int    // filesystem reads, in bytes per second
	writebps        int    // filesystem writes, in bytes per second
	readiops        int    // filesystem reads, in operations per seconds
	writeiops       int    // filesystem writes, in operations per seconds
}

func (r *Resource) CpuTime() int {
	return r.cputime
}

func (r *Resource) DataSize() int {
	return r.datasize
}

func (r *Resource) StackSize() int {
	return r.stacksize
}

func (r *Resource) CoreDumpSize() int {
	return r.coredumpsize
}

func (r *Resource) MemoryUse() int {
	return r.memoryuse
}

func (r *Resource) MemoryLocked() int {
	return r.memorylocked
}

func (r *Resource) MaxProc() int {
	return r.maxproc
}

func (r *Resource) OpenFiles() int {
	return r.openfiles
}

func (r *Resource) VMemoryUse() int {
	return r.vmemoryuse
}

func (r *Resource) PseudoTerminals() int {
	return r.pseudoterminals
}

func (r *Resource) SwapUse() int {
	return r.swapuse
}

func (r *Resource) NrThread() int {
	return r.nthr
}

func (r *Resource) MsqQueued() int {
	return r.msgqqueued
}

func (r *Resource) MsgQueueSize() int {
	return r.msgqsize
}

func (r *Resource) NrMsgQueues() int {
	return r.nmsgq
}

func (r *Resource) NrSemaphores() int {
	return r.nsem
}

func (r *Resource) NrSemaphoresSemop() int {
	return r.nsemop
}

func (r *Resource) NrShm() int {
	return r.nshm
}

func (r *Resource) ShmSize() int {
	return r.shmsize
}

func (r *Resource) WallClock() int {
	return r.wallclock
}

func (r *Resource) PCpu() int {
	return r.pcpu
}

func (r *Resource) ReadBps() int {
	return r.readbps
}

func (r *Resource) WriteBps() int {
	return r.writebps
}

func (r *Resource) ReadIops() int {
	return r.readiops
}

func (r *Resource) WriteIops() int {
	return r.writeiops
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

// Check rule subjetc is valid and supported
func checkSubject(rule string) error {
	s := strings.Split(rule, ":")

	for _, v := range SUPPORTED_SUBJECTS {
		if v == s[0] {
			return nil
		}
	}

	return errors.New("subject not supported")
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
	_out := make([]byte, 1024)

	_, _, e1 := syscall.Syscall6(SYS_RCTL_GET_RACCT, uintptr(unsafe.Pointer(_rule)), uintptr(len(rule)+1), uintptr(unsafe.Pointer(&_out[0])), uintptr(len(_out)), 0, 0)
	if e1 != 0 {
		// 78 = "RACCT/RCTL present, but disabled; enable using kern.racct.enable=1 tunable"
		return string(_out), e1
	}

	result = string(_out)
	return result, nil
}

func parse_resource(resrc string) Resource {
	var result Resource
	for _, r := range strings.Split(resrc, ",") {
		s := strings.Split(r, "=")
		if len(s) != 2 {
			return result
		}
		if s[0] == "cputime" {
			result.cputime, _ = strconv.Atoi(s[1])
		}
		if s[0] == "datasize" {
			result.datasize, _ = strconv.Atoi(s[1])
		}
		if s[0] == "stacksize" {
			result.stacksize, _ = strconv.Atoi(s[1])
		}
		if s[0] == "coredumpsize" {
			result.coredumpsize, _ = strconv.Atoi(s[1])
		}
		if s[0] == "memoryuse" {
			result.memoryuse, _ = strconv.Atoi(s[1])
		}
		if s[0] == "memorylocked" {
			result.memorylocked, _ = strconv.Atoi(s[1])
		}
		if s[0] == "maxproc" {
			result.maxproc, _ = strconv.Atoi(s[1])
		}
		if s[0] == "openfiles" {
			result.openfiles, _ = strconv.Atoi(s[1])
		}
		if s[0] == "vmemoryuse" {
			result.vmemoryuse, _ = strconv.Atoi(s[1])
		}
		if s[0] == "pseudoterminals" {
			result.pseudoterminals, _ = strconv.Atoi(s[1])
		}
		if s[0] == "swapuse" {
			result.swapuse, _ = strconv.Atoi(s[1])
		}
		if s[0] == "nthr" {
			result.nthr, _ = strconv.Atoi(s[1])
		}
		if s[0] == "msgqqueued" {
			result.msgqqueued, _ = strconv.Atoi(s[1])
		}
		if s[0] == "msgqsize" {
			result.msgqsize, _ = strconv.Atoi(s[1])
		}
		if s[0] == "nmsgq" {
			result.nmsgq, _ = strconv.Atoi(s[1])
		}
		if s[0] == "nsem" {
			result.nsem, _ = strconv.Atoi(s[1])
		}
		if s[0] == "nsemop" {
			result.nsemop, _ = strconv.Atoi(s[1])
		}
		if s[0] == "nshm" {
			result.nshm, _ = strconv.Atoi(s[1])
		}
		if s[0] == "shmsize" {
			result.shmsize, _ = strconv.Atoi(s[1])
		}
		if s[0] == "wallclock" {
			result.wallclock, _ = strconv.Atoi(s[1])
		}
		if s[0] == "pcpu" {
			result.pcpu, _ = strconv.Atoi(s[1])
		}
		if s[0] == "readbps" {
			result.readbps, _ = strconv.Atoi(s[1])
		}
		if s[0] == "writebps" {
			result.writebps, _ = strconv.Atoi(s[1])
		}
		if s[0] == "readiops" {
			result.readiops, _ = strconv.Atoi(s[1])
		}
		if s[0] == "writeiops" {
			result.writeiops, _ = strconv.Atoi(s[1])
		}
	}

	return result
}

// Returns resources usage as a raw string
func getRawResourceUsage(rule string) (string, error) {
	err := checkSubject(rule)
	if err != nil {
		return "", err
	}

	buf, err := rctlGetRacct(rule)

	return buf, err
}

// Returns resources usage as a structure which can be used to pick resources
func getResourceUsage(rule string) (Resource, error) {
	var result Resource

	err := checkSubject(rule)
	if err != nil {
		return result, err
	}

	buf, err := rctlGetRacct(rule)
	if err != nil {
		return result, err
	}

	result = parse_resource(buf)

	return result, nil
}
