// Copyright 2020, johan@nosd.in
// +build freebsd
//
// Use libjail.so to get/set jail params
package rctl

/*
#cgo CFLAGS: -I /usr/lib
#cgo LDFLAGS: -L. -ljail
#include <stdlib.h>
#include <jail.h>
*/
import "C"
import (
	"errors"
	"fmt"
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/prometheus/common/log"
	"github.com/sirupsen/logrus"
	ps "github.com/yo000/go-ps"
	"golang.org/x/sys/unix"
)

var (
	GLog *logrus.Logger

	// Supported rctl subjects
	SUPPORTED_SUBJECTS = []string{"process", "user", "loginclass", "jail"}
)

const (
	RESRC_PROCESS    = 1
	RESRC_USER       = 2
	RESRC_LOGINCLASS = 3
	RESRC_JAIL       = 4

	// copied from sys/syscall.h
	SYS_RCTL_GET_RACCT = 525
)

// Resource : Represent a resource and its usage as reported by rctl(8)
type Resource struct {
	ResourceType    int    // Resource type : process, jail, loginclass or user
	ResourceID      string // Resource identifier : PID, UID, jail name or loginclass from login.conf
	ProcessPPid     int    // For process type, this is the PPID
	ProcessCmdLine  string // For process type, this is the full command line with path and args
	ProcessName     string // For process type, this is the binary name
	UserName        string // For user type, this is the username
	JailName        string // For jail type, this is the jail name as seen by "jls -N" (JID column)
	LoginClassName  string // For loginclass type, this is the loginclass name as in login.conf
	RawResources    string // Raw string resources, as returned by rctl binary
	CPUTime         int    // CPU time, in seconds
	DataSize        int    // data size, in bytes
	StackSize       int    // stack size, in bytes
	CoreDumpSize    int    // core dump size, in bytes
	MemoryUse       int    // resident set size, in bytes
	MemoryLocked    int    // locked memory, in bytes
	MaxProc         int    // number of processes
	OpenFiles       int    // file descriptor table size
	VMemoryUse      int    // address space limit, in bytes
	PseudoTerminals int    // number of PTYs
	SwapUse         int    // swap space that may be reserved or used, in bytes
	NThr            int    // number of threads
	MsgQQueued      int    // number of queued SysV messages
	MsgQSize        int    // SysV message queue size, in bytes
	NMsgQ           int    // number of SysV message queues
	NSem            int    // number of SysV semaphores
	NSemop          int    // number of SysV semaphores modified in a single semop(2) call
	NShm            int    // number of SysV shared memory segments
	ShmSize         int    // SysV shared memory size, in bytes
	WallClock       int    // wallclock time, in seconds
	PCpu            int    // %CPU, in percents of a single CPU core
	ReadBps         int    // filesystem reads, in bytes per second
	WriteBps        int    // filesystem writes, in bytes per second
	ReadIops        int    // filesystem reads, in operations per seconds
	WriteIops       int    // filesystem writes, in operations per seconds
}

// ResourceMgr : Contains resources filters and an array of resources
type ResourceMgr struct {
	resrcesfilter []string
	log           *logrus.Logger
	Resources     []Resource
}

type user struct {
	name string
	uid  int
}

type jail struct {
	name string
	jid  int
}

// Refresh : Refreshes resources usage
func (r *ResourceMgr) Refresh() (*ResourceMgr, error) {
	var results []Resource
	var err error

	// Temporaire
	//var resrc string

	for _, resrcFilter := range r.resrcesfilter {
		// split 2 first words, so resrcFilter value can contains ':'
		s := strings.SplitN(resrcFilter, ":", 2)
		subject, filter := s[0], s[1]

		if subject == "process" {
			res, err := getProcessResources(subject, filter)
			if err != nil {
				return r, err
			}
			results = append(results, res...)
		} else if subject == "user" {
			res, err := getUserResources(subject, filter)
			if err != nil {
				return r, err
			}
			results = append(results, res...)
		} else if subject == "loginclass" {
			res, err := getLoginClassResources(subject, filter)
			if err != nil {
				return r, err
			}
			results = append(results, res...)
		} else if subject == "jail" {
			res, err := getJailResources(subject, filter)
			if err != nil {
				return r, err
			}
			results = append(results, res...)
		}
	}

	r.Resources = results

	return r, err
}

// Check rule subject is valid and supported
func checkSubject(rule string) (string, error) {
	s := strings.Split(rule, ":")

	for _, v := range SUPPORTED_SUBJECTS {
		if v == s[0] {
			return s[0], nil
		}
	}

	return "", errors.New("subject not supported")
}

// Appel du syscall sys_rctl_get_racct implémenté dans sys/kern/kern_rctl.c:1609
// Le corps de fonction est copié de https://go.googlesource.com/go/+/refs/tags/go1.15.3/src/syscall/zsyscall_freebsd_amd64.go
func rctlGetRacct(rule string) (string, error) {
	var result string

	_rule, err := unix.BytePtrFromString(rule)
	if err != nil {
		return result, err
	}

	// FIXME: 1024bytes should be enough for anybody
	_out := make([]byte, 1024)

	_, _, e1 := syscall.Syscall6(SYS_RCTL_GET_RACCT, uintptr(unsafe.Pointer(_rule)),
		uintptr(len(rule)+1), uintptr(unsafe.Pointer(&_out[0])),
		uintptr(len(_out)), 0, 0)
	if e1 != 0 {
		GLog.Error("syscall rctl_get_racct returned an error : ", e1)
		// 78 = "RACCT/RCTL present, but disabled; enable using kern.racct.enable=1 tunable"
		return string(_out), e1
	}

	var i int
	for i, _ = range _out {
		if _out[i] == 0 {
			break
		}
	}

	return string(_out[0:i]), nil
}

// Parses rctl_get_racct return to fill Resource structure
func parseResource(subject string, resrc string) Resource {
	var result Resource

	if subject == "process" {
		result.ResourceType = RESRC_PROCESS
	}
	if subject == "user" {
		result.ResourceType = RESRC_USER
	}
	if subject == "loginclass" {
		result.ResourceType = RESRC_LOGINCLASS
	}
	if subject == "jail" {
		result.ResourceType = RESRC_JAIL
	}

	// Save raw result...
	result.RawResources = resrc

	// ...then parse into fields
	for _, r := range strings.Split(resrc, ",") {
		s := strings.Split(r, "=")
		if len(s) != 2 {
			return result
		}
		if s[0] == "cputime" {
			result.CPUTime, _ = strconv.Atoi(s[1])
		}
		if s[0] == "datasize" {
			result.DataSize, _ = strconv.Atoi(s[1])
		}
		if s[0] == "stacksize" {
			result.StackSize, _ = strconv.Atoi(s[1])
		}
		if s[0] == "coredumpsize" {
			result.CoreDumpSize, _ = strconv.Atoi(s[1])
		}
		if s[0] == "memoryuse" {
			result.MemoryUse, _ = strconv.Atoi(s[1])
		}
		if s[0] == "memorylocked" {
			result.MemoryLocked, _ = strconv.Atoi(s[1])
		}
		if s[0] == "maxproc" {
			result.MaxProc, _ = strconv.Atoi(s[1])
		}
		if s[0] == "openfiles" {
			result.OpenFiles, _ = strconv.Atoi(s[1])
		}
		if s[0] == "vmemoryuse" {
			result.VMemoryUse, _ = strconv.Atoi(s[1])
		}
		if s[0] == "pseudoterminals" {
			result.PseudoTerminals, _ = strconv.Atoi(s[1])
		}
		if s[0] == "swapuse" {
			result.SwapUse, _ = strconv.Atoi(s[1])
		}
		if s[0] == "nthr" {
			result.NThr, _ = strconv.Atoi(s[1])
		}
		if s[0] == "msgqqueued" {
			result.MsgQQueued, _ = strconv.Atoi(s[1])
		}
		if s[0] == "msgqsize" {
			result.MsgQSize, _ = strconv.Atoi(s[1])
		}
		if s[0] == "nmsgq" {
			result.NMsgQ, _ = strconv.Atoi(s[1])
		}
		if s[0] == "nsem" {
			result.NSem, _ = strconv.Atoi(s[1])
		}
		if s[0] == "nsemop" {
			result.NSemop, _ = strconv.Atoi(s[1])
		}
		if s[0] == "nshm" {
			result.NShm, _ = strconv.Atoi(s[1])
		}
		if s[0] == "shmsize" {
			result.ShmSize, _ = strconv.Atoi(s[1])
		}
		if s[0] == "wallclock" {
			result.WallClock, _ = strconv.Atoi(s[1])
		}
		if s[0] == "pcpu" {
			result.PCpu, _ = strconv.Atoi(s[1])
		}
		if s[0] == "readbps" {
			result.ReadBps, _ = strconv.Atoi(s[1])
		}
		if s[0] == "writebps" {
			result.WriteBps, _ = strconv.Atoi(s[1])
		}
		if s[0] == "readiops" {
			result.ReadIops, _ = strconv.Atoi(s[1])
		}
		if s[0] == "writeiops" {
			result.WriteIops, _ = strconv.Atoi(s[1])
		}
	}

	return result
}

// Returns resources usage as a raw string
func getRawResourceUsage(rule string) (string, error) {
	_, err := checkSubject(rule)
	if err != nil {
		return "", err
	}

	buf, err := rctlGetRacct(rule)

	return buf, err
}

// Returns resources usage as a structure which can be used to pick resources
func getResourceUsage(rule string) (Resource, error) {
	var result Resource

	subject, err := checkSubject(rule)
	if err != nil {
		return result, err
	}

	buf, err := rctlGetRacct(rule)
	if err != nil {
		return result, err
	}

	result = parseResource(subject, buf)

	//log.Info("Returned resources as raw : " + result.GetRawResources())

	return result, nil
}

// Get Resources for a process, then glue process informations to Resource structure
func getProcessResources(subject string, filter string) ([]Resource, error) {
	var results []Resource
	var err error

	re, err := regexp.Compile(filter)
	if err != nil {
		GLog.Fatal("rctlCollect %s do not compile", filter)
	}

	processList, err := ps.Processes()
	if err != nil {
		GLog.Fatal("ps.Processes() Failed, are you using windows?")
		return results, err
	}

	// Allocate an array of 0, to max len(processList)
	results = make([]Resource, 0, len(processList))

	for _, process := range processList {
		if len(re.FindString(process.CommandLine())) > 0 {
			rule := fmt.Sprintf("%s:%d:", subject, process.Pid())
			r, err := getResourceUsage(rule)
			if err != nil {
				log.Error("Error while getting resource usage for rule : " + rule)
				return results, err
			}
			r.ResourceID = strconv.Itoa(process.Pid())
			r.ProcessPPid = process.PPid()
			r.ProcessName = process.Executable()
			r.ProcessCmdLine = process.CommandLine()
			results = append(results, r)
			log.Debug("Added process " + r.ProcessCmdLine + " with resources : " + r.RawResources)
		}
	}
	return results, err
}

// get current users from /etc/passwd
func getUsersFromPasswd() ([]user, error) {
	var usr user
	var usrs []user

	data, err := ioutil.ReadFile("/etc/passwd")
	if err != nil {
		return usrs, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if len(line) > 0 && strings.HasPrefix(string(line), "#") == false {
			s := strings.Split(string(line), ":")
			if len(s) > 0 {
				if strings.Count(string(s[0]), "") > 0 {
					usr.name = s[0]
					usr.uid, _ = strconv.Atoi(s[2])
					log.Debug("Appending user " + usr.name + " with UID " + strconv.Itoa(usr.uid))
					usrs = append(usrs, usr)
				}
			}
		}
	}

	return usrs, err
}

func getUserResources(subject string, filter string) ([]Resource, error) {
	var resources []Resource

	usrs, err := getUsersFromPasswd()
	if err != nil {
		return resources, err
	}
	re, err := regexp.Compile(filter)
	if err != nil {
		log.Fatal("rctlCollect %s do not compile", filter)
	}

	for _, usr := range usrs {
		if len(re.FindString(usr.name)) > 0 {
			rule := fmt.Sprintf("%s:%d:", subject, usr.uid)
			log.Debug("Rule : " + rule)
			r, err := getResourceUsage(rule)
			if err != nil {
				log.Error("Error while getting resource usage for rule : " + rule)
				return resources, err
			}
			r.ResourceID = strconv.Itoa(usr.uid)
			r.UserName = usr.name
			resources = append(resources, r)
			log.Debug("Added user " + r.UserName + " with resources : " + r.RawResources)
		}
	}

	return resources, err
}

// We can not use jail_getv ou jail_setv because they are variadic C functions (would need a C wrapper)
func getJails() ([]jail, error) {
	var jls []jail
	var jl jail
	var err error

	params := make([]C.struct_jailparam, 3)

	// initialize parameter names
	csname := C.CString("name")
	defer C.free(unsafe.Pointer(csname))
	csjid := C.CString("jid")
	defer C.free(unsafe.Pointer(csjid))
	cslastjid := C.CString("lastjid")
	defer C.free(unsafe.Pointer(cslastjid))

	// initialize params struct with parameter names
	C.jailparam_init(&params[0], csname)
	C.jailparam_init(&params[1], csjid)

	// The key to retrive jail. lastjid = 0 returns first jail and its jid as jailparam_get return value
	C.jailparam_init(&params[2], cslastjid)

	lastjailid := 0
	cslastjidval := C.CString(strconv.Itoa(lastjailid))
	defer C.free(unsafe.Pointer(cslastjidval))

	C.jailparam_import(&params[2], cslastjidval)

	// loop on existing jails
	for lastjailid >= 0 {
		// get parameter values
		lastjailid = int(C.jailparam_get(&params[0], 3, 0))
		if lastjailid > 0 {
			nametmp := C.jailparam_export(&params[0])
			jl.name = C.GoString(nametmp)
			// Memory mgmt : Non gere par Go
			C.free(unsafe.Pointer(nametmp))
			jidtmp := C.jailparam_export(&params[1])
			jl.jid, _ = strconv.Atoi(C.GoString(jidtmp))
			// Memory mgmt : Non gere par Go
			C.free(unsafe.Pointer(jidtmp))
			jls = append(jls, jl)
			//log.Debug("Got jid " + strconv.Itoa(jl.jid) + " with name " + jl.name)

			// Prepare next loop iteration
			cslastjidval := C.CString(strconv.Itoa(lastjailid))
			defer C.free(unsafe.Pointer(cslastjidval))
			C.jailparam_import(&params[2], cslastjidval)
		}
	}

	C.jailparam_free(&params[0], 3)

	return jls, err
}

func getJailResources(subject string, filter string) ([]Resource, error) {
	var resources []Resource

	jls, err := getJails()
	if err != nil {
		return resources, err
	}
	re, err := regexp.Compile(filter)
	if err != nil {
		log.Fatal("rctlCollect %s do not compile", filter)
	}

	for _, jl := range jls {
		if len(re.FindString(jl.name)) > 0 {
			rule := fmt.Sprintf("%s:%s", subject, jl.name)
			log.Debug("Rule : " + rule)
			r, err := getResourceUsage(rule)
			if err != nil {
				log.Error("Error while getting resource usage for rule : " + rule)
				return resources, err
			}
			r.ResourceID = strconv.Itoa(jl.jid)
			r.JailName = jl.name
			resources = append(resources, r)
			log.Debug("Added jail " + r.JailName + " with resources : " + r.RawResources)
		}
	}

	return resources, err
}

// get currently enabled login classes from /etc/login.conf
func getLoginClasses() ([]string, error) {
	var lcs []string

	data, err := ioutil.ReadFile("/etc/login.conf")
	if err != nil {
		return lcs, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if len(line) > 0 && strings.HasPrefix(string(line), "#") == false && strings.HasPrefix(string(line), " ") == false {
			s := strings.Split(string(line), ":")
			if len(s) == 2 {
				lc := strings.Split(s[0], "|")[0]
				log.Debug("Appending loginclass " + lc)
				lcs = append(lcs, lc)
			}
		}
	}

	return lcs, err
}

// TODO : Return ([]Resource, error), list login classes and support regex
func getLoginClassResources(subject string, filter string) ([]Resource, error) {
	var resources []Resource

	lcs, err := getLoginClasses()
	if err != nil {
		return resources, err
	}
	re, err := regexp.Compile(filter)
	if err != nil {
		log.Fatal("rctlCollect %s do not compile", filter)
	}

	for _, lc := range lcs {
		if len(re.FindString(lc)) > 0 {
			rule := fmt.Sprintf("%s:%s", subject, lc)
			log.Debug("Rule : " + rule)
			r, err := getResourceUsage(rule)
			if err != nil {
				log.Error("Error while getting resource usage for rule : " + rule)
				return resources, err
			}
			//r.ResourceID = strconv.Itoa(jl.jid)
			r.LoginClassName = lc
			resources = append(resources, r)
			log.Debug("Added loginclass " + r.LoginClassName + " with resources : " + r.RawResources)
		}
	}

	return resources, err
}

// Bootstrap function to build Resource objects matching given filter
// Should be the first function called, init GLog
func NewResourceManager(resrcesFilter []string, log *logrus.Logger) (ResourceMgr, error) {
	var resmgr ResourceMgr

	// "log" var exists at global scope, but the value of the local variable inside a function takes preference
	// FIXME
	GLog = log
	resmgr.log = log
	resmgr.resrcesfilter = resrcesFilter

	resmgr.Refresh()

	return resmgr, nil
}
