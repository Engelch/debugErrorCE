package debugErrorCE

// small helper class for logging + writing to stderr

import (
	"fmt"
	"log"
	"log/syslog"
	"os"
	"time"
)

var logInitialised = false
var loggerInfo *syslog.Writer
var loggerWarn *syslog.Writer
var loggerError *syslog.Writer
var stringLog = false

// verifyLogInitialised panics if log is not initialised.
func verifyLogInitialised() {
	if !logInitialised {
		panic("Log was not initialsed")
	}
}

// LogInit tries to initialise the logging service.
func LogInit(tag string) {
	logInitialised = true
	stringLog = false
	var err error
	loggerInfo, err = syslog.New(syslog.LOG_INFO, "tag")
	if err != nil {
		panic("Cannot initialise loggerInfo")
	}
	loggerWarn, err = syslog.New(syslog.LOG_WARNING, "tag")
	if err != nil {
		panic("Cannot initialise loggerWarn")
	}
	loggerError, err = syslog.New(syslog.LOG_ERR, "tag")
	if err != nil {
		panic("Cannot initialise loggerError")
	}
}

// LogStringInit does not use syslog (for dockerised environments. Instead, it writes all messages to stderr)
// This is suited for dockerised environments.
func LogStringInit() {
	logInitialised = true
	stringLog = true
}

// doLog handles the actual writing of the logging message
func doLog(msg string, syslogWriter *syslog.Writer) {
	if stringLog {
		_, _ = fmt.Fprintln(os.Stderr, msg)
	} else {
		log.SetOutput(syslogWriter)
		log.Println(msg)
	}
}

// LogErr creates a message preprended with ERROR to syslog and stderr, but tries to continue execution.
func LogErr(msg string) {
	verifyLogInitialised()
	doLog("ERROR:"+time.Now().UTC().Format(time.RFC3339)+":"+msg, loggerError)
}

// LogWarn creates a syslog and STDERR message labeled with WARNING.
func LogWarn(msg string) {
	verifyLogInitialised()
	doLog("Warning:"+time.Now().UTC().Format(time.RFC3339)+":"+msg, loggerWarn)
}

// LogInfo creates an info error message to syslog and STDERR.
func LogInfo(msg string) {
	verifyLogInitialised()
	doLog("info:"+time.Now().UTC().Format(time.RFC3339)+":"+msg, loggerInfo)
}

// EOF
