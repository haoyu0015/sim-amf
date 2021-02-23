package logger

import (
	//"bytes"
	"fmt"
	"os"
	"runtime"

	axlog "gitlab.casa-systems.com/platform/go/axyom/log"
)

var MainLog AgfLog

func init() {
	MainLog = NewLog()
}

func SetLogLevel(level string) error {
	log := NewLog()
	// Validate input
	switch level {
	case "debug", "info", "warn", "error", "all": // no-op
	default:
		// not supported
		return fmt.Errorf("set global log level to %s not supported", level)
	}
	axlog.SetGlobalLevel(level)
	log.Info(fmt.Sprintf("global log level set to %s", level))

	setLocalLogLevel(level)
	return nil
}

type AgfLog interface {
	Error(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
	Info(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
	All(msg string, args ...interface{})
	WithUE(key string) AgfLog
}

type logType int

const (
	logTypeNone logType = iota
	logTypeError
	logTypeWarning
	logTypeInfo
	logTypeDebug
	logTypeAll
)

type agfLogger struct {
	axlogger *axlog.Logger
}

var localLogLevel logType

func setLocalLogLevel(logTypeStr string) {
	switch logTypeStr {
	case "none":
		localLogLevel = logTypeNone
	case "error":
		localLogLevel = logTypeError
	case "warn":
		localLogLevel = logTypeWarning
	case "info":
		localLogLevel = logTypeInfo
	case "debug":
		localLogLevel = logTypeDebug
	case "all":
		localLogLevel = logTypeAll
	default:
		localLogLevel = logTypeError
	}

	return
}

func getCaller(depth int) (fileName string, lineNum int, funcName string) {
	pc, fileName, lineNum, ok := runtime.Caller(depth + 1)
	if !ok {
		return
	}
	frames := runtime.CallersFrames([]uintptr{pc})
	frame, _ := frames.Next()
	funcName = frame.Function
	return
}

func CompareLocalLogLevel(logLevelStr string) bool {
	switch logLevelStr {
	case "none":
		if localLogLevel == logTypeNone {
			return true
		}
	case "error":
		if localLogLevel == logTypeError {
			return true
		}
	case "warn":
		if localLogLevel == logTypeWarning {
			return true
		}
	case "info":
		if localLogLevel == logTypeInfo {
			return true
		}
	case "debug":
		if localLogLevel == logTypeDebug {
			return true
		}
	case "all":
		if localLogLevel == logTypeAll {
			return true
		}
	}

	return false
}

func (l *agfLogger) Error(fmtString string, args ...interface{}) {
	if localLogLevel >= logTypeError {
		_, line, fn := getCaller(1)
		msg := fmt.Sprintf(fmt.Sprintf("%s:%d:%s", fn, line, fmtString), args...)
		l.axlogger.Error(msg)
	}
}

func (l *agfLogger) Warn(fmtString string, args ...interface{}) {
	if localLogLevel >= logTypeWarning {
		msg := fmt.Sprintf(fmtString, args...)
		l.axlogger.Warn(msg)
	}
}

func (l *agfLogger) Info(fmtString string, args ...interface{}) {
	if localLogLevel >= logTypeInfo {
		msg := fmt.Sprintf(fmtString, args...)
		l.axlogger.Info(msg)
	}
}

func (l *agfLogger) Debug(fmtString string, args ...interface{}) {
	if localLogLevel >= logTypeDebug {
		msg := fmt.Sprintf(fmtString, args...)
		l.axlogger.Debug(msg)
	}
}

func (l *agfLogger) All(fmtString string, args ...interface{}) {
	if localLogLevel >= logTypeAll {
		msg := fmt.Sprintf(fmtString, args...)
		l.axlogger.Debug(msg)
	}
}

func (l *agfLogger) WithUE(key string) AgfLog {
	l.axlogger = l.axlogger.WithUE(key)
	return l
}

var NewLog = func() AgfLog {
	log := &agfLogger{}
	log.axlogger = axlog.NewLogger(os.Stdout, true).WithSrc(5)
	return log
}

var NewUeLog = func(ueid string) AgfLog {
	log := NewLog()
	log = log.WithUE(ueid)
	return log
}
