package logs

import "os"

var (
	DebugMode = os.Getenv("OME_DEBUG") == "1"
)

func Set(l Logger) {
	logger = l
}

var logger Logger

func getLogger() Logger {
	if logger == nil {
		return &defaultLogger{}
	}
	return logger
}

// Logger is a convenience for logging
type Logger interface {
	Named(string) Logger
	Info(msg string, NameValues ...NameValue)
	Debug(msg string, NameValues ...NameValue)
	Warning(msg string, NameValues ...NameValue)
	Error(msg string, NameValues ...NameValue)
	Panic(msg string, NameValues ...NameValue)
	Fatal(msg string, NameValues ...NameValue)
}

func Named(name string) Logger {
	return getLogger().Named(name)
}

func Info(msg string, NameValues ...NameValue) {
	getLogger().Info(msg, NameValues...)
}

// Debug used for showing more detailed activity
func Debug(msg string, NameValues ...NameValue) {
	getLogger().Debug(msg, NameValues...)
}

func Warning(msg string, NameValues ...NameValue) {
	getLogger().Warning(msg, NameValues...)
}

// Error displays more detailed error message
func Error(msg string, NameValues ...NameValue) {
	getLogger().Error(msg, NameValues...)
}

func Panic(msg string, NameValues ...NameValue) {
	getLogger().Panic(msg, NameValues...)
}

// Error displays more detailed error message
func Fatal(msg string, NameValues ...NameValue) {
	getLogger().Fatal(msg, NameValues...)
}
