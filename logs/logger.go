package logs

import "os"

var (
	DebugMode = os.Getenv("OME_DEBUG") == "1"
)

func Set(l Logger) {
	logger = l
}

func Field(key string, value interface{}) field {
	return field{
		Key:   key,
		Value: value,
	}
}

func Err(err error) field {
	return field{
		Key:   "error",
		Value: err,
	}
}

type field struct {
	Key   string
	Value interface{}
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
	Info(msg string, fields ...field)
	Debug(msg string, fields ...field)
	Warning(msg string, fields ...field)
	Error(msg string, fields ...field)
	Panic(msg string, fields ...field)
	Fatal(msg string, fields ...field)
}

func Named(name string) Logger {
	return getLogger().Named(name)
}

func Info(msg string, fields ...field) {
	getLogger().Info(msg, fields...)
}

// Debug used for showing more detailed activity
func Debug(msg string, fields ...field) {
	getLogger().Debug(msg, fields...)
}

func Warning(msg string, fields ...field) {
	getLogger().Warning(msg, fields...)
}

// Error displays more detailed error message
func Error(msg string, fields ...field) {
	getLogger().Error(msg, fields...)
}

func Panic(msg string, fields ...field) {
	getLogger().Panic(msg, fields...)
}

// Error displays more detailed error message
func Fatal(msg string, fields ...field) {
	getLogger().Fatal(msg, fields...)
}
