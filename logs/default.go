package logs

import (
	"fmt"
	"log"
	"strings"
)

type defaultLogger struct {
	name string
}

func (ul *defaultLogger) Named(name string) Logger {
	return &defaultLogger{}
}

func (ul *defaultLogger) Info(msg string, fields ...field) {
	builder := strings.Builder{}
	for _, f := range fields {
		builder.WriteString(fmt.Sprintf("{\"%s\": %v}", f.Key, f.Value))
	}
	log.Println("INFO\t", msg, builder.String())
}

func (ul *defaultLogger) Debug(msg string, fields ...field) {
	if DebugMode {
		builder := strings.Builder{}
		for _, f := range fields {
			builder.WriteString(fmt.Sprintf("{\"%s\": %v}", f.Key, f.Value))
		}
		log.Println("DEBUG\t", msg, builder.String())
	}
}

func (ul *defaultLogger) Warning(msg string, fields ...field) {
	builder := strings.Builder{}
	for _, f := range fields {
		builder.WriteString(fmt.Sprintf("{\"%s\": %v}", f.Key, f.Value))
	}
	log.Println("WARNING\t", msg, builder.String())
}

func (ul *defaultLogger) Error(msg string, fields ...field) {
	builder := strings.Builder{}
	for _, f := range fields {
		builder.WriteString(fmt.Sprintf("{\"%s\": %v}", f.Key, f.Value))
	}
	log.Println("ERROR\t", msg, builder.String())
}

func (ul *defaultLogger) Panic(msg string, fields ...field) {
	builder := strings.Builder{}
	for _, f := range fields {
		builder.WriteString(fmt.Sprintf("{\"%s\": %v}", f.Key, f.Value))
	}
	log.Panicln("PANIC\t", msg, builder.String())
}

func (ul *defaultLogger) Fatal(msg string, fields ...field) {
	builder := strings.Builder{}
	for _, f := range fields {
		builder.WriteString(fmt.Sprintf("{\"%s\": %v}", f.Key, f.Value))
	}
	log.Fatalln("FATAL\t", msg, builder.String())
}
