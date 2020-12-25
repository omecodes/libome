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

func (ul *defaultLogger) Info(msg string, NameValues ...NameValue) {
	builder := strings.Builder{}
	for _, nv := range NameValues {
		builder.WriteString(fmt.Sprintf("{\"%s\": %v}", nv.Name(), nv.Value()))
	}
	log.Println("INFO\t", msg, builder.String())
}

func (ul *defaultLogger) Debug(msg string, NameValues ...NameValue) {
	if DebugMode {
		builder := strings.Builder{}
		for _, nv := range NameValues {
			builder.WriteString(fmt.Sprintf("{\"%s\": %v}", nv.Name(), nv.Value()))
		}
		log.Println("DEBUG\t", msg, builder.String())
	}
}

func (ul *defaultLogger) Warning(msg string, NameValues ...NameValue) {
	builder := strings.Builder{}
	for _, nv := range NameValues {
		builder.WriteString(fmt.Sprintf("{\"%s\": %v}", nv.Name(), nv.Value()))
	}
	log.Println("WARNING\t", msg, builder.String())
}

func (ul *defaultLogger) Error(msg string, NameValues ...NameValue) {
	builder := strings.Builder{}
	for _, nv := range NameValues {
		builder.WriteString(fmt.Sprintf("{\"%s\": %v}", nv.Name(), nv.Value()))
	}
	log.Println("ERROR\t", msg, builder.String())
}

func (ul *defaultLogger) Panic(msg string, NameValues ...NameValue) {
	builder := strings.Builder{}
	for _, nv := range NameValues {
		builder.WriteString(fmt.Sprintf("{\"%s\": %v}", nv.Name(), nv.Value()))
	}
	log.Panicln("PANIC\t", msg, builder.String())
}

func (ul *defaultLogger) Fatal(msg string, NameValues ...NameValue) {
	builder := strings.Builder{}
	for _, nv := range NameValues {
		builder.WriteString(fmt.Sprintf("{\"%s\": %v}", nv.Name(), nv.Value()))
	}
	log.Fatalln("FATAL\t", msg, builder.String())
}
