package ome

type FileEventHandler interface {
	OnEvent(event *FileEvent)
}

type Watcher interface {
	Watch(EventHandler) error
	Stop() error
}
