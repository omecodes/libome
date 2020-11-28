package ome

type EventHandler interface {
	Handle(event *RegistryEvent)
}

type EventHandlerFunc func(*RegistryEvent)

func (h EventHandlerFunc) Handle(event *RegistryEvent) {
	h(event)
}

type Selector func(info *ServiceInfo) bool

type Registry interface {
	RegisterService(info *ServiceInfo) error
	DeregisterService(id string, nodes ...string) error
	GetService(id string) (*ServiceInfo, error)
	GetNode(id string, nodeId string) (*Node, error)
	Certificate(id string) ([]byte, error)
	ConnectionInfo(id string, protocol Protocol) (*ConnectionInfo, error)
	RegisterEventHandler(h EventHandler) string
	DeregisterEventHandler(string)
	GetOfType(t ServiceType) ([]*ServiceInfo, error)
	FirstOfType(t ServiceType) (*ServiceInfo, error)
	Stop() error
}
