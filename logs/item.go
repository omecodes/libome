package logs

type NameValue interface {
	Name() string
	Value() interface{}
}

func Details(key string, value interface{}) NameValue {
	return &item{
		key:   key,
		value: value,
	}
}

func Err(err error) NameValue {
	return &item{
		key:   "error",
		value: err,
	}
}

type item struct {
	key   string
	value interface{}
}

func (i *item) Name() string {
	return i.key
}

func (i *item) Value() interface{} {
	return i.value
}
