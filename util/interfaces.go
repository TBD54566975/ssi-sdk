package util

type Emptyable interface {
	IsEmpty() bool
}

type Validatable interface {
	IsValid() error
}
