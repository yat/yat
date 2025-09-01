package yat

type Subscription interface {
	Stopped() <-chan struct{}
	Stop()
}
