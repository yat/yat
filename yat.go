package yat

type Publisher interface {
	Publish(Msg) error
}

type Subscriber interface {
	Subscribe(Sel, func(Msg)) (Subscription, error)
}

type Subscription interface {
	Stopped() <-chan struct{}
	Stop()
}
