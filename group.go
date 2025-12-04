package yat

type Group struct {
	name string
}

func NewGroup(name string) Group {
	return Group{name}
}

func (g Group) String() string {
	return g.name
}

func (g Group) IsZero() bool {
	return g == Group{}
}
