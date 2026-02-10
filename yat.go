package yat

type Msg struct {
	Path  Path
	Data  []byte
	Inbox Path
}

type Sel struct {
	Path Path
}
