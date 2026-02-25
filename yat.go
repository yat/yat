package yat

type Msg struct {
	Path  Path   `json:"path"`
	Data  []byte `json:"data,omitempty"`
	Inbox Path   `json:"inbox,omitzero"`
}

type Sel struct {
	Path Path
}
