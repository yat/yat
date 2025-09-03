// Package flagset provides a minimal interface to the standard [flag] package.
// It only supports a few flag types and expects someone else to handle usage and help.
package flagset

import (
	"encoding"
	"flag"
	"io"
	"strings"
)

type Set struct {
	Help bool
	set  *flag.FlagSet
}

type TextValue interface {
	encoding.TextMarshaler
	encoding.TextUnmarshaler
}

func New() *Set {
	flags := &Set{
		set: &flag.FlagSet{
			Usage: func() {},
		},
	}

	flags.set.SetOutput(io.Discard)
	flags.Bool(&flags.Help, "help", "h", "?")
	return flags
}

func (fs *Set) NArg() int {
	return fs.set.NArg()
}

func (fs *Set) Arg(i int) string {
	return fs.set.Arg(i)
}

func (fs *Set) Split() (command string, args []string) {
	if fs.set.NArg() == 0 {
		return "", nil
	}

	args = fs.set.Args()
	command = args[0]
	args = args[1:]
	return
}

func (fs *Set) Bool(p *bool, names ...string) {
	for _, name := range names {
		fs.set.BoolVar(p, name, *p, "")
	}
}

func (fs *Set) Int(p *int, names ...string) {
	for _, name := range names {
		fs.set.IntVar(p, name, *p, "")
	}
}

func (fs *Set) String(p *string, names ...string) {
	for _, name := range names {
		fs.set.StringVar(p, name, *p, "")
	}
}

func (fs *Set) Strings(p *[]string, names ...string) {
	for _, name := range names {
		fs.set.Var((*stringsValue)(p), name, "")
	}
}

func (fs *Set) Text(p TextValue, names ...string) {
	for _, name := range names {
		fs.set.TextVar(p, name, p, "")
	}
}

func (fs *Set) Value(p flag.Value, names ...string) {
	for _, name := range names {
		fs.set.Var(p, name, "")
	}
}

func (fs *Set) Parse(args []string) ([]string, error) {
	if err := fs.set.Parse(args); err != nil {
		return nil, err
	}

	return fs.set.Args(), nil
}

func (fs *Set) Clone() *Set {
	new := New()
	new.Merge(fs)
	return new
}

// Merge adds other flags to this flag set if they aren't defined already.
func (fs *Set) Merge(other *Set) {
	other.set.VisitAll(func(f *flag.Flag) {
		if fs.set.Lookup(f.Name) == nil {
			fs.set.Var(f.Value, f.Name, f.Usage)
		}
	})

	other.set.Visit(func(f *flag.Flag) {
		fs.set.Set(f.Name, f.Value.String())
	})
}

type stringsValue []string

func (ss *stringsValue) String() string {
	return strings.Join(*ss, ",")
}

func (ss *stringsValue) Set(value string) error {
	*ss = append(*ss, value)
	return nil
}
