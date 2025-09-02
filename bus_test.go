package yat_test

import "yat.io"

var _ yat.Publisher = (*yat.Bus)(nil)
var _ yat.Subscriber = (*yat.Bus)(nil)
