package yat_test

import "github.com/yat/yat"

var _ yat.Publisher = (*yat.Bus)(nil)
var _ yat.Subscriber = (*yat.Bus)(nil)
