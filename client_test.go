package yat_test

import "github.com/yat/yat"

var _ yat.Publisher = (*yat.Client)(nil)
var _ yat.Subscriber = (*yat.Client)(nil)
