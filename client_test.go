package yat_test

import "yat.io"

var _ yat.Publisher = (*yat.Client)(nil)
var _ yat.Subscriber = (*yat.Client)(nil)
