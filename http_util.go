package yat

import (
	"fmt"
	"math"
	"strconv"
	"time"
)

// The types and functions in this file were copied from http_util.go
// in the grpc module's internal/transport package. They are unmodified,
// other than prefixing their names with "grpc".

/*
 *
 * Copyright 2014 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

type grpcTimeoutUnit uint8

const (
	grpcHour        grpcTimeoutUnit = 'H'
	grpcMinute      grpcTimeoutUnit = 'M'
	grpcSecond      grpcTimeoutUnit = 'S'
	grpcMillisecond grpcTimeoutUnit = 'm'
	grpcMicrosecond grpcTimeoutUnit = 'u'
	grpcNanosecond  grpcTimeoutUnit = 'n'
)

func grpcTimeoutUnitToDuration(u grpcTimeoutUnit) (d time.Duration, ok bool) {
	switch u {
	case grpcHour:
		return time.Hour, true
	case grpcMinute:
		return time.Minute, true
	case grpcSecond:
		return time.Second, true
	case grpcMillisecond:
		return time.Millisecond, true
	case grpcMicrosecond:
		return time.Microsecond, true
	case grpcNanosecond:
		return time.Nanosecond, true
	default:
	}
	return
}

func grpcDecodeTimeout(s string) (time.Duration, error) {
	size := len(s)
	if size < 2 {
		return 0, fmt.Errorf("transport: timeout string is too short: %q", s)
	}
	if size > 9 {
		// Spec allows for 8 digits plus the unit.
		return 0, fmt.Errorf("transport: timeout string is too long: %q", s)
	}
	unit := grpcTimeoutUnit(s[size-1])
	d, ok := grpcTimeoutUnitToDuration(unit)
	if !ok {
		return 0, fmt.Errorf("transport: timeout unit is not recognized: %q", s)
	}
	t, err := strconv.ParseUint(s[:size-1], 10, 64)
	if err != nil {
		return 0, err
	}
	const maxHours = math.MaxInt64 / uint64(time.Hour)
	if d == time.Hour && t > maxHours {
		// This timeout would overflow math.MaxInt64; clamp it.
		return time.Duration(math.MaxInt64), nil
	}
	return d * time.Duration(t), nil
}
