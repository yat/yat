// Setup generates dev creds.
package main

import "yat.io/yat/devyat"

func main() {
	if err := devyat.GenerateCreds("tmp/dev", "::1"); err != nil {
		panic(err)
	}
}
