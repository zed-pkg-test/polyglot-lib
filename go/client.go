// Package polyglot is the Go slice of polyglot-lib, published as
// zedtest/polyglot-lib-golang.
package polyglot

import "fmt"

const Language = "golang"

func Greet(who string) string {
	return fmt.Sprintf("hello %s from polyglot-lib/go", who)
}
