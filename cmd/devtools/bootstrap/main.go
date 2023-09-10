package main

import (
	"fmt"

	"github.com/koalatea/authserver/server/certificates"
)

func main() {
	_, err := certificates.NewCertProvider()
	if err != nil {
		fmt.Errorf("%w", err)
	}
}
