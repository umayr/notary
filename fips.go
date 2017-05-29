package notary

import "os"

const FIPSEnvVar = "GOFIPS"

func FIPSEnabled() bool {
	if env := os.Getenv(FIPSEnvVar); env != "" {
		return true
	}
	return false
}
