package debugerrorce

import (
	"fmt"
	"testing"
)

func TestEnv(t *testing.T) {
	_, err := GetEnvValue("PATH")
	if err != nil {
		t.Error(CurrentFunctionName() + ":PATH should always be set.")
	}
}

func TestEnvGetInt(t *testing.T) {
	val := GetEnvValueOrDefaultInt("UID", -1)
	if val < 0 {
		t.Error(fmt.Sprintf("%s%d", CurrentFunctionName()+":UID is expected to be positive:", val))
	}
}

// EOF
