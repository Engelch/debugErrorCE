package debugerrorce

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestExecutableReachableByPath1(t *testing.T) {
	// we expect that bash, sed, grep, wc are available
	err := ExecutableReachableByPath("bash", "sed", "grep", "wc")
	assert.Nil(t, err)
}

func TestExecutableReachableByPath2(t *testing.T) {
	// we expect that the binary jfdaslkjd09jlk does not exist
	err := ExecutableReachableByPath("jfdaslkjd09jlk")
	assert.NotNil(t, err)
}

// EOF
