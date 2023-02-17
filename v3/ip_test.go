package debugerrorce

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIPv4_00(t *testing.T) {
	assert.Nil(t, ValidIPv4Address("0.0.0.0"), "valid IP address not detected as such 00")
}

func TestIPv4_01(t *testing.T) {
	assert.Nil(t, ValidIPv4Address("192.168.255.255"), "valid IP address not detected as such 00")
}

func TestIPv4_02(t *testing.T) {
	assert.Nil(t, ValidIPv4Address("255.255.255.255"), "valid IP address not detected as such 00")
}

func TestIPv4_03(t *testing.T) {
	assert.Nil(t, ValidIPv4Address("1.1.1.255"), "valid IP address not detected as such 00")
}
