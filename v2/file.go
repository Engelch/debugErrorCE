package debugerrorce

import (
	"os"
	"strings"
)

// isPlainFile is a predicate returning true if the supplied argument is an existing, plain file (no directory, device-file,...)
func IsPlainFile(filename string) bool {
	if stat, err := os.Stat(filename); err == nil && strings.HasPrefix(stat.Mode().String(), "-") {
		// fmt.Printf("filename mode: %v\n", stat.Mode())
		return true
	}
	return false
}

// isExistingFile predicate that sometimes can make the code easier (if we do not are about the error value)
func IsExistingFile(filename string) bool {
	if _, err := os.Stat(filename); err == nil {
		return true
	}
	return false
}
