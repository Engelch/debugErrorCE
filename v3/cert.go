package debugerrorce

import (
	"errors"
	"strings"
)

func GetCertAttributesCnOu(headers map[string][]string) (string, string, error) {
	for _, header := range []string{"Ssl-Client-Subject-Dn", "X-Client-Dn"} { // 1st field with k8s, 2nd was used by nginx in a container with docker
		if (headers[header]) != nil {
			if len(headers[header]) != 1 {
				return "", "", errors.New("ERROR: multiple header entries found in request for the field:" + header)
			}
			cn, ou := parseHeaderFields(headers[header][0])
			return cn, ou, nil
		}
	}
	return "", "", nil // no header lines found
}

func parseHeaderFields(val string) (string, string) {
	var cn, ou string
	strarr := strings.Split(val, ",") // split the map value field by , which should separate the fields as in OU=a,CN=test1
	for _, val2 := range strarr {
		if strings.HasPrefix(val2, "CN=") {
			cn = strings.TrimPrefix(val2, "CN=")
		}
		if strings.HasPrefix(val2, "OU=") {
			ou = strings.TrimPrefix(val2, "OU=")
		}
	}
	return strings.ToLower(cn), strings.ToLower(ou) // simply return the string, "" by default, and hopefully changed from above code
}
