// Copyright (C) 2023 Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package authenticator

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sftpgo/sftpgo-plugin-auth/logger"
)

func contains[T comparable](elems []T, v T) bool {
	for _, s := range elems {
		if v == s {
			return true
		}
	}
	return false
}

func removeDuplicates(obj []string) []string {
	if len(obj) == 0 {
		return obj
	}
	seen := make(map[string]bool)
	validIdx := 0
	for _, item := range obj {
		if !seen[item] {
			seen[item] = true
			obj[validIdx] = item
			validIdx++
		}
	}
	return obj[:validIdx]
}

func loadCACerts(caCertificates []string) (*x509.CertPool, error) {
	if len(caCertificates) == 0 {
		return nil, nil
	}
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		rootCAs = x509.NewCertPool()
	}
	for _, ca := range caCertificates {
		ca = filepath.Clean(ca)
		if !filepath.IsAbs(ca) {
			return nil, fmt.Errorf("CA certificate %q is not an absolute path", ca)
		}
		certs, err := os.ReadFile(ca)
		if err != nil {
			return nil, fmt.Errorf("unable to load CA certificate: %w", err)
		}
		if rootCAs.AppendCertsFromPEM(certs) {
			logger.AppLogger.Debug("CA certificate added to the trusted certificates", "path", ca)
		} else {
			return nil, fmt.Errorf("unable to add CA certificate %q to the trusted cetificates", ca)
		}
	}
	return rootCAs, nil
}

func getCNFromDN(dn string) string {
	if dn == "" {
		return ""
	}
	parts := strings.Split(dn, ",")
	if len(parts) > 0 {
		cn := strings.ToLower(parts[0])
		if strings.HasPrefix(cn, "cn=") || strings.HasPrefix(cn, "ou=") {
			return strings.TrimSpace(cn[3:])
		}
		return cn
	}
	return ""
}
