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
	"crypto/tls"
	"errors"
	"strings"
	"time"

	"github.com/sftpgo/sdk"

	"github.com/sftpgo/sftpgo-plugin-auth/logger"
)

var (
	errNotImplemented     = errors.New("not implemented")
	errInvalidCredentials = errors.New("invalid credentials")
	webClientPerms        = []string{sdk.WebClientPasswordChangeDisabled,
		sdk.WebClientPasswordResetDisabled}
)

func NewAuthenticator(dialURLs []string, baseDN, username, password string, startTLS int, skipTLSVerify bool,
	baseDir string, cacheTime int, searchQuery string, groupAttributes, caCertificates []string,
	primaryGroupPrefix, secondaryGroupPrefix, membershipGroupPrefix string, requiresGroup bool,
	sftpgoUserRequirements int,
) (*LDAPAuthenticator, error) {
	rootCAs, err := loadCACerts(caCertificates)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		RootCAs:            rootCAs,
		InsecureSkipVerify: skipTLSVerify,
	}
	auth := &LDAPAuthenticator{
		DialURLs:               dialURLs,
		BaseDN:                 baseDN,
		Username:               username,
		Password:               password,
		StartTLS:               startTLS,
		SearchQuery:            searchQuery,
		GroupAttributes:        groupAttributes,
		BaseDir:                baseDir,
		PrimaryGroupPrefix:     strings.ToLower(primaryGroupPrefix),
		SecondaryGroupPrefix:   strings.ToLower(secondaryGroupPrefix),
		MembershipGroupPrefix:  strings.ToLower(membershipGroupPrefix),
		RequireGroups:          requiresGroup,
		SFTPGoUserRequirements: sftpgoUserRequirements,
		tlsConfig:              tlsConfig,
	}
	if err := auth.validate(); err != nil {
		return nil, err
	}
	if cacheTime > 0 {
		logger.AppLogger.Info("enable user caching", "cache time (sec)", cacheTime)
		cache = &authCache{
			cacheTime: cacheTime,
			cache:     make(map[string]cachedUser),
		}
		startCleanupTicker(10 * time.Minute)
	}
	logger.AppLogger.Info("authenticator created", "dial URLs", auth.DialURLs, "base dn", auth.BaseDN,
		"search query", auth.SearchQuery)
	return auth, nil
}
