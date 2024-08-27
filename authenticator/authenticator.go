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

type Config struct {
	DialURLs               []string `json:"dial_urls"`
	BaseDN                 string   `json:"base_dn"`
	Username               string   `json:"username"`
	Password               string   `json:"password"`
	StartTLS               int      `json:"start_tls"`
	SkipTLSVerify          bool     `json:"skip_tls_verify"`
	CACertificates         []string `json:"ca_certificates"`
	SearchQuery            string   `json:"search_query"`
	GroupAttributes        []string `json:"group_attributes"`
	PrimaryGroupPrefix     string   `json:"primary_group_prefix"`
	SecondaryGroupPrefix   string   `json:"secondary_group_prefix"`
	MembershipGroupPrefix  string   `json:"membership_group_prefix"`
	RequireGroups          bool     `json:"require_groups"`
	SFTPGoUserRequirements int      `json:"sftpgo_user_requirements"`
	BaseDir                string   `json:"base_dir"`
	CacheTime              int      `json:"cache_time"`
}

func NewAuthenticator(config *Config) (*LDAPAuthenticator, error) {
	rootCAs, err := loadCACerts(config.CACertificates)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		RootCAs:            rootCAs,
		InsecureSkipVerify: config.SkipTLSVerify,
	}
	auth := &LDAPAuthenticator{
		DialURLs:               config.DialURLs,
		BaseDN:                 config.BaseDN,
		Username:               config.Username,
		Password:               config.Password,
		StartTLS:               config.StartTLS,
		SearchQuery:            config.SearchQuery,
		GroupAttributes:        config.GroupAttributes,
		BaseDir:                config.BaseDir,
		PrimaryGroupPrefix:     strings.ToLower(config.PrimaryGroupPrefix),
		SecondaryGroupPrefix:   strings.ToLower(config.SecondaryGroupPrefix),
		MembershipGroupPrefix:  strings.ToLower(config.MembershipGroupPrefix),
		RequireGroups:          config.RequireGroups,
		SFTPGoUserRequirements: config.SFTPGoUserRequirements,
		tlsConfig:              tlsConfig,
	}
	if err := auth.validate(); err != nil {
		return nil, err
	}
	if config.CacheTime > 0 {
		if auth.hasGroups() {
			logger.AppLogger.Warn("user caching cannot be enabled when groups are defined, continuing without caching")
		} else {
			logger.AppLogger.Info("enable users caching", "cache time (sec)", config.CacheTime)
			cache = &authCache{
				cacheTime: config.CacheTime,
				cache:     make(map[string]cachedUser),
			}
			startCleanupTicker(10 * time.Minute)
		}
	}
	logger.AppLogger.Info("authenticator created", "dial URLs", auth.DialURLs, "base dn", auth.BaseDN,
		"search query", auth.SearchQuery)
	return auth, nil
}
