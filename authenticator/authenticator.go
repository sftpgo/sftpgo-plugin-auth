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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
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
	Username               string   `json:"bind_dn"`
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

type multiAuthConfig struct {
	LRUCacheSize int      `json:"cache_size"`
	Configs      []Config `json:"configs"`
}

func NewMultiAuthenticator(configFile string) (*MultiAuthenticator, error) {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("unable to read config file %q: %w", configFile, err)
	}
	var c multiAuthConfig
	err = json.Unmarshal(data, &c)
	if err != nil {
		return nil, fmt.Errorf("invalid config file %q: %w", configFile, err)
	}

	if len(c.Configs) == 0 {
		return nil, errors.New("no configurations defined")
	}
	if c.LRUCacheSize == 0 {
		c.LRUCacheSize = 100
	}

	mapping, err := lru.New[string, int](c.LRUCacheSize)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize users mapping: %w", err)
	}
	multiAuth := &MultiAuthenticator{
		usersMapping: mapping,
	}
	for idx, c := range c.Configs {
		auth, err := NewAuthenticator(&c)
		if err != nil {
			return nil, fmt.Errorf("unable to create authenticator at index %d: %w", idx, err)
		}
		multiAuth.Authenticators = append(multiAuth.Authenticators, auth)
	}

	logger.AppLogger.Debug("multi authenticator initialized", "LDAP servers", len(c.Configs), "cache size", c.LRUCacheSize)
	return multiAuth, nil
}

type MultiAuthenticator struct {
	Authenticators []*LDAPAuthenticator
	usersMapping   *lru.Cache[string, int]
}

func (m *MultiAuthenticator) getMappedIndex(username string) int {
	if val, ok := m.usersMapping.Get(username); ok {
		return val
	}
	return -1
}

func (m *MultiAuthenticator) addUserMapping(username string, idx int) {
	m.usersMapping.Add(username, idx)
	logger.AppLogger.Debug("user mapped to server", "username", username, "server number", idx+1)
}

func (m *MultiAuthenticator) CheckUserAndPass(username, password, ip, protocol string, userAsJSON []byte) ([]byte, error) {
	var res []byte
	var err error

	cachedIdx := m.getMappedIndex(username)
	if cachedIdx >= 0 {
		res, err = m.Authenticators[cachedIdx].CheckUserAndPass(username, password, ip, protocol, userAsJSON)
		if err == nil {
			return res, nil
		}
	}

	for idx := range m.Authenticators {
		if idx == cachedIdx {
			continue
		}
		res, err = m.Authenticators[idx].CheckUserAndPass(username, password, ip, protocol, userAsJSON)
		if err == nil {
			m.addUserMapping(username, idx)
			return res, nil
		}
	}
	return res, err
}

func (m *MultiAuthenticator) CheckUserAndTLSCert(username, tlsCert, ip, protocol string, userAsJSON []byte) ([]byte, error) {
	var res []byte
	var err error

	cachedIdx := m.getMappedIndex(username)
	if cachedIdx >= 0 {
		res, err = m.Authenticators[cachedIdx].CheckUserAndTLSCert(username, tlsCert, ip, protocol, userAsJSON)
		if err == nil {
			return res, nil
		}
	}

	for idx := range m.Authenticators {
		if idx == cachedIdx {
			continue
		}
		res, err = m.Authenticators[idx].CheckUserAndTLSCert(username, tlsCert, ip, protocol, userAsJSON)
		if err == nil {
			m.addUserMapping(username, idx)
			return res, nil
		}
	}
	return res, err
}

func (m *MultiAuthenticator) CheckUserAndPublicKey(username, pubKey, ip, protocol string, userAsJSON []byte) ([]byte, error) {
	var res []byte
	var err error

	cachedIdx := m.getMappedIndex(username)
	if cachedIdx >= 0 {
		res, err = m.Authenticators[cachedIdx].CheckUserAndPublicKey(username, pubKey, ip, protocol, userAsJSON)
		if err == nil {
			return res, nil
		}
	}

	for idx := range m.Authenticators {
		if idx == cachedIdx {
			continue
		}
		res, err = m.Authenticators[idx].CheckUserAndPublicKey(username, pubKey, ip, protocol, userAsJSON)
		if err == nil {
			m.addUserMapping(username, idx)
			return res, nil
		}
	}
	return res, err
}

func (m *MultiAuthenticator) CheckUserAndKeyboardInteractive(username, ip, protocol string, userAsJSON []byte) ([]byte, error) {
	var res []byte
	var err error

	cachedIdx := m.getMappedIndex(username)
	if cachedIdx >= 0 {
		res, err = m.Authenticators[cachedIdx].CheckUserAndKeyboardInteractive(username, ip, protocol, userAsJSON)
		if err == nil {
			return res, err
		}
	}

	for idx := range m.Authenticators {
		if idx == cachedIdx {
			continue
		}
		res, err = m.Authenticators[idx].CheckUserAndKeyboardInteractive(username, ip, protocol, userAsJSON)
		if err == nil {
			m.addUserMapping(username, idx)
			return res, nil
		}
	}
	return res, err
}

func (m *MultiAuthenticator) SendKeyboardAuthRequest(requestID, username, password, ip string, answers,
	questions []string, step int32,
) (string, []string, []bool, int, int, error) {
	var instructions string
	var quests []string
	var echos []bool
	var authResult, checkPassword int
	var err error

	cachedIdx := m.getMappedIndex(username)
	if cachedIdx >= 0 {
		instructions, quests, echos, authResult, checkPassword, err = m.Authenticators[cachedIdx].SendKeyboardAuthRequest(
			requestID, username, password, ip, answers, questions, step)
		if err == nil {
			return instructions, quests, echos, authResult, checkPassword, nil
		}
	}

	for idx := range m.Authenticators {
		if idx == cachedIdx {
			continue
		}
		instructions, quests, echos, authResult, checkPassword, err = m.Authenticators[idx].SendKeyboardAuthRequest(
			requestID, username, password, ip, answers, questions, step)
		if err == nil {
			m.addUserMapping(username, idx)
			return instructions, quests, echos, authResult, checkPassword, nil
		}
	}
	return instructions, quests, echos, authResult, checkPassword, err
}
