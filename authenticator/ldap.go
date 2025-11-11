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
	"math/rand"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/sftpgo/sdk"

	"github.com/sftpgo/sftpgo-plugin-auth/logger"
)

type LDAPAuthenticator struct {
	DialURLs               []string
	BaseDN                 string
	Username               string
	Password               string
	StartTLS               int
	SearchQuery            string
	GroupAttributes        []string
	PrimaryGroupPrefix     string
	SecondaryGroupPrefix   string
	MembershipGroupPrefix  string
	RequireGroups          bool
	SFTPGoUserRequirements int
	BaseDir                string
	tlsConfig              *tls.Config
	monitorTicker          *time.Ticker
	cleanupDone            chan bool
	mu                     sync.RWMutex
	activeURLs             []string
}

func (a *LDAPAuthenticator) validate() error {
	var urls []string
	for _, u := range a.DialURLs {
		if u != "" && !contains(urls, u) {
			urls = append(urls, u)
		}
	}
	a.DialURLs = urls
	if len(a.DialURLs) == 0 {
		return errors.New("ldap: dial URL is required")
	}
	if a.BaseDN == "" {
		return errors.New("ldap: base DN is required")
	}
	if a.Username == "" {
		return errors.New("ldap: username is required")
	}
	if a.SearchQuery == "" {
		return errors.New("ldap: search query is required")
	}
	if !strings.Contains(a.SearchQuery, "%username%") {
		return errors.New("ldap: search query must contain the username placeholder")
	}
	if a.BaseDir != "" && !filepath.IsAbs(a.BaseDir) {
		return errors.New("users base dir must be an absolute path")
	}
	if a.RequireGroups {
		if len(a.GroupAttributes) == 0 {
			return errors.New("group attributes are required")
		}
		if a.PrimaryGroupPrefix == "" && a.SecondaryGroupPrefix == "" && a.MembershipGroupPrefix == "" {
			return errors.New("at least a group prefix is required")
		}
	}
	if len(a.GroupAttributes) == 0 {
		if a.PrimaryGroupPrefix != "" || a.SecondaryGroupPrefix != "" || a.MembershipGroupPrefix != "" {
			return errors.New("group attributes not set, group prefixes are ineffective")
		}
	}
	a.setActiveDialURLs(a.DialURLs)
	return nil
}

func (a *LDAPAuthenticator) setActiveDialURLs(urls []string) {
	if len(a.DialURLs) == 1 {
		return
	}
	a.startMonitorTicker(2 * time.Minute)

	a.mu.Lock()
	defer a.mu.Unlock()

	a.activeURLs = nil
	a.activeURLs = append(a.activeURLs, urls...)
}

func (a *LDAPAuthenticator) addActiveDialURL(val string) {
	if len(a.DialURLs) == 1 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	if !contains(a.activeURLs, val) {
		a.activeURLs = append(a.activeURLs, val)
		logger.AppLogger.Info("ldap connection restored", "dial URL", val,
			"number of active dial URLs", len(a.activeURLs))
	}
}

func (a *LDAPAuthenticator) removeActiveDialURL(val string, err error) {
	if len(a.DialURLs) == 1 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	var urls []string
	for _, u := range a.activeURLs {
		if u != val {
			urls = append(urls, u)
		}
	}
	a.activeURLs = urls
	logger.AppLogger.Error("ldap connection error", "dial URL", val, "error", err,
		"number of active dial URLs", len(a.activeURLs))
}

func (a *LDAPAuthenticator) getDialURLs() []string {
	if len(a.DialURLs) == 1 {
		return a.DialURLs
	}
	a.mu.RLock()
	defer a.mu.RUnlock()

	if len(a.activeURLs) == 0 {
		logger.AppLogger.Warn("no active dial URL, trying all the defined URLs")
		return a.DialURLs
	}

	urls := make([]string, len(a.activeURLs))
	copy(urls, a.activeURLs)

	rand.Shuffle(len(urls), func(i, j int) {
		urls[i], urls[j] = urls[j], urls[i]
	})

	return urls
}

func (a *LDAPAuthenticator) isDialURLActive(val string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return contains(a.activeURLs, val)
}

func (a *LDAPAuthenticator) monitorDialURLs() {
	for _, u := range a.DialURLs {
		if !a.isDialURLActive(u) {
			conn, err := a.getLDAPConnection(u)
			if err == nil {
				conn.Close() //nolint:errcheck
				a.addActiveDialURL(u)
			}
		}
	}
}

func (a *LDAPAuthenticator) CheckUserAndPass(username, password, _, _ string, userAsJSON []byte) ([]byte, error) {
	if password == "" {
		return nil, errInvalidCredentials
	}
	if cache != nil {
		found, match := cache.Check(username, password)
		if found {
			if match {
				logger.AppLogger.Debug("password auth ok from cache", "user", username)
				return nil, nil
			}
			return nil, errInvalidCredentials
		}
	}
	l, err := a.connect()
	if err != nil {
		return nil, err
	}
	defer l.Close() //nolint:errcheck

	entry, err := a.searchUser(l, username)
	if err != nil {
		return nil, err
	}
	if err := l.Bind(entry.DN, password); err != nil {
		return nil, err
	}
	result, err := a.getUser(userAsJSON, entry.Attributes)
	if err != nil {
		return nil, err
	}
	if cache != nil {
		cache.Add(username, password)
	}
	return result, nil
}

func (a *LDAPAuthenticator) CheckUserAndTLSCert(_, _, _, _ string, _ []byte) ([]byte, error) {
	return nil, errNotImplemented
}

func (a *LDAPAuthenticator) CheckUserAndPublicKey(_, _, _, _ string, _ []byte) ([]byte, error) {
	return nil, errNotImplemented
}

func (a *LDAPAuthenticator) CheckUserAndKeyboardInteractive(username, _, _ string, userAsJSON []byte) ([]byte, error) {
	if cache != nil {
		if cache.Has(username) {
			return nil, nil
		}
	}
	l, err := a.connect()
	if err != nil {
		return nil, err
	}
	defer l.Close() //nolint:errcheck

	entry, err := a.searchUser(l, username)
	if err != nil {
		return nil, err
	}
	return a.getUser(userAsJSON, entry.Attributes)
}

func (a *LDAPAuthenticator) SendKeyboardAuthRequest(requestID, username, _, _ string, answers, _ []string,
	step int32,
) (string, []string, []bool, int, int, error) {
	switch step {
	case 1:
		return "", []string{"Password: "}, []bool{false}, 0, 0, nil
	case 2:
		if len(answers) != 1 {
			return "", nil, nil, 0, 0, fmt.Errorf("unexpected number of answers: %d", len(answers))
		}
		password := answers[0]
		if password == "" {
			return "", nil, nil, 0, 0, errInvalidCredentials
		}
		if cache != nil {
			found, match := cache.Check(username, password)
			if found {
				if match {
					logger.AppLogger.Debug("keyboard interactive password auth ok from cache", "user", username)
					return "", nil, nil, 1, 0, nil
				}
				return "", nil, nil, 0, 0, errInvalidCredentials
			}
		}
		l, err := a.connect()
		if err != nil {
			return "", nil, nil, 0, 0, err
		}
		defer l.Close() //nolint:errcheck

		entry, err := a.searchUser(l, username)
		if err != nil {
			return "", nil, nil, 0, 0, err
		}
		if err := l.Bind(entry.DN, password); err != nil {
			return "", nil, nil, 0, 0, err
		}
		if cache != nil {
			cache.Add(username, password)
		}
		return "", nil, nil, 1, 0, nil
	default:
		return "", nil, nil, 0, 0, errNotImplemented
	}
}

func (a *LDAPAuthenticator) searchUser(l *ldap.Conn, username string) (*ldap.Entry, error) {
	attributes := append([]string{"dn"}, a.GroupAttributes...)
	searchRequest := ldap.NewSearchRequest(a.BaseDN,
		ldap.ScopeWholeSubtree, ldap.DerefInSearching, 0, 0, false,
		strings.ReplaceAll(a.SearchQuery, "%username%", ldap.EscapeFilter(username)),
		attributes,
		nil,
	)
	sr, err := l.Search(searchRequest)
	if err != nil {
		logger.AppLogger.Debug("search error", "user", username, "err", err)
		return nil, err
	}
	if len(sr.Entries) != 1 {
		logger.AppLogger.Debug("unexpected search result", "user", username, "entries", len(sr.Entries))
		return nil, fmt.Errorf("user %q does not exist", username)
	}
	if sr.Entries[0].DN == "" {
		logger.AppLogger.Debug("unable to find dn", "user", username)
		return nil, errors.New("unable to find dn")
	}
	return sr.Entries[0], nil
}

func (a *LDAPAuthenticator) getUser(userAsJSON []byte, attributes []*ldap.EntryAttribute) ([]byte, error) {
	var user sdk.User
	if err := json.Unmarshal(userAsJSON, &user); err != nil {
		return nil, err
	}
	if user.ID == 0 && a.isSFTPGoUserRequired() {
		err := errors.New("LDAP users not defined in SFTPGo are not allowed")
		logger.AppLogger.Debug("no SFTPGo user defined", "username", user.Username, "err", err)
		return nil, err
	}
	var groups []sdk.GroupMapping

	for _, attr := range attributes {
		if !contains(a.GroupAttributes, attr.Name) {
			continue
		}
		for _, val := range attr.Values {
			val = getCNFromDN(val)
			if val == "" {
				continue
			}
			if a.PrimaryGroupPrefix != "" && strings.HasPrefix(val, a.PrimaryGroupPrefix) {
				groups = append(groups, sdk.GroupMapping{
					Name: val,
					Type: sdk.GroupTypePrimary,
				})
			} else if a.SecondaryGroupPrefix != "" && strings.HasPrefix(val, a.SecondaryGroupPrefix) {
				groups = append(groups, sdk.GroupMapping{
					Name: val,
					Type: sdk.GroupTypeSecondary,
				})
			} else if a.MembershipGroupPrefix != "" && strings.HasPrefix(val, a.MembershipGroupPrefix) {
				groups = append(groups, sdk.GroupMapping{
					Name: val,
					Type: sdk.GroupTypeMembership,
				})
			}
		}
	}
	if a.RequireGroups && len(groups) == 0 {
		err := errors.New("users without group membership are not allowed")
		logger.AppLogger.Debug("no group found", "username", user.Username, "err", err)
		return nil, err
	}

	if !a.isUserToUpdate(&user, groups) {
		return nil, nil
	}
	if user.ID == 0 {
		user.Status = 1
		user.Permissions = map[string][]string{
			"/": {"*"},
		}
		if a.BaseDir != "" {
			user.HomeDir = filepath.Join(a.BaseDir, user.Username)
		}
	}
	user.Filters.WebClient = append(user.Filters.WebClient, webClientPerms...)
	user.Filters.WebClient = removeDuplicates(user.Filters.WebClient)
	user.Groups = groups

	return json.Marshal(user)
}

func (a *LDAPAuthenticator) hasGroups() bool {
	return len(a.GroupAttributes) > 0 &&
		(a.PrimaryGroupPrefix != "" || a.SecondaryGroupPrefix != "" || a.MembershipGroupPrefix != "")
}

func (a *LDAPAuthenticator) isSFTPGoUserRequired() bool {
	return a.SFTPGoUserRequirements == 1
}

func (a *LDAPAuthenticator) isUserToUpdate(u *sdk.User, groups []sdk.GroupMapping) bool {
	if a.isSFTPGoUserRequired() {
		return false
	}
	if u.ID == 0 {
		return true
	}
	if u.Password == "" {
		return true
	}
	for _, perm := range webClientPerms {
		if !contains(u.Filters.WebClient, perm) {
			logger.AppLogger.Debug("web client permissions to update", "user", u.Username, "perm", perm)
			return true
		}
	}
	if !a.hasGroups() {
		return false
	}
	if len(groups) != len(u.Groups) {
		logger.AppLogger.Debug("groups to update", "user", u.Username, "groups", groups)
		return true
	}
	for _, g := range groups {
		found := false
		for _, ug := range u.Groups {
			if g.Name == ug.Name && g.Type == ug.Type {
				found = true
				break
			}
		}
		if !found {
			logger.AppLogger.Debug("groups to update", "user", u.Username, "group", g.Name, "type", g.Type)
			return true
		}
	}
	return false
}

func (a *LDAPAuthenticator) connect() (conn *ldap.Conn, err error) {
	for _, url := range a.getDialURLs() {
		conn, err = a.getLDAPConnection(url)
		if err == nil {
			a.addActiveDialURL(url)
		} else {
			a.removeActiveDialURL(url, err)
		}
		if !a.isRetryableError(err) {
			return
		}
	}
	return
}

func (a *LDAPAuthenticator) bind(l *ldap.Conn) error {
	if a.Password == "" {
		if err := l.UnauthenticatedBind(a.Username); err != nil {
			logger.AppLogger.Debug("unable to bind to the directory server in anonymous mode", "err", err)
			return err
		}
		return nil
	}
	if err := l.Bind(a.Username, a.Password); err != nil {
		logger.AppLogger.Debug("unable to bind to the directory server", "err", err)
		return err
	}
	return nil
}

func (a *LDAPAuthenticator) getLDAPConnection(dialURL string) (*ldap.Conn, error) {
	opts := []ldap.DialOpt{
		ldap.DialWithDialer(&net.Dialer{Timeout: 15 * time.Second}),
		ldap.DialWithTLSConfig(a.tlsConfig),
	}
	l, err := ldap.DialURL(dialURL, opts...)
	if err != nil {
		return nil, err
	}
	if a.StartTLS == 1 {
		if err := l.StartTLS(a.tlsConfig); err != nil {
			l.Close() //nolint:errcheck
			return nil, err
		}
	}
	l.SetTimeout(15 * time.Second)
	if err := a.bind(l); err != nil {
		l.Close() //nolint:errcheck
		return nil, err
	}
	return l, nil
}

func (*LDAPAuthenticator) isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) {
		return ldapErr.ResultCode == ldap.ErrorNetwork
	}
	return false
}

func (a *LDAPAuthenticator) stopMonitorTicker() {
	if a.monitorTicker != nil {
		a.monitorTicker.Stop()
		a.cleanupDone <- true
		a.monitorTicker = nil
	}
}

func (a *LDAPAuthenticator) startMonitorTicker(interval time.Duration) {
	a.stopMonitorTicker()
	a.monitorTicker = time.NewTicker(interval)
	a.cleanupDone = make(chan bool)

	go func() {
		logger.AppLogger.Info("start monitor task for dial URLs", "dial URLs", len(a.DialURLs))
		for {
			select {
			case <-a.cleanupDone:
				logger.AppLogger.Info("monitor task for dial URLs ended")
				return
			case <-a.monitorTicker.C:
				a.monitorDialURLs()
			}
		}
	}()
}

func (a *LDAPAuthenticator) Cleanup() {
	a.stopMonitorTicker()
}
