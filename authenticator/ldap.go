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
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/sftpgo/sdk"

	"github.com/sftpgo/sftpgo-plugin-auth/logger"
)

type LDAPAuthenticator struct {
	DialURL               string
	BaseDN                string
	Username              string
	Password              string
	StartTLS              int
	SearchQuery           string
	GroupAttributes       []string
	PrimaryGroupPrefix    string
	SecondaryGroupPrefix  string
	MembershipGroupPrefix string
	RequireGroups         bool
	BaseDir               string
	tlsConfig             *tls.Config
}

func (a *LDAPAuthenticator) validate() error {
	if a.DialURL == "" {
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
	return nil
}

func (a *LDAPAuthenticator) CheckUserAndPass(username, password, _, _ string, userAsJSON []byte) ([]byte, error) {
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
	defer l.Close()

	entry, err := a.searchUser(l, username)
	if err != nil {
		return nil, err
	}
	if err := l.Bind(entry.DN, password); err != nil {
		return nil, err
	}
	if cache != nil {
		cache.Add(username, password)
	}
	return a.getUser(userAsJSON, entry.Attributes)
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
	defer l.Close()

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
		defer l.Close()

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
	if a.Password == "" {
		if err := l.UnauthenticatedBind(a.Username); err != nil {
			logger.AppLogger.Debug("unable to bind to the directory server in anonymous mode", "err", err)
			return nil, err
		}
	} else {
		if err := l.Bind(a.Username, a.Password); err != nil {
			logger.AppLogger.Debug("unable to bind to the directory server", "err", err)
			return nil, err
		}
	}
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
			val = strings.ToLower(val)
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
		logger.AppLogger.Debug("no group for found", "user", user.Username, "err", err)
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

func (a *LDAPAuthenticator) isUserToUpdate(u *sdk.User, groups []sdk.GroupMapping) bool {
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
	if len(groups) != len(u.Groups) {
		logger.AppLogger.Debug("groups to update", "user", u.Username)
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

func (a *LDAPAuthenticator) connect() (*ldap.Conn, error) {
	opts := []ldap.DialOpt{
		ldap.DialWithDialer(&net.Dialer{Timeout: 15 * time.Second}),
		ldap.DialWithTLSConfig(a.tlsConfig),
	}
	l, err := ldap.DialURL(a.DialURL, opts...)
	if err != nil {
		return nil, err
	}
	if a.StartTLS == 1 {
		if err := l.StartTLS(a.tlsConfig); err != nil {
			l.Close()
			return nil, err
		}
	}
	return l, err
}
