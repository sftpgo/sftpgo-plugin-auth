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
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/sftpgo/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	ldapURL               = "ldap://localhost:3893"
	ldapsURL              = "ldaps://localhost:3894"
	baseDN                = "dc=glauth,dc=com"
	username              = "cn=serviceuser,dc=glauth,dc=com"
	password              = "mysecret"
	searchQuery           = "(&(objectClass=*)(uid=%username%))"
	groupAttribute        = "memberOf"
	primaryGroupPrefix    = "sftpgo_primary"
	secondaryGroupPrefix  = "sftpgo_secondary"
	membershipGroupPrefix = "sftpgo_membership"
	user1                 = "user1"
	user2                 = "user2"
	caCRT                 = `-----BEGIN CERTIFICATE-----
MIIE5jCCAs6gAwIBAgIBATANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDEwhDZXJ0
QXV0aDAeFw0yMzAxMDMxMDIwNDdaFw0zMzAxMDMxMDMwNDZaMBMxETAPBgNVBAMT
CENlcnRBdXRoMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxq6Wl1Ih
hgvGdM8M2IVI7dwnv3yShJygZsnREQSEW0xeWJL5DtNeHCME5WByFUAlZKpePtW8
TNwln9DYDtgNSMiWwvO/wR0mXsyU8Ma4ZBMlX0oOkWo1Ff/M/u8YY9X78Vvwdt62
Yt7QmU5oUUW2HdAgh4AlhKJSjm3t0uDP5s54uvueL5bjChHwEb1ZGOtST9Zt86cj
YA/xtVHnDXCJbhohpzQI6dK96NegONZVDaxEohVCyYYOgI1I14Bxu0ZCMm5GjwoO
QohnUfEJ+BRgZqFpbsnYCE+PoVayVVFoLA+GMeqbQ2SHej1Pr1K0dbjUz6SAk8/+
DL7h8d+YAtflATsMtdsVJ4WzEfvZbSbiYKYmlVC6zk6ooXWadvQ5+aezVes9WMpH
YnAoScuKoeerRuKlsSU7u+XCmy/i7Hii5FwMrSvIL2GLtVE+tJFCTABA55OWZikt
ULMQfg3P2Hk3GFIE35M10mSjKQkGhz06WC5UQ7f2Xl9GzO6PqRSorzugewgMK6L4
SnN7XBFnUHHqx1bWNkUG8NPYB6Zs7UDHygemTWxqqxun43s501DNTSunCKIhwFbt
1ol5gOvYAFG+BXxnggBT815Mgz1Zht3S9CuprAgz0grNEwAYjRTm1PSaX3t8I1kv
oUUuMF6BzWLHJ66uZKOCsPs3ouGq+G3GfWUCAwEAAaNFMEMwDgYDVR0PAQH/BAQD
AgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFCj8lmcR7loB9zAP/feo
t1eIHWmIMA0GCSqGSIb3DQEBCwUAA4ICAQCu46fF0Tr2tZz1wkYt2Ty3OU77jcG9
zYU/7uxPqPC8OYIzQJrumXKLOkTYJXJ7k+7RQdsn/nbxdH1PbslNDD3Eid/sZsF/
dFdGR1ZYwXVQbpYwEd19CvJTALn9CyAZpMS8J2RJrmdScAeSSb0+nAGTYP7GvPm+
8ktOnrz3w8FtzTw+seuCW/DI/5UpfC9Jf+i/3XgxDozXWNW6YNOIw/CicyaqbBTk
5WFcJ0WJN+8qQurw8n+sOvQcNsuDTO7K3Tqu0wGTDUQKou7kiMX0UISRvd8roNOl
zvvokNQe4VgCGQA+Y2SxvSxVG1BaymYeNw/0Yxm7QiKSUI400V1iKIcpnIvIedJR
j2bGIlslVSV/P6zkRuF1srRVxTxSf1imEfs8J8mMhHB6DkOsP4Y93z5s6JZ0sPiM
eOb0CVKul/e1R0Kq23AdPf5eUv63RhfmokN1OsdarRKMFyHphWMxqGJXsSvRP+dl
3DaKeTDx/91OSWiMc+glHHKKJveMYQLeJ7GXmcxhuoBm6o4Coowgw8NFKMCtAsp0
ktvsQuhB3uFUterw/2ONsOChx7Ybu36Zk47TKBpktfxDQ578TVoZ7xWSAFqCPHvx
A5VSwAg7tdBvORfqQjhiJRnhwr50RaNQABTLS0l5Vsn2mitApPs7iKiIts2ieWsU
EsdgvPZR2e5IkA==
-----END CERTIFICATE-----`
)

func TestLDAPAuthenticator(t *testing.T) {
	baseDir := filepath.Clean(os.TempDir())
	auth, err := NewAuthenticator(ldapURL, baseDN, username, password, 0, false, baseDir, 2, searchQuery,
		[]string{groupAttribute}, nil, primaryGroupPrefix, secondaryGroupPrefix, membershipGroupPrefix, true)
	require.NoError(t, err)
	require.Nil(t, auth.tlsConfig.RootCAs)
	defer func() {
		cache = nil
	}()

	_, err = auth.CheckUserAndPass(user1, "wrong", "", "", nil)
	require.Error(t, err)
	e, ok := err.(*ldap.Error)
	require.True(t, ok)
	require.Equal(t, uint16(49), e.ResultCode)
	userJSON, err := auth.CheckUserAndPass(user1, password, "", "", []byte(`{"username":"user1"}`))
	require.NoError(t, err)
	var user sdk.User
	err = json.Unmarshal(userJSON, &user)
	require.NoError(t, err)
	require.Equal(t, 1, user.Status)
	require.Equal(t, filepath.Join(baseDir, user1), user.HomeDir)
	require.Len(t, user.Groups, 2)
	// error from cache
	_, err = auth.CheckUserAndPass(user1, "wrong", "", "", nil)
	require.ErrorIs(t, err, errInvalidCredentials)
	// auth ok from cache
	userJSON, err = auth.CheckUserAndPass(user1, password, "", "", userJSON)
	require.NoError(t, err)
	require.Nil(t, userJSON)
	// auth with a different user
	userJSON, err = auth.CheckUserAndPass(user2, password, "", "", []byte(`{"username":"user2"}`))
	require.NoError(t, err)
	user = sdk.User{}
	err = json.Unmarshal(userJSON, &user)
	require.NoError(t, err)
	require.Equal(t, 1, user.Status)
	require.Equal(t, filepath.Join(baseDir, user2), user.HomeDir)
	require.Len(t, user.Groups, 1)
	// test keyboard interactive authentication
	_, err = auth.CheckUserAndKeyboardInteractive("missing user", "", "", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not exist")
	userJSON, err = auth.CheckUserAndKeyboardInteractive(user1, "", "", userJSON)
	require.NoError(t, err)
	require.Nil(t, userJSON)
	_, _, _, _, _, err = auth.SendKeyboardAuthRequest("", user1, "", "", nil, nil, 1)
	require.NoError(t, err)
	_, _, _, res, _, err := auth.SendKeyboardAuthRequest("", user1, "", "", []string{password}, nil, 2)
	require.NoError(t, err)
	require.Equal(t, 1, res)
	// wrong password
	_, _, _, _, _, err = auth.SendKeyboardAuthRequest("", user1, "", "", []string{"wrong"}, nil, 2)
	require.ErrorIs(t, err, errInvalidCredentials)
	found := cache.Has(user1)
	require.True(t, found)
	// wait for cache expiration
	time.Sleep(2100 * time.Millisecond)
	found = cache.Has(user1)
	require.False(t, found)
	_, _, _, _, _, err = auth.SendKeyboardAuthRequest("", user1, "", "", []string{"wrong"}, nil, 2)
	require.Error(t, err)
	e, ok = err.(*ldap.Error)
	require.True(t, ok)
	require.Equal(t, uint16(49), e.ResultCode)
	_, _, _, res, _, err = auth.SendKeyboardAuthRequest("", user1, "", "", []string{password}, nil, 2)
	require.NoError(t, err)
	require.Equal(t, 1, res)
	// no group
	_, err = auth.CheckUserAndPass("serviceuser", password, "", "", []byte(`{"username":"serviceuser"}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "users without group membership are not allowed")
}

func TestPreserveUserChanges(t *testing.T) {
	auth, err := NewAuthenticator(ldapURL, baseDN, username, password, 0, false, "", 0, searchQuery,
		[]string{groupAttribute}, nil, primaryGroupPrefix, secondaryGroupPrefix, membershipGroupPrefix, false)
	require.NoError(t, err)
	userJSON, err := auth.CheckUserAndPass(user1, password, "", "", []byte(`{"username":"user1"}`))
	require.NoError(t, err)
	var user sdk.User
	err = json.Unmarshal(userJSON, &user)
	require.NoError(t, err)
	require.Equal(t, 1, user.Status)
	require.Len(t, user.Groups, 2)
	user.ID = 1
	user.Password = password
	userJSON, err = json.Marshal(user)
	require.NoError(t, err)
	userJSON, err = auth.CheckUserAndPass(user1, password, "", "", userJSON)
	require.NoError(t, err)
	require.Nil(t, userJSON)
	// keyboard interactive
	userJSON, err = json.Marshal(user)
	require.NoError(t, err)
	userJSON, err = auth.CheckUserAndKeyboardInteractive(user1, "", "", userJSON)
	require.NoError(t, err)
	require.Nil(t, userJSON)
}

func TestLDAPS(t *testing.T) {
	auth, err := NewAuthenticator(ldapsURL, baseDN, username, password, 0, true, "", 0, searchQuery,
		[]string{groupAttribute}, nil, primaryGroupPrefix, secondaryGroupPrefix, membershipGroupPrefix, false)
	require.NoError(t, err)
	l, err := auth.connect()
	require.NoError(t, err)
	err = l.Close()
	require.NoError(t, err)
}

func TestLDAPConnectionErrors(t *testing.T) {
	auth, err := NewAuthenticator("ldap://localhost:3892", baseDN, username, password, 0, true, "", 0, searchQuery,
		[]string{groupAttribute}, nil, primaryGroupPrefix, secondaryGroupPrefix, membershipGroupPrefix, false)
	require.NoError(t, err)
	_, err = auth.CheckUserAndPass(user1, password, "", "", nil)
	require.Error(t, err)
	_, err = auth.CheckUserAndKeyboardInteractive(user1, "", "", nil)
	require.Error(t, err)
	_, _, _, _, _, err = auth.SendKeyboardAuthRequest("", user1, "", "", nil, nil, 2)
	require.Error(t, err)
}

func TestStartTLS(t *testing.T) {
	// glauth does not support STARTTLS
	auth, err := NewAuthenticator(ldapURL, baseDN, username, password, 1, true, "", 0, searchQuery,
		[]string{groupAttribute}, nil, primaryGroupPrefix, secondaryGroupPrefix, membershipGroupPrefix, false)
	require.NoError(t, err)
	_, err = auth.connect()
	require.Error(t, err)
	e, ok := err.(*ldap.Error)
	require.True(t, ok)
	require.Equal(t, uint16(2), e.ResultCode)
}

func TestValidation(t *testing.T) {
	_, err := NewAuthenticator("", "", "", "", 0, false, "", 0, "", nil, nil, "", "", "", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dial URL is required")
	a := LDAPAuthenticator{
		DialURL: ldapURL,
	}
	err = a.validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "base DN is required")
	a.BaseDN = "dc=mylab,dc=local"
	err = a.validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "username is required")
	a.Username = "username"
	err = a.validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "search query is required")
	a.SearchQuery = "(&(objectClass=user)(sAMAccountType=805306368)(sAMAccountName=username)))"
	err = a.validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "search query must contain the username placeholder")
	a.SearchQuery = "(&(objectClass=user)(sAMAccountType=805306368)(sAMAccountName=%username%)))"
	err = a.validate()
	require.NoError(t, err)
	a.BaseDir = "relative"
	err = a.validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "users base dir must be an absolute path")
	a.BaseDir = filepath.Clean(os.TempDir())
	a.RequireGroups = true
	err = a.validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "group attributes are required")
	a.GroupAttributes = []string{"memberOf"}
	err = a.validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least a group prefix is required")
	a.PrimaryGroupPrefix = "sftpgo_primary"
	err = a.validate()
	require.NoError(t, err)
}

func TestUnsupportedAuthMethods(t *testing.T) {
	a := LDAPAuthenticator{}
	_, err := a.CheckUserAndTLSCert(user1, "", "", "", nil)
	require.ErrorIs(t, err, errNotImplemented)
	_, err = a.CheckUserAndPublicKey(user2, "", "", "", nil)
	require.ErrorIs(t, err, errNotImplemented)
	_, _, _, _, _, err = a.SendKeyboardAuthRequest("", user1, "", "", nil, nil, 100)
	require.ErrorIs(t, err, errNotImplemented)
}

func TestUserToUpdate(t *testing.T) {
	u := &sdk.User{
		BaseUser: sdk.BaseUser{
			ID: 1,
		},
	}
	a := LDAPAuthenticator{}
	res := a.isUserToUpdate(u, nil)
	require.True(t, res)
	u.Password = password
	res = a.isUserToUpdate(u, nil)
	require.True(t, res)
	u.Filters.WebClient = []string{sdk.WebClientPasswordChangeDisabled, sdk.WebClientPasswordResetDisabled,
		sdk.WebClientShareNoPasswordDisabled}
	groups := []sdk.GroupMapping{
		{
			Name: "g1",
			Type: sdk.GroupTypePrimary,
		},
	}
	res = a.isUserToUpdate(u, groups)
	require.True(t, res)
	u.Groups = []sdk.GroupMapping{
		{
			Name: "g1",
			Type: sdk.GroupTypeSecondary,
		},
	}
	res = a.isUserToUpdate(u, groups)
	require.True(t, res)
	u.Groups = groups
	res = a.isUserToUpdate(u, groups)
	require.False(t, res)
}

func TestGetCNFromDN(t *testing.T) {
	res := getCNFromDN("")
	assert.Empty(t, res)
	res = getCNFromDN("cn=test")
	assert.Equal(t, "test", res)
	res = getCNFromDN("test")
	assert.Empty(t, res)
	res = getCNFromDN("cn=admin ,ou=users,dc=mylab,dc=local")
	assert.Equal(t, "admin", res)
	res = getCNFromDN("ou=first,ou=users,dc=mylab,dc=local")
	assert.Equal(t, "first", res)
}

func TestLoadCACerts(t *testing.T) {
	caCrtPath := "testcacrt"
	_, err := NewAuthenticator(ldapURL, baseDN, username, password, 0, true, "", 0,
		searchQuery, nil, []string{caCrtPath}, "", "", "", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is not an absolute path")
	caCrtPath = filepath.Join(os.TempDir(), caCrtPath)
	_, err = NewAuthenticator(ldapURL, baseDN, username, password, 0, true, "", 0,
		searchQuery, nil, []string{caCrtPath}, "", "", "", false)
	require.ErrorIs(t, err, fs.ErrNotExist)
	err = os.WriteFile(caCrtPath, []byte(caCRT), 0600)
	require.NoError(t, err)
	auth, err := NewAuthenticator(ldapURL, baseDN, username, password, 0, true, "", 0,
		searchQuery, nil, []string{caCrtPath}, "", "", "", false)
	require.NoError(t, err)
	require.NotNil(t, auth.tlsConfig.RootCAs)
	err = os.Remove(caCrtPath)
	require.NoError(t, err)
}
