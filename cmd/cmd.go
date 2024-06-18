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

package cmd

import (
	"errors"
	"os"
	"strings"

	"github.com/hashicorp/go-plugin"
	"github.com/sftpgo/sdk/plugin/auth"
	"github.com/urfave/cli/v2"

	"github.com/sftpgo/sftpgo-plugin-auth/authenticator"
	"github.com/sftpgo/sftpgo-plugin-auth/logger"
)

const (
	version   = "1.0.8"
	envPrefix = "SFTPGO_PLUGIN_AUTH_"
)

const (
	defaultSearchQuery = "(&(objectClass=user)(sAMAccountType=805306368)(sAMAccountName=%username%))"
)

var (
	commitHash = ""
	buildDate  = ""
)

var (
	defaultGroupAttributes cli.StringSlice
)

func init() {
	defaultGroupAttributes.Set("memberOf") //nolint:errcheck
}

var (
	ldapURL                cli.StringSlice
	ldapBaseDN             string
	ldapUsername           string
	ldapPassword           string
	ldapSearchQuery        string
	ldapGroupAttributes    cli.StringSlice
	startTLS               int
	cacheTime              int
	skipTLSVerify          int
	caCertificates         cli.StringSlice
	usersBaseDir           string
	primaryGroupPrefix     string
	secondaryGroupPrefix   string
	membershipGroupPrefix  string
	requireGroupMembership bool
	sftpgoUserRequirements int

	rootCmd = &cli.App{
		Name:    "sftpgo-plugin-auth",
		Version: getVersionString(),
		Usage:   "SFTPGo authentication plugin",
		Commands: []*cli.Command{
			{
				Name:  "serve",
				Usage: "Launch the SFTPGo plugin, it must be called from an SFTPGo instance",
				Flags: []cli.Flag{
					&cli.StringSliceFlag{
						Name:        "ldap-url",
						Usage:       "LDAP url, e.g ldap://192.168.1.5:389 or ldaps://192.168.1.5:636. By specifying multiple URLs you will achieve load balancing and high availability",
						Destination: &ldapURL,
						EnvVars:     []string{envPrefix + "LDAP_URL"},
					},
					&cli.StringFlag{
						Name:        "ldap-base-dn",
						Usage:       "The base DN defines the address of the root object in the LDAP directory, e.g dc=mylab,dc=local",
						Destination: &ldapBaseDN,
						EnvVars:     []string{envPrefix + "LDAP_BASE_DN"},
					},
					&cli.StringFlag{
						Name:        "ldap-bind-dn",
						Usage:       "The bind DN used to log in at the LDAP server in order to perform searches, e.g cn=Administrator,cn=users,dc=mylab,dc=local. This should be a read-oly user",
						Destination: &ldapUsername,
						EnvVars:     []string{envPrefix + "LDAP_USERNAME", envPrefix + "LDAP_BIND_DN"},
					},
					&cli.StringFlag{
						Name:        "ldap-password",
						Usage:       "The password for the defined ldap-bind-dn. If empty an anonymous bind will be attempted",
						Destination: &ldapPassword,
						EnvVars:     []string{envPrefix + "LDAP_PASSWORD"},
					},
					&cli.StringFlag{
						Name:        "ldap-search-query",
						Usage:       "The ldap query to use to find users attempting to login. The %username% placeholder will be replaced with the username attempting to log in",
						Destination: &ldapSearchQuery,
						Value:       defaultSearchQuery,
						DefaultText: defaultSearchQuery,
						EnvVars:     []string{envPrefix + "LDAP_SEARCH_QUERY"},
					},
					&cli.StringSliceFlag{
						Name:        "ldap-group-attributes",
						Usage:       "The ldap attributes containing the groups the users are members of",
						Destination: &ldapGroupAttributes,
						Value:       &defaultGroupAttributes,
						DefaultText: "memberOf",
						EnvVars:     []string{envPrefix + "LDAP_GROUP_ATTRIBUTES"},
					},
					&cli.StringFlag{
						Name:        "primary-group-prefix",
						Usage:       "Prefix for LDAP groups to map to the primary group for SFTPGo users. SFTPGo users can have only one primary group",
						Destination: &primaryGroupPrefix,
						EnvVars:     []string{envPrefix + "PRIMARY_GROUP_PREFIX"},
					},
					&cli.StringFlag{
						Name:        "secondary-group-prefix",
						Usage:       "Prefix for LDAP groups to map to secondary groups of SFTPGo users",
						Destination: &secondaryGroupPrefix,
						EnvVars:     []string{envPrefix + "SECONDARY_GROUP_PREFIX"},
					},
					&cli.StringFlag{
						Name:        "membership-group-prefix",
						Usage:       "Prefix for LDAP groups to map to membership groups of SFTPGo users",
						Destination: &membershipGroupPrefix,
						EnvVars:     []string{envPrefix + "MEMBERSHIP_GROUP_PREFIX"},
					},
					&cli.BoolFlag{
						Name:        "require-groups",
						Usage:       "Require authenticated users to be members of at least one SFTPGo group",
						Destination: &requireGroupMembership,
						EnvVars:     []string{envPrefix + "REQUIRE_GROUPS"},
					},
					&cli.IntFlag{
						Name:        "user-requirements",
						Usage:       "Requirements for SFTPGo users. 1 means users must be already defined in SFTPGo",
						Destination: &sftpgoUserRequirements,
						EnvVars:     []string{envPrefix + "USER_REQUIREMENTS"},
					},
					&cli.IntFlag{
						Name:        "starttls",
						Usage:       "STARTTLS is the preferred method of encrypting an LDAP connection. Use it instead of using the ldaps:// URL schema",
						Destination: &startTLS,
						EnvVars:     []string{envPrefix + "STARTTLS"},
					},
					&cli.StringFlag{
						Name:        "users-base-dir",
						Usage:       "Users default base directory. Leave empty if already set in SFTPGo. If set it must be an absolute path",
						Destination: &usersBaseDir,
						EnvVars:     []string{envPrefix + "USERS_BASE_DIR"},
					},
					&cli.IntFlag{
						Name:        "cache-time",
						Usage:       "Defines the cache time, in seconds, for authenticated users. 0 means no cache",
						Destination: &cacheTime,
						DefaultText: "0",
						EnvVars:     []string{envPrefix + "CACHE_TIME"},
					},
					&cli.IntFlag{
						Name:        "skip-tls-verify",
						Usage:       "If set to 1 the plugin accepts any TLS certificate presented by the server and any host name in that certificate. In this mode, TLS is susceptible to man-in-the-middle attacks. This should be used only for testing",
						Destination: &skipTLSVerify,
						DefaultText: "0",
						EnvVars:     []string{envPrefix + "SKIP_TLS_VERIFY"},
					},
					&cli.StringSliceFlag{
						Name:        "ca-certificates",
						Usage:       "List of absolute paths to extra CA certificates to trust",
						Destination: &caCertificates,
						EnvVars:     []string{envPrefix + "CA_CERTIFICATES"},
					},
				},
				Action: func(ctx *cli.Context) error {
					a, err := authenticator.NewAuthenticator(ldapURL.Value(), ldapBaseDN, ldapUsername, ldapPassword, startTLS,
						skipTLSVerify == 1, usersBaseDir, cacheTime, ldapSearchQuery, ldapGroupAttributes.Value(),
						caCertificates.Value(), primaryGroupPrefix, secondaryGroupPrefix, membershipGroupPrefix,
						requireGroupMembership, sftpgoUserRequirements)
					if err != nil {
						logger.AppLogger.Error("unable to create the authenticator", "err", err)
						return err
					}
					plugin.Serve(&plugin.ServeConfig{
						HandshakeConfig: auth.Handshake,
						Plugins: map[string]plugin.Plugin{
							auth.PluginName: &auth.Plugin{Impl: a},
						},
						GRPCServer: plugin.DefaultGRPCServer,
					})

					a.Cleanup()
					return errors.New("the plugin exited unexpectedly")
				},
			},
		},
	}
)

// Execute runs the root command
func Execute() error {
	return rootCmd.Run(os.Args)
}

func getVersionString() string {
	var sb strings.Builder
	sb.WriteString(version)
	if commitHash != "" {
		sb.WriteString("-")
		sb.WriteString(commitHash)
	}
	if buildDate != "" {
		sb.WriteString("-")
		sb.WriteString(buildDate)
	}
	return sb.String()
}
