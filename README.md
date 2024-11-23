# SFTPGo auth plugin

![CI](https://github.com/sftpgo/sftpgo-plugin-auth/workflows/CI/badge.svg)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPLv3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

This plugin enables LDAP/Active Directory authentication for SFTPGo.

## Configuration

The plugin can be configured within the `plugins` section of the SFTPGo configuration file or (recommended) using environment variables. To start the plugin you have to use the `serve` subcommand. Here is the usage.

```shell
NAME:
   sftpgo-plugin-auth serve - Launch the SFTPGo plugin, it must be called from an SFTPGo instance

USAGE:
   sftpgo-plugin-auth serve [command options]

OPTIONS:
   --ldap-url value [ --ldap-url value ]                            LDAP url, e.g ldap://192.168.1.5:389 or ldaps://192.168.1.5:636. By specifying multiple URLs you will achieve load balancing and high availability [$SFTPGO_PLUGIN_AUTH_LDAP_URL]
   --ldap-base-dn value                                             The base DN defines the address of the root object in the LDAP directory, e.g dc=mylab,dc=local [$SFTPGO_PLUGIN_AUTH_LDAP_BASE_DN]
   --ldap-bind-dn value                                             The bind DN used to log in at the LDAP server in order to perform searches, e.g cn=Administrator,cn=users,dc=mylab,dc=local. This should be a read-oly user [$SFTPGO_PLUGIN_AUTH_LDAP_USERNAME, $SFTPGO_PLUGIN_AUTH_LDAP_BIND_DN]
   --ldap-password value                                            The password for the defined ldap-bind-dn. If empty an anonymous bind will be attempted [$SFTPGO_PLUGIN_AUTH_LDAP_PASSWORD]
   --ldap-search-query value                                        The ldap query to use to find users attempting to login. The %username% placeholder will be replaced with the username attempting to log in (default: (&(objectClass=user)(sAMAccountType=805306368)(sAMAccountName=%username%))) [$SFTPGO_PLUGIN_AUTH_LDAP_SEARCH_QUERY]
   --ldap-group-attributes value [ --ldap-group-attributes value ]  The ldap attributes containing the groups the users are members of (default: memberOf) [$SFTPGO_PLUGIN_AUTH_LDAP_GROUP_ATTRIBUTES]
   --primary-group-prefix value                                     Prefix for LDAP groups to map to the primary group for SFTPGo users. SFTPGo users can have only one primary group [$SFTPGO_PLUGIN_AUTH_PRIMARY_GROUP_PREFIX]
   --secondary-group-prefix value                                   Prefix for LDAP groups to map to secondary groups of SFTPGo users [$SFTPGO_PLUGIN_AUTH_SECONDARY_GROUP_PREFIX]
   --membership-group-prefix value                                  Prefix for LDAP groups to map to membership groups of SFTPGo users [$SFTPGO_PLUGIN_AUTH_MEMBERSHIP_GROUP_PREFIX]
   --require-groups                                                 Require authenticated users to be members of at least one SFTPGo group (default: false) [$SFTPGO_PLUGIN_AUTH_REQUIRE_GROUPS]
   --user-requirements value                                        Requirements for SFTPGo users. 1 means users must be already defined in SFTPGo (default: 0) [$SFTPGO_PLUGIN_AUTH_USER_REQUIREMENTS]
   --starttls value                                                 STARTTLS is the preferred method of encrypting an LDAP connection. Use it instead of using the ldaps:// URL schema (default: 0) [$SFTPGO_PLUGIN_AUTH_STARTTLS]
   --users-base-dir value                                           Users default base directory. Leave empty if already set in SFTPGo. If set it must be an absolute path [$SFTPGO_PLUGIN_AUTH_USERS_BASE_DIR]
   --cache-time value                                               Defines the cache time, in seconds, for authenticated users. 0 means no cache (default: 0) [$SFTPGO_PLUGIN_AUTH_CACHE_TIME]
   --skip-tls-verify value                                          If set to 1 the plugin accepts any TLS certificate presented by the server and any host name in that certificate. In this mode, TLS is susceptible to man-in-the-middle attacks. This should be used only for testing (default: 0) [$SFTPGO_PLUGIN_AUTH_SKIP_TLS_VERIFY]
   --ca-certificates value [ --ca-certificates value ]              List of absolute paths to extra CA certificates to trust [$SFTPGO_PLUGIN_AUTH_CA_CERTIFICATES]
   --config-file value                                              Defines the path to an optional JSON configuration file. The configuration file can be used to configure a list of LDAP servers, with different configurations, to be used in order until one works. If set the other configuration flags are ignored [$SFTPGO_PLUGIN_AUTH_CONFIG_FILE]
   --help, -h                                                       show help
```

As you can see from the above usage, you can customize the search query and LDAP attributes containing group membership.
The plugin returns a minimal SFTPGo user after successful authentication.
You can use the SFTPGo group feature to customize your users, also the plugin tries to preserve the changes made to users from SFTPGo's WebAdmin UI.
Groups are always matched in lower case.

Password and keyboard interactive authentication methods are supported.
SFTPGo users can add their public key and configure two-factor authentication from the SFTPGo WebClient UI.

Here is an example configuration using environment variables.

```text
SFTPGO_PLUGIN_AUTH_LDAP_URL="ldap://192.168.1.5:389"
SFTPGO_PLUGIN_AUTH_LDAP_BASE_DN="dc=mylab,dc=local"
SFTPGO_PLUGIN_AUTH_LDAP_BIND_DN="cn=Administrator,cn=users,dc=mylab,dc=local"
SFTPGO_PLUGIN_AUTH_LDAP_PASSWORD="Password.123456"
SFTPGO_PLUGIN_AUTH_LDAP_SEARCH_QUERY="(&(objectClass=user)(sAMAccountType=805306368)(sAMAccountName=%username%))"
SFTPGO_PLUGINS__0__TYPE=auth
SFTPGO_PLUGINS__0__AUTH_OPTIONS__SCOPE=5
SFTPGO_PLUGINS__0__CMD="/usr/local/bin/sftpgo-plugin-auth"
SFTPGO_PLUGINS__0__ARGS="serve"
SFTPGO_PLUGINS__0__AUTO_MTLS=1
```

Example configuration file.

```json
{
    "cache_size": 100,
    "configs": [
        {
            "dial_urls": [
                "ldap://192.168.5.21:389"
            ],
            "base_dn": "dc=mydomain,dc=local",
            "bind_dn": "cn=Administrator,cn=users,dc=mydomain,dc=local",
            "password": "super secret",
            "start_tls": 0,
            "skip_tls_verify": false,
            "ca_certificates": [],
            "search_query": "(&(objectClass=user)(sAMAccountType=805306368)(sAMAccountName=%username%))",
            "group_attributes": [
                "memberOf"
            ],
            "primary_group_prefix": "",
            "secondary_group_prefix": "",
            "membership_group_prefix": "",
            "require_groups": false,
            "sftpgo_user_requirements": 0,
            "base_dir": "",
            "cache_time": 0
        },
        {
            "dial_urls": [
                "ldap://192.168.1.5:389"
            ],
            "base_dn": "dc=mylab,dc=local",
            "bind_dn": "cn=Administrator,cn=users,dc=mylab,dc=local",
            "password": "Password.123456",
            "start_tls": 0,
            "skip_tls_verify": false,
            "ca_certificates": [],
            "search_query": "(&(objectClass=user)(sAMAccountType=805306368)(sAMAccountName=%username%))",
            "group_attributes": [
                "memberOf"
            ],
            "primary_group_prefix": "",
            "secondary_group_prefix": "",
            "membership_group_prefix": "",
            "require_groups": false,
            "sftpgo_user_requirements": 0,
            "base_dir": "",
            "cache_time": 0
        }
    ]
}
```

The `cache_size` configuration parameter defines the size of the LRU cache used to dynamically map users to LDAP servers.
