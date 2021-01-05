# Version 3.1.0 (2021-01-05)

* [new] Config option `additionalRolesClaim` enable gathering additional roles from a custom claim.
* [new] Config option `additionalPermissionsClaim` enable gathering additional permissions from a custom claim.


# Version 3.0.1 (2020-12-15)

* [chg] Better token validation error messages.

# Version 3.0.0 (2020-11-23)

* [brk] Moved everything under the `org.seedstack.oauth.spi` package to `org.seedstack.oauth`.
* [chg] The application id is now used as the default allowed audience if none is configured.
* [chg] Raw user info is available as implementation-specific subject principal of type `com.nimbusds.openid.connect.sdk.claims.UserInfo`.
* [chg] Raw tokens are available as `org.seedstack.oauth.OAuthAuthenticationToken` subject principal.

# Version 2.0.0 (2020-11-09)

* [brk] Simplified and new configuration options.
* [new] A default opaque token validator is now provided (validating the access token by calling the userInfo endpoint if available). 
* [new] Improved token validation (at_hash optional, try validating access token as JWT first, then as an opaque token if it fails).
* [new] Allow treating scopes either as direct permissions (the default) or as roles (which then can give permissions through a `RolePermissionResolver`).
* [new] Claims are now extracted from identity token and optionally enriched with the userInfo endpoint if enabled (off by default).
* [new] Proper support for bearer access tokens.
* [chg] Improved client error messages.

# Version 1.1.3 (2020-10-05)

* [fix] Avoid throwing an exception when no scope is returned by the identity provider.
* [fix] Check `at_hash` claim only if present.

# Version 1.1.2 (2020-09-17)

* [fix] Force `json-smart` transitive dependency to use a fixed version instead of a range, which can break build.

# Version 1.1.1 (2020-08-10)

* [chg] Updated OAuth2 SDK

# Version 1.1.0 (2019-12-19)

* [new] OAuthRealm now provides subject roles based on OAuth scopes.
* [new] UserInfo data is now available as a subject principal.
* [new] Client credentials flow is now supported.

# Version 1.0.0 (2018-05-04)

* [new] Initial version.
