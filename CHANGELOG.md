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
