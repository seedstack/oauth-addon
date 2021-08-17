---
title: "OAuth"
addon: "OAuth"
repo: "https://github.com/seedstack/oauth-addon"
author: Jyoti ATHALYE & Adrien LAUER 
description: "Provides authentication and authorization using OAuth and OpenID Connect protocols."
tags:
    - security
zones:
    - Addons
noMenu: true    
---

Seedstack OAuth add-on provides the ability to authenticate and authorize subjects using OAuth and OpenID Connect.

## Dependencies

{{< dependency g="org.seedstack.addons.oauth" a="oauth" >}}

In a Web context you also need to add the following dependency (otherwise security filters will be ignored):

{{< dependency g="org.seedstack.seed" a="seed-web-security" >}}

## Overview

The OAuth 2.0 authorization framework is a protocol that allows a user to grant a third-party website or application 
access to the user's protected resources, without necessarily revealing their long-term credentials or even their identity.

OpenID Connect (OIDC) is an identity layer built on top of the OAuth 2.0 framework. It allows third-party applications 
to verify the identity of the end-user and to obtain basic user profile information. OIDC uses JSON web tokens (JWTs), 
which you can obtain using flows conforming to the OAuth 2.0 specifications.

{{< callout warning >}}
OAuth2/OpenIdConnect are complex protocols. While the SeedStack OAuth add-on greatly simplifies their use in applications,
a basic understanding of the roles, flows and security best practices is mandatory. 
{{< /callout >}}

### Roles

An OAuth 2.0 flow has the following roles:

* **Resource Owner**: entity that can grant access to a protected resource. Typically, this is the end-user.
* **Resource Server**: server hosting the protected resources. This is the API you want to access.
* **Client**: application requesting access to a protected resource on behalf of the Resource Owner.
* **Authorization Server**: server that authenticates the Resource Owner and issues access tokens after getting proper authorization.

### Use cases

OAuth 2.0 defines four flows to get an access token. Deciding which one is suited for your case depends mostly on your 
application type:

* **Traditional web application**: use the *authorization code flow*. In this case the application server is the OAuth
client which request the tokens. It stores them in the web session, making the application stateful. 
* **Single-page application (SPA)**: use the *authorization code flow with PKCE* which replaces the deprecated *implicit
grant flow*. In this case the SPA is the OAuth client which request the tokens. They are sent to one or more resource 
server(s) in an HTTP `Authorization` header as Bearer tokens.
* **Native mobile application**: also use the *authorization code flow with PKCE*.
* **Machine-to-Machine**: use the *client credentials flow*. In this case, one of the machines acts as the OAuth client
and request tokens directly using its client credentials. No end-user is involved in this case. This is the functional
equivalent of a technical account. 

## Usage

The add-on comes with a few components that must be used according to the chosen OAuth flow:

* The `oauth` security filter. It's used in HTTP-based scenarios and protects URL patterns by requiring a valid access
token to let the request go trough. It is also responsible to redirect the end-user to the authorization server login
page in the *authorization code flow* scenario (when a callback URL is configured).
* The `oauthCallback` security filter. It's also used in HTTP-based scenarios and should be placed on its own, on a 
specific callback URL. It is responsible for exchanging the authorization code for tokens in the *authorization code
flow*.
* The {{< java "org.seedstack.oauth.spi.OAuthService" >}}. It's used in programmatic cases like machine-to-machine
or custom scenarios to execute OAuth operations (like token resquest, validation, fetching user info, ...) on demand. It 
is used by the security filters, behind the scenes.
* The `OAuthRealm` security realm. This realm will validate tokens, extract relevant data (claims) and map them to
SeedStack security data structures. It must be configured as soon as a SeedStack security context should be created from
tokens. It is used by the security filters, behind the scenes.

### Authorization code flow

The following configuration is typical for traditional Web application using the *authorization code flow*:

```yaml
rest:
  path: /api

security:
  realms: OAuthRealm
  web:
    urls:
      - pattern: /callback
        filters: oauthCallback
      - pattern: /api/**
        filters: oauth
  oauth:
    discoveryDocument: https://my-authorization-server.com/.well-known/openid-configuration
    redirect: ${runtime.web.baseUrl}/callback
    scopes: [openid, email, profile]
    clientId: ...
    clientSecret: ...
```

* The authorization server is configured through the OpenIDConnect discovery document. If this is not supported by your
authorization server, you'll have to configure the provider manually in the `security.oauth.provider` section (see below).
* The redirect (callback) URL is configured, so you're in an *authorization code flow* situation.
* The `oauth` filter will intercept any request to `/api/**` and check for an existing security context. If absent, it
will check for a bearer token and use it to establish the security context. If absent, it will redirect the request to 
the authorization server login.
* The `oauthCallback` filter will be redirected to by the authorization server upon a successful login. It will exchange the
authorization code for tokens and establish the security context, then redirect to the original request, which should then
be allowed.

{{< callout info >}}
The `openid` scope tells the add-on and the authorization server to exchange using the OpenIdConnect protocol. Alongside
the access token, an identity token will also be provided with identity information about the logged in subject.
{{< /callout >}}

### Authorization code with PKCE

The following configuration is typical for Single-Page Application (SPA) or mobile application, using the 
*authorization code flow with PKCE*:

```yaml
security:
  realms: OAuthRealm
  web:
    urls:
      - pattern: /**
        filters: oauth
  oauth:
    discoveryDocument: https://my-authorization-server.com/.well-known/openid-configuration
    scopes: [openid, email, profile]
    allowedAudiences: myApiAudience
```

* The authorization server is configured through the OpenIDConnect discovery document. If this is not supported by your
authorization server, you'll have to configure the provider manually in the `security.oauth.provider` section (see below).
* The `oauth` filter will intercept any request to `/api/**` and check for an existing security context. If absent, it
will check for a bearer token and use it to establish the security context. If absent, it will deny the request.
* The `allowedAudiences` specifies which audience(s) (access token `aud` claim) will be allowed.

{{< callout info >}}
The `openid` scope tells the add-on and the authorization server to exchange using the OpenIdConnect protocol. Alongside
the access token, an identity token will also be provided with identity information about the logged in subject.
{{< /callout >}}

### Client-credentials flow

The following configuration is typical in machine-to-machine scenarios, using the *client-credentials flow*:

```yaml
security:
  realms: OAuthRealm
  oauth:
    discoveryDocument: https://my-authorization-server.com/.well-known/openid-configuration
    scopes: [openid, email, profile]
    clientId: sXpRGGxj3N6ETt0m63Wji161PiBsJVuh
    clientSecret: Jn2jAXp6mfa8-sKS3C29FwbXSeD5gIKkrlFG_vUq0IXhxwZOAULL2y4ucnbSD3gF
    allowedAudiences: myApiAudience
```

* No security web filter is involved in this scenario.
* The `allowedAudiences` specifies which audience(s) (access token `aud` claim) will be allowed.

To programmatically request tokens using client credentials, use the following code:

```java
public class SomeClass {
    @Inject
    private OAuthService oAuthService;
    @Inject
    private SecuritySupport securitySupport;
    
    public void someMethod() {
        OAuthAuthenticationToken tokens = oAuthService.requestTokensWithClientCredentials("email", "profile");

        // Option 1: call a remote API
        String bearerToken = "Bearer " + tokens.getAccessToken();

        // Option 2: login locally
        securitySupport.login(tokens);
    }   
}
```

{{< callout info >}}
We are not specifying the `openid` scope here because OpenIdConnect is often not supported in the *client credentials
flow*, as there is no subject to be authenticated. 
{{< /callout >}}

From there you have two options:

* Option 1: use the `getAccessToken()` method on the returned object to access a protected resource, like a remote API.
* Option 2: use the returned object to login locally using `securitySupport.login(tokens)` method.

## All configuration options

All configuration options are described below:

{{% config p="security.oauth" %}}
```yaml
security:
  oauth:
    # This url defines how clients dynamically discover information about authorization server.
    discoveryDocument: (Absolute url as a String)

    # This sections allows to manually configure the provider details (and/or override discovered information)
    provider:
      # Authorization endpoint
      authorization: (Absolute url as a String)
      # Token endpoint
      token: (Absolute url as a String)
      # Revocation endpoint
      revocation: (Absolute url as a String)
      # User info endpoint
      userInfo: (Absolute url as a String)
      # JWKS url
      jwks: (Absolute url as a String)
      # Issuer
      issuer: (String)

    # This sections allows to manually configure accepted cryptographic algorithms
    algorithms:
      # Access token signing algorithm (RS256 by default)
      accessSigningAlgorithm: (String)
      # Id token signing algorithm (RS256 by default)
      idSigningAlgorithm: (String)
      # If true, unsecured (unsigned) tokens are accepted (false by default) 
      plainTokenAllowed: (boolean)

    # Redirection URI when configured for authorization code flow
    redirect: (Absolute url in String format)

    # Client identifier when the application acts as OAuth/OpenIdConnect client
    clientId: (String)
    # Client secret when the application acts as OAuth/OpenIdConnect client
    clientSecret: (String)
    # Requested scopes when the application acts as OAuth/OpenIdConnect client
    scopes: (List of comma separated String values)
  
    # Required claims in the access token (["sub"] by default)
    requiredClaims: (Set<String>)
    # Prohibited claims in the access token (empty set by default)
    prohibitedClaims: (Set<String>)
    # Allowed audiences for the access token ("aud" claim, empty set by default)
    allowedAudiences: (Set<String>)
    # Custom parameters to be sent to the authorization server when requesting tokens (as query params)
    customParameters: (Map<String, List<String>>)

    # Class implementing validation for opaque access tokens (default to userInfo request if endpoint is configured)
    accessTokenValidator: (Class<? extends AccessTokenValidator>)
    # If true, the user info endpoint will be requested if it is configured to enrich principals with subject personal claims (false by default)
    autoFetchUserInfo: (boolean)
    # If true, the scopes will be treated as realm roles instead of direct subject permissions roles (false by default)
    treatScopesAsRoles: (boolean)
```
{{% /config %}}  

## Examples

Working examples for the three common scenarios described in this page are available at https://github.com/seedstack/samples/tree/master/addons/oauth.

## Advanced configuration

### Scopes interpretation

By default the add-on will treat OAuth scopes as subject permission (like `order:refund`, `product:edit`, ...). While this is the obvious interpretation of the OAuth protocol, it bypasses the usual SeedStack roles/permissions mapping mechanism. If you want to use this mechanism, set the `treatScopesAsRoles` option to `true`:

```yaml
oauth:
    treatScopesAsRoles: true
```

Scopes will then be used as realm roles that can be [mapped to applicative roles]({{< ref "docs/core/security.md#role-mapper" >}}), which in turn can be [resolved to permissions]({{< ref "docs/core/security.md#permission-resolver" >}}).

### Audiences

It is good practice to only allow OAuth tokens that are intended for your application or API. In that spirit, the token validation mechanism has a default audience check: it will only allow tokens that have an `aud` containing the application identifier (`application.id` config option). You cannot always make the application id match the `aud` claim, so you can override the allowed audiences like this:

```yaml
oauth:
    allowedAudiences: [ 'myAudience' ]
```

If you want to allow tokens without audience, add a null to the set of allowed audiences:

```yaml
oauth:
    allowedAudiences: [ ~ ]
```

