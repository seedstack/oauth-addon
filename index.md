---
title: "OAuth"
addon: "OAuth"
repo: "https://github.com/seedstack/oauth-addon"
author: Jyoti ATHALYE 
description: "Provides the ability to authenticate and authorize subjects using OAuth and OpenID Connect."
tags:
    - security
zones:
    - Addons
noMenu: true    
---

Seedstack OAuth add-on provides the ability to authenticate and authorize subjects using OAuth and OpenID Connect.

## Dependencies

{{< dependency g="org.seedstack.addons.oauth" a="oauth" v="1.0.0-SNAPSHOT">}}

### OAuth Pre-requisite

Before starting to use OAuth, the user must create an app with the service, which user wants to access.
During registration user provides basic information such as app name, redirect url etc.
Once registration is complete, user will receive client id, client secret.

## Configuration

To use the oauth add-on, its realm, oauth provider details, filter mapping urls must be specified in security configuration:

{{% config p="oauth" %}}
```yaml
security:
  # Name of realm, responsible for authenticating and authorizing subjects. 
  # Realm fetches user information from the authentication token.
  realms: OAuthRealm
  web:
	#In built filters are invoked based on the provided url mapping.
    urls:
      -
        pattern: /api/provider/**
        filters: anon
      -
	    # Based on the callback url sent by the provider, callback process is invoked.
		# This callback url pattern must match with redirect url set during app registration process.
        pattern: /callback
        filters: oauthCallback
      -
		# Based on the url pattern, oauth process is invoked.
        pattern: /profile.html
        filters: oauth
      - 
	    # Based on the url pattern, oauth process is invoked.
        pattern: /api/**
        filters: oauth
  oauth:
    # This url defines how clients dynamically discover information about OpenID Provider.
    discoveryDocument: (Absolute url in String format)
	
    # Redirection URI to which the authorisation response will be sent.
	redirect: (Absolute url in String format)
	
	# List of available resources, when they are used to access OAuth 2 protected endpoints.
    scopes: (List of comma separated String values)
	
	# Provides information about the service being accessed.
    clientId: (String)
	
	# Means of authorising client.
    clientSecret: (String)
	
	# Name of class which will provide custom validations for token if any.
	accessTokenValidator: (Fully qualified java class name which implements AccessTokenValidator interface)

```	
	
### Example

Assuming, we are using google as the provider(using open id authentication and authorisation mechanism), the following configuration needs to be done.

```yaml
security: 
  realms: OAuthRealm
  web:
    urls:
      -
        pattern: /api/provider/**
        filters: anon
      -
        pattern: /callback
        filters: oauthCallback
      -
        pattern: /profile.html
        filters: oauth
      - 
        pattern: /api/**
        filters: oauth
  oauth:
    discoveryDocument: https://accounts.google.com/.well-known/openid-configuration
	redirect: http://localhost:8080/callback
    scopes: email
    clientId: 243402117109-3ia596dogjjo.client.id
    clientSecret: 2f_1qSp1Nhah9.tclientSecret

```	





