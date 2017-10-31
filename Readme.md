# Auth0 integration with Symfony

[![Latest Version](https://img.shields.io/github/release/Happyr/auth0-bundle.svg?style=flat-square)](https://github.com/Happyr/auth0-bundle/releases)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE)
[![Build Status](https://img.shields.io/travis/Happyr/auth0-bundle.svg?style=flat-square)](https://travis-ci.org/Happyr/auth0-bundle)
[![Code Coverage](https://img.shields.io/scrutinizer/coverage/g/Happyr/auth0-bundle.svg?style=flat-square)](https://scrutinizer-ci.com/g/Happyr/auth0-bundle)
[![Quality Score](https://img.shields.io/scrutinizer/g/Happyr/auth0-bundle.svg?style=flat-square)](https://scrutinizer-ci.com/g/Happyr/auth0-bundle)
[![Total Downloads](https://img.shields.io/packagist/dt/happyr/auth0-bundle.svg?style=flat-square)](https://packagist.org/packages/happyr/auth0-bundle)

### Warning

This bundle is in very early development. However, it is being used in production for at least 3 applications.

### Installation

Install with Composer:

```bash
composer require happyr/auth0-bundle auth0/auth0-php:@alpha php-http/message php-http/guzzle6-adapter
```

Enable the bundle in AppKernel.php

```php
public function registerBundles()
{
    $bundles = [
        // ...
        new \Happyr\Auth0Bundle\HappyrAuth0Bundle(),
    ];

    return $bundles;
}
```

Add your credentials:

```yaml
// app/config/config.yml
happyr_auth0:
  domain: example.eu.auth0.com
  client_id: my_client_id
  client_secret: my_secret
  cache: 'cache.provider.apc'
```

Configure your application for Single Sign On (SSO).

```yaml
// app/config/security.yml
security:
  firewalls:
    default:
      pattern:  ^/.*
      entry_point: 'happyr.auth0.security.authentication.entry_point.sso.default'
      auth0_sso:
        check_path: default_login_check
        login_path: user_login
        failure_path: startpage
      provider: default
      anonymous: ~
      logout:
        path:   default_logout
        target: _user_logout
        invalidate_session: true
```

#### Auth0 Lock ([Documentation][1])

A Twig extension is provided which can be used to include a return url in the state parameter, together with the csrf nonce.

```javascript
  var lock = new Auth0Lock('{{ auth0_client_id }}', '{{ auth0_domain }}', {
    auth: {
      redirectUrl: '{{ auth0_callback_url }}',
      responseType: 'code',
      params: {
        scope: 'openid',
        state: '{{ state_parameter(app.request.uri) }}'
      }
    }
  });
```

There is also an option which may be specified in the firewall to use a local login page, instead of redirecting to the auth0 subdomain.

```yaml
security:
    firewalls:
        default:
            auth0_sso:
                check_path: default_login_check
                login_path: user_login
                use_local_login: true
```

The use-case for this is to use the Auth0 Lock embeddable login form instead of the Auth0 Hosted Login Page while still using SSO.

Sample controller code handling the local login page route, the same route specified as the `login_path` in config.

```php
    /**
     * @Route("/login", name="user_login")
     */
    public function loginAction(Request $request)
    {
        return $this->render('login.html.twig', [
            'forceLogin' => true,
            'sessionUrl' => $this->get('session')->get('_security.default.target_path'),
        ]);
    }
```

Sample template code (the variables `auth0_client_id` and `auth0_domain` are here injected as twig global variables).

```twig
<script src="//cdn.auth0.com/js/lock/10.22.0/lock.min.js"></script>

{% set forceLogin = forceLogin|default(false) %}
{% set sessionUrl = sessionUrl|default(false) %}
<script type="text/javascript">
    var lock = new Auth0Lock('{{ auth0_client_id }}', '{{ auth0_domain }}', {
        {% if forceLogin %}
            closable: false,
        {% endif %}
        auth: {
            redirectUrl: '{{ url("default_login_check") }}',
            responseType: 'code',
            params: {
                scope: 'openid',
                state: '{{ state_parameter(sessionUrl ? sessionUrl : forceLogin ? url("root") : app.request.uri) }}'
            }
        }
    });

    {% if forceLogin %}
        lock.show();
    {% endif %}
</script>
```

[1]: https://auth0.com/docs/libraries/lock/v10


