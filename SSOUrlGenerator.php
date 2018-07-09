<?php

namespace Happyr\Auth0Bundle;

use Happyr\Auth0Bundle\Security\CsrfProtection;


class SSOUrlGenerator
{
    /** @var string */
    protected $auth0Domain;
    /** @var string */
    protected $auth0ClientId;
    /** @var string */
    protected $scope;
    /** @var CsrfProtection */
    protected $csrfProtection;

    public function __construct($auth0Domain, $auth0ClientId, $scope, CsrfProtection $csrfProtection)
    {
        $this->auth0Domain = $auth0Domain;
        $this->auth0ClientId = $auth0ClientId;
        $this->scope = $scope;
        $this->csrfProtection = $csrfProtection;
    }

    public function generateUrl($redirectUri, array $options = [])
    {
        $query = [
            'client_id' => $this->auth0ClientId,
            'redirect_uri' => $redirectUri,
            'response_type' => 'code',
            'scope' => implode(' ', $this->scope),
        ];

        if ($this->csrfProtection->isEnabled()) {
            if (isset($options['state'])) {
                $state = json_decode(base64_decode($options['state']), true);
            }

            $csrfToken = $this->csrfProtection->manager()->getToken('auth0-sso');

            $state['nonce'] = $csrfToken->getValue();

            $options['state'] = base64_encode(json_encode($state));
        }

        $query = array_merge($query, $options);

        return sprintf('https://%s/authorize?%s', $this->auth0Domain, http_build_query($query));
    }
}
