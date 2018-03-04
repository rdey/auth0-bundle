<?php

namespace Happyr\Auth0Bundle\Twig;

use Happyr\Auth0Bundle\SSOUrlGenerator;
use Symfony\Component\Security\Csrf\CsrfTokenManager;

class Auth0Extension extends \Twig_Extension
{
    private $csrfTokenManager;

    /**
     * @var array
     */
    private $scopes;
    /**
     * @var SSOUrlGenerator
     */
    private $generator;

    public function __construct(array $scopes, SSOUrlGenerator $generator, CsrfTokenManager $csrfTokenManager = null)
    {
        $this->csrfTokenManager = $csrfTokenManager;
        $this->scopes = $scopes;
        $this->generator = $generator;
    }

    public function getName()
    {
        return 'auth0_extension';
    }

    public function getGlobals()
    {
        return [
            'auth0_scope' => implode($this->scopes, ' '),
        ];
    }

    public function getFunctions()
    {
        return [
            new \Twig_SimpleFunction('state_parameter', [$this, 'stateParameter']),
            new \Twig_SimpleFunction('sso_params', [$this, 'ssoParams']),
            new \Twig_SimpleFunction('sso_login_url', [$this, 'loginUrl']),
        ];
    }

    public function ssoParams()
    {
        if ($this->csrfTokenManager) {
            $csrfToken = $this->csrfTokenManager->getToken('auth0-sso');

            $csrf_token = $csrfToken->getValue();
            $domain = $this->generator->getAuth0Domain();
            $client_id = $this->generator->getAuth0ClientId();
            return [
                'csrf_token' => $csrf_token,
                'domain' => $domain,
                'client_id' => $client_id
            ];
        }

        return [];
    }

    public function stateParameter($uri)
    {
        $stateParameter = [
            'returnUrl' => $uri,
        ];

        if ($this->csrfTokenManager) {
            $csrfToken = $this->csrfTokenManager->getToken('auth0-sso');

            $stateParameter['nonce'] = $csrfToken->getValue();
        }

        return base64_encode(json_encode($stateParameter));
    }

    public function loginUrl($returnUrl, array $options = [])
    {
        return $this->generator->generateUrl($returnUrl, $options);
    }
}
