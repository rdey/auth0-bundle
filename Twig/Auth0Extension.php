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
    /** @var  string */
    protected $auth0Domain;
    /** @var  string */
    protected $auth0ClientId;

    public function __construct(array $scopes, SSOUrlGenerator $generator, $auth0Domain, $auth0ClientId, CsrfTokenManager $csrfTokenManager = null)
    {
        $this->csrfTokenManager = $csrfTokenManager;
        $this->scopes = $scopes;
        $this->generator = $generator;
        $this->auth0Domain = $auth0Domain;
        $this->auth0ClientId = $auth0ClientId;
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
            return [
                'csrf_token' => $this->csrfTokenManager->getToken('auth0-sso')->getValue(),
                'domain' => $this->auth0Domain,
                'client_id' => $this->auth0ClientId
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
