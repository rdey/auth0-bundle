<?php

namespace Happyr\Auth0Bundle\Twig;

use Symfony\Component\Security\Csrf\CsrfTokenManager;

class Auth0Extension extends \Twig_Extension
{
    private $csrfTokenManager;

    /**
     * @var array
     */
    private $scopes;

    public function __construct(array $scopes, CsrfTokenManager $csrfTokenManager = null)
    {
        $this->csrfTokenManager = $csrfTokenManager;
        $this->scopes = $scopes;
    }

    public function getName()
    {
        return 'state_parameter_extension';
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
        ];
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
}
