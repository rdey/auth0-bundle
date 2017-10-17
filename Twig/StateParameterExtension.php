<?php

namespace Happyr\Auth0Bundle\Twig;

use Symfony\Component\Security\Csrf\CsrfTokenManager;

class StateParameterExtension extends \Twig_Extension
{
    private $csrfTokenManager;

    public function __construct(CsrfTokenManager $csrfTokenManager = null)
    {
        $this->csrfTokenManager = $csrfTokenManager;
    }

    public function getName()
    {
        return 'state_parameter_extension';
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
