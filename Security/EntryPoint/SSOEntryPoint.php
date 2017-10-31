<?php

namespace Happyr\Auth0Bundle\Security\EntryPoint;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Csrf\CsrfTokenManager;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Http\HttpUtils;

/**
 * @author Tobias Nyholm <tobias.nyholm@gmail.com>
 */
class SSOEntryPoint implements AuthenticationEntryPointInterface
{
    /**
     * @var CsrfTokenManager
     */
    private $csrfTokenManager;

    /**
     * @var HttpUtils
     */
    private $httpUtils;

    /**
     * @var string
     */
    private $auth0ClientId;

    /**
     * @var string
     */
    private $auth0Domain;

    /**
     * @var string
     */
    private $callbackPath;

    /**
     * @var boolean
     */
    private $useLocalLogin;

    /**
     * @var string
     */
    private $loginPath;

    /**
     * @param HttpUtils $httpUtils
     * @param $auth0ClientId
     * @param string $auth0Domain
     */
    public function __construct(CsrfTokenManager $csrfTokenManager = null, HttpUtils $httpUtils, $auth0ClientId, $auth0Domain, $callbackPath, $loginPath, $useLocalLogin = false)
    {
        $this->csrfTokenManager = $csrfTokenManager;
        $this->httpUtils = $httpUtils;
        $this->auth0ClientId = $auth0ClientId;
        $this->auth0Domain = $auth0Domain;
        $this->callbackPath = $callbackPath;
        $this->loginPath = $loginPath;
        $this->useLocalLogin = $useLocalLogin;
    }

    /**
     * {@inheritdoc}
     */
    public function start(Request $request, AuthenticationException $authException = null)
    {
        if ($this->useLocalLogin) {
            return $this->httpUtils->createRedirectResponse($request, $this->loginPath);
        }

        $query = [
            'client_id' => $this->auth0ClientId,
            'redirect_uri' => $this->httpUtils->generateUri($request, $this->callbackPath),
            'response_type' => 'code',
            'language' => $request->getLocale(),
        ];

        if ($this->csrfTokenManager) {
            $csrfToken = $this->csrfTokenManager->getToken('auth0-sso');

            $stateParameter = [
                'nonce' => $csrfToken->getValue(),
            ];

            $query['state'] = base64_encode(json_encode($stateParameter));
        }

        return new RedirectResponse(sprintf('https://%s/authorize?%s', $this->auth0Domain, http_build_query($query)));
    }
}
