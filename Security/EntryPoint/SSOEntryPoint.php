<?php

namespace Happyr\Auth0Bundle\Security\EntryPoint;

use Happyr\Auth0Bundle\SSOUrlGenerator;
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
     * @var array
     */
    private $scope;
    /**
     * @var SSOUrlGenerator
     */
    private $ssoUrlGenerator;

    /**
     * @param HttpUtils $httpUtils
     * @param $auth0ClientId
     * @param string $auth0Domain
     */
    public function __construct(CsrfTokenManager $csrfTokenManager = null, HttpUtils $httpUtils, SSOUrlGenerator $ssoUrlGenerator, $callbackPath, $loginPath, $useLocalLogin = false)
    {
        $this->csrfTokenManager = $csrfTokenManager;
        $this->httpUtils = $httpUtils;
        $this->callbackPath = $callbackPath;
        $this->loginPath = $loginPath;
        $this->useLocalLogin = $useLocalLogin;
        $this->ssoUrlGenerator = $ssoUrlGenerator;
    }

    /**
     * {@inheritdoc}
     */
    public function start(Request $request, AuthenticationException $authException = null)
    {
        if ($this->useLocalLogin) {
            return $this->httpUtils->createRedirectResponse($request, $this->loginPath);
        }

        $options = [];
        if ($returnUrl = $request->query->get('returnUrl')) {
            $stateParameter = [
                'returnUrl' => $returnUrl,
            ];

            $options = ['state' => base64_encode(json_encode($stateParameter))];
        }

        return new RedirectResponse($this->ssoUrlGenerator->generateUrl($this->httpUtils->generateUri($request, $this->callbackPath), $options));
    }
}
