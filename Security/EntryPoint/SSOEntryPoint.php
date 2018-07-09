<?php

namespace Happyr\Auth0Bundle\Security\EntryPoint;

use Happyr\Auth0Bundle\SSOUrlGenerator;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Http\HttpUtils;

/**
 * @author Tobias Nyholm <tobias.nyholm@gmail.com>
 */
class SSOEntryPoint implements AuthenticationEntryPointInterface
{
    /**
     * @var HttpUtils
     */
    private $httpUtils;

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
     * @var SSOUrlGenerator
     */
    private $ssoUrlGenerator;

    /**
     * @param HttpUtils $httpUtils
     * @param SSOUrlGenerator $ssoUrlGenerator
     * @param $callbackPath
     * @param $loginPath
     * @param bool $useLocalLogin
     */
    public function __construct(HttpUtils $httpUtils, SSOUrlGenerator $ssoUrlGenerator, $callbackPath, $loginPath, $useLocalLogin = false)
    {
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
