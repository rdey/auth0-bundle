<?php

namespace Happyr\Auth0Bundle\Security\Firewall;

use Auth0\SDK\API\Authentication;
use Auth0\SDK\Exception;
use Auth0\SDK\Exception\ApiException;
use Auth0\SDK\Exception\CoreException;
use Happyr\Auth0Bundle\Model\Authentication\Claims;
use Happyr\Auth0Bundle\Model\Authorization\Token\Token;
use Happyr\Auth0Bundle\Security\Authentication\Token\SSOToken;
use Happyr\Auth0Bundle\Security\CsrfProtection;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManager;
use Symfony\Component\Security\Http\Firewall\AbstractAuthenticationListener;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Security\Http\HttpUtils;


/**
 * @author Tobias Nyholm <tobias.nyholm@gmail.com>
 */
class SSOListener extends AbstractAuthenticationListener
{
    /**
     * @var Authentication
     */
    private $authenticationApi;

    /**
     * @var string
     */
    private $callbackPath;

    /**
     * @var CsrfProtection
     */
    private $csrfProtection;

    /** @var string */
    private $clientSecret;

    /** @var TokenStorageInterface */
    private $tokenStore;

    /**
     * SSOListener constructor.
     */
    public function __construct(TokenStorageInterface $tokenStorage, AuthenticationManagerInterface $authenticationManager, SessionAuthenticationStrategyInterface $sessionStrategy, HttpUtils $httpUtils, $providerKey, AuthenticationSuccessHandlerInterface $successHandler, AuthenticationFailureHandlerInterface $failureHandler, array $options = array(), LoggerInterface $logger = null, EventDispatcherInterface $dispatcher = null)
    {
        $this->tokenStore = $tokenStorage;
        parent::__construct($tokenStorage, $authenticationManager, $sessionStrategy, $httpUtils, $providerKey, $successHandler, $failureHandler, $options, $logger, $dispatcher);
    }

    public function setCsrfProtection(CsrfProtection $csrfProtection)
    {
        $this->csrfProtection = $csrfProtection;
    }

    public function setClientSecret(string $clientSecret)
    {
        $this->clientSecret = $clientSecret;
    }

    /**
     * @param Authentication $authenticationApi
     */
    public function setAuthenticationApi($authenticationApi)
    {
        $this->authenticationApi = $authenticationApi;
    }

    /**
     * @param string $callbackPath
     *
     * @return SSOListener
     */
    public function setCallbackPath($callbackPath)
    {
        $this->callbackPath = $callbackPath;

        return $this;
    }

    /**
     * Whether this request requires authentication.
     *
     * The default implementation only processes requests to a specific path,
     * but a subclass could change this to only authenticate requests where a
     * certain parameters is present.
     *
     * @param Request $request
     *
     * @return bool
     */
    protected function requiresAuthentication(Request $request)
    {
        if ($this->currentSSOTokenIsExpired()) {
            return true;
        }

        return parent::requiresAuthentication($request);
    }

    protected function attemptAuthentication(Request $request)
    {
        // We're doing a regular code-based authentication.
        if (parent::requiresAuthentication($request)) {
            return $this->attemptAuthenticationUsingCode($request);
        }

        $token = $this->tokenStore->getToken();

        if ($token instanceof SSOToken && $token->isExpired()) {
            $refreshToken = $token->getRefreshToken();

            $this->tokenStore->setToken(null);

            if ($refreshToken) {
                return $this->attemptAuthenticationUsingRefreshToken($refreshToken);
            }
        }

        return null;
    }

    protected function attemptAuthenticationUsingRefreshToken($refreshToken)
    {
        try {
            $tokenStruct = $this->authenticationApi->refreshTokenExchange($refreshToken);
        } catch (ApiException $e) {
            throw new AuthenticationException("Unable to authenticate", 0, $e);
        }

        $auth0Token = Token::create($tokenStruct);

        $token = new SSOToken();
        $token->setCreatedFromRefreshToken(true);
        $token->setExpiresAt($auth0Token->getExpiresAt());
        $token->setRefreshToken($refreshToken);

        if ($auth0Token->getAccessToken()) {
            $token->setAccessToken($auth0Token->getAccessToken());
        }

        if ($auth0Token->getIdToken()) {
            $token->setIdToken(Claims::createFromJWT($auth0Token->getIdToken(), $this->clientSecret));
        }

        return $this->authenticationManager->authenticate($token);
    }


    protected function attemptAuthenticationUsingCode(Request $request)
    {
        if (null === $code = $request->query->get('code')) {
            throw new AuthenticationException('No oauth code in the request.');
        }

        $stateParameter = null;
        if ($state = $request->query->get('state')) {
            $stateParameter = json_decode(base64_decode($state), true);
        }

        if ($this->csrfProtection->isEnabled()) {
            if (null === $stateParameter || !isset($stateParameter['nonce'])) {
                throw new AuthenticationException('No state nonce in the request.');
            }

            if (!$this->csrfProtection->manager()->isTokenValid(new CsrfToken('auth0-sso', $stateParameter['nonce']))) {
                throw new AuthenticationException('Invalid CSRF token');
            }
        }

        if (isset($stateParameter['returnUrl'])) {
            $request->getSession()->set('_security.'.$this->providerKey.'.target_path', $stateParameter['returnUrl']);
        }

        try {
            $redirectUri = $this->httpUtils->generateUri($request, $this->callbackPath);
            $tokenStruct = $this->authenticationApi->codeExchange($code, $redirectUri);
        } catch (Exception\ForbiddenException $e) {
            throw new AuthenticationException($e->getMessage(), $e->getCode(), $e);
        }

        // TODO, remove this legacy code
        if (isset($tokenStruct['error'])) {
            switch ($tokenStruct['error']) {
                case 'invalid_grant':
                    throw new AuthenticationException($tokenStruct['error_description']);
                default:
                    throw new CoreException($tokenStruct['error_description']);
            }
        }

        $auth0Token = Token::create($tokenStruct);

        $token = new SSOToken();
        $token->setExpiresAt($auth0Token->getExpiresAt());

        if ($auth0Token->getAccessToken()) {
            $token->setAccessToken($auth0Token->getAccessToken());
        }

        if ($auth0Token->getIdToken()) {
            $token->setIdToken(Claims::createFromJWT($auth0Token->getIdToken(), $this->clientSecret));
        }

        if ($auth0Token->getRefreshToken()) {
            $token->setRefreshToken($auth0Token->getRefreshToken());
        }

        return $this->authenticationManager->authenticate($token);
    }

    protected function currentSSOTokenIsExpired()
    {
        $token = $this->tokenStore->getToken();

        if ($token instanceof SSOToken) {
            if ($token->isExpired()) {
                return true;
            }
        }

        return false;
    }
}
