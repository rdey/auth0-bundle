<?php
declare(strict_types=1);

namespace Happyr\Auth0Bundle;


use Symfony\Component\Security\Csrf\CsrfTokenManager;

class SSOUrlGenerator
{
    /** @var  string */
    protected $auth0Domain;
    /** @var  string */
    protected $auth0ClientId;
    /** @var  string */
    protected $scope;
    /** @var CsrfTokenManager|null */
    protected $csrfTokenManager;

    /**
     * SSOUrlGenerator constructor.
     */
    public function __construct($auth0Domain, $auth0ClientId, $scope, ?CsrfTokenManager $csrfTokenManager)
    {
        $this->auth0Domain = $auth0Domain;
        $this->auth0ClientId = $auth0ClientId;
        $this->scope = $scope;
        $this->csrfTokenManager = $csrfTokenManager;
    }

    public function generateUrl($redirectUri, $options = [])
    {
        $query = [
            'client_id' => $this->auth0ClientId,
            'redirect_uri' => $redirectUri,
            'response_type' => 'code',
            'scope' => implode(' ', $this->scope),
        ];

        if ($this->csrfTokenManager) {
            $csrfToken = $this->csrfTokenManager->getToken('auth0-sso');

            $stateParameter = [
                'nonce' => $csrfToken->getValue(),
            ];

            $query['state'] = base64_encode(json_encode($stateParameter));
        }

        $query = array_merge($query, $options);

        return sprintf('https://%s/authorize?%s', $this->auth0Domain, http_build_query($query));
    }
    public function getAuth0Domain()
    {
        return $this->auth0Domain;
    }
    public function getAuth0ClientId()
    {
        return $this->auth0ClientId;
    }
}
