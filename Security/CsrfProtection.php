<?php

namespace Happyr\Auth0Bundle\Security;

use Exception;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

final class CsrfProtection
{
    private $csrfProtectionEnabled;
    private $csrfTokenManager;

    /**
     * @param bool $csrfProtectionEnabled
     * @param CsrfTokenManagerInterface $csrfTokenManager
     */
    public function __construct(
        $csrfProtectionEnabled = true,
        CsrfTokenManagerInterface $csrfTokenManager
    ) {
        $this->csrfProtectionEnabled = $csrfProtectionEnabled;
        $this->csrfTokenManager = $csrfTokenManager;
    }

    /**
     * @return bool
     */
    public function isEnabled()
    {
        return (bool) $this->csrfProtectionEnabled;
    }

    /**
     * @return CsrfTokenManagerInterface
     * @throws Exception
     */
    public function manager()
    {
        if (!$this->csrfProtectionEnabled) {
            throw new Exception(
                'CSRF protection is disabled, the token manager should not be used.'
            );
        }

        return $this->csrfTokenManager;
    }
}
