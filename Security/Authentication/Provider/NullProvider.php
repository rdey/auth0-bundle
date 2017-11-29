<?php
declare(strict_types=1);

namespace Happyr\Auth0Bundle\Security\Authentication\Provider;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

final class NullProvider implements AuthenticationProviderInterface
{
    public function authenticate(TokenInterface $token)
    {
        return $token;
    }

    public function supports(TokenInterface $token)
    {
        return false;
    }

}