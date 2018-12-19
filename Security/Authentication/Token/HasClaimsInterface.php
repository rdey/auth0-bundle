<?php
declare(strict_types=1);

namespace Happyr\Auth0Bundle\Security\Authentication\Token;


use Happyr\Auth0Bundle\Model\Authentication\Claims;

interface HasClaimsInterface
{
    public function getClaims(): ?Claims;
}
