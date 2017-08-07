<?php

namespace Happyr\Auth0Bundle;

use Happyr\Auth0Bundle\Security\Factory\SSOFactory;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;

class HappyrAuth0Bundle extends Bundle
{
    public function build(ContainerBuilder $container)
    {
        parent::build($container);

        if ($container->hasExtension('security') && $container->has('happyr.auth0.security.authentication.provider.sso')) {
            $extension = $container->getExtension('security');
            $extension->addSecurityListenerFactory(new SSOFactory());
        }
    }
}
