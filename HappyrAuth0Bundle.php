<?php

namespace Happyr\Auth0Bundle;

use Happyr\Auth0Bundle\Security\Factory\Auth0LogoutFactory;
use Happyr\Auth0Bundle\Security\Factory\SSOFactory;
use Symfony\Bundle\SecurityBundle\DependencyInjection\SecurityExtension;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;

class HappyrAuth0Bundle extends Bundle
{
    public function build(ContainerBuilder $container)
    {
        parent::build($container);

        if ($container->hasExtension('security')) {
            /** @var SecurityExtension $extension */
            $extension = $container->getExtension('security');
            $extension->addSecurityListenerFactory(new SSOFactory());
            $extension->addSecurityListenerFactory(new Auth0LogoutFactory());
        }
    }
}
