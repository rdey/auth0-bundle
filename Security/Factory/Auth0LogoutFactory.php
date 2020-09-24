<?php
declare(strict_types=1);

namespace Happyr\Auth0Bundle\Security\Factory;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\SecurityFactoryInterface;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\DefinitionDecorator;
use Symfony\Component\DependencyInjection\Reference;

final class Auth0LogoutFactory implements SecurityFactoryInterface
{
    /**
     * Configures the container services required to use the authentication listener.
     *
     * @param ContainerBuilder $container
     * @param string $id The unique id of the firewall
     * @param array $config The options array for the listener
     * @param string $userProvider The service id of the user provider
     * @param string $defaultEntryPoint
     *
     * @return array containing three values:
     *               - the provider id
     *               - the listener id
     *               - the entry point id
     */
    public function create(ContainerBuilder $container, $id, $config, $userProvider, $defaultEntryPoint)
    {
        $listenerKeys[] = 'logout';
        $listenerId = 'happyr_auth0.security.logout_listener.'.$id;

        if (class_exists(ChildDefinition::class)) {
            $definition = new ChildDefinition('happyr.auth0.security.authentication.listener.logout');
        } else {
            $definition = new DefinitionDecorator('happyr.auth0.security.authentication.listener.logout');
        }

        $listener = $container->setDefinition($listenerId, $definition);
        $listener->replaceArgument(3, array(
            'csrf_parameter' => $config['csrf_parameter'],
            'csrf_token_id' => $config['csrf_token_id'],
            'logout_path' => $config['path'],
        ));
        $listeners[] = new Reference($listenerId);

        // always use default success handler
        $logoutSuccessHandlerId = 'happyr_auth0.security.logout.success_handler.'.$id;

        if (class_exists(ChildDefinition::class)) {
            $definition = new ChildDefinition('security.logout.success_handler');
        } else {
            $definition = new DefinitionDecorator('security.logout.success_handler');
        }

        $logoutSuccessHandler = $container->setDefinition($logoutSuccessHandlerId, $definition);
        $logoutSuccessHandler->replaceArgument(1, $config['target']);
        $listener->replaceArgument(2, new Reference($logoutSuccessHandlerId));

        // add CSRF provider
        if (isset($config['csrf_token_generator'])) {
            $listener->addArgument(new Reference($config['csrf_token_generator']));
        }

        // add session logout handler
        if (true === $config['invalidate_session']) {
            $listener->addMethodCall('addHandler', array(new Reference('security.logout.handler.session')));
        }

        // add cookie logout handler
        if (count($config['delete_cookies']) > 0) {
            $cookieHandlerId = 'happyr_auth0.security.logout.handler.cookie_clearing.'.$id;

            if (class_exists(ChildDefinition::class)) {
                $definition = new ChildDefinition('security.logout.handler.cookie_clearing');
            } else {
                $definition = new DefinitionDecorator('security.logout.handler.cookie_clearing');
            }

            $cookieHandler = $container->setDefinition($cookieHandlerId, $definition);
            $cookieHandler->addArgument($config['delete_cookies']);

            $listener->addMethodCall('addHandler', array(new Reference($cookieHandlerId)));
        }

        // add custom handlers
        foreach ($config['handlers'] as $handlerId) {
            $listener->addMethodCall('addHandler', array(new Reference($handlerId)));
        }

        // register with LogoutUrlGenerator
        $container
            ->getDefinition('security.logout_url_generator')
            ->addMethodCall('registerListener', array(
                $id,
                $config['path'],
                $config['csrf_token_id'],
                $config['csrf_parameter'],
                isset($config['csrf_token_generator']) ? new Reference($config['csrf_token_generator']) : null,
                null, // This is wrong in Symfony 4.0. We should be able to detect and pass the firewall context somehow.
            ))
        ;


        return [
            'happyr.auth0.security.authentication.provider.null',
            $listenerId,
            $defaultEntryPoint
        ];
    }

    public function addConfiguration(NodeDefinition $builder)
    {
        $builder
            ->treatTrueLike(array())
            ->canBeUnset()
            ->children()
                ->scalarNode('csrf_parameter')->defaultValue('_csrf_token')->end()
                ->scalarNode('csrf_token_generator')->cannotBeEmpty()->end()
                ->scalarNode('csrf_token_id')->defaultValue('logout')->end()
                ->scalarNode('path')->defaultValue('/logout')->end()
                ->scalarNode('target')->defaultValue('/')->end()
                ->scalarNode('success_handler')->end()
                ->booleanNode('invalidate_session')->defaultTrue()->end()
            ->end()
            ->fixXmlConfig('delete_cookie')
            ->children()
                ->arrayNode('delete_cookies')
                    ->beforeNormalization()
                        ->ifTrue(function ($v) { return is_array($v) && is_int(key($v)); })
                        ->then(function ($v) { return array_map(function ($v) { return array('name' => $v); }, $v); })
                    ->end()
                    ->useAttributeAsKey('name')
                    ->prototype('array')
                        ->children()
                            ->scalarNode('path')->defaultNull()->end()
                            ->scalarNode('domain')->defaultNull()->end()
                        ->end()
                    ->end()
                ->end()
            ->end()
            ->fixXmlConfig('handler')
            ->children()
                ->arrayNode('handlers')
                    ->prototype('scalar')->end()
                ->end()
            ->end()
        ;
    }

    public function getPosition()
    {
        return 'remember_me';
    }

    public function getKey()
    {
        return 'auth0_logout';
    }

}
