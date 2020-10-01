<?php

namespace Happyr\Auth0Bundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * This is the class that validates and merges configuration from your app/config files.
 */
class Configuration implements ConfigurationInterface
{
    /**
     * {@inheritdoc}
     */
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder('happyr_auth0');

        if (method_exists($treeBuilder, 'getRootNode')) {
            $rootNode = $treeBuilder->getRootNode();
        } else {
            // BC layer for symfony/config 4.1 and older
            $rootNode = $treeBuilder->root('happyr_auth0');
        }

        $rootNode
            ->children()
                ->scalarNode('domain')->isRequired()->cannotBeEmpty()->end()
                ->scalarNode('client_id')->isRequired()->cannotBeEmpty()->end()
                ->scalarNode('client_secret')->isRequired()->cannotBeEmpty()->end()
                ->scalarNode('cache')->defaultNull()->end()
                ->scalarNode('httplug_client_service')->defaultNull()->end()
                ->scalarNode('csrf_protection')->defaultTrue()->end()
                ->booleanNode('security')->defaultTrue()->info(
                    "Whether or not the SecurityBundle integration should be enabled. Set to false if and only if your app does not use SecurityBundle."
                )->end()
                ->arrayNode('scopes')
                    ->prototype('scalar')->end()
                    ->defaultValue(['openid'])
                    ->validate()
                        ->ifTrue(function($scopes) {
                            return in_array('offline_access', $scopes) && !in_array('openid', $scopes);
                        })
                        ->thenInvalid("If you're requesting the 'offline_access' scope, the bundle requires that you also request the 'openid' scope.")
                    ->end()
                ->end()
            ->end();

        return $treeBuilder;
    }
}
