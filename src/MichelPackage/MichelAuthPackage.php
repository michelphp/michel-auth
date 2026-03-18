<?php

namespace Michel\Auth\MichelPackage;

use Michel\Auth\Command\AuthPasswordHashCommand;
use Michel\Auth\Handler\FormAuthHandler;
use Michel\Auth\Handler\HttpBasicAuthHandler;
use Michel\Auth\Handler\TokenAuthHandler;
use Michel\Auth\Middlewares\FormAuthMiddleware;
use Michel\Auth\Middlewares\HttpBasicAuthMiddleware;
use Michel\Auth\Middlewares\TokenAuthMiddleware;
use Michel\Auth\UserProviderInterface;
use Michel\Package\PackageInterface;
use Michel\Session\Storage\SessionStorageInterface;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Log\LoggerInterface;

class MichelAuthPackage implements PackageInterface
{

    public function getDefinitions(): array
    {
        return [
            FormAuthMiddleware::class => static function (ContainerInterface $container) {
                return new FormAuthMiddleware(
                    $container->get(FormAuthHandler::class),
                    $container->get(ResponseFactoryInterface::class),
                    $container->get(LoggerInterface::class)
                );
            },
            TokenAuthMiddleware::class => static function (ContainerInterface $container) {
                return new TokenAuthMiddleware(
                    $container->get(TokenAuthHandler::class),
                    $container->get(ResponseFactoryInterface::class),
                    $container->get(LoggerInterface::class)
                );
            },
            HttpBasicAuthMiddleware::class => static function (ContainerInterface $container) {
                return new HttpBasicAuthMiddleware(
                    $container->get(HttpBasicAuthHandler::class),
                    $container->get(ResponseFactoryInterface::class),
                    $container->get(LoggerInterface::class)
                );
            },
            FormAuthHandler::class => static function (ContainerInterface $container) {
                return new FormAuthHandler(
                    $container->get(UserProviderInterface::class),
                    $container->get(SessionStorageInterface::class),
                    [
                        'login_path' => $container->get('auth.form.login_path'),
                        'logout_path' => $container->get('auth.form.logout_path'),
                        'login_key' => $container->get('auth.form.login_key'),
                        'password_key' => $container->get('auth.form.password_key'),
                        'on_failure' => $container->get('auth.form.on_failure')
                    ]
                );
            },
            TokenAuthHandler::class => static function (ContainerInterface $container) {
                return new TokenAuthHandler(
                    $container->get(UserProviderInterface::class),
                    $container->get('auth.token.header_name'),
                    $container->get('auth.token.on_failure')
                );
            },
            HttpBasicAuthHandler::class => static function (ContainerInterface $container) {
                return new HttpBasicAuthHandler(
                    $container->get(UserProviderInterface::class),
                    $container->get('auth.http.basic.realm'),
                    $container->get('auth.http.basic.on_failure')
                );
            }
        ];
    }

    public function getParameters(): array
    {
        return [
            'auth.form.login_path' => '/login',
            'auth.form.logout_path' => '/logout',
            'auth.form.login_key' => '_username',
            'auth.form.password_key' => '_password',
            'auth.form.on_failure' => null,

            'auth.token.header_name' => 'X-Api-Key',
            'auth.token.on_failure' => null,

            'auth.http.basic.realm' => 'Restricted Area',
            'auth.http_basic.on_failure' => null
        ];
    }

    public function getRoutes(): array
    {
        return [];
    }

    public function getControllerSources(): array
    {
        return [];
    }

    public function getListeners(): array
    {
        return [];
    }

    public function getCommandSources(): array
    {
        return [
            AuthPasswordHashCommand::class
        ];
    }
}
