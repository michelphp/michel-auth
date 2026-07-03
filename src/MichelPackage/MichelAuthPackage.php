<?php

namespace Michel\Auth\MichelPackage;

use Michel\Auth\Command\AuthPasswordHashCommand;
use Michel\Auth\Handler\Authentication\UserFormAuthHandler;
use Michel\Auth\Handler\Authentication\UserTokenAuthHandler;
use Michel\Auth\Handler\Guard\TokenGuardHandler;
use Michel\Auth\Handler\Guard\HttpBasicGuardHandler;
use Michel\Auth\Middlewares\Authentication\UserFormAuthMiddleware;
use Michel\Auth\Middlewares\Authentication\UserTokenAuthMiddleware;
use Michel\Auth\Middlewares\Guard\HttpBasicGuardMiddleware;
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
            UserFormAuthMiddleware::class => static function (ContainerInterface $container) {
                return new UserFormAuthMiddleware(
                    $container->get(UserFormAuthHandler::class),
                    $container->get(ResponseFactoryInterface::class),
                    $container->get(LoggerInterface::class)
                );
            },
            UserTokenAuthMiddleware::class => static function (ContainerInterface $container) {
                return new UserTokenAuthMiddleware(
                    $container->get(UserTokenAuthHandler::class),
                    $container->get(ResponseFactoryInterface::class),
                    $container->get(LoggerInterface::class)
                );
            },
            HttpBasicGuardMiddleware::class => static function (ContainerInterface $container) {
                return new HttpBasicGuardMiddleware(
                    $container->get(HttpBasicGuardHandler::class),
                    $container->get(ResponseFactoryInterface::class),
                    $container->get(LoggerInterface::class)
                );
            },
            UserFormAuthHandler::class => static function (ContainerInterface $container) {
                return new UserFormAuthHandler(
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
            UserTokenAuthHandler::class => static function (ContainerInterface $container) {
                return new UserTokenAuthHandler(
                    $container->get(UserProviderInterface::class),
                    $container->get('auth.token.header_name'),
                    $container->get('auth.token.on_failure')
                );
            },
            HttpBasicGuardHandler::class => static function (ContainerInterface $container) {
                return new HttpBasicGuardHandler(
                    $container->get('guard.basic.user'),
                    $container->get('guard.basic.password'),
                    $container->get('guard.basic.realm'),
                    $container->get('guard.basic.on_failure')
                );
            },
            TokenGuardHandler::class => static function (ContainerInterface $container) {
                return new TokenGuardHandler(
                    $container->get('guard.token.secret'),
                    $container->get('guard.token.header_name'),
                    $container->get('guard.token.on_failure')
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

            'auth.token.header_name' => 'X-AUTH-TOKEN',
            'auth.token.on_failure' => null,

            'guard.basic.user' => '',
            'guard.basic.password' => '',
            'guard.basic.realm' => 'Restricted Area',
            'guard.basic.on_failure' => null,

            'guard.token.secret'      => '',
            'guard.token.header_name' => 'X-API-KEY',
            'guard.token.on_failure'  => null,
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
