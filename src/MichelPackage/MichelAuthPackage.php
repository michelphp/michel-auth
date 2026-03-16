<?php

namespace Michel\Auth\MichelPackage;

use Michel\Auth\Command\AuthPasswordHashCommand;
use Michel\Auth\Handler\FormAuthAuthHandler;
use Michel\Auth\Middlewares\AuthMiddleware;
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
            AuthMiddleware::class => static function (ContainerInterface $container) {
                return new AuthMiddleware(
                    $container->get(FormAuthAuthHandler::class),
                    $container->get(ResponseFactoryInterface::class),
                    $container->get(LoggerInterface::class)
                );
            },
            FormAuthAuthHandler::class => static function (ContainerInterface $container) {
                return new FormAuthAuthHandler(
                    $container->get(UserProviderInterface::class),
                    $container->get(SessionStorageInterface::class),
                    [
                        'login_path' => $container->get('auth.form_login_path'),
                        'login_key' => $container->get('auth.form_login_key'),
                        'password_key' => $container->get('auth.form_password_key'),
                        'on_failure' => $container->get('auth.form_on_failure')
                    ]
                );
            },
        ];
    }

    public function getParameters(): array
    {
        return [
            'auth.form_login_path' => '/login',
            'auth.form_login_key' => '_username',
            'auth.form_password_key' => '_password',
            'auth.form_on_failure' => null
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
