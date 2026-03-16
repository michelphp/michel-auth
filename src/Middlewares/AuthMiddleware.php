<?php

namespace Michel\Auth\Middlewares;

use Michel\Auth\AuthHandlerInterface;
use Michel\Auth\AuthIdentity;
use Michel\Auth\Exception\AuthenticationException;
use Michel\Auth\Helper\IpHelper;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;

final class AuthMiddleware implements MiddlewareInterface
{
    private AuthHandlerInterface $authHandler;
    private ResponseFactoryInterface $responseFactory;
    private ?LoggerInterface $logger;

    public function __construct(
        AuthHandlerInterface $authHandler,
        ResponseFactoryInterface $responseFactory,
        LoggerInterface $logger = null
    )
    {
        $this->authHandler = $authHandler;
        $this->responseFactory = $responseFactory;
        $this->logger = $logger;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $handlerName = get_class($this->authHandler);

        try {
            $authIdentity = $this->authHandler->authenticate($request);
            if (!$authIdentity instanceof AuthIdentity) {
                return $handler->handle($request);
            }
            $user = $authIdentity->getUser();
            $request = $request->withAttribute("user", $user);
            if ($authIdentity->isNewLogin()) {
                $this->log('info',
                    '[{handler}] User authenticated successfully (identifier: {identifier}, ip: {ip})',
                    [
                        'handler'    => $handlerName,
                        'identifier' => $user->getUserIdentifier(),
                        'ip'         => IpHelper::getIpFromRequest($request),
                    ]
                );
            }
            return $handler->handle($request);
        }catch (AuthenticationException $exception) {
            $this->log(
                'warning',
                '[{handler}] Authentication failed (ip: {ip}, path: {path}) : {message}',
                [
                    'handler' => $handlerName,
                    'message' => $exception->getMessage(),
                    'ip'      => IpHelper::getIpFromRequest($request),
                    'path'    => $request->getUri()->getPath(),
                ]
            );
            return $this->authHandler->onFailure($request, $this->responseFactory, $exception);
        }
    }


    private function log(string $level, string $message, array $context = []): void
    {
        if ($this->logger === null) {
            return;
        }
        $this->logger->log($level, $message, $context);
    }
}
