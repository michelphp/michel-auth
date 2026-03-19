<?php

namespace Michel\Auth\Middlewares\Guard;

use Michel\Auth\AuthIdentity;
use Michel\Auth\Exception\AuthenticationException;
use Michel\Auth\Handler\Authentication\AuthHandlerInterface;
use Michel\Auth\Handler\Authentication\StatefulAuthHandlerInterface;
use Michel\Auth\Handler\Guard\GuardHandlerInterface;
use Michel\Auth\Helper\IpHelper;
use Michel\Auth\UserInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;

abstract class GuardMiddleware implements MiddlewareInterface
{
    private GuardHandlerInterface $guardHandler;
    private ResponseFactoryInterface $responseFactory;
    private ?LoggerInterface $logger;

    public function __construct(
        GuardHandlerInterface     $guardHandler,
        ResponseFactoryInterface $responseFactory,
        LoggerInterface          $logger = null
    )
    {
        $this->guardHandler = $guardHandler;
        $this->responseFactory = $responseFactory;
        $this->logger = $logger;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $handlerName = get_class($this->guardHandler);
        if ($request->getAttribute('user') instanceof UserInterface) {
            return $handler->handle($request);
        }

        try {
            $this->guardHandler->check($request);
            return $handler->handle($request);
        }catch (AuthenticationException $exception) {
            if ($this->logger) {
                $this->logger->log(
                    'warning',
                    '[{handler}] Authentication failed (ip: {ip}, path: {path}) : {message}',
                    [
                        'handler' => $handlerName,
                        'message' => $exception->getMessage(),
                        'ip'      => IpHelper::getIpFromRequest($request),
                        'path'    => $request->getUri()->getPath(),
                    ]
                );
            }
            return $this->guardHandler->onFailure($request, $this->responseFactory, $exception);
        }
    }

}
