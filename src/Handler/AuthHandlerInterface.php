<?php

namespace Michel\Auth\Handler;

use Michel\Auth\AuthIdentity;
use Michel\Auth\Exception\AuthenticationException;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

interface AuthHandlerInterface
{
    /**
     * @throws AuthenticationException
     */
    public function authenticate(ServerRequestInterface $request):  ?AuthIdentity;

    public function onFailure(
        ServerRequestInterface $request,
        ResponseFactoryInterface $responseFactory,
        ?AuthenticationException $exception = null
    ): ResponseInterface;
}
