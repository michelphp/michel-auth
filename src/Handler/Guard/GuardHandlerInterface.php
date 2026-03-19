<?php

namespace Michel\Auth\Handler\Guard;

use Michel\Auth\AuthIdentity;
use Michel\Auth\Exception\AuthenticationException;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

interface GuardHandlerInterface
{

    /**
     * @throws AuthenticationException
     */
    public function check(ServerRequestInterface $request):  void;

    public function onFailure(
        ServerRequestInterface $request,
        ResponseFactoryInterface $responseFactory,
        ?AuthenticationException $exception = null
    ): ResponseInterface;

}
