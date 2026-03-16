<?php

namespace Michel\Auth\Handler;

use Michel\Auth\Exception\AuthenticationException;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

interface StatefulAuthHandlerInterface
{
    public function onSuccess(ServerRequestInterface $request, ResponseFactoryInterface $responseFactory): ?ResponseInterface;
}
