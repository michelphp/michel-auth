<?php

namespace Michel\Auth\Handler\Authentication;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

interface StatefulAuthHandlerInterface
{
    public function onSuccess(ServerRequestInterface $request, ResponseFactoryInterface $responseFactory): ?ResponseInterface;
}
