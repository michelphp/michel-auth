<?php

namespace Michel\Auth\Handler;

use Michel\Auth\AuthIdentity;
use Michel\Auth\Exception\AuthenticationException;
use Michel\Auth\Exception\InvalidCredentialsException;
use Michel\Auth\Exception\UserNotFoundException;
use Michel\Auth\PasswordAuthenticatedUserInterface;
use Michel\Auth\UserInterface;
use Michel\Auth\UserProviderInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class HttpBasicAuthHandler implements AuthHandlerInterface
{
    private string $user;
    private string $password;
    private string $realm;
    /**
     * @var callable|null
     */
    private $onFailure;

    public function __construct(
        string $user,
        string $password,
        string                $realm = "Restricted Area",
        callable              $onFailure = null
    )
    {
        $this->user = $user;
        $this->password = $password;
        $this->realm = $realm;
        $this->onFailure = $onFailure;
    }


    /**
     * @throws AuthenticationException
     * @throws UserNotFoundException
     * @throws InvalidCredentialsException
     */
    public function authenticate(ServerRequestInterface $request): ?AuthIdentity
    {
        $authHeader = $request->getHeaderLine('Authorization');
        if (empty($authHeader)) {
            throw new AuthenticationException("Authentication required.");
        }

        if (0 !== strpos(strtolower($authHeader), 'basic ')) {
            throw new AuthenticationException("Only Basic authentication is allowed.");
        }

        $base64Credentials = substr($authHeader, 6);
        $credentials = base64_decode($base64Credentials);
        if (false === $credentials || false === strpos($credentials, ':')) {
            throw new InvalidCredentialsException("Malformed credentials.");
        }

        [$login, $password] = explode(':', $credentials, 2);
        $login = trim($login);

        if ($login !== $this->user || $password !== $this->password) {
            throw new InvalidCredentialsException("Access denied.");
        }

        return null;
    }

    public function onFailure(ServerRequestInterface $request, ResponseFactoryInterface $responseFactory, ?AuthenticationException $exception = null): ResponseInterface
    {
        if (is_callable($this->onFailure)) {
            return ($this->onFailure)($request, $responseFactory, $exception);
        }

        $response = $responseFactory->createResponse(401);
        return $response
            ->withHeader('WWW-Authenticate', sprintf('Basic realm="%s", charset="UTF-8"', $this->realm))
            ->withHeader('Content-Type', 'text/plain')
            ->withHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    }
}
