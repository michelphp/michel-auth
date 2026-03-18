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
    private UserProviderInterface $userProvider;

    private string $realm;
    /**
     * @var callable|null
     */
    private $onFailure;
    public function __construct(
        UserProviderInterface $userProvider,
         string $realm = "Restricted Area",
        callable              $onFailure = null
    )
    {
        $this->userProvider = $userProvider;
        $this->onFailure = $onFailure;
        $this->realm = $realm;
    }


    /**
     * @throws AuthenticationException
     * @throws UserNotFoundException
     * @throws InvalidCredentialsException
     */
    public function authenticate(ServerRequestInterface $request): ?AuthIdentity
    {
        $authHeader = $request->getHeaderLine('Authorization');
        if (0 !== strpos(strtolower($authHeader), 'basic ')) {
            return null;
        }

        $base64Credentials = substr($authHeader, 6);
        $credentials = base64_decode($base64Credentials);
        if (false === $credentials || false === strpos($credentials, ':')) {
            throw new InvalidCredentialsException("Invalid Basic Auth format.");
        }

        [$login, $password] = explode(':', $credentials, 2);
        $login = trim($login);
        /**
         * @var PasswordAuthenticatedUserInterface|UserInterface $user
         */
        $user = $this->userProvider->findByIdentifier($login);
        if (!$user instanceof UserInterface) {
            throw new UserNotFoundException("User not found.");
        }

        if (!$user instanceof PasswordAuthenticatedUserInterface || !$this->userProvider->isPasswordValid($user, $password)) {
            throw new InvalidCredentialsException("Invalid username or password.");
        }

        return new AuthIdentity($user, false);
    }

    public function onFailure(ServerRequestInterface $request, ResponseFactoryInterface $responseFactory, ?AuthenticationException $exception = null): ResponseInterface
    {
        if (is_callable($this->onFailure)) {
            return ($this->onFailure)($request, $responseFactory, $exception);
        }

        return $responseFactory->createResponse(401)
            ->withHeader('WWW-Authenticate', sprintf('Basic realm="%s"', $this->realm))
            ->withHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    }
}
