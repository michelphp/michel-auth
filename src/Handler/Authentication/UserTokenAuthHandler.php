<?php

namespace Michel\Auth\Handler\Authentication;

use Michel\Auth\AuthIdentity;
use Michel\Auth\Exception\AuthenticationException;
use Michel\Auth\Exception\InvalidCredentialsException;
use Michel\Auth\Exception\UserNotFoundException;
use Michel\Auth\UserInterface;
use Michel\Auth\UserProviderInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class UserTokenAuthHandler implements AuthHandlerInterface
{
    private UserProviderInterface $userProvider;

    private string $headerName;

    /**
     * @var callable|null
     */
    private $onFailure;
    public function __construct(
        UserProviderInterface $userProvider,
        string                $headerName,
        callable              $onFailure = null
    )
    {
        $this->userProvider = $userProvider;
        $this->headerName = $headerName;
        $this->onFailure = $onFailure;
    }


    /**
     * @throws AuthenticationException
     * @throws UserNotFoundException
     * @throws InvalidCredentialsException
     */
    public function authenticate(ServerRequestInterface $request): ?AuthIdentity
    {
        $token = $request->getHeaderLine($this->headerName);
        if (empty($token)) {
            throw new AuthenticationException("Token is required.");
        }

        $user = $this->userProvider->findByToken($token);
        if (!$user instanceof UserInterface) {
            throw new InvalidCredentialsException("The provided API key is invalid.");
        }
        return new AuthIdentity($user,  false);
    }

    public function onFailure(ServerRequestInterface $request, ResponseFactoryInterface $responseFactory, ?AuthenticationException $exception = null): ResponseInterface
    {
        if (!is_callable($this->onFailure)) {
            $status = 401;
            $message = $exception ? $exception->getMessage() : "Unauthorized access.";
            $payload = [
                'status' => $status,
                'title'  => 'Authentication Failed',
                'detail' => $message,
            ];

            $response = $responseFactory->createResponse($status);
            $response->getBody()->write(json_encode($payload, JSON_UNESCAPED_SLASHES ));
            return $response
                ->withHeader('Content-Type', 'application/json')
                ->withHeader('Cache-Control', 'no-store');

        }
        return ($this->onFailure)($request, $responseFactory, $exception);
    }

}
