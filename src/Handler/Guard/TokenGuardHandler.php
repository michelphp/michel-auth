<?php

namespace Michel\Auth\Handler\Guard;

use Michel\Auth\Exception\AuthenticationException;
use Michel\Auth\Exception\InvalidCredentialsException;
use Michel\Auth\Exception\UserNotFoundException;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class TokenGuardHandler implements GuardHandlerInterface
{
    private string $apiKey;
    private string $headerName;
    /**
     * @var callable|null
     */
    private $onFailure;

    public function __construct(
        string $apiKey,
        string                $headerName,
        callable              $onFailure = null
    )
    {
        $this->apiKey = $apiKey;
        $this->headerName = $headerName;
        $this->onFailure = $onFailure;
    }


    /**
     * @throws AuthenticationException
     * @throws UserNotFoundException
     * @throws InvalidCredentialsException
     */
    public function check(ServerRequestInterface $request): void
    {
        if (empty($this->apiKey)) {
            throw new InvalidCredentialsException("Invalid or expired token.");
        }

        $token = $request->getHeaderLine($this->headerName);
        if (empty($token)) {
            throw new AuthenticationException("Authentication token is required.");
        }

        if (!hash_equals($this->apiKey, $token)) {
            throw new InvalidCredentialsException("Invalid or expired token.");
        }
    }

    public function onFailure(ServerRequestInterface $request, ResponseFactoryInterface $responseFactory, ?AuthenticationException $exception = null): ResponseInterface
    {
        if (!is_callable($this->onFailure)) {
            $status = 401;
            $message = $exception ? $exception->getMessage() : "Invalid API key.";
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
