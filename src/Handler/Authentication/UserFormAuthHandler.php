<?php

namespace Michel\Auth\Handler\Authentication;

use Michel\Auth\AuthIdentity;
use Michel\Auth\Exception\AuthenticationException;
use Michel\Auth\Exception\InvalidCredentialsException;
use Michel\Auth\Exception\LogoutException;
use Michel\Auth\Exception\UserNotFoundException;
use Michel\Auth\PasswordAuthenticatedUserInterface;
use Michel\Auth\UserInterface;
use Michel\Auth\UserProviderInterface;
use Michel\Resolver\Option;
use Michel\Resolver\OptionsResolver;
use Michel\Session\Storage\SessionStorageInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class UserFormAuthHandler implements AuthHandlerInterface, StatefulAuthHandlerInterface
{
    public const AUTHENTICATION_ERROR = '_form.last_error';
    public const LAST_USERNAME = '_form.last_username';

    private UserProviderInterface $userProvider;
    private SessionStorageInterface $sessionStorage;
    private string $loginPath;
    private string $logoutPath;
    private string $loginKey;
    private string $passwordKey;
    private string $targetPath;

    /**
     * @var callable
     */
    private $onFailure;

    public function __construct(
        UserProviderInterface   $userProvider,
        SessionStorageInterface $sessionStorage,
        array $options = []
    )
    {
        $this->userProvider = $userProvider;
        $this->sessionStorage = $sessionStorage;

        $optionResolver = new OptionsResolver([
            Option::string('login_path', '/login')->min(1),
            Option::string('logout_path', '/logout')->min(1),
            Option::string('login_key', 'login')->min(1),
            Option::string('password_key', 'password')->min(1),
            Option::string('target_path', '/')->min(1),
            Option::mixed('on_failure')->validator(function ($value) {
                return is_callable($value) || $value === null;
            })->setOptional(null),
        ]);

        $options = $optionResolver->resolve($options);
        $this->loginPath = '/'.ltrim($options['login_path'], '/');
        $this->logoutPath = '/'.ltrim($options['logout_path'], '/');
        $this->loginKey = $options['login_key'];
        $this->passwordKey = $options['password_key'];
        $this->targetPath = '/'.ltrim($options['target_path'], '/');
        $this->onFailure = $options['on_failure'];
    }

    /**
     * @throws AuthenticationException
     * @throws UserNotFoundException
     * @throws InvalidCredentialsException
     */
    public function authenticate(ServerRequestInterface $request): ?AuthIdentity
    {
        $path = $request->getUri()->getPath();

        if ($path === $this->logoutPath) {
            $this->sessionStorage->remove('user_identifier');
            throw new LogoutException('User logged out.');
        }

        if ($this->sessionStorage->has('user_identifier')) {
            $identifier = $this->sessionStorage->get('user_identifier');
            $user = $this->userProvider->findByIdentifier($identifier);
            if ($user instanceof UserInterface) {
                return new AuthIdentity($user,  false);
            }
        }

        $method = $request->getMethod();
        if ($path === $this->loginPath && $method === 'GET') {
            return null;
        }

        if ($path !== $this->loginPath) {
            throw new AuthenticationException('Authentication required.');
        }

        if ($method !== 'POST') {
            throw new AuthenticationException('Login form must be submitted using POST.');
        }

        list($login, $password) = self::extractCredentials($request, $this->loginKey, $this->passwordKey);
        if (empty($login) || empty($password)) {
            throw new InvalidCredentialsException("Credentials cannot be empty.");
        }
        $this->sessionStorage->put(self::LAST_USERNAME, $login);

        /**
         * @var PasswordAuthenticatedUserInterface|UserInterface|null $user
         */
        $user = $this->userProvider->findByIdentifier($login);
        if (!$user instanceof UserInterface) {
            throw new UserNotFoundException("Invalid username or password.");
        }

        if (!$user instanceof PasswordAuthenticatedUserInterface) {
            throw new AuthenticationException("The resolved user does not support password authentication.");
        }

        if (!$this->userProvider->isPasswordValid($user, $password)) {
            throw new InvalidCredentialsException("Invalid username or password.");
        }

        $this->sessionStorage->put('user_identifier', $user->getUserIdentifier());
        return new AuthIdentity($user,  true);
    }

    public function onSuccess(ServerRequestInterface $request, ResponseFactoryInterface $responseFactory): ?ResponseInterface
    {
        $response = $responseFactory->createResponse(302);
        return $response->withHeader('Location', $this->targetPath);
    }

    public function onFailure(ServerRequestInterface $request, ResponseFactoryInterface $responseFactory, ?AuthenticationException $exception = null): ResponseInterface
    {
        if ($exception instanceof LogoutException) {
            return $responseFactory->createResponse(302)->withHeader('Location', $this->loginPath);
        }

        if ($exception && !empty($exception->getMessage())) {
            $this->sessionStorage->put(self::AUTHENTICATION_ERROR, $exception->getMessage());
            $request = $request->withAttribute(self::AUTHENTICATION_ERROR, $exception->getMessage());
        }

        if (!is_callable($this->onFailure)) {
            $response = $responseFactory->createResponse(302);
            return $response->withHeader('Location', $this->loginPath);
        }
        return ($this->onFailure)($request, $responseFactory, $exception);
    }

    private static function extractCredentials(ServerRequestInterface $request, string $keyLogin, string $keyPassword): array
    {
        $data = $request->getParsedBody();
        $login = $data[$keyLogin] ?? '';
        $pass = $data[$keyPassword] ?? '';
        return [
            $login,
            $pass
        ];
    }
}
