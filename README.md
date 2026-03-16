# Michel Auth

A flexible and lightweight PSR-15 compliant authentication library for PHP applications. This library provides a middleware-based approach to handle user authentication, supporting both traditional form-based logins and token-based API authentication.

## Features

- **PSR-15 Middleware:** Seamlessly integrates into any modern PHP framework or application that supports PSR-15 middleware (`AuthMiddleware`).
- **Multiple Handlers:**
  - `FormAuthHandler`: For handling classical HTML form logins. Relies on `michel/session` to persist user sessions.
  - `TokenAuthHandler`: For handling API authentications via HTTP headers (e.g., Bearer tokens, API keys).
- **Customizable:** Implements `UserProviderInterface` to easily plug in your own user storage (database, memory, external APIs).
- **Security:** Built-in interfaces (`PasswordAuthenticatedUserInterface`) for secure password checking and automatic password upgrades.
- **Error Handling:** Easily catch and handle authentication failures gracefully with custom callbacks (`onFailure`).

## Installation

You can install the library via Composer:

```bash
composer require michel/michel-auth
```

## Basic Usage

### 1. Implement User and Provider Interfaces

First, create a user class that implements `Michel\Auth\UserInterface` (and optionally `Michel\Auth\PasswordAuthenticatedUserInterface` for form login).

Then, create a provider implementing `Michel\Auth\UserProviderInterface` to fetch these users.

### 2. Form Authentication

Set up form authentication for your web application.

```php
use Michel\Auth\Handler\FormAuthAuthHandler;
use Michel\Auth\Middlewares\AuthMiddleware;

// $userProvider = new YourUserProvider();
// $sessionStorage = new YourSessionStorage();

$formHandler = new FormAuthAuthHandler($userProvider, $sessionStorage, [
    'login_path' => '/login',
    'login_key' => 'email',
    'password_key' => 'password',
]);

$authMiddleware = new AuthMiddleware($formHandler, $responseFactory, $logger);
// Add $authMiddleware to your PSR-15 compatible application router/dispatcher
```

### 3. Token Authentication (API)

Ideal for stateless APIs using header tokens.

```php
use Michel\Auth\Handler\TokenAuthHandler;
use Michel\Auth\Middlewares\AuthMiddleware;

$tokenHandler = new TokenAuthHandler($userProvider, 'Authorization');

$authMiddleware = new AuthMiddleware($tokenHandler, $responseFactory, $logger);
// Add $authMiddleware to your API routes
```

## License

This project is licensed under the MPL-2.0 License. See the [LICENSE](LICENSE) file for details.
