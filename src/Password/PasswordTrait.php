<?php

namespace Michel\Auth\Password;

use Michel\Auth\PasswordAuthenticatedUserInterface;

trait PasswordTrait
{
    private string $algorithm = PASSWORD_BCRYPT;
    private int $cost = 10;

    public function hashPassword(string $plainPassword): string
    {
        return password_hash($plainPassword, $this->algorithm, ['cost' => $this->cost]);
    }

    public function isPasswordValid(PasswordAuthenticatedUserInterface $user, string $plainPassword): bool
    {
        return password_verify($plainPassword, $user->getPassword());
    }

    public function setCost(int $cost): void
    {
        if ($cost < 4 || $cost > 12) {
            throw new \InvalidArgumentException('Cost must be in the range of 4-31.');
        }
        $this->cost = $cost;
    }

    public function setAlgorithm(string $algorithm): void
    {
        if (!password_algos() || !in_array($algorithm, password_algos())) {
            throw new \InvalidArgumentException(
                sprintf(
                    'Invalid password hashing algorithm "%s". Available algorithms: %s.',
                    $algorithm,
                    implode(', ', password_algos())
                )
            );
        }

        $this->algorithm = $algorithm;
    }
}
