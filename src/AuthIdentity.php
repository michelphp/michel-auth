<?php

namespace Michel\Auth;

final class AuthIdentity
{
    private UserInterface $user;
    private bool $isNewLogin;

    public function __construct(
        UserInterface $user,
        bool          $isNewLogin = false
    )
    {
        $this->user = $user;
        $this->isNewLogin = $isNewLogin;
    }

    public function getUser(): UserInterface
    {
        return $this->user;
    }

    public function isNewLogin(): bool
    {
        return $this->isNewLogin;
    }
}
