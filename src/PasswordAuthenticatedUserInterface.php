<?php

namespace Michel\Auth;

interface PasswordAuthenticatedUserInterface
{
    public function getPassword(): string;

    public function setPassword(?string $password);
}
