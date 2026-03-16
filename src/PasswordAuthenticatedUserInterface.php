<?php

namespace Michel\Auth;

interface PasswordAuthenticatedUserInterface
{
    public function getPassword(): ?string;
}
