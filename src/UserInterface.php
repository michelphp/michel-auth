<?php

namespace Michel\Auth;

interface UserInterface
{
    public function getUserIdentifier(): string;
}
