<?php

namespace Michel\Auth;

interface UserProviderInterface
{
    public function findByIdentifier(string $identifier): ?UserInterface;
    public function findByToken(string $token): ?UserInterface;
    public function checkPassword(PasswordAuthenticatedUserInterface $user, string $plainPassword): bool;
    public function upgradePassword(PasswordAuthenticatedUserInterface $user, string $newPlainPassword): void;
    public function hashPassword(string $plainPassword): string;
}
