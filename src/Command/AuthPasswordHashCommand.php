<?php

namespace Michel\Auth\Command;

use Michel\Auth\UserProviderInterface;
use Michel\Console\Argument\CommandArgument;
use Michel\Console\Command\CommandInterface;
use Michel\Console\InputInterface;
use Michel\Console\Output\ConsoleOutput;
use Michel\Console\OutputInterface;

class AuthPasswordHashCommand implements CommandInterface
{
    private UserProviderInterface $userProvider;
    public function __construct(UserProviderInterface $userProvider)
    {
        $this->userProvider = $userProvider;
    }

    public function getName(): string
    {
        return 'auth:password:hash';
    }

    public function getDescription(): string
    {
        return 'Hash a raw password string into a secure hash compatible with UserProvider.';
    }

    public function getOptions(): array
    {
        return[];
    }

    public function getArguments(): array
    {
        return [
            CommandArgument::required('password', 'The plain-text password to hash')
        ];
    }

    public function execute(InputInterface $input, OutputInterface $output): void
    {
        $io = new ConsoleOutput($output);
        $plainPassword = $input->getArgumentValue('password');
        if (empty($plainPassword)) {
            $io->error('The password cannot be empty.');
            return;
        }


        $io->title('Password Hashing Tool');

        $hash = $this->userProvider->hashPassword($plainPassword);
        $info = password_get_info($hash);
        $io->listKeyValues([
            'Algorithm' => $info['algoName'] ?? 'unknown',
            'Options'   => json_encode($info['options']),
        ]);

        $io->writeln('');
        $io->writeln("Computed Hash: " . $hash);
        $io->writeln('');

        $io->success('Password hashed successfully.');
    }
}
