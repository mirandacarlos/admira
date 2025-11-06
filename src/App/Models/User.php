<?php

namespace App\Models;

class User
{
    private int $id;
    private string $username;
    private string $email;
    private string $password;
    private string $two_factor_method;
    private ?string $totp_secret;
    private string $created_at;
    private string $updated_at;

    public function __construct(array $data = [])
    {
        $this->id = $data['id'] ?? 0;
        $this->username = $data['username'] ?? '';
        $this->email = $data['email'] ?? '';
        $this->password = $data['password'] ?? '';
        $this->two_factor_method = $data['two_factor_method'] ?? 'none';
        $this->totp_secret = $data['totp_secret'] ?? null;
        $this->created_at = $data['created_at'] ?? date('Y-m-d H:i:s');
        $this->updated_at = $data['updated_at'] ?? date('Y-m-d H:i:s');
    }

    public function getId(): int
    {
        return $this->id;
    }

    public function getUsername(): string
    {
        return $this->username;
    }

    public function getEmail(): string
    {
        return $this->email;
    }

    public function getPassword(): string
    {
        return $this->password;
    }

    public function getTwoFactorMethod(): string
    {
        return $this->two_factor_method;
    }

    public function getTotpSecret(): ?string
    {
        return $this->totp_secret;
    }

    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'username' => $this->username,
            'email' => $this->email,
            'two_factor_method' => $this->two_factor_method,
            'created_at' => $this->created_at,
            'updated_at' => $this->updated_at
        ];
    }
}