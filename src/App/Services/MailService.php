<?php

namespace App\Services;

class MailService
{
    /**
     * Send a simple email. Uses PHP mail(); for production consider using a robust mailer (PHPMailer, Symfony Mailer, etc.)
     *
     * @param string $to
     * @param string $subject
     * @param string $body
     * @return bool
     */
    public function send(string $to, string $subject, string $body): bool
    {
        $from = $_ENV['MAIL_FROM'] ?? 'no-reply@example.com';
        $headers = "From: " . $from . "\r\n";
        $headers .= "Content-Type: text/plain; charset=utf-8\r\n";

        // Note: mail() may not be configured in local environments. Replace with a proper mailer when available.
        return mail($to, $subject, $body, $headers);
    }
}
