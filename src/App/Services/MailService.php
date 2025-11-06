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
        // If PHPMailer is installed use it (allows SMTP), otherwise fallback to mail()
        if (class_exists('\\PHPMailer\\PHPMailer\\PHPMailer')) {
            $mail = new \PHPMailer\PHPMailer\PHPMailer(true);
            try {
                // Use SMTP if configured
                if (!empty($_ENV['SMTP_HOST'])) {
                    $mail->isSMTP();
                    $mail->Host = $_ENV['SMTP_HOST'];
                    $mail->SMTPAuth = ($_ENV['SMTP_AUTH'] ?? 'true') === 'true';
                    if (!empty($_ENV['SMTP_USER'])) {
                        $mail->Username = $_ENV['SMTP_USER'];
                    }
                    if (!empty($_ENV['SMTP_PASS'])) {
                        $mail->Password = $_ENV['SMTP_PASS'];
                    }
                    if (!empty($_ENV['SMTP_SECURE'])) {
                        $mail->SMTPSecure = $_ENV['SMTP_SECURE'];
                    }
                    if (!empty($_ENV['SMTP_PORT'])) {
                        $mail->Port = (int)$_ENV['SMTP_PORT'];
                    }
                }

                $from = $_ENV['MAIL_FROM'] ?? 'no-reply@example.com';
                $mail->setFrom($from);
                $mail->addAddress($to);
                $mail->Subject = $subject;
                $mail->Body = $body;
                $mail->isHTML(false);

                return $mail->send();
            } catch (\Exception $e) {
                error_log('PHPMailer error: ' . $e->getMessage());
                return false;
            }
        }

        $from = $_ENV['MAIL_FROM'] ?? 'no-reply@example.com';
        $headers = "From: " . $from . "\r\n";
        $headers .= "Content-Type: text/plain; charset=utf-8\r\n";

        // Fallback to mail()
        return mail($to, $subject, $body, $headers);
    }
}
