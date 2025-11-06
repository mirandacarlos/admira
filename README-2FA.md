# 2FA by email — quick setup

This project has an email-based 2FA flow implemented.

Steps to enable and test locally (Windows PowerShell):

1. Install composer dependencies (from project root):

```powershell
cd c:\Users\casa\Desktop\admira
composer require
```

(If you added `phpmailer/phpmailer` to `composer.json`, run `composer install` or `composer update`.)

2. Set environment variables (example .env or server env):

- DB_HOST, DB_NAME, DB_USER, DB_PASS
- MAIL_FROM (optional)
- SMTP_HOST, SMTP_USER, SMTP_PASS, SMTP_PORT, SMTP_SECURE (optional — only if using SMTP)

3. Create DB tables (users, user_sessions, two_factor_codes). See `sql/two_factor.sql` for 2FA table.

4. Start PHP built-in server for quick testing (from project root):

```powershell
# starts server on port 8080
php -S 127.0.0.1:8080 -t public
```

5. Test endpoints with PowerShell (replace values):

```powershell
# Login (will trigger 2FA email if credentials valid)
Invoke-RestMethod -Uri http://127.0.0.1:8080/login -Method POST -Body (@{ user = 'alice'; pass = 'secret' } | ConvertTo-Json) -ContentType 'application/json'

# Verify 2FA (use token returned or cookie)
Invoke-RestMethod -Uri http://127.0.0.1:8080/verify-2fa -Method POST -Body (@{ token = '...'; code = '123456' } | ConvertTo-Json) -ContentType 'application/json'

# Logout
Invoke-RestMethod -Uri http://127.0.0.1:8080/logout -Method POST
```

Notes:
- `MailService` uses PHPMailer if installed (recommended) and falls back to `mail()` if not.
- In production, ensure HTTPS and proper mailer configuration.
