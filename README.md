# Admira

Sistema de autenticación PHP con soporte opcional de autenticación de dos factores (2FA) por email y TOTP (Google Authenticator).

Este repositorio contiene una implementación ligera pensada para aprendizaje y pruebas. Incluye:

- Protección básica contra inyección SQL (consultas preparadas)
- Límite de intentos (rate limiting) en login
- Gestión segura de sesiones (tabla `user_sessions` + cookie `session_id`)
- Hashing de contraseñas con `password_hash`
- Flujo 2FA por correo (envío de códigos) y TOTP (provisioning URI / secreto)
- Servicios para envío de correo (`MailService`) que usan PHPMailer si está disponible, o `mail()` como fallback

Contenido principal
- `public/index.php` — enrutamiento y endpoints HTTP (login, register, verify-2fa, settings, logout, etc.)
- `src/App/Controllers/AuthController.php` — lógica de controlador de autenticación
- `src/App/Services/AuthService.php` — lógica de persistencia y verificación (usuarios, sesiones, 2FA)
- `src/App/Services/TotpService.php` — generación/verificación TOTP
- `src/App/Services/MailService.php` — envío de correos
- `sql/two_factor.sql` — DDL para tablas de 2FA usadas por el proyecto

Instalación

1) Clona el repositorio y entra en la carpeta del proyecto:

```powershell
cd C:\ruta\a\admira
```

2) Instala dependencias de PHP con Composer (si aplica):

```powershell
composer install
```

3) Variables de entorno

Define las variables de entorno mínimas (por ejemplo en un archivo `.env` cargado por `vlucas/phpdotenv`):

- `MYSQL_HOST` — host de la base de datos
- `MYSQL_DATABASE` — nombre de la base de datos
- `MYSQL_USER` — usuario DB
- `MYSQL_PASSWORD` — contraseña DB
- `APP_NAME` — nombre de la aplicación (opcional, usado en TOTP issuer)
- `MAIL_FROM` — dirección From para los correos (opcional)
- `SMTP_HOST`, `SMTP_USER`, `SMTP_PASS`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_AUTH` — (opcional) para usar SMTP vía PHPMailer

4) Crear las tablas en la base de datos

Ejecuta el SQL en `sql/two_factor.sql` y asegúrate de tener las tablas `users` y `user_sessions`. El archivo contiene la DDL necesaria para los códigos 2FA.

5) Ejecutar la aplicación

Modo rápido con servidor embebido PHP (desarrollo):

```powershell
php -S 127.0.0.1:8080 -t public
```

Modo Docker (si usas `docker-compose` incluido):

```powershell
docker compose up --build -d
```

Uso — endpoints principales

Todos los endpoints devuelven JSON salvo los formularios HTML de `GET /login`, `GET /register` y `GET /settings`.

- `GET /` — redirige a `/login` o `/settings` según si la sesión (`session_id` cookie) existe.
- `GET /login` — formulario de login (si ya estás autenticado redirige a `/settings`).
- `POST /login` — procesa credenciales; devuelve JSON. Si 2FA está activado para el usuario puede devolver:
	- `{ success: false, two_factor_required: true, two_factor_method: 'email', two_factor_token: '...' }` (email)
	- `{ success: false, two_factor_required: true, two_factor_method: 'totp' }` (totp)
	- Si no hay 2FA devuelve `{ success: true, user: {...} }` y fija cookie `session_id`.
- `POST /verify-2fa` — recibe `token` y `code` para verificar el código enviado por email o TOTP; al verificar crea sesión y devuelve `{ success: true, user: {...} }`.
- `GET /register` — formulario de registro.
- `POST /register` — crea usuario; si eliges `totp` en el registro devuelve `totp_provisioning_uri` y `totp_secret`.
- `GET /settings` — página para ver/cambiar la configuración 2FA (requiere sesión). Si el usuario ya tiene TOTP configurado muestra el provisioning URI y el secreto.
- `POST /settings` — actualiza método 2FA del usuario (none/email/totp). Si se activa `totp` genera un secreto nuevo y devuelve `totp_provisioning_uri` y `totp_secret`.
- `POST /logout` — invalida la sesión y borra la cookie `session_id`.

Ejemplos rápidos (PowerShell)

Login (JSON API):

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:8080/login -Method POST -Body (@{ user = 'alice'; pass = 'secret' } | ConvertTo-Json) -ContentType 'application/json'
```

Verificar 2FA (usar token o cookie `two_factor_token` si corresponde):

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:8080/verify-2fa -Method POST -Body (@{ token = '...'; code = '123456' } | ConvertTo-Json) -ContentType 'application/json'
```

Logout:

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:8080/logout -Method POST
```

Detalles de 2FA (contenido integrado de `README-2FA.md`)

El proyecto implementa dos modos de 2FA:

- Email: se genera un token (almacenado en `two_factor_codes`) y un código de 6 dígitos, se envía por correo y el usuario debe verificarlo mediante `POST /verify-2fa`.
- TOTP: el sistema puede generar un secreto base32 y una provisioning URI compatible con Google Authenticator. Al activarlo, el usuario añade la cuenta en su app de autenticación y, en el login, deberá introducir el código que genera su app.

Notas para pruebas locales:

- El servicio de correo utiliza `PHPMailer` si está instalado (permite SMTP). Si no, cae en `mail()` de PHP.
- Para pruebas rápidas en local puedes usar servicios como MailHog o configurar SMTP de pruebas en las variables de entorno.

Seguridad y recomendaciones

- No expongas el `totp_secret` en producción. Actualmente se devuelve para facilitar pruebas; en entornos reales devuelve sólo la provisioning URI o muestra un QR.
- Habilita HTTPS en producción y configura correctamente `MAIL_FROM` y SMTP.
- Agrega protección CSRF en los formularios HTML (`/login`, `/register`, `/settings`) antes de desplegar.
- Revisa y ajusta políticas de rate limiting y bloqueo de cuentas si existen muchos intentos fallidos.


Contribuciones

Si quieres mejorar el proyecto:

- Añade pruebas automatizadas en `tests/`.
- Implementa CSRF y protección adicional en las páginas HTML.
- Añade una interfaz de usuario más completa y manejo de sesiones del lado cliente.

Contacto

Si tienes preguntas o quieres sugerir mejoras, abre un issue en el repositorio.

---
