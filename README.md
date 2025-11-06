# admira
sistema de autenticación con opción de 2 factores

The system includes:

Protection against SQL injection
Protection against brute force attacks
Protection against session hijacking
Password hashing
Rate limiting
Secure session management
Input validation and sanitization
Error logging
HTTPS enforcement

Cómo usar (flujo)
Llamar al endpoint/controlador que invoque AuthController::login($user, $pass) (por ejemplo desde su ruta de API). Respuesta esperada cuando 2FA está habilitado y credenciales correctas:
{ success: false, two_factor_required: true, two_factor_token: "..." }
Se envía el código por email al user->email. También se fija una cookie two_factor_token con 10 minutos de validez.
El cliente solicita verificación: enviar token y code a AuthController::verifyTwoFactor($token, $code).
Si el código es correcto: se crea la sesión (registro en user_sessions) y se fija cookie session_id.
Respuesta: { success: true, user: {...} }


Instalar dependencias composer (desde la raíz del proyecto):
Asegurarse de exportar/definir variables de entorno (o usar un .env loader en su app). Variables mínimas recomendadas:
DB_HOST, DB_NAME, DB_USER, DB_PASS
MAIL_FROM (opcional)
SMTP_HOST, SMTP_USER, SMTP_PASS, SMTP_PORT, SMTP_SECURE (opcional — si usará SMTP)
Crear las tablas en la base de datos (ejecute SQL). Al menos ejecute:
Tablas users y user_sessions (si no existen).
Tabla 2FA (archivo sql/two_factor.sql contiene el SQL). Por ejemplo en MySQL:
Levantar servidor PHP para pruebas:
Probar endpoints (ejemplos PowerShell):
# Login -> recibirá respuesta que indica que se envió código 2FA
Invoke-RestMethod -Uri http://127.0.0.1:8080/login -Method POST -Body (@{ user = 'usuario'; pass = 'contraseña' } | ConvertTo-Json) -ContentType 'application/json'

# Verificar 2FA (usar token y código recibido por email)
Invoke-RestMethod -Uri http://127.0.0.1:8080/verify-2fa -Method POST -Body (@{ token = 'TOKEN_RET' ; code = '123456' } | ConvertTo-Json) -ContentType 'application/json'

# Logout
Invoke-RestMethod -Uri http://127.0.0.1:8080/logout -Method POST