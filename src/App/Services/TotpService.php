<?php

namespace App\Services;

class TotpService
{
    private int $digits = 6;
    private int $period = 30;
    private string $algo = 'sha1';

    /**
     * Generate a base32 secret for TOTP
     */
    public function generateSecret(int $length = 16): string
    {
        $bytes = random_bytes($length);
        return $this->base32Encode($bytes);
    }

    /**
     * Create provisioning URI for Google Authenticator
     */
    public function getProvisioningUri(string $accountName, string $secret, string $issuer = 'Admira'): string
    {
        $label = rawurlencode($issuer . ':' . $accountName);
        $params = http_build_query([
            'secret' => $secret,
            'issuer' => $issuer,
            'algorithm' => strtoupper($this->algo),
            'digits' => $this->digits,
            'period' => $this->period
        ]);
        return "otpauth://totp/{$label}?{$params}";
    }

    /**
     * Verify a TOTP code
     */
    public function verifyCode(string $secret, string $code, int $window = 1): bool
    {
        $secretKey = $this->base32Decode($secret);
        if ($secretKey === false) {
            return false;
        }

        $currentTimeSlice = floor(time() / $this->period);

        for ($i = -$window; $i <= $window; $i++) {
            $calculated = $this->hotp($secretKey, $currentTimeSlice + $i);
            if (hash_equals(str_pad((string)$calculated, $this->digits, '0', STR_PAD_LEFT), (string)$code)) {
                return true;
            }
        }
        return false;
    }

    private function hotp(string $key, int $counter): int
    {
        $counterBytes = pack('N*', 0) . pack('N*', $counter);
        $hash = hash_hmac($this->algo, $counterBytes, $key, true);
        $offset = ord($hash[strlen($hash) - 1]) & 0x0F;
        $truncated = substr($hash, $offset, 4);
        $value = unpack('N', $truncated)[1] & 0x7FFFFFFF;
        return $value % (10 ** $this->digits);
    }

    // Base32 encode / decode (RFC 4648)
    private function base32Encode(string $data): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $bits = '';
        $output = '';
        foreach (str_split($data) as $c) {
            $bits .= str_pad(decbin(ord($c)), 8, '0', STR_PAD_LEFT);
            while (strlen($bits) >= 5) {
                $chunk = substr($bits, 0, 5);
                $bits = substr($bits, 5);
                $output .= $alphabet[bindec($chunk)];
            }
        }
        if (strlen($bits) > 0) {
            $output .= $alphabet[bindec(str_pad($bits, 5, '0', STR_PAD_RIGHT))];
        }
        return $output;
    }

    private function base32Decode(string $b32)
    {
        $b32 = strtoupper($b32);
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $bits = '';
        $output = '';
        foreach (str_split($b32) as $c) {
            $pos = strpos($alphabet, $c);
            if ($pos === false) continue;
            $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
            while (strlen($bits) >= 8) {
                $byte = substr($bits, 0, 8);
                $bits = substr($bits, 8);
                $output .= chr(bindec($byte));
            }
        }
        return $output === '' ? false : $output;
    }
}
