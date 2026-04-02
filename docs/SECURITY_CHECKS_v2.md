# ChainSentinel Security Checks Reference v2.0

## Overview
ChainSentinel performs **42+ automated security checks** across 7 scanner modules, specifically designed for warehouse and supply chain environments.

## Scanner Modules

### 1. IoT Device Scanner (8 checks)
| # | Check | Severity | CVSS | Description |
|---|-------|----------|------|-------------|
| 1 | Open Ports Detection | Medium | 5.3 | Identifies unnecessarily exposed network ports |
| 2 | Default Credentials (HTTP) | Critical | 9.8 | Tests login forms with 17 common credential pairs |
| 3 | Default Credentials (Telnet) | Critical | 9.8 | Tests Telnet services on ports 23/2323 |
| 4 | Unauthenticated Data Access | High | 7.5 | Checks for exposed sensor/data endpoints |
| 5 | Information Disclosure | Medium | 5.3 | Detects exposed device info, configs, keys |
| 6 | Command Injection | Critical | 10.0 | Tests forms and API endpoints for OS command execution |
| 7 | Directory Traversal | High | 7.5 | Tests for path traversal to read system files |
| 8 | Missing Security Headers | Low | 3.7 | Checks for X-Frame-Options, CSP, etc. |

### 2. Web Portal Scanner (12 checks)
| # | Check | Severity | CVSS | Description |
|---|-------|----------|------|-------------|
| 1 | SQL Injection (Auth Bypass) | Critical | 9.8 | Tests login forms with SQLi payloads |
| 2 | No Brute Force Protection | Medium | 5.3 | Sends 20 failed logins, checks for lockout |
| 3 | Weak Session Tokens | High | 7.5 | Analyzes session cookie strength and encoding |
| 4 | Session Fixation | High | 7.5 | Tests if app accepts external session IDs |
| 5 | Debug Mode / Info Disclosure | Medium | 5.3 | Triggers errors to detect stack traces |
| 6 | Exposed Sensitive Files | High | 7.2 | Checks for backup files, .git, .env, etc. |
| 7 | Reflected XSS | High | 6.1 | Tests input reflection without sanitization |
| 8 | Missing CSRF Protection | Medium | 4.3 | Checks POST forms for CSRF tokens |
| 9 | Missing Security Headers | Medium | 5.3 | Checks 6 critical HTTP security headers |
| 10 | Insecure Cookie Config | Medium | 5.3 | Checks HttpOnly, Secure, SameSite flags |
| 11 | Directory Traversal | High | 7.5 | Tests file download endpoints for path traversal |
| 12 | Unrestricted File Upload | High | 7.5 | Tests if dangerous file types are accepted |

### 3. API Scanner (8 checks)
| # | Check | Severity | CVSS | Description |
|---|-------|----------|------|-------------|
| 1 | SQL Injection (Boolean-based) | Critical | 9.8 | Tests search/query parameters with SQLi |
| 2 | IDOR - Unauthorized Access | High | 7.5 | Tests sequential ID access without auth |
| 3 | API Key in URL Parameter | Medium | 5.3 | Checks if API keys work in query strings |
| 4 | No Rate Limiting | Medium | 5.3 | Sends 50 rapid requests to detect throttling |
| 5 | Mass Assignment | High | 7.5 | Tests PUT with unexpected fields (is_admin, price) |
| 6 | Missing Input Validation | Low | 3.7 | Tests negative values, extreme values, wrong types |
| 7 | CORS Misconfiguration | Medium | 5.3 | Tests for wildcard or reflected origin |
| 8 | Missing Security Headers | Low | 3.7 | Checks API response security headers |

### 4. MQTT Scanner (4 checks)
| # | Check | Severity | CVSS | Description |
|---|-------|----------|------|-------------|
| 1 | Anonymous Access | Critical | 9.1 | Tests connection without credentials |
| 2 | Default Credentials | Critical | 9.8 | Tests 10 common MQTT credential pairs |
| 3 | Wildcard Topic Subscription | High | 7.5 | Tests if '#' topic subscription is allowed |
| 4 | Broker Version Disclosure | Low | 3.7 | Checks for software version information leak |

### 5. Protocol Scanner (6 checks)
| # | Check | Severity | CVSS | Description |
|---|-------|----------|------|-------------|
| 1 | Modbus Unauthenticated Access | Critical | 9.8 | Tests reading Modbus registers without auth |
| 2 | SNMP Default Community String | High | 7.5 | Tests public/private/community strings |
| 3 | FTP Anonymous/Default Access | High | 7.5 | Tests anonymous login and default credentials |
| 4 | DNS Zone Transfer | Medium | 5.3 | Tests AXFR query acceptance |
| 5 | Open Redirect | Medium | 4.7 | Tests URL redirect parameters |
| 6 | SSL/TLS Issues | Medium | 5.3 | Checks encryption, ciphers, certificates |

## Severity Distribution
- **Critical:** 9 checks (CVSS 9.0+)
- **High:** 13 checks (CVSS 7.0-8.9)
- **Medium:** 14 checks (CVSS 4.0-6.9)
- **Low:** 6 checks (CVSS < 4.0)

## Warehouse-Specific Coverage
ChainSentinel is specifically designed for warehouse environments:
- **IoT/Sensor Layer:** Barcode readers, RFID gateways, temperature sensors, conveyor controllers
- **Communication Layer:** MQTT brokers, Modbus PLCs, SNMP-managed switches
- **Application Layer:** WMS portals, supplier portals, inventory APIs
- **Network Layer:** FTP file transfers, DNS, SSL/TLS encryption
