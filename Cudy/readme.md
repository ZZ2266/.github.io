# Insecure Default Password in Cudy WR1200EA Router

## Overview
An insecure default password vulnerability was identified in the Cudy WR1200EA router, version 2.3.7. The root user account uses a default password，which is stored in the `/etc/shadow` file using an MD5-crypt hash. This weak password can be easily decrypted using tools like John the Ripper or directly used to log in to the router's web interface or other network-accessible services, allowing attackers to gain unauthorized root access.

## Vulnerability Details
- **Vulnerability Type**: Insecure Permissions
- **Affected Product**: Cudy WR1200EA Router
- **Affected Version**: 2.3.7
- **Attack Type**: Remote
- **Attack Vector**: Unauthorized login using the default root user password via the web interface or other network-accessible services
- **Impact**:
  - Escalation of Privileges
  - Information Disclosure
  - Potential Code Execution
- **Affected Component**: `/etc/shadow` file, root user authentication mechanism
- **CVE ID**: Pending (CVE application in progress)
- **Discovered by**:n0ps1ed (n0ps1edzz@gmail.com)

## Discovery
The vulnerability was discovered by analyzing the firmware (WR1200EA-R62-2.3.7-20250113-121810-flash.bin). The `/etc/shadow` file was extracted, and the root user's MD5-crypt hash was cracked using John the Ripper, revealing the default password "admin." This weak credential allows attackers to log in to the router's administrative interface or other services without additional exploits.

## Steps to Reproduce
1. Extract the firmware image `WR1200EA-R62-2.3.7-20250113-121810-flash.bin`.
2. Locate the `/etc/shadow` file in the extracted squashfs-root directory.
3. Use a password-cracking tool (e.g., John the Ripper) to crack the MD5-crypt hash for the root user:
![PoC 2 Result: Root Directory Listing](./imgs/1.png)
4. Alternatively, attempt to log in to the router's web interface or other services using the credentials `root:admin`.

## Impact
An attacker with network access to the router can:
- Gain full administrative control by logging in with the default root credentials.
- Access sensitive configuration data, potentially exposing network details.
- Modify router settings or execute arbitrary code, leading to further network compromise.
