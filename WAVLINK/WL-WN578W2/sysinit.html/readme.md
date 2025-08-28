# WAVLINK WL-WN578W2 M78W2\_V221110 Unverified Password Change (sysinit.html)

PS:



1.  Use physical device for testing (QEMU simulation difficult).

2.  No auth needed: Modify password via `sysinit.html` without login/old password.

## Overview

A critical unverified password change vulnerability exists in `sysinit.html` (WAVLINK WL-WN578W2, firmware M78W2\_V221110). Attackers can directly access `sysinit.html` to modify the admin password—no login or old password required—taking full control of the device.



![Vulnerability Flow](./imgs/15.png)

## Details



*   **Vendor**: WAVLINK

*   **Vendor Website**: [https](https://www.wavlink.com/zh_cn/index.html)[://ww](https://www.wavlink.com/zh_cn/index.html)[w.wav](https://www.wavlink.com/zh_cn/index.html)[link.](https://www.wavlink.com/zh_cn/index.html)[com/z](https://www.wavlink.com/zh_cn/index.html)[h\_cn/](https://www.wavlink.com/zh_cn/index.html)[index](https://www.wavlink.com/zh_cn/index.html)[.html](https://www.wavlink.com/zh_cn/index.html)

*   **Product**: WL-WN578W2 (wireless range extender)

*   **Firmware**: M78W2\_V221110

*   **Firmware Download**: [ht](https://docs.wavlink.xyz/Firmware_ch/fm-578w2/)[tps:/](https://docs.wavlink.xyz/Firmware_ch/fm-578w2/)[/docs](https://docs.wavlink.xyz/Firmware_ch/fm-578w2/)[.wavl](https://docs.wavlink.xyz/Firmware_ch/fm-578w2/)[ink.x](https://docs.wavlink.xyz/Firmware_ch/fm-578w2/)[yz/Fi](https://docs.wavlink.xyz/Firmware_ch/fm-578w2/)[rmwar](https://docs.wavlink.xyz/Firmware_ch/fm-578w2/)[e\_ch/](https://docs.wavlink.xyz/Firmware_ch/fm-578w2/)[fm-57](https://docs.wavlink.xyz/Firmware_ch/fm-578w2/)[8w2/](https://docs.wavlink.xyz/Firmware_ch/fm-578w2/)

*   **Affected Endpoint**: `sysinit.html` (POST, no auth)

*   **Vulnerable Params**: `newpass` (new password), `confpass` (confirm password)

*   **Type**: Unverified Password Change (Unauthenticated)

*   **CVE ID**: Pending

*   **Impact**: Take over device by modifying admin password without authorization.

*   **Reported by**: n0ps1ed (n0ps1edzz@gmail.com)

### Description



1.  No auth check: `sysinit.html` allows access without login.

2.  No old password check.


####  Prove

1.Visit sysinit.html
2.change password
3.Log in via `login.html` with `123456789`—success confirms password change.



![Login Success with New Password](./imgs/1.mp4)


