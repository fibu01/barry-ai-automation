# Barry University — SOC Notification Suppression Request
**To:** Oculus IT SOC Team (soc@oculusit.com)  
**From:** Barry University IT — Justin Moses / John Baldwin  
**Date:** April 2026  
**Re:** Alert categories approved for notification suppression

---

## Instructions to Oculus IT

For all categories listed below:
- **Continue opening and closing tickets** on your side for tracking and SLA purposes.
- **Stop sending email notifications** to jmoses@barry.edu and jbaldwin@barry.edu.
- These were reviewed against 24 months of ticket history (April 2024 – April 2026) and John Baldwin's triage responses.

If a ticket in any of these categories shows genuinely anomalous behavior not covered by the justification below, please call or Teams-message John Baldwin directly.

---

## TIER 1 — SUPPRESS IMMEDIATELY (≥80% noise)

---

### 1. Anomalous Token
**Ticket volume:** 833 notifications over 24 months (highest-volume alert by far)  
**Noise rate:** 92.8% (773 of 833 tickets closed as Investigated-Benign or False Positive)  
**Remaining 7%:** Most are still open/unclassified, not confirmed threats

**Why this is noise:**  
Every single confirmed resolution by John Baldwin on these tickets was "investigated — IP registered to [consumer ISP / telecom], login history consistent with user's normal pattern." The Entra ID anomalous token detector fires when a token is used from a device or location slightly different from the user's last session — which happens constantly in a university environment where students use phones, home computers, campus labs, and VPNs interchangeably.

**Sample triage response (actual):** *"This looks like a false positive. The previous known good logins show from IP registered to BIGTELECOM, showing the same location."*

**Suppress. Continue ticketing for SLA. No email notification.**

---

### 2. Sign-in from Anonymous Proxy
**Ticket volume:** 237 notifications over 24 months  
**Noise rate:** 84.4% (200 of 237 closed as Investigated-Benign or Auto-Remediated)

**Why this is noise:**  
Consistently resolves to students or staff using commercial VPN services (private VPNs, consumer ISPs that route through proxy infrastructure) or ISPs that Scamalytics classifies as proxy-adjacent. No credential compromise was ever confirmed on a ticket resolved as benign. Students travel internationally and use VPNs routinely.

**Sample triage response (actual):** *"The IP is registered to Gradwell.com LTD - DSL Customer, location shows as UK."*  
**Sample triage response (actual):** *"Evidence suggests she was using a private VPN on a mobile device."*

**Suppress. Continue ticketing. No email notification.**

---

### 3. Sign-in from Password-Spray IP
**Ticket volume:** 19 notifications  
**Noise rate:** 100% (19 of 19 closed as Investigated-Benign)

**Why this is noise:**  
Every single ticket resolved as benign. The IP flagged as "password-spray associated" is consistently T.K. Bytech Ltd or XS Usenet — consumer ISPs that appear on threat intel IP lists but whose logins at Barry are legitimate student accounts completing MFA successfully. The password-spray categorization is based on the IP's reputation, not any failed login pattern at Barry.

**Sample triage response (actual):** *"The IP is registered to T.K Bytech Ltd... login history is not suspicious."*  
**Sample triage response (actual):** *"The IP is registered to XS Usenet, showing location as Tokyo."*

**Suppress. Continue ticketing. No email notification.**

---

## TIER 2 — SUPPRESS WITH CONDITION (60–80% noise, suppress if MFA passes)

---

### 4. Sign-in from Anonymous IP
**Ticket volume:** 261 notifications  
**Noise rate:** 74.7% (195 of 261 closed as Benign or False Positive)

**Why this is mostly noise:**  
The majority resolve to users on consumer ISPs, state government networks (FL Dept. of...), or Pacemaker/education networks whose IP ranges carry an "anonymous" classification in threat intel feeds. In every confirmed FP, the user completed MFA successfully.

**Condition for suppression:** Only suppress if MFA was completed successfully. If MFA was NOT completed or was bypassed, continue to notify.

**Sample triage response (actual):** *"Christie Novius logged in from IP registered to FL Dept. [of Children and Families] — this is a false positive similar to yesterday's incident."*

**Suppress when MFA passed. Notify only when MFA was not completed or sign-in succeeded without MFA.**

---

### 5. Unfamiliar Sign-in Properties
**Ticket volume:** 221 notifications  
**Noise rate:** 71.0% (157 of 221 closed as Benign, False Positive, or Duplicate)

**Why this is mostly noise:**  
The most common resolution is that the user logged in from a new device (new phone, new laptop) or a different browser and the sign-in completed with MFA. The "unfamiliar properties" detection fires on device, EAS ID, or IP subnet changes — all routine in a university.

Also: 43 tickets (19%) were explicitly marked False Positive by Baldwin because the logins failed (user did not complete MFA), meaning the alert fired on a blocked attempt with no real risk. Avepoint Pool service accounts generated a cluster of these.

**Condition for suppression:** Suppress if MFA completed. Continue to notify for successful sign-ins where MFA was not required or was bypassed.

**Sample triage response (actual):** *"This is a false positive — the logins failed (user did not complete MFA) from iOS device."*  
**Sample triage response (actual):** *"These incidents involving the Avepoint Pool accounts are false positives — IPs are registered to education networks."*

---

### 6. Defense Evasion (OneStart / Potentially Unwanted Application)
**Ticket volume:** 11 notifications  
**Noise rate:** 72.7% (8 of 11 closed as False Positive)

**Why this is noise:**  
The overwhelming pattern is Defender flagging the "OneStart" browser application (adware/PUP) as a defense evasion attempt. Baldwin's consistent response: *"Full scan returned clean. I did a remote session with the user and removed the OneStart app."* This is a nuisance software removal, not a security incident. The removal is handled at the endpoint level without SOC escalation.

**Suppress OneStart/PUP detection sub-category specifically. Continue notifying for genuine evasion tools (Cobalt Strike, Mimikatz, etc.).**

**Sample triage response (actual):** *"Full scan returned clean. Also, I did a remote session with the user and we removed the OneStart app that was showing up."*

---

### 7. Process Injection / Code Execution (Gaming Clients)
**Ticket volume:** 7 notifications  
**Noise rate:** 57.1% (4 of 7 closed as False Positive)

**Why this is noise:**  
Defender flags legitimate game client updates (Riot Games/League of Legends, Roblox) as process injection because the installer modifies running processes. This is expected behavior for those applications. Barry's student population includes an eSports program.

**Suppress for known gaming client processes: RobloxPlayerBeta.exe, Riot Games client updater, Valorant. Continue notifying for all other process injection detections.**

**Sample triage response (actual):** *"Lance Hotchkiss was updating the Riot game client — this is a false positive."*  
**Sample triage response (actual):** *"The detection is for RobloxPlayerBeta.exe installer — this is the actual game client."*

---

## TIER 3 — REDUCE FREQUENCY (40–60% noise, change from per-alert to daily digest)

---

### 8. Password Spray Attack (not from flagged IP)
**Ticket volume:** 228 notifications  
**Noise rate:** 48.7% (111 of 228 closed as Benign or False Positive — 51 each)

**What to do:**  
Do not suppress entirely — 22% of tickets led to real investigation. However, stop sending individual email notifications. **Send a daily digest at 8am** listing all new Password Spray tickets opened in the last 24 hours. John Baldwin reviews the digest and flags any that need individual action.

**Suppress per-alert emails. Send daily digest instead.**

---

### 9. Malicious URL Click
**Ticket volume:** 106 notifications  
**Noise rate:** 45.3% (48 of 106 closed as False Positive or Auto-Remediated)

**Why many are noise:**  
39% (41 tickets) explicitly marked False Positive by Baldwin — the most common pattern is a legitimate payment receipt email (e.g., vendor receipt from July 2024) where Defender flagged a link in the email as malicious due to a third-party URL scanner classification, not an actual phish or credential harvest.

**What to do:** Suppress per-alert notification for tickets where the offending URL resolves to a known payment processor or e-commerce domain (PayPal, Stripe, Square, etc.). Continue full notifications for credential phishing URLs.

**Sample triage response (actual):** *"This is a false positive — the email was a receipt for a payment done on 7/28/24."*

---

### 10. Multi-stage Incident (eSports / Student Devices)
**Ticket volume:** 102 notifications  
**Noise rate:** 46.1% (47 of 102 closed as FP, Auto-Remediated, or Duplicate)

**Why many are noise:**  
Repeated pattern: eSports lab devices and student gaming machines generate multi-stage incident chains because game clients make network calls that look like C2 activity. Baldwin's consistent response: *"These are also false positives — expected behavior on eSports devices."*

Also, Genio.co (a student learning platform) generated several multi-stage detections from link tracking behavior.

**Suppress for devices in the eSports lab device group and known student learning platforms. Continue full notification for all other multi-stage detections.**

---

### 11. Malware Detected — Auto-Remediated Subset
**Ticket volume:** 260 notifications total  
**Of which auto-remediated by Defender:** 42 (16%)  
**Of which explicit False Positive:** 55 (21%)

**What to do:**  
For the 42 tickets where Defender auto-quarantined the file and no user action was needed, suppress the email notification — Defender already handled it. Keep notifying for malware detections where remediation is still pending or where it's a new/unrecognized strain.

**Suppress notification for sub-category: "Malware auto-quarantined by Defender — no further action required." Continue all others.**

---

## CATEGORIES TO KEEP AS-IS (Active monitoring required)

The following categories have <30% noise rate and must continue with full notification:

| Category | Volume | Noise % | Why Keep |
|---|---|---|---|
| Unusual Sign-in Location | 205 | 10% | Active investigations, account actions taken |
| Sign-in from Tor / Malware C2 | 191 | 18% | High-risk vector, real compromise potential |
| Network Reconnaissance | 173 | 6% | Mostly unclassified — needs eyes on it |
| Pass-the-Ticket / Kerberos | 155 | 19% | Credential theft vector, cannot suppress |
| Mail Forwarding / Inbox Rule | 144 | 1% | BEC indicator, nearly always actionable |
| Sign-in Disabled Accounts | 62 | 14% | Potential credential stuffing |
| Sensitive Files / DLP | 102 | 0% | No benign resolutions observed |
| Data Exfiltration | 10 | — | Low volume, high risk, always investigate |
| Sign-in from Tor / C2 | 191 | 18% | Keep — too high risk |
| Account Action Taken cases | — | — | Any ticket that escalated to account action |

---

## Summary

| Action | Categories | Estimated tickets suppressed/year |
|---|---|---|
| Full suppress (Tier 1) | 3 categories | ~540/yr |
| Conditional suppress (Tier 2) | 4 categories | ~280/yr |
| Daily digest instead of per-alert | 2 categories | ~165/yr (consolidated from ~165 individual emails) |
| Partial suppress (auto-rem. only) | 1 category | ~65/yr |
| **Total reduction** | | **~1,050 fewer email notifications per year** |

Current annual SOC email volume: ~2,150 emails/year (based on Apr 2024–Apr 2026 data)  
**Post-suppression estimate: ~1,100 emails/year — approximately 49% reduction in noise.**

---

*Data source: Phase 1 (4,300 SOC emails), Phase 3 (1,170 Baldwin triage responses), April 2024–April 2026.*  
*Analysis generated: April 2026*
