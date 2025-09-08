##Threat Hunt Scenario. Devices Accidentally Exposed to the Internet##

<img width="1940" height="1216" alt="image" src="https://github.com/user-attachments/assets/34efe54f-3e8e-4870-800e-e0f7837d1037" />

_____
Platforms and Languages Leveraged:

- Windows 11 Virtual Machines (Microsoft Azure)

- EDR Platform: Microsoft Defender for Endpoint

- Kusto Query Language (KQL)
_____
Scenario

During routine maintenance, the security team is tasked with investigating any VMs in the shared services cluster (handling DNS, Domain Services, DHCP, etc.) that have mistakenly been exposed to the public internet. The goal is to identify any misconfigured VMs and check for potential brute-force login attempts/successes from external sources.
Activity: Develop a hypothesis based on threat intelligence and security gaps (e.g., “Could there be lateral movement in the network?”).
During the time the devices were unknowingly exposed to the internet, it’s possible that someone could have actually brute-force logged into some of them since some of the older devices do not have account lockout configured for excessive failed login attempts.

_____

Steps taken:

1. Preparation
Goal:

- Set up the hunt by defining what you're looking for.

3. Data Collection
   
Goal:

- Gather relevant data from logs, network traffic, and endpoints.

- Consider inspecting the logs to see which devices have been exposed to the internet and have received excessive failed login attempts.

- Take note of the source IP addresses and number of failures, etc.

Activity: Ensure data is available from all key sources for analysis.
- Ensure the relevant tables contain recent logs:
DeviceInfo
DeviceLogonEvents
_____

3. Data Analysis
   
Goal: Analyze data to test your hypothesis.
Activity: Look for anomalies, patterns, or indicators of compromise (IOCs) using various tools and techniques.

- Is there any evidence of brute force success (many failed logins followed by a success?) on your VM or ANY VMs in the environment?

- If so, what else happened on that machine around the same time? Were any bad actors able to log in?
_____

4. Investigation
   
Goal: Investigate any suspicious findings.
Activity: Dig deeper into detected threats, determine their scope, and escalate if necessary.

- See if anything you find matches TTPs within the MITRE ATT&CK Framework.

_____

5. Response
   
Goal: Mitigate any confirmed threats.
Activity: Work with security teams to contain, remove, and recover from the threat.
- Can anything be done?
_____

6. Documentation

Goal: Record your findings and learn from them.
Activity: Document what you found and use it to improve future hunts and defenses.
- Document what you did
_____

7. Improvement

Goal: Improve your security posture or refine your methods for the next hunt. 
Activity: Adjust strategies and tools based on what worked or didn’t.
- Anything we could have done to prevent the thing we hunted for? Any way we could have improved our hunting process?
_____

Timeline Summary and Findings:

Windows-target-1 has been internet facing for several days: 
DeviceInfo 
| where DeviceName == "windows-target-1" 
| where IsInternetFacing == true 
| order by Timestamp desc 
Last internet facing time: 2025-08-14T03:48:07.7293463Z 
____ 
Several bad actors have been discovered attempting to log into the target machine 
| where DeviceName == "windows-target-1" 
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock") 
| where ActionType == "LogonFailed" 
| where isnotempty(RemoteIP) 
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName 
| order by Attempts 

<img width="963" height="594" alt="image" src="https://github.com/user-attachments/assets/3e1ed82e-f767-43e9-b94f-7b7f1b348ad5" />

_____ 
The top 5 most failed login attempt IP addresses have not been able to successfully break into the VM: 

// Take the top 10 IPs with the most logon failures and see if any succeeded to logon 
let RemoteIPsInQuestion = dynamic(["57.129.140.32","45.134.26.142", "77.83.207.193", "209.15.123.95", 
"27.123.9.202"]);
DeviceLogonEvents 
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock") 
| where ActionType == "LogonSuccess" 
| where RemoteIP has_any(RemoteIPsInQuestion) 
_____

<Query no results> 

The only successful remote/network logons in the last 30 days was for the ‘labuser’ account (13 total)

DeviceLogonEvents 
| where DeviceName == "windows-target-1" 
| where LogonType == "Network" 
| where ActionType == "LogonSuccess" 
| where AccountName == "labuser" 
| summarize count() 
_____

There were zero (0) failed logons for the ‘labuser’ account, indicating that a brute force attempt for this 
account didn’t take place, and a 1-time password guess is unlikely.

DeviceLogonEvents 
| where DeviceName == "windows-target-1" 
| where LogonType == "Network" 
| where ActionType == "LogonFailed" 
| where AccountName == "labuser" 
| summarize count() 
_____ 

We checked all of the successful login IP addresses for the ‘labuser’ account to see if any of them were 
unusual or from an unexpected location. All were normal.

DeviceLogonEvents 
| where DeviceName == "windows-target-1" 
| where LogonType == "Network" 
| where ActionType == "LogonSuccess" 
| where AccountName == "labuser" 
| summarize LoginCount = count() by DeviceName, ActionType, AccountName, RemoteIP 

<img width="1080" height="435" alt="image" src="https://github.com/user-attachments/assets/29db760b-d1cf-4bb5-9aca-547052f97ebc" />

_____ 
Conclusion:

Though the device was exposed to the internet and clear brute force attempts have taken place. There is 
no evidence of any brute force success or unauthorized access from the legitimate account ‘labuser’ 
_____ 
Relevant MITRE ATT&CK TTPs: - **T1583.003 – Acquire Infrastructure: Virtual Private Server**   
(System exposed to the internet as a potential entry point) 
- **T1078 – Valid Accounts**   
(Legitimate account “labuser” used for network logon)
- **T1110.001 – Brute Force: Password Guessing**   
(Multiple failed login attempts from various remote IPs)
- **T1110.003 – Brute Force: Password Spraying**   
(Likely broad login attempts across accounts)
- **T1078.003 – Valid Accounts: Local Accounts**   
(Remote logons leveraging a legitimate local account) 
_____ 
Response Actions: 
Hardened the NSG attached to windows-target-1 to allow only RDP traffic from specific endpoints (no 
public internet access) 
Implemented account lockout policy 
Implemented MFA 
