### Recovering Active Directory

We learned basic concepts on implementing group policies and the least privilege model in the previous room. In this room, we will focus on Active Directory vulnerabilities, methods for recovering the compromised Active Directory domain controller, and preventive measures to avoid hacking attempts. We will also discuss the Active Directory red architecture to implement operating system hardening and benchmarks defined for the server environment.

**Learning Objectives**
- Immediate actions after infection  
- Identifying attack patterns and how to locate an infection vector
- Basic recovery process
- Common misconfigurations by domain administrators
- Post-recovery steps

1. **Immediate Actions - First Response**

The foremost important attempt of hackers is to gain persistent access to the system. Evicting threat actors entirely from a system is a complex and time-taking process; therefore, it is of utmost importance to limit the attack surface for the attacker and isolate the infrastructure (servers, objects) that are probably not compromised. Below is a quick checklist of steps that are recommended to be carried out before digging deep into the recovery process.  

* Take a backup of the compromised AD server using the built-in utility "Windows Server Backup". **You can access it through Run > wbadmin.msc**. Analysts would use the backup later for detailed malware and threat analysis.
* Restore the trusted backup of the Windows Server. This restore operation will result in the loss of some data, like AD objects (users, computers, etc.) that were added to the domain after creating the trusted backup.
* Segregate the network and activate the secondary domain controller to provide non-disruptive services to the user.
* Enable enhanced monitoring and filtering of traffic from the restored AD server to identify any attack pattern at the network level.
* Limit the creation and modification of new user accounts, GPOs etc., till the completion of the recovery process (if possible).

2. **Identifying Attack Patterns**

Understanding how the attack occurred is crucial to recover a compromised machine, as every device prepares logs based on specific events that help troubleshoot and investigate. Below is a list of tools used to analyse an Active Directory compromise incident.

**Event Viewer**
Event Viewer is a valuable tool for troubleshooting errors regarding Windows and applications. The event log service automatically starts with Windows and gives you detailed information about all critical events on your system. For example, if a computer program crashes or your system encounters a famous blue screen of death. You can read more about Windows services and Telemetry in the Windows Hardening room.
Events are grouped as Error, Warning, and Information, whereas significant categories are as below:
* Application: Records events of already installed programs.
* System: Records events of system components.
* Security: Logs events related to security and authentication.
We can access Event Viewer by typing **eventvwr** in the Run dialog.

**Bloodhound**
BloodHound is an Active Directory relational graphing tool with two primary functions:
* It can amazingly reveal the Active Directory's hidden relationships.
* It can miraculously determine the attack paths in an Active Directory environment.  

The assessment of BloodHound can be helpful for any organisation or company to outpace a wide array of security concerns. It utilises graph theory to perform the above-listed primary functions. It has an ingestor (called SharpHound) for data collection from all AD computers, groups, and users. Besides, it offers several benefits, like online backups and high-availability extensions (licensed ones). If you require the tool, you can easily download it from this link. You can visit the MITRE ATT&CK website to see the techniques used by this software.

**PowerView**
PowerView is a famous tool used by red teamers for Active Directory enumeration and identification of privileged accounts. Enumeration or profiling of AD is the first step taken by hackers to increase the attack surface and maximise the digital footprint of the target. Therefore, during the security assessment of an Active Directory, PowerView identifies loopholes that may result in a complete compromise of AD. You can download the PowerView PowerShell script from this link. The link contains various PowerShell scripts for LDAP, domain trust, user enumeration etc. 
We can execute PowerView in the attached VM through the following:
` Run the command Import-Module C:\Users\Administrator\Desktop\PowerView\pw.ps1 in a PowerShell terminal.
Once the module is imported, we can run various commands like Get-NetDomainController, which gets information about the domain controller.`


**Identification**:

**Powershell**
* Detection of User(s) Creation/Modifications
`Get-ADUser -Filter {((Enabled -eq $True) -and (Created-gt "Monday, April 10, 2023 00:00:00 AM"))} -Property Created, LastLogonDate | select SamAccountName, Name, Created | Sort-Object Created`

* Detection of Computers Joined the Domain
`Get-ADComputer -filter * -properties whencreated | Select Name,@{n="Owner";e={(Get-acl "ad:\$($_.distinguishedname)").owner}},whencreated`

* Group Membership Modification
To check the group membership changes, we can view the event logs and search for the specific event IDs generated in certain scenarios. Below is a list of the most interesting event IDs:
* ID 4756: Member added to a universal security group.
* ID 4757: Member removed from a universal security group.
* ID 4728: Member added to a global security group.
* ID 4729: Member removed from a global security group.

**Identifying Group Policy Changes**
After gaining access to the system, an attacker modifies the group policies to weaken the system's overall strength and enable multiple entry points. The event ID 4719 is associated with policy modification, which means that if any valid or invalid user tries to update the system audit policy, this action will generate an event log with ID 4719. Similarly, event ID 4739 is associated with domain policy change. We can search the Event Viewer for the ID as shown below:

**Domain Takeback**

Due to the enormous usage of AD in organisations, hackers always seek to compromise a less secure system. In this regard, a Post-Compromise plan must be in place to ensure the availability of services and minimise downtime for AD users. The process of recovering an AD after being compromised is called Domain Takeback. 

Steps for Recovery Plan
A few essential things that might be part of this plan are as follows: 
Reset the password for Tier 0 accounts. You can reset or disable an account by simply selecting the desired option

* Look for possibly compromised (suspicious) accounts and reset their password to avoid privilege escalation.
* Change the password for the Kerberos service account and make it unusable for the attacker.
* Reset the passwords of accounts with administrative privileges.
* Use the Reset-ComputerMachinePassword PowerShell command to perform reset operations for computer objects on the domain.
* Reset the password of the domain controller machine to prevent silver ticket abuse. You can learn more about the different types of Kerberos-based attacks here. 

Domain Controllers are the essential element for protection and recovery. If you have configured a writable domain controller (DC) as a backup for a compromised one, you can restore it to avoid disruption (Be careful while performing this step. Do not restore an instance of a compromised DC).
Perform malware analysis on any targeted domain controller server for identification of malicious scripts.
Verify that the attacker has not added any scheduled tasks or start-up applications for persistent access. You can access the task scheduler through Run > taskschd.msc.

* Check event logs, Access Control Lists (ACLs), and group policies for any possible change.
* Enable traffic filtering on inbound and outbound traffic to identify Indicators of Compromise (IOC) at the network level (to be carried out at the Security Operation Center level).  

Several AD protection and risk assessment tools, like Ping Castle, are available for auditing and identifying AD environment loopholes. Moreover, we can also forward logs to some SIEM solutions like Wazuh and Splunk, for detailed network analysis.
