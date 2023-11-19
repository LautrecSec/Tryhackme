### Recovering Active Directory

We learned basic concepts on implementing group policies and the least privilege model in the previous room. In this room, we will focus on Active Directory vulnerabilities, methods for recovering the compromised Active Directory domain controller, and preventive measures to avoid hacking attempts. We will also discuss the Active Directory red architecture to implement operating system hardening and benchmarks defined for the server environment.

**Learning Objectives**
- Immediate actions after infection  
- Identifying attack patterns and how to locate an infection vector
- Basic recovery process
- Common misconfigurations by domain administrators
- Post-recovery steps

**Immediate Actions - First Response**

The foremost important attempt of hackers is to gain persistent access to the system. Evicting threat actors entirely from a system is a complex and time-taking process; therefore, it is of utmost importance to limit the attack surface for the attacker and isolate the infrastructure (servers, objects) that are probably not compromised. Below is a quick checklist of steps that are recommended to be carried out before digging deep into the recovery process.  

* Take a backup of the compromised AD server using the built-in utility "Windows Server Backup". **You can access it through Run > wbadmin.msc**. Analysts would use the backup later for detailed malware and threat analysis.
* Restore the trusted backup of the Windows Server. This restore operation will result in the loss of some data, like AD objects (users, computers, etc.) that were added to the domain after creating the trusted backup.
* Segregate the network and activate the secondary domain controller to provide non-disruptive services to the user.
* Enable enhanced monitoring and filtering of traffic from the restored AD server to identify any attack pattern at the network level.
* Limit the creation and modification of new user accounts, GPOs etc., till the completion of the recovery process (if possible).


