Enumeration

nmap -sC -sV 10.10.44.64
Nmap scan report for 10.10.44.64
Host is up (0.19s latency).
Not shown: 999 closed ports
PORT STATE SERVICE VERSION
80/tcp open http Apache httpd 2.4.18 ((Ubuntu))
|_hhtp-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works

Looks like Apache is open

GoBuster time to smash through some directories

GoBuster has shown us there is a /secret page we can visit, but when we navigate there in chrome it is an empty body. We can tell at the very least that secret is a directory, so lets gobuster it again.

Hmm nothing, lets check for files with .txt extensions.

Read the contents of secret.txt with a browser or cURL, and use the credentials to connect to ssh.

Hashed?
HashID
Run the hash through hashid to see what kind of hash it is. Use the -m flag to see the correlating hashcat mode

Hashcat
hashid thinks it is most likely a SHA1 hash. Crack the hash with hashcat using the mode provided by hashid.

Ssh
Connect with the cracked credentials and you’ll find the user flag in nyan’s home directory.

PrivEsc
sudo -l
Check the users sudo privileges.

and from here we get the first flag.

Next is just a bunch of tools intro to tools like Nikto, metasploit,nc, hashcat, john

Task 5 Web Enumeration:

#1 How do you specify which host to use? 
ANSWER: -h

#2 What flag disables ssl?
ANSWER: -nossl

#3 How do you force ssl?
ANSWER: -ssl

#4 How do you specify authentication(username + pass)?
ANSWER: -id

#5 How do you select which plugin to use?
ANSWER: -plugins

#6 Which plugin checks if you can enumerate apache users? 
You have to run this command:

1
nikto --list-plugins
Then you can show the answer:

ANSWER: apacheuser

Done, now onto the metasploit part



