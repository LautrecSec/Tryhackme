From Nmap scan we are understand that which ports and services are running behind the scene.

intitle:”report”(nmap)filetype:.txt
Here I got two open ports 80 and 443 and indicates we have website running.

This is themed of Mr.Robot and there redirection command which is redirected to another page like image,video.
So we have a website now this is a time for enumeration like searching of directories from url(uniform resource locator)
For Web Directory enumeration I am using here Gobuster cli(command line interface) based utility and using wordlist from /usr/share/worlists/dirbuster/directory-list-2.3-small.txt
Gobuster Scan:

This output saved in a robotsdir.txt
Now open robotsdir.txt file helps of “cat(concatenate)” linux command.

Now open interesting directory with status code 200


From /robots I got key-1-of-3.txt
Just feel awesome. Open that .txt ,

Bingo !!! Key 1 : #Captured.
Now check that fsocity.dic from robots.Download it and open with cat linux command


Now perform a dictionary attack on the login page we got earlier
In login page using wrong credential like admin password at capture it on burpsuite proxy tool.


The username and password field by log and pwd.
Dictionary attack using Hydra:
For username and password the dictionary would be fsocity.dic. Otherwise we would try to use seclists worldlists for dictionary attack on username and password.
Https://github.com/danielmiessler/SecLists.
First we will try to find the username with password as constants.

Now check with username Elliot and password test.

We get error here.
So now again here using hydra, now Username constant and password change.

We are getting 9 digit password and access on account. It’s take time when you bruteforcing like dictionary attack.

Version of wordpess is 4.3.1 .
Now check for php-reverse-shell on kali linux.if you are not user of kali so u can download from pentestmonkey website.

Open /usr/share/webshells/php/php-reverse-shell.php with leafpad and paste it on appearance — -editor — — -paste php-reverse-shell script on archive.php field and change ip address of Kali linux.
php-reverse-shell
This tool is designed for those situations during a pentest where you have upload access to a webserver that's running…
pentestmonkey.net


Now after update open archive.php.


Bingo reverse_shell is working;;;; oh shit!!!!!!
Now check the process with help of slide


But here is no executable permission for key-2-of-3.txt
But we can execute and read file of password.raw-md5 and here for that we have used john the ripper or crackstation.net

OR

Now try to access on robot user and switching to robot user we can not open terminal from /bin/sh –i

For terminal access now using here python shell spawning script.
Spawning a TTY Shell
Often during pen tests you may obtain a shell without having tty, yet wish to interact further with the system. Here…
netsec.ws


So we open terminal from above method
Now trying for second key .

Oh no!!!!!! finally found you second key!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
Now looking for third no. of key,for that switching to root and for root will perform privilege escalation ,
For that figure out which programs have SUID (set owner user id upon execution) of 4000 , so here run find command.

As you can see on above nmap is ran as root,So,nmap suid shell script is not working here.

After some digging the version of nmap is too old.

So after some time I found that nmap used to have an interactive mode from where you could spawn shells,Lucky for me the version is compatible.
Finally got it my last and third no. of key.


I having amazing time with this room.learn so much things from here.
