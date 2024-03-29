TRYHACKME TSHARK

Before jumping in, a quick note: TShark is a tool that helps you perform network analysis, packet captures, etc., which is usually done through Wireshark. Due to this, if you are unfamiliar with Wireshark, do the Wireshark room first before proceeding to this room.


If you’re unfamiliar with what this is, go do the Wireshark room first!
Task 1: Pre-Reqs
As opposed to walkthrough posts created by others, I am not going to copy down what was written by the room’s author, m4lwhere (also, check out their site: plenty of really good resources). This site is just as much of a learning resource for me as it is for you.

The first resource I usually check out when learning a new tool or technique is the creator’s github — particularly the README files — or website. As such, TShark’s manual page’s website provides the following description of the tool:

TShark is a network protocol analyzer. It lets you capture packet data from a live network, or read packets from a previously saved capture file, either printing a decoded form of those packets to the standard output or writing the packets to a file.

https://www.wireshark.org/docs/man-pages/tshark.html
Taken together with the room author’s initial questions (“Bored with trying to extract packets by hand? Need to get info from a pcap file that doesn’t extract easily from Wireshark? Are GUIs for losers but no you realized you can’t open Wireshark? Well my friend, TShark is the solution to all your problems.”) tells me that this is a CLI tool that will help us read through packet captures. Whereas before you had to walk slowly through packet captures in Wireshark, this provides a more readable output.

As with other tools, you have to make sure the tool is installed. I suggest that, if you have not done so already, you get a Kali Linux virtual image and use it to practice these tools. TShark is usually installed: you can check running the following command:

1
apt list tshark
If you get a file location, it’s installed. If not, install it with:

1
sudo apt install tshark
While I suggest using Kali Linux, you can also use Windows by downloading and running the tshark.exe file in the Wireshark install directory.

Task 2: Reading PCAP Files
The next step you should always take when trying a new tool is go to the manual and help page. I’ve already linked to TShark’s online manual page, but you can use the man option (man tshark) or the help flag (tshark -h).

The first switch you should be aware of is the -r switch. This allows you to read the pcap file; it will show each packet like tcpdump does. Use this for a high-level view, like the room’s author says.

┌──(kali㉿kali)-[~/THM/tshark]
└─$ tshark -r cap
    1   0.000000 192.168.170.8 → 192.168.170.20 DNS 70 Standard query 0x1032 TXT google.com
    2   0.000530 192.168.170.20 → 192.168.170.8 DNS 98 Standard query response 0x1032 TXT google.com TXT
    3   4.005222 192.168.170.8 → 192.168.170.20 DNS 70 Standard query 0xf76f MX google.com
    4   4.837355 192.168.170.20 → 192.168.170.8 DNS 298 Standard query response 0xf76f MX google.com MX 40 smtp4.google.com MX 10 smtp5.google.com MX 10 smtp6.google.com MX 10 smtp1.google.com MX 10 smtp2.google.com MX 40 smtp3.google.com A 216.239.37.26 A 64.233.167.25 A 66.102.9.25 A 216.239.57.25 A 216.239.37.25 A 216.239.57.26
    5  12.817185 192.168.170.8 → 192.168.170.20 DNS 70 Standard query 0x49a1 LOC google.com
    6  12.956209 192.168.170.20 → 192.168.170.8 DNS 70 Standard query response 0x49a1 LOC google.com
    7  20.824827 192.168.170.8 → 192.168.170.20 DNS 85 Standard query 0x9bbb PTR 104.9.192.66.in-addr.arpa
    8  20.825333 192.168.170.20 → 192.168.170.8 DNS 129 Standard query response 0x9bbb PTR 104.9.192.66.in-addr.arpa PTR 66-192-9-104.gen.twtelecom.net
    9  92.189905 192.168.170.8 → 192.168.170.20 DNS 74 Standard query 0x75c0 A www.netbsd.org
   10  92.238816 192.168.170.20 → 192.168.170.8 DNS 90 Standard query response 0x75c0 A www.netbsd.org A 204.152.190.12
   11 108.965135 192.168.170.8 → 192.168.170.20 DNS 74 Standard query 0xf0d4 AAAA www.netbsd.org
   12 109.202803 192.168.170.20 → 192.168.170.8 DNS 102 Standard query response 0xf0d4 AAAA www.netbsd.org AAAA 2001:4f8:4:7:2e0:81ff:fe52:9a6b
   13 169.027394 192.168.170.8 → 192.168.170.20 DNS 74 Standard query 0x7f39 AAAA www.netbsd.org
   14 169.027781 192.168.170.20 → 192.168.170.8 DNS 102 Standard query response 0x7f39 AAAA www.netbsd.org AAAA 2001:4f8:4:7:2e0:81ff:fe52:9a6b
   15 178.239844 192.168.170.8 → 192.168.170.20 DNS 74 Standard query 0x8db3 AAAA www.google.com
   16 178.256382 192.168.170.20 → 192.168.170.8 DNS 94 Standard query response 0x8db3 AAAA www.google.com CNAME www.l.google.com
   17 187.853816 192.168.170.8 → 192.168.170.20 DNS 76 Standard query 0xdca2 AAAA www.l.google.com
   18 187.870481 192.168.170.20 → 192.168.170.8 DNS 76 Standard query response 0xdca2 AAAA www.l.google.com
   19 228.708302 192.168.170.8 → 192.168.170.20 DNS 75 Standard query 0xbc1f AAAA www.example.com
   20 228.941445 192.168.170.20 → 192.168.170.8 DNS 75 Standard query response 0xbc1f AAAA www.example.com
   21 240.323938 192.168.170.8 → 192.168.170.20 DNS 79 Standard query 0x266d AAAA www.example.notginh
   22 240.536930 192.168.170.20 → 192.168.170.8 DNS 79 Standard query response 0x266d No such name AAAA www.example.notginh
   23 271.164734 192.168.170.8 → 192.168.170.20 DNS 71 Standard query 0xfee3 ANY www.isc.org
   24 271.237338 192.168.170.20 → 192.168.170.8 DNS 115 Standard query response 0xfee3 ANY www.isc.org AAAA 2001:4f8:0:2::d A 204.152.184.88
   25 271.241158 192.168.170.8 → 192.168.170.20 DNS 82 Standard query 0x5a53 PTR 1.0.0.127.in-addr.arpa
   26 271.241746 192.168.170.20 → 192.168.170.8 DNS 105 Standard query response 0x5a53 PTR 1.0.0.127.in-addr.arpa PTR localhost
   27 271.244120 192.168.170.8 → 192.168.170.20 DNS 67 Standard query 0x208a NS isc.org
   28 271.259884 192.168.170.56 → 217.13.4.24  DNS 129 Standard query 0x326e SRV _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.utelsystems.local
   29 271.262407 192.168.170.20 → 192.168.170.8 DNS 166 Standard query response 0x208a NS isc.org NS ns-ext.nrt1.isc.org NS ns-ext.sth1.isc.org NS ns-ext.isc.org NS ns-ext.lga1.isc.org
   30 271.279695  217.13.4.24 → 192.168.170.56 DNS 129 Standard query response 0x326e No such name SRV _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.utelsystems.local
   31 271.280350 192.168.170.56 → 217.13.4.24  DNS 98 Standard query 0xf161 SRV _ldap._tcp.dc._msdcs.utelsystems.local
   32 271.297651  217.13.4.24 → 192.168.170.56 DNS 98 Standard query response 0xf161 No such name SRV _ldap._tcp.dc._msdcs.utelsystems.local
   33 271.298194 192.168.170.56 → 217.13.4.24  DNS 140 Standard query 0x8361 SRV _ldap._tcp.05b5292b-34b8-4fb7-85a3-8beef5fd2069.domains._msdcs.utelsystems.local
   34 271.317878  217.13.4.24 → 192.168.170.56 DNS 140 Standard query response 0x8361 No such name SRV _ldap._tcp.05b5292b-34b8-4fb7-85a3-8beef5fd2069.domains._msdcs.utelsystems.local
   35 271.419659 192.168.170.56 → 217.13.4.24  DNS 83 Standard query 0xd060 A GRIMM.utelsystems.local
   36 271.436583  217.13.4.24 → 192.168.170.56 DNS 83 Standard query response 0xd060 No such name A GRIMM.utelsystems.local
   37 278.861300 192.168.170.56 → 217.13.4.24  DNS 83 Standard query 0x7663 A GRIMM.utelsystems.local
   38 278.879313  217.13.4.24 → 192.168.170.56 DNS 83 Standard query response 0x7663 No such name A GRIMM.utelsystems.local
Continuing on, we can pair the -r flag with | wc -l to see how many packets are included in the packet capture file:

┌──(kali㉿kali)-[~/THM/tshark]
└─$ tshark -r cap | wc -l                                         
                        
Usually, though, you are going to be working with pcap files that are hundreds, thousands, tens of thousands, or even larger amount of lines. This is where the next command comes in, which allows you to use Wireshark’s filters to list only the packets you want to see. You use the -Y switch to add filters.

Using the same examples as the page walkthrough, to see only DNS A packets, you use dns.qry.type == 1, like so:

┌──(kali㉿kali)-[~/THM/tshark]
└─$ tshark -r cap -Y "dns.qry.type == 1"                         
As the walkthrough says, “[t]he power of TShark comes with combining traditional Wireshark filters with extraction.” This is true, but as will be seen, you will have to explore the switches included with TShark in order to really bring this power out.

That being said, you can narrow the Wireshark filters down even more to extract only the fields you want to see. You can do so using the -T fields and -e [fieldname] switches. Using the same example above, we would tack on -T fields -e dns.qry.name at the end of the tshark command to see the A records in the pcap file:

1
2
┌──(kali㉿kali)-[~/THM/tshark]
└─$ tshark -r cap -Y "dns.qry.type == 1" -T  fields -e dns.qry.name
To wrap up the lesson part of Task 2, the last note provided is really helpful: if you want to know what field name to use in the query above, you can open the pcap file in Wireshark, click a packet matching the same you are filtering for in TShark, go down to the Packet Details Window (the middle window or the one right before the window with all the hex code), click the arrows next to the following: DNS > Queries > website > and then select the “Name” field. At the bottom of the screen, Wireshark will show something like “Query Name (dns.qry.name).”

Exercises
How many packets are in the dns.cap file?
First, note that when you download the task file, it will be named “cap”
Go back up in the lesson: run the first command listed and it will show the answer.
How many A records are in the capture? (Including responses)
Run the second command above to get your answer.
Which A record was present the most?
You won’t have to run another command for this one. Just look at the output of the command from question 2.
Task 3: DNS Exfil
Go ahead and download the task files. We will walk through answering the questions together.

Exercises
1. How many packets are in this capture?

Run: tshark -r pcap
One of the things not mentioned in the lessons above is that when you run the simple -r pcap command, each packet will be numbered in the order they were captured. You can use this to find how many packets you are dealing with.
2. How many DNS queries are in this pcap? (Not responses!)

Looking at the hint, the room’s author suggests we use “dns.flags.response == 0” display filter. This is similar to one of the commands in the lesson examples in Task 2.
The command should look like this:

┌──(kali㉿kali)-[~/THM/tshark]
└─$ tshark -r pcap -Y "dns.flags.response == 0" | wc -l   
3. What is the DNS transaction ID of the suspicious queries (in hex)?

There are really two ways to find the answer to this question. The easiest is to look at the results from entering the command for question 1, above. You should see a rather strange looking string. Or, if you are so inclined, you can open the pcap file in Wireshark and look at the DNS requests: again, you should see a weird looking string. That’ll be your answer.
4. What is the string extracted from the DNS queries?

I’ll have to admit, this one tripped me up a bit. I searched through the commands included in Task 2’s lesson, searched online for a command to find it, and then realized the answer was staring right at me through the results used by the second command above.
You should see two sets of letters running throughout the results. Don’t worry about the A — that is a DNS record type. Pay attention to the second set of random letters.
Unfortunately, I couldn’t find a method easier than just copying those out by hand into the answer box.
5. What is the flag?

On to the grand finale. You won’t have to do any more searching because the random letters are encrypted.
I fed this into hash-identifier and found that it is base32 encoded, so I ran:

echo "MZWGCZ33ORUDC427NFZV65BQOVTWQX3XNF2GQMDVG5PXI43IGRZGWIL5" | base32 -d
That should return the flag.
