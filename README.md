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

By understanding and mitigating OS command injection, you can ensure your applications remain secure. Let me know if you’d like more examples or specific mitigation techniques!
