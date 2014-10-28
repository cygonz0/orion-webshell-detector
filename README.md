by : hjerold & gaber52
maintained by: hjerold


Synopsis
--------
This work-in-progress "Orion Webshell Detector" was created with the intention of assisting web application code reviews coded in PHP, ASP and JSP technologies. It is capable of detecting potential web shells as well as detecting dangerous usage of system function calls (e.g. shell_exec etc.)

What is a webshell?
-------------------
More and more web sites are currently making use of server side web application languages like ASP, PHP and JSP to produce dynamically generated web pages. This provides a way to customize web content for different, individual users. These web application languages are powerful, and a security issue within a web application can often lead to the execution of arbitrary scripting codes. As we know that web application codes are often not maintained upon deployment, resulting in weak points which are open to attack and this is one of the main reasons why web servers have become a favorite target of malicious attackers.

A malicious attacker will be able to exploit those vulnerabilities to leave a backdoor into a compromised system. A backdoor using server side web application is also known as a “web shell”. These shells usually allow system command execution and remote file access, which can be a huge problem if used by unintended parties.

Brief program flow
------------------
1. Scan files in a directory and all sub directories
2. Scan for webshell signature matches
3. Scan for dangerous function matches
4. Scan for codes placed on the same line:

Scan for php:
-	Scanning for user input via $_GET, $_POST etc.
-	Scanning for variables used in dangerous functions
-	Scanning for user input assigned to variables
-	Scanning for variables of user input assigned to other variables
-	Scan for codes encoded using base64
-	Properly identify user-defined functions, and identify dangerous functions used in them

Scan for asp:
-	Scan for user input
-	Scan for user input assigned to variables
-	Scan for variables of user input assigned to other variables
-	Scan for use of user input in dangerous functions
-	Scan for user-defined functions, and identify dangerous functions used in them

Scan for jsp:
-	Scan for user input
-	Scan for user input assigned to variables
-	Scan for variables of user input assigned to other variables
-	Scan for use of user input in dangerous functions

Compilation notes
-----------------
Quincy 2005 was used to develop and compile this webshell detector. The GUI is compiled using Microsoft Visual Studio 2010. (.sln file provided)

Note: More info can be found in the Appendix file.
