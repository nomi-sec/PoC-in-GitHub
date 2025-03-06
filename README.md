# PoC in GitHub

## 2025

## 2024
### CVE-2024-0012 (2024-11-18)

<code>An authentication bypass in Palo Alto Networks PAN-OS software enables an unauthenticated attacker with network access to the management web interface to gain PAN-OS administrator privileges to perform administrative actions, tamper with the configuration, or exploit other authenticated privilege escalation vulnerabilities like  CVE-2024-9474 https://security.paloaltonetworks.com/CVE-2024-9474 .\n\nThe risk of this issue is greatly reduced if you secure access to the management web interface by restricting access to only trusted internal IP addresses according to our recommended  best practice deployment guidelines https://live.paloaltonetworks.com/t5/community-blogs/tips-amp-tricks-how-to-secure-the-management-access-of-your-palo/ba-p/464431 .\n\nThis issue is applicable only to PAN-OS 10.2, PAN-OS 11.0, PAN-OS 11.1, and PAN-OS 11.2 software.\n\nCloud NGFW and Prisma Access are not impacted by this vulnerability.
</code>

- [0xjessie21/CVE-2024-0012](https://github.com/0xjessie21/CVE-2024-0012)
- [TalatumLabs/CVE-2024-0012_CVE-2024-9474_PoC](https://github.com/TalatumLabs/CVE-2024-0012_CVE-2024-9474_PoC)
- [dcollaoa/cve-2024-0012-gui-poc](https://github.com/dcollaoa/cve-2024-0012-gui-poc)

### CVE-2024-0015 (2024-02-16)

<code>In convertToComponentName of DreamService.java, there is a possible way to launch arbitrary protected activities due to intent redirection. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation.
</code>

- [UmVfX1BvaW50/CVE-2024-0015](https://github.com/UmVfX1BvaW50/CVE-2024-0015)

### CVE-2024-0044 (2024-03-11)

<code>In createSessionInternal of PackageInstallerService.java, there is a possible run-as any app due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.
</code>

- [scs-labrat/android_autorooter](https://github.com/scs-labrat/android_autorooter)
- [0xbinder/CVE-2024-0044](https://github.com/0xbinder/CVE-2024-0044)
- [Dit-Developers/CVE-2024-0044-](https://github.com/Dit-Developers/CVE-2024-0044-)

### CVE-2024-0132 (2024-09-26)

<code>NVIDIA Container Toolkit 1.16.1 or earlier contains a Time-of-check Time-of-Use (TOCTOU) vulnerability when used with default configuration where a specifically crafted container image may gain access to the host file system. This does not impact use cases where CDI is used. A successful exploit of this vulnerability may lead to code execution, denial of service, escalation of privileges, information disclosure, and data tampering.
</code>

- [ssst0n3/poc-cve-2024-0132](https://github.com/ssst0n3/poc-cve-2024-0132)
- [r0binak/CVE-2024-0132](https://github.com/r0binak/CVE-2024-0132)

### CVE-2024-0195 (2024-01-02)

<code>Es wurde eine Schwachstelle in spider-flow 0.4.3 gefunden. Sie wurde als kritisch eingestuft. Es betrifft die Funktion FunctionService.saveFunction der Datei src/main/java/org/spiderflow/controller/FunctionController.java. Durch Manipulieren mit unbekannten Daten kann eine code injection-Schwachstelle ausgenutzt werden. Der Angriff kann über das Netzwerk erfolgen. Der Exploit steht zur öffentlichen Verfügung.
</code>

- [Cappricio-Securities/CVE-2024-0195](https://github.com/Cappricio-Securities/CVE-2024-0195)

### CVE-2024-0235 (2024-01-16)

<code>The EventON WordPress plugin before 4.5.5, EventON WordPress plugin before 2.2.7 do not have authorisation in an AJAX action, allowing unauthenticated users to retrieve email addresses of any users on the blog
</code>

- [Nxploited/CVE-2024-0235-PoC](https://github.com/Nxploited/CVE-2024-0235-PoC)

### CVE-2024-0324 (2024-02-05)

<code>The User Profile Builder – Beautiful User Registration Forms, User Profiles &amp; User Role Editor plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'wppb_two_factor_authentication_settings_update' function in all versions up to, and including, 3.10.8. This makes it possible for unauthenticated attackers to enable or disable the 2FA functionality present in the Premium version of the plugin for arbitrary user roles.
</code>

- [kodaichodai/CVE-2024-0324](https://github.com/kodaichodai/CVE-2024-0324)

### CVE-2024-0352 (2024-01-09)

<code>In Likeshop bis 2.5.7.20210311 wurde eine Schwachstelle entdeckt. Sie wurde als kritisch eingestuft. Es geht um die Funktion FileServer::userFormImage der Datei server/application/api/controller/File.php der Komponente HTTP POST Request Handler. Mit der Manipulation des Arguments file mit unbekannten Daten kann eine unrestricted upload-Schwachstelle ausgenutzt werden. Der Angriff kann über das Netzwerk erfolgen. Der Exploit steht zur öffentlichen Verfügung.
</code>

- [Cappricio-Securities/CVE-2024-0352](https://github.com/Cappricio-Securities/CVE-2024-0352)

### CVE-2024-0507 (2024-01-16)

<code>An attacker with access to a Management Console user account with the editor role could escalate privileges through a command injection vulnerability in the Management Console. This vulnerability affected all versions of GitHub Enterprise Server and was fixed in versions 3.11.3, 3.10.5, 3.9.8, and 3.8.13 This vulnerability was reported via the GitHub Bug Bounty program.
</code>

- [convisolabs/CVE-2024-0507_CVE-2024-0200-github](https://github.com/convisolabs/CVE-2024-0507_CVE-2024-0200-github)

### CVE-2024-0582 (2024-01-16)

<code>A memory leak flaw was found in the Linux kernel’s io_uring functionality in how a user registers a buffer ring with IORING_REGISTER_PBUF_RING, mmap() it, and then frees it. This flaw allows a local user to crash or potentially escalate their privileges on the system.
</code>

- [101010zyl/CVE-2024-0582-dataonly](https://github.com/101010zyl/CVE-2024-0582-dataonly)

### CVE-2024-0683 (2024-03-13)

<code>The Bulgarisation for WooCommerce plugin for WordPress is vulnerable to unauthorized access due to missing capability checks on several functions in all versions up to, and including, 3.0.14. This makes it possible for unauthenticated and authenticated attackers, with subscriber-level access and above, to generate and delete labels.
</code>

- [3474458191/CVE-2024-0683](https://github.com/3474458191/CVE-2024-0683)

### CVE-2024-0986 (2024-01-28)

<code>Eine Schwachstelle wurde in Issabel PBX 4.0.0 ausgemacht. Sie wurde als kritisch eingestuft. Es geht hierbei um eine nicht näher spezifizierte Funktion der Datei /index.php?menu=asterisk_cli der Komponente Asterisk-Cli. Durch Beeinflussen des Arguments Command mit unbekannten Daten kann eine os command injection-Schwachstelle ausgenutzt werden. Der Angriff kann über das Netzwerk angegangen werden. Der Exploit steht zur öffentlichen Verfügung.
</code>

- [gunzf0x/Issabel-PBX-4.0.0-RCE-Authenticated](https://github.com/gunzf0x/Issabel-PBX-4.0.0-RCE-Authenticated)

### CVE-2024-1086 (2024-01-31)

<code>A use-after-free vulnerability in the Linux kernel's netfilter: nf_tables component can be exploited to achieve local privilege escalation.\n\nThe nft_verdict_init() function allows positive values as drop error within the hook verdict, and hence the nf_hook_slow() function can cause a double free vulnerability when NF_DROP is issued with a drop error which resembles NF_ACCEPT.\n\nWe recommend upgrading past commit f342de4e2f33e0e39165d8639387aa6c19dff660.
</code>

- [LLfam/CVE-2024-1086](https://github.com/LLfam/CVE-2024-1086)

### CVE-2024-1212 (2024-02-21)

<code>Unauthenticated remote attackers can access the system through the LoadMaster management interface, enabling arbitrary system command execution.\n\n\n
</code>

- [Rehan07-Human/Exploiting-RCE-Cyber_Project_CVE-2024-1212](https://github.com/Rehan07-Human/Exploiting-RCE-Cyber_Project_CVE-2024-1212)

### CVE-2024-1651 (2024-02-19)

<code>Torrentpier version 2.4.1 allows executing arbitrary commands on the server.\n\nThis is possible because the application is vulnerable to insecure deserialization.\n\n\n\n\n
</code>

- [killukeren/cve-2024-1651](https://github.com/killukeren/cve-2024-1651)

### CVE-2024-1709 (2024-02-21)

<code>ConnectWise ScreenConnect 23.9.7 and prior are affected by an Authentication Bypass Using an Alternate Path or Channel\n\n vulnerability, which may allow an attacker direct access to confidential information or \n\ncritical systems.\n\n
</code>

- [W01fh4cker/ScreenConnect-AuthBypass-RCE](https://github.com/W01fh4cker/ScreenConnect-AuthBypass-RCE)

### CVE-2024-1728 (2024-04-10)

<code>gradio-app/gradio is vulnerable to a local file inclusion vulnerability due to improper validation of user-supplied input in the UploadButton component. Attackers can exploit this vulnerability to read arbitrary files on the filesystem, such as private SSH keys, by manipulating the file path in the request to the `/queue/join` endpoint. This issue could potentially lead to remote code execution. The vulnerability is present in the handling of file upload paths, allowing attackers to redirect file uploads to unintended locations on the server.
</code>

- [yuanmeng-MINGI/CVE-2024-1728](https://github.com/yuanmeng-MINGI/CVE-2024-1728)

### CVE-2024-2876 (2024-05-02)

<code>The Email Subscribers by Icegram Express – Email Marketing, Newsletters, Automation for WordPress &amp; WooCommerce plugin for WordPress is vulnerable to SQL Injection via the 'run' function of the 'IG_ES_Subscribers_Query' class in all versions up to, and including, 5.7.14 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.
</code>

- [Quantum-Hacker/CVE-2024-2876](https://github.com/Quantum-Hacker/CVE-2024-2876)
- [0xlf/CVE-2024-2876](https://github.com/0xlf/CVE-2024-2876)

### CVE-2024-2961 (2024-04-17)

<code>The iconv() function in the GNU C Library versions 2.39 and older may overflow the output buffer passed to it by up to 4 bytes when converting strings to the ISO-2022-CN-EXT character set, which may be used to crash an application or overwrite a neighbouring variable.
</code>

- [ambionics/cnext-exploits](https://github.com/ambionics/cnext-exploits)
- [4wayhandshake/CVE-2024-2961](https://github.com/4wayhandshake/CVE-2024-2961)
- [omarelshopky/exploit_cve-2023-26326_using_cve-2024-2961](https://github.com/omarelshopky/exploit_cve-2023-26326_using_cve-2024-2961)
- [suce0155/CVE-2024-2961_buddyforms_2.7.7](https://github.com/suce0155/CVE-2024-2961_buddyforms_2.7.7)
- [regantemudo/PHP-file-read-to-RCE-CVE-2024-2961-](https://github.com/regantemudo/PHP-file-read-to-RCE-CVE-2024-2961-)

### CVE-2024-2997 (2024-03-27)

<code>In Bdtask Multi-Store Inventory Management System bis 20240320 wurde eine problematische Schwachstelle ausgemacht. Hierbei betrifft es unbekannten Programmcode. Durch das Manipulieren des Arguments Category Name/Model Name/Brand Name/Unit Name mit unbekannten Daten kann eine cross site scripting-Schwachstelle ausgenutzt werden. Umgesetzt werden kann der Angriff über das Netzwerk. Der Exploit steht zur öffentlichen Verfügung.
</code>

- [lfillaz/CVE-2024-2997](https://github.com/lfillaz/CVE-2024-2997)

### CVE-2024-3094 (2024-03-29)

<code>Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0. \r\nThrough a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.
</code>

- [XiaomingX/cve-2024-3094-xz-backdoor-exploit](https://github.com/XiaomingX/cve-2024-3094-xz-backdoor-exploit)

### CVE-2024-3273 (2024-04-04)

<code>Es wurde eine Schwachstelle in D-Link DNS-320L, DNS-325, DNS-327L and DNS-340L bis 20240403 gefunden. Sie wurde als kritisch eingestuft. Betroffen hiervon ist ein unbekannter Ablauf der Datei /cgi-bin/nas_sharing.cgi der Komponente HTTP GET Request Handler. Durch die Manipulation des Arguments system mit unbekannten Daten kann eine command injection-Schwachstelle ausgenutzt werden. Umgesetzt werden kann der Angriff über das Netzwerk. Der Exploit steht zur öffentlichen Verfügung.
</code>

- [GSTEINF/CVE-2024-3273](https://github.com/GSTEINF/CVE-2024-3273)

### CVE-2024-3400 (2024-04-12)

<code>A command injection as a result of arbitrary file creation vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software for specific PAN-OS versions and distinct feature configurations may enable an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.\n\nCloud NGFW, Panorama appliances, and Prisma Access are not impacted by this vulnerability.
</code>

- [AdaniKamal/CVE-2024-3400](https://github.com/AdaniKamal/CVE-2024-3400)
- [hashdr1ft/SOC274-Palo-Alto-Networks-PAN-OS-Command-Injection-Vulnerability-Exploitation-CVE-2024-3400](https://github.com/hashdr1ft/SOC274-Palo-Alto-Networks-PAN-OS-Command-Injection-Vulnerability-Exploitation-CVE-2024-3400)

### CVE-2024-3690 (2024-04-12)

<code>In PHPGurukul Small CRM 3.0 wurde eine kritische Schwachstelle entdeckt. Hierbei betrifft es unbekannten Programmcode der Komponente Change Password Handler. Durch Beeinflussen mit unbekannten Daten kann eine sql injection-Schwachstelle ausgenutzt werden. Umgesetzt werden kann der Angriff über das Netzwerk. Der Exploit steht zur öffentlichen Verfügung.
</code>

- [taeseongk/CVE-2024-3690](https://github.com/taeseongk/CVE-2024-3690)

### CVE-2024-4040 (2024-04-22)

<code>A server side template injection vulnerability in CrushFTP in all versions before 10.7.1 and 11.1.0 on all platforms allows unauthenticated remote attackers to read files from the filesystem outside of the VFS Sandbox, bypass authentication to gain administrative access, and perform remote code execution on the server.\n
</code>

- [Stuub/CVE-2024-4040-SSTI-LFI-PoC](https://github.com/Stuub/CVE-2024-4040-SSTI-LFI-PoC)
- [olebris/CVE-2024-4040](https://github.com/olebris/CVE-2024-4040)

### CVE-2024-4358 (2024-05-29)

<code>In Progress Telerik Report Server, version 2024 Q1 (10.0.24.305) or earlier, on IIS, an unauthenticated attacker can gain access to Telerik Report Server restricted functionality via an authentication bypass vulnerability.
</code>

- [verylazytech/CVE-2024-4358](https://github.com/verylazytech/CVE-2024-4358)

### CVE-2024-4367 (2024-05-14)

<code>A type check was missing when handling fonts in PDF.js, which would allow arbitrary JavaScript execution in the PDF.js context. This vulnerability affects Firefox &lt; 126, Firefox ESR &lt; 115.11, and Thunderbird &lt; 115.11.
</code>

- [clarkio/pdfjs-vuln-demo](https://github.com/clarkio/pdfjs-vuln-demo)
- [inpentest/CVE-2024-4367-PoC](https://github.com/inpentest/CVE-2024-4367-PoC)

### CVE-2024-4573
- [Castro-Ian/CVE-2024-4573-Mitigation-Script](https://github.com/Castro-Ian/CVE-2024-4573-Mitigation-Script)

### CVE-2024-4577 (2024-06-09)

<code>In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use &quot;Best-Fit&quot; behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.
</code>

- [huseyinstif/CVE-2024-4577-Nuclei-Template](https://github.com/huseyinstif/CVE-2024-4577-Nuclei-Template)
- [xcanwin/CVE-2024-4577-PHP-RCE](https://github.com/xcanwin/CVE-2024-4577-PHP-RCE)
- [K3ysTr0K3R/CVE-2024-4577-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2024-4577-EXPLOIT)
- [aaddmin1122345/cve-2024-4577](https://github.com/aaddmin1122345/cve-2024-4577)
- [Entropt/CVE-2024-4577_Analysis](https://github.com/Entropt/CVE-2024-4577_Analysis)
- [VictorShem/CVE-2024-4577](https://github.com/VictorShem/CVE-2024-4577)
- [PhinehasNarh/CVE-2024-4577-LetsDefend-walkthrough](https://github.com/PhinehasNarh/CVE-2024-4577-LetsDefend-walkthrough)
- [ggfzx/CVE-2024-4577](https://github.com/ggfzx/CVE-2024-4577)
- [olebris/CVE-2024-4577](https://github.com/olebris/CVE-2024-4577)
- [AlperenY-cs/CVE-2024-4577](https://github.com/AlperenY-cs/CVE-2024-4577)
- [chihyeonwon/php-cgi-cve-2024-4577](https://github.com/chihyeonwon/php-cgi-cve-2024-4577)
- [Didarul342/CVE-2024-4577](https://github.com/Didarul342/CVE-2024-4577)
- [sug4r-wr41th/CVE-2024-4577](https://github.com/sug4r-wr41th/CVE-2024-4577)

### CVE-2024-4956 (2024-05-16)

<code>Path Traversal in Sonatype Nexus Repository 3 allows an unauthenticated attacker to read system files. Fixed in version 3.68.1.
</code>

- [ifconfig-me/CVE-2024-4956-Bulk-Scanner](https://github.com/ifconfig-me/CVE-2024-4956-Bulk-Scanner)
- [fin3ss3g0d/CVE-2024-4956](https://github.com/fin3ss3g0d/CVE-2024-4956)
- [verylazytech/CVE-2024-4956](https://github.com/verylazytech/CVE-2024-4956)
- [XiaomingX/cve-2024-4956](https://github.com/XiaomingX/cve-2024-4956)

### CVE-2024-5084 (2024-05-23)

<code>The Hash Form – Drag &amp; Drop Form Builder plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'file_upload_action' function in all versions up to, and including, 1.1.0. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.
</code>

- [Chocapikk/CVE-2024-5084](https://github.com/Chocapikk/CVE-2024-5084)
- [ModeBrutal/CVE-2024-5084-Auto-Exploit](https://github.com/ModeBrutal/CVE-2024-5084-Auto-Exploit)

### CVE-2024-5124 (2024-06-06)

<code>A timing attack vulnerability exists in the gaizhenbiao/chuanhuchatgpt repository, specifically within the password comparison logic. The vulnerability is present in version 20240310 of the software, where passwords are compared using the '=' operator in Python. This method of comparison allows an attacker to guess passwords based on the timing of each character's comparison. The issue arises from the code segment that checks a password for a particular username, which can lead to the exposure of sensitive information to an unauthorized actor. An attacker exploiting this vulnerability could potentially guess user passwords, compromising the security of the system.
</code>

- [XiaomingX/cve-2024-5124-poc](https://github.com/XiaomingX/cve-2024-5124-poc)

### CVE-2024-5452 (2024-06-06)

<code>A remote code execution (RCE) vulnerability exists in the lightning-ai/pytorch-lightning library version 2.2.1 due to improper handling of deserialized user input and mismanagement of dunder attributes by the `deepdiff` library. The library uses `deepdiff.Delta` objects to modify application state based on frontend actions. However, it is possible to bypass the intended restrictions on modifying dunder attributes, allowing an attacker to construct a serialized delta that passes the deserializer whitelist and contains dunder attributes. When processed, this can be exploited to access other modules, classes, and instances, leading to arbitrary attribute write and total RCE on any self-hosted pytorch-lightning application in its default configuration, as the delta endpoint is enabled by default.
</code>

- [skrkcb2/CVE-2024-5452](https://github.com/skrkcb2/CVE-2024-5452)

### CVE-2024-5735 (2024-06-28)

<code>Full Path Disclosure vulnerability in AdmirorFrames Joomla! extension in afHelper.php script allows an unauthorised attacker to retrieve location of web root folder. This issue affects AdmirorFrames: before 5.0.
</code>

- [afine-com/CVE-2024-5735](https://github.com/afine-com/CVE-2024-5735)

### CVE-2024-5736 (2024-06-28)

<code>Server Side Request Forgery (SSRF) vulnerability in AdmirorFrames Joomla! extension in afGdStream.php script allows to access local files or server pages available only from localhost. This issue affects AdmirorFrames: before 5.0.
</code>

- [afine-com/CVE-2024-5736](https://github.com/afine-com/CVE-2024-5736)

### CVE-2024-5737 (2024-06-28)

<code>Script afGdStream.php in AdmirorFrames Joomla! extension doesn’t specify a content type and as a result default (text/html) is used. An attacker may embed HTML tags directly in image data which is rendered by a webpage as HTML. This issue affects AdmirorFrames: before 5.0.
</code>

- [afine-com/CVE-2024-5737](https://github.com/afine-com/CVE-2024-5737)

### CVE-2024-5806 (2024-06-25)

<code>Improper Authentication vulnerability in Progress MOVEit Transfer (SFTP module) can lead to Authentication Bypass.This issue affects MOVEit Transfer: from 2023.0.0 before 2023.0.11, from 2023.1.0 before 2023.1.6, from 2024.0.0 before 2024.0.2.
</code>

- [watchtowrlabs/watchTowr-vs-progress-moveit_CVE-2024-5806](https://github.com/watchtowrlabs/watchTowr-vs-progress-moveit_CVE-2024-5806)

### CVE-2024-5909 (2024-06-12)

<code>A problem with a protection mechanism in the Palo Alto Networks Cortex XDR agent on Windows devices allows a low privileged local Windows user to disable the agent. This issue may be leveraged by malware to disable the Cortex XDR agent and then to perform malicious activity.
</code>

- [ig-labs/EDR-ALPC-Block-POC](https://github.com/ig-labs/EDR-ALPC-Block-POC)

### CVE-2024-5932 (2024-08-20)

<code>The GiveWP – Donation Plugin and Fundraising Platform plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 3.14.1 via deserialization of untrusted input from the 'give_title' parameter. This makes it possible for unauthenticated attackers to inject a PHP Object. The additional presence of a POP chain allows attackers to execute code remotely, and to delete arbitrary files.
</code>

- [0xb0mb3r/CVE-2024-5932-PoC](https://github.com/0xb0mb3r/CVE-2024-5932-PoC)
- [EQSTLab/CVE-2024-5932](https://github.com/EQSTLab/CVE-2024-5932)

### CVE-2024-6028 (2024-06-25)

<code>The Quiz Maker plugin for WordPress is vulnerable to time-based SQL Injection via the 'ays_questions' parameter in all versions up to, and including, 6.5.8.3 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.
</code>

- [truonghuuphuc/CVE-2024-6028-Poc](https://github.com/truonghuuphuc/CVE-2024-6028-Poc)

### CVE-2024-6244 (2024-07-22)

<code>The PZ Frontend Manager WordPress plugin before 1.0.6 does not have CSRF checks in some places, which could allow attackers to make logged in users perform unwanted actions via CSRF attacks
</code>

- [Nxploited/CVE-2024-6244](https://github.com/Nxploited/CVE-2024-6244)

### CVE-2024-6330 (2024-08-19)

<code>The GEO my WP WordPress plugin before 4.5.0.2 does not prevent unauthenticated attackers from including arbitrary files in PHP's execution context, which leads to Remote Code Execution.
</code>

- [RandomRobbieBF/CVE-2024-6330](https://github.com/RandomRobbieBF/CVE-2024-6330)

### CVE-2024-6366 (2024-07-29)

<code>The User Profile Builder  WordPress plugin before 3.11.8 does not have proper authorisation, allowing unauthenticated users to upload media files via the async upload functionality of WP.
</code>

- [Nxploited/CVE-2024-6366-PoC](https://github.com/Nxploited/CVE-2024-6366-PoC)

### CVE-2024-6387 (2024-07-01)

<code>A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race condition which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be able to trigger it by failing to authenticate within a set time period.
</code>

- [xaitax/CVE-2024-6387_Check](https://github.com/xaitax/CVE-2024-6387_Check)
- [SkyGodling/CVE-2024-6387-POC](https://github.com/SkyGodling/CVE-2024-6387-POC)
- [dream434/CVE-2024-6387](https://github.com/dream434/CVE-2024-6387)
- [zql-gif/CVE-2024-6387](https://github.com/zql-gif/CVE-2024-6387)
- [awusan125/test_for6387](https://github.com/awusan125/test_for6387)

### CVE-2024-6624 (2024-07-11)

<code>The JSON API User plugin for WordPress is vulnerable to privilege escalation in all versions up to, and including, 3.9.3. This is due to improper controls on custom user meta fields. This makes it possible for unauthenticated attackers to register as administrators on the site. The plugin requires the JSON API plugin to also be installed.
</code>

- [Jenderal92/CVE-2024-6624](https://github.com/Jenderal92/CVE-2024-6624)

### CVE-2024-6782 (2024-08-06)

<code>Improper access control in Calibre 6.9.0 ~ 7.14.0 allow unauthenticated attackers to achieve remote code execution.
</code>

- [NketiahGodfred/CVE-2024-6782](https://github.com/NketiahGodfred/CVE-2024-6782)

### CVE-2024-7014 (2024-07-23)

<code>EvilVideo vulnerability allows sending malicious apps disguised as videos in Telegram for Android application affecting \n versions 10.14.4 and older.
</code>

- [hexspectrum1/CVE-2024-7014](https://github.com/hexspectrum1/CVE-2024-7014)

### CVE-2024-7479 (2024-09-25)

<code>Improper verification of cryptographic signature during installation of a VPN driver via the TeamViewer_service.exe component of TeamViewer Remote Clients prior version 15.58.4 for Windows allows an attacker with local unprivileged access on a Windows system to elevate their privileges and install drivers.
</code>

- [PeterGabaldon/CVE-2024-7479_CVE-2024-7481](https://github.com/PeterGabaldon/CVE-2024-7479_CVE-2024-7481)

### CVE-2024-7627 (2024-09-05)

<code>The Bit File Manager plugin for WordPress is vulnerable to Remote Code Execution in versions 6.0 to 6.5.5 via the 'checkSyntax' function. This is due to writing a temporary file to a publicly accessible directory before performing file validation. This makes it possible for unauthenticated attackers to execute code on the server if an administrator has allowed Guest User read permissions.
</code>

- [siunam321/CVE-2024-7627-PoC](https://github.com/siunam321/CVE-2024-7627-PoC)

### CVE-2024-7954 (2024-08-23)

<code>The porte_plume plugin used by SPIP before 4.30-alpha2, 4.2.13, and 4.1.16 is vulnerable to an arbitrary code execution vulnerability. A remote and unauthenticated attacker can execute arbitrary PHP as the SPIP user by sending a crafted HTTP request.
</code>

- [zxj-hub/CVE-2024-7954POC](https://github.com/zxj-hub/CVE-2024-7954POC)
- [0dayan0n/RCE_CVE-2024-7954-](https://github.com/0dayan0n/RCE_CVE-2024-7954-)
- [Arthikw3b/RCE-CVE-2024-7954](https://github.com/Arthikw3b/RCE-CVE-2024-7954)

### CVE-2024-7985 (2024-10-29)

<code>The FileOrganizer – Manage WordPress and Website Files plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the &quot;fileorganizer_ajax_handler&quot; function in all versions up to, and including, 1.0.9. This makes it possible for authenticated attackers, with Subscriber-level access and above, and permissions granted by an administrator, to upload arbitrary files on the affected site's server which may make remote code execution possible. NOTE: The FileOrganizer Pro plugin must be installed and active to allow Subscriber+ users to upload files.
</code>

- [Nxploited/CVE-2024-7985-PoC](https://github.com/Nxploited/CVE-2024-7985-PoC)

### CVE-2024-8190 (2024-09-10)

<code>An OS command injection vulnerability in Ivanti Cloud Services Appliance versions 4.6 Patch 518 and before allows a remote authenticated attacker to obtain remote code execution. The attacker must have admin level privileges to exploit this vulnerability.
</code>

- [flyingllama87/CVE-2024-8190-unauth](https://github.com/flyingllama87/CVE-2024-8190-unauth)

### CVE-2024-8381 (2024-09-03)

<code>A potentially exploitable type confusion could be triggered when looking up a property name on an object being used as the `with` environment. This vulnerability affects Firefox &lt; 130, Firefox ESR &lt; 128.2, Firefox ESR &lt; 115.15, Thunderbird &lt; 128.2, and Thunderbird &lt; 115.15.
</code>

- [bjrjk/CVE-2024-8381](https://github.com/bjrjk/CVE-2024-8381)

### CVE-2024-8672 (2024-11-28)

<code>The Widget Options – The #1 WordPress Widget &amp; Block Control Plugin plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 4.0.7 via the display logic functionality that extends several page builders. This is due to the plugin allowing users to supply input that will be passed through eval() without any filtering or capability checks. This makes it possible for authenticated attackers, with contributor-level access and above, to execute code on the server. Special note: We suggested the vendor implement an allowlist of functions and limit the ability to execute commands to just administrators, however, they did not take our advice. We are considering this patched, however, we believe it could still be further hardened and there may be residual risk with how the issue is currently patched.
</code>

- [Chocapikk/CVE-2024-8672](https://github.com/Chocapikk/CVE-2024-8672)

### CVE-2024-8743 (2024-10-05)

<code>The Bit File Manager – 100% Free &amp; Open Source File Manager and Code Editor for WordPress plugin for WordPress is vulnerable to Limited JavaScript File Upload in all versions up to, and including, 6.5.7. This is due to a lack of proper checks on allowed file types. This makes it possible for authenticated attackers, with Subscriber-level access and above, and granted permissions by an administrator, to upload .css and .js files, which could lead to Stored Cross-Site Scripting.
</code>

- [siunam321/CVE-2024-8743-PoC](https://github.com/siunam321/CVE-2024-8743-PoC)

### CVE-2024-9014 (2024-09-23)

<code>pgAdmin versions 8.11 and earlier are vulnerable to a security flaw in OAuth2 authentication. This vulnerability allows an attacker to potentially obtain the client ID and secret, leading to unauthorized access to user data.
</code>

- [EQSTLab/CVE-2024-9014](https://github.com/EQSTLab/CVE-2024-9014)

### CVE-2024-9047 (2024-10-12)

<code>The WordPress File Upload plugin for WordPress is vulnerable to Path Traversal in all versions up to, and including, 4.24.11 via wfu_file_downloader.php. This makes it possible for unauthenticated attackers to read or delete files outside of the originally intended directory. Successful exploitation requires the targeted WordPress installation to be using PHP 7.4 or earlier.
</code>

- [iSee857/CVE-2024-9047-PoC](https://github.com/iSee857/CVE-2024-9047-PoC)

### CVE-2024-9234 (2024-10-11)

<code>The GutenKit – Page Builder Blocks, Patterns, and Templates for Gutenberg Block Editor plugin for WordPress is vulnerable to arbitrary file uploads due to a missing capability check on the install_and_activate_plugin_from_external() function  (install-active-plugin REST API endpoint) in all versions up to, and including, 2.1.0. This makes it possible for unauthenticated attackers to install and activate arbitrary plugins, or utilize the functionality to upload arbitrary files spoofed like plugins.
</code>

- [Nxploited/CVE-2024-9234](https://github.com/Nxploited/CVE-2024-9234)

### CVE-2024-9264 (2024-10-18)

<code>The SQL Expressions experimental feature of Grafana allows for the evaluation of `duckdb` queries containing user input. These queries are insufficiently sanitized before being passed to `duckdb`, leading to a command injection and local file inclusion vulnerability. Any user with the VIEWER or higher permission is capable of executing this attack.  The `duckdb` binary must be present in Grafana's $PATH for this attack to function; by default, this binary is not installed in Grafana distributions.
</code>

- [nollium/CVE-2024-9264](https://github.com/nollium/CVE-2024-9264)

### CVE-2024-9290 (2024-12-13)

<code>The Super Backup &amp; Clone - Migrate for WordPress plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation and a missing capability check on the ibk_restore_migrate_check() function in all versions up to, and including, 2.3.3. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.
</code>

- [RandomRobbieBF/CVE-2024-9290](https://github.com/RandomRobbieBF/CVE-2024-9290)
- [Jenderal92/CVE-2024-9290](https://github.com/Jenderal92/CVE-2024-9290)

### CVE-2024-9441 (2024-10-02)

<code>The Linear eMerge e3-Series through version 1.00-07 is vulnerable to an OS command injection vulnerability. A remote and unauthenticated attacker can execute arbitrary OS commands via the login_id parameter when invoking the forgot_password functionality over HTTP.
</code>

- [jk-mayne/CVE-2024-9441-Checker](https://github.com/jk-mayne/CVE-2024-9441-Checker)

### CVE-2024-9465 (2024-10-09)

<code>An SQL injection vulnerability in Palo Alto Networks Expedition allows an unauthenticated attacker to reveal Expedition database contents, such as password hashes, usernames, device configurations, and device API keys. With this, attackers can also create and read arbitrary files on the Expedition system.
</code>

- [XiaomingX/cve-2024-9465-poc](https://github.com/XiaomingX/cve-2024-9465-poc)

### CVE-2024-9474 (2024-11-18)

<code>A privilege escalation vulnerability in Palo Alto Networks PAN-OS software allows a PAN-OS administrator with access to the management web interface to perform actions on the firewall with root privileges.\n\nCloud NGFW and Prisma Access are not impacted by this vulnerability.
</code>

- [coskper-papa/PAN-OS_CVE-2024-9474](https://github.com/coskper-papa/PAN-OS_CVE-2024-9474)

### CVE-2024-9698 (2024-12-14)

<code>The Crafthemes Demo Import plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'process_uploaded_files' function in all versions up to, and including, 3.3. This makes it possible for authenticated attackers, with Administrator-level access and above, to upload arbitrary files on the affected site's server which may make remote code execution possible.
</code>

- [Nxploited/CVE-2024-9698](https://github.com/Nxploited/CVE-2024-9698)

### CVE-2024-9933 (2024-10-26)

<code>The WatchTowerHQ plugin for WordPress is vulnerable to authentication bypass in versions up to, and including, 3.9.6. This is due to the 'watchtower_ota_token' default value is empty, and the not empty check is missing in the 'Password_Less_Access::login' function. This makes it possible for unauthenticated attackers to log in to the WatchTowerHQ client administrator user.
</code>

- [Nxploited/CVE-2024-9933](https://github.com/Nxploited/CVE-2024-9933)

### CVE-2024-9935 (2024-11-16)

<code>The PDF Generator Addon for Elementor Page Builder plugin for WordPress is vulnerable to Path Traversal in all versions up to, and including, 1.7.5 via the rtw_pgaepb_dwnld_pdf() function. This makes it possible for unauthenticated attackers to read the contents of arbitrary files on the server, which can contain sensitive information.
</code>

- [verylazytech/CVE-2024-9935](https://github.com/verylazytech/CVE-2024-9935)
- [Nxploited/CVE-2024-9935](https://github.com/Nxploited/CVE-2024-9935)

### CVE-2024-10124 (2024-12-12)

<code>The Vayu Blocks – Gutenberg Blocks for WordPress &amp; WooCommerce plugin for WordPress is vulnerable to unauthorized arbitrary plugin installation and activation due to a missing capability check on the tp_install() function in all versions up to, and including, 1.1.1. This makes it possible for unauthenticated attackers to install and activate arbitrary plugins which can be leveraged to achieve remote code execution if another vulnerable plugin is installed and activated. This vulnerability was partially patched in version 1.1.1.
</code>

- [RandomRobbieBF/CVE-2024-10124](https://github.com/RandomRobbieBF/CVE-2024-10124)

### CVE-2024-10220 (2024-11-22)

<code>The Kubernetes kubelet component allows arbitrary command execution via specially crafted gitRepo volumes.This issue affects kubelet: through 1.28.11, from 1.29.0 through 1.29.6, from 1.30.0 through 1.30.2.
</code>

- [XiaomingX/cve-2024-10220-githooks](https://github.com/XiaomingX/cve-2024-10220-githooks)
- [filipzag/CVE-2024-10220](https://github.com/filipzag/CVE-2024-10220)
- [candranapits/poc-CVE-2024-10220](https://github.com/candranapits/poc-CVE-2024-10220)

### CVE-2024-10511 (2024-12-11)

<code>CWE-287: Improper Authentication vulnerability exists that could cause Denial of access to the web interface\nwhen someone on the local network repeatedly requests the /accessdenied URL.
</code>

- [revengsmK/CVE-2024-10511](https://github.com/revengsmK/CVE-2024-10511)

### CVE-2024-10516 (2024-12-06)

<code>The Swift Performance Lite plugin for WordPress is vulnerable to Local PHP File Inclusion in all versions up to, and including, 2.3.7.1 via the 'ajaxify' function. This makes it possible for unauthenticated attackers to include and execute arbitrary files on the server, allowing the execution of any PHP code in those files. This can be used to bypass access controls, obtain sensitive data, or achieve code execution in cases where images and other “safe” file types can be uploaded and included.
</code>

- [RandomRobbieBF/CVE-2024-10516](https://github.com/RandomRobbieBF/CVE-2024-10516)

### CVE-2024-10793 (2024-11-15)

<code>The WP Activity Log plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the user_id parameter in all versions up to, and including, 5.2.1 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever an administrative user accesses an injected page.
</code>

- [MAHajian/CVE-2024-10793](https://github.com/MAHajian/CVE-2024-10793)

### CVE-2024-10914 (2024-11-06)

<code>In D-Link DNS-320, DNS-320LW, DNS-325 and DNS-340L bis 20241028 wurde eine kritische Schwachstelle ausgemacht. Hierbei betrifft es die Funktion cgi_user_add der Datei /cgi-bin/account_mgr.cgi?cmd=cgi_user_add. Durch Manipulation des Arguments name mit unbekannten Daten kann eine os command injection-Schwachstelle ausgenutzt werden. Umgesetzt werden kann der Angriff über das Netzwerk. Die Komplexität eines Angriffs ist eher hoch. Sie gilt als schwierig ausnutzbar. Der Exploit steht zur öffentlichen Verfügung.
</code>

- [ThemeHackers/CVE-2024-10914](https://github.com/ThemeHackers/CVE-2024-10914)
- [jahithoque/CVE-2024-10914-Exploit](https://github.com/jahithoque/CVE-2024-10914-Exploit)
- [redspy-sec/D-Link](https://github.com/redspy-sec/D-Link)
- [dragonXZH/CVE-2024-10914](https://github.com/dragonXZH/CVE-2024-10914)
- [yenyangmjaze/cve-2024-10914](https://github.com/yenyangmjaze/cve-2024-10914)
- [silverxpymaster/CVE-2024-10914-Exploit](https://github.com/silverxpymaster/CVE-2024-10914-Exploit)

### CVE-2024-10924 (2024-11-15)

<code>The Really Simple Security (Free, Pro, and Pro Multisite) plugins for WordPress are vulnerable to authentication bypass in versions 9.0.0 to 9.1.1.1. This is due to improper user check error handling in the two-factor REST API actions with the 'check_login_and_get_user' function. This makes it possible for unauthenticated attackers to log in as any existing user on the site, such as an administrator, when the &quot;Two-Factor Authentication&quot; setting is enabled (disabled by default).
</code>

- [D1se0/CVE-2024-10924-Bypass-MFA-Wordpress-LAB](https://github.com/D1se0/CVE-2024-10924-Bypass-MFA-Wordpress-LAB)
- [Hunt3r850/CVE-2024-10924-PoC](https://github.com/Hunt3r850/CVE-2024-10924-PoC)
- [Hunt3r850/CVE-2024-10924-Wordpress-Docker](https://github.com/Hunt3r850/CVE-2024-10924-Wordpress-Docker)
- [Nxploited/CVE-2024-10924-Exploit](https://github.com/Nxploited/CVE-2024-10924-Exploit)
- [cy3erdr4g0n/CVE-2024-10924](https://github.com/cy3erdr4g0n/CVE-2024-10924)
- [h8sU/wordpress-cve-2024-10924-exploit](https://github.com/h8sU/wordpress-cve-2024-10924-exploit)
- [sariamubeen/CVE-2024-10924](https://github.com/sariamubeen/CVE-2024-10924)
- [MaleeshaUdan/wordpress-CVE-2024-10924--exploit](https://github.com/MaleeshaUdan/wordpress-CVE-2024-10924--exploit)

### CVE-2024-10930 (2025-03-04)

<code>An Uncontrolled Search Path Element vulnerability exists which could allow a malicious actor to perform DLL hijacking and execute arbitrary code with escalated privileges.
</code>

- [sahil3276/CVE-2024-10930](https://github.com/sahil3276/CVE-2024-10930)

### CVE-2024-11252 (2024-11-30)

<code>The Social Sharing Plugin – Sassy Social Share plugin for WordPress is vulnerable to Reflected Cross-Site Scripting via the heateor_mastodon_share parameter in all versions up to, and including, 3.3.69 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that execute if they can successfully trick a user into performing an action such as clicking on a link.
</code>

- [reinh3rz/CVE-2024-11252-Sassy-Social-Share-XSS](https://github.com/reinh3rz/CVE-2024-11252-Sassy-Social-Share-XSS)

### CVE-2024-11318 (2024-11-18)

<code>An IDOR (Insecure Direct Object Reference) vulnerability has been discovered in AbsysNet, affecting version 2.3.1. This vulnerability could allow a remote attacker to obtain the session of an unauthenticated user by brute-force attacking the session identifier on the &quot;/cgi-bin/ocap/&quot; endpoint.
</code>

- [xthalach/CVE-2024-11318](https://github.com/xthalach/CVE-2024-11318)

### CVE-2024-11320 (2024-11-21)

<code>Arbitrary commands execution on the server by exploiting a command injection vulnerability in the LDAP authentication mechanism. This issue affects Pandora FMS: from 700 through &lt;=777.4
</code>

- [mhaskar/CVE-2024-11320](https://github.com/mhaskar/CVE-2024-11320)

### CVE-2024-11392 (2024-11-22)

<code>Hugging Face Transformers MobileViTV2 Deserialization of Untrusted Data Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Hugging Face Transformers. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.\n\nThe specific flaw exists within the handling of configuration files. The issue results from the lack of proper validation of user-supplied data, which can result in deserialization of untrusted data. An attacker can leverage this vulnerability to execute code in the context of the current user. Was ZDI-CAN-24322.
</code>

- [Piyush-Bhor/CVE-2024-11392](https://github.com/Piyush-Bhor/CVE-2024-11392)

### CVE-2024-11393 (2024-11-22)

<code>Hugging Face Transformers MaskFormer Model Deserialization of Untrusted Data Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Hugging Face Transformers. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.\n\nThe specific flaw exists within the parsing of model files. The issue results from the lack of proper validation of user-supplied data, which can result in deserialization of untrusted data. An attacker can leverage this vulnerability to execute code in the context of the current user. Was ZDI-CAN-25191.
</code>

- [Piyush-Bhor/CVE-2024-11393](https://github.com/Piyush-Bhor/CVE-2024-11393)

### CVE-2024-11394 (2024-11-22)

<code>Hugging Face Transformers Trax Model Deserialization of Untrusted Data Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Hugging Face Transformers. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.\n\nThe specific flaw exists within the handling of model files. The issue results from the lack of proper validation of user-supplied data, which can result in deserialization of untrusted data. An attacker can leverage this vulnerability to execute code in the context of the current user. Was ZDI-CAN-25012.
</code>

- [Piyush-Bhor/CVE-2024-11394](https://github.com/Piyush-Bhor/CVE-2024-11394)

### CVE-2024-11477 (2024-11-22)

<code>7-Zip Zstandard Decompression Integer Underflow Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of 7-Zip. Interaction with this library is required to exploit this vulnerability but attack vectors may vary depending on the implementation.\n\nThe specific flaw exists within the implementation of Zstandard decompression. The issue results from the lack of proper validation of user-supplied data, which can result in an integer underflow before writing to memory. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-24346.
</code>

- [TheN00bBuilder/cve-2024-11477-writeup](https://github.com/TheN00bBuilder/cve-2024-11477-writeup)

### CVE-2024-11616 (2024-12-19)

<code>Netskope was made aware of a security vulnerability in Netskope Endpoint DLP’s Content Control Driver where a double-fetch issue leads to heap overflow. The vulnerability arises from the fact that the NumberOfBytes argument to ExAllocatePoolWithTag, and the Length argument for RtlCopyMemory, both independently dereference their value from the user supplied input buffer inside the EpdlpSetUsbAction function, known as a double-fetch. If this length value grows to a higher value in between these two calls, it will result in the RtlCopyMemory call copying user-supplied memory contents outside the range of the allocated buffer, resulting in a heap overflow. A malicious attacker will need admin privileges to exploit the issue.\nThis issue affects Endpoint DLP version below R119.
</code>

- [inb1ts/CVE-2024-11616](https://github.com/inb1ts/CVE-2024-11616)

### CVE-2024-11643 (2024-12-04)

<code>The Accessibility by AllAccessible plugin for WordPress is vulnerable to unauthorized modification of data that can lead to privilege escalation due to a missing capability check on the 'AllAccessible_save_settings' function in all versions up to, and including, 1.3.4. This makes it possible for authenticated attackers, with Subscriber-level access and above, to update arbitrary options on the WordPress site. This can be leveraged to update the default role for registration to administrator and enable user registration for attackers to gain administrative user access to a vulnerable site.
</code>

- [RandomRobbieBF/CVE-2024-11643](https://github.com/RandomRobbieBF/CVE-2024-11643)

### CVE-2024-11680 (2024-11-26)

<code>ProjectSend versions prior to r1720 are affected by an improper authentication vulnerability. Remote, unauthenticated attackers can exploit this flaw by sending crafted HTTP requests to options.php, enabling unauthorized modification of the application's configuration. Successful exploitation allows attackers to create accounts, upload webshells, and embed malicious JavaScript.
</code>

- [D3N14LD15K/CVE-2024-11680_PoC_Exploit](https://github.com/D3N14LD15K/CVE-2024-11680_PoC_Exploit)

### CVE-2024-11728 (2024-12-06)

<code>The KiviCare – Clinic &amp; Patient Management System (EHR) plugin for WordPress is vulnerable to SQL Injection via the 'visit_type[service_id]' parameter of the tax_calculated_data AJAX action in all versions up to, and including, 3.6.4 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.
</code>

- [samogod/CVE-2024-11728](https://github.com/samogod/CVE-2024-11728)

### CVE-2024-11972 (2024-12-31)

<code>The Hunk Companion WordPress plugin before 1.9.0 does not correctly authorize some REST API endpoints, allowing unauthenticated requests to install and activate arbitrary Hunk Companion WordPress plugin before 1.9.0 from the WordPress.org repo, including vulnerable Hunk Companion WordPress plugin before 1.9.0 that have been closed.
</code>

- [JunTakemura/exploit-CVE-2024-11972](https://github.com/JunTakemura/exploit-CVE-2024-11972)

### CVE-2024-12025 (2024-12-18)

<code>The Collapsing Categories plugin for WordPress is vulnerable to SQL Injection via the 'taxonomy' parameter of the /wp-json/collapsing-categories/v1/get REST API in all versions up to, and including, 3.0.8 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.
</code>

- [RandomRobbieBF/CVE-2024-12025](https://github.com/RandomRobbieBF/CVE-2024-12025)

### CVE-2024-12172 (2024-12-12)

<code>The WP Courses LMS – Online Courses Builder, eLearning Courses, Courses Solution, Education Courses plugin for WordPress is vulnerable to unauthorized access due to a missing capability check on the wpc_update_user_meta_option() function in all versions up to, and including, 3.2.21. This makes it possible for authenticated attackers, with Subscriber-level access and above, to update arbitrary user's metadata which can be levereged to block an administrator from accessing their site when wp_capabilities is set to 0.
</code>

- [RandomRobbieBF/CVE-2024-12172](https://github.com/RandomRobbieBF/CVE-2024-12172)

### CVE-2024-12209 (2024-12-08)

<code>The WP Umbrella: Update Backup Restore &amp; Monitoring plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 2.17.0 via the 'filename' parameter of the 'umbrella-restore' action. This makes it possible for unauthenticated attackers to include and execute arbitrary files on the server, allowing the execution of any PHP code in those files. This can be used to bypass access controls, obtain sensitive data, or achieve code execution in cases where images and other “safe” file types can be uploaded and included.
</code>

- [RandomRobbieBF/CVE-2024-12209](https://github.com/RandomRobbieBF/CVE-2024-12209)
- [Nxploited/CVE-2024-12209](https://github.com/Nxploited/CVE-2024-12209)

### CVE-2024-12270 (2024-12-07)

<code>The Beautiful taxonomy filters plugin for WordPress is vulnerable to SQL Injection via the 'selects[0][term]' parameter in all versions up to, and including, 2.4.3 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.
</code>

- [RandomRobbieBF/CVE-2024-12270](https://github.com/RandomRobbieBF/CVE-2024-12270)

### CVE-2024-12484 (2024-12-11)

<code>In Codezips Technical Discussion Forum 1.0 wurde eine Schwachstelle entdeckt. Sie wurde als kritisch eingestuft. Das betrifft eine unbekannte Funktionalität der Datei /signuppost.php. Durch das Manipulieren des Arguments Username mit unbekannten Daten kann eine sql injection-Schwachstelle ausgenutzt werden. Der Angriff kann über das Netzwerk angegangen werden. Der Exploit steht zur öffentlichen Verfügung.
</code>

- [LiChaser/CVE-2024-12484](https://github.com/LiChaser/CVE-2024-12484)

### CVE-2024-12542 (2025-01-09)

<code>The linkID plugin for WordPress is vulnerable to unauthorized access of data due to a missing capability check when including the 'phpinfo' function in all versions up to, and including, 0.1.2. This makes it possible for unauthenticated attackers to read configuration settings and predefined variables on the site's server. The plugin does not need to be activated for the vulnerability to be exploited.
</code>

- [Nxploited/CVE-2024-12542-PoC](https://github.com/Nxploited/CVE-2024-12542-PoC)

### CVE-2024-13159 (2025-01-14)

<code>Absolute path traversal in Ivanti EPM before the 2024 January-2025 Security Update and 2022 SU6 January-2025 Security Update allows a remote unauthenticated attacker to leak sensitive information.
</code>

- [horizon3ai/Ivanti-EPM-Coercion-Vulnerabilities](https://github.com/horizon3ai/Ivanti-EPM-Coercion-Vulnerabilities)

### CVE-2024-13375 (2025-01-18)

<code>The Adifier System plugin for WordPress is vulnerable to privilege escalation via account takeover in all versions up to, and including, 3.1.7. This is due to the plugin not properly validating a user's identity prior to updating their details like password through the adifier_recover() function. This makes it possible for unauthenticated attackers to change arbitrary user's passwords, including administrators, and leverage that to gain access to their account.
</code>

- [McTavishSue/CVE-2024-13375](https://github.com/McTavishSue/CVE-2024-13375)

### CVE-2024-13478 (2025-02-19)

<code>The LTL Freight Quotes – TForce Edition plugin for WordPress is vulnerable to SQL Injection via the 'dropship_edit_id' and 'edit_id' parameters in all versions up to, and including, 3.6.4 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.
</code>

- [RandomRobbieBF/CVE-2024-13478](https://github.com/RandomRobbieBF/CVE-2024-13478)

### CVE-2024-13479 (2025-02-19)

<code>The LTL Freight Quotes – SEFL Edition plugin for WordPress is vulnerable to SQL Injection via the 'dropship_edit_id' and 'edit_id' parameters in all versions up to, and including, 3.2.4 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.
</code>

- [RandomRobbieBF/CVE-2024-13479](https://github.com/RandomRobbieBF/CVE-2024-13479)

### CVE-2024-13481 (2025-02-19)

<code>The LTL Freight Quotes – R+L Carriers Edition plugin for WordPress is vulnerable to SQL Injection via the 'edit_id' and 'dropship_edit_id' parameters in all versions up to, and including, 3.3.4 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.
</code>

- [RandomRobbieBF/CVE-2024-13481](https://github.com/RandomRobbieBF/CVE-2024-13481)

### CVE-2024-13483 (2025-02-19)

<code>The LTL Freight Quotes – SAIA Edition plugin for WordPress is vulnerable to SQL Injection via the 'edit_id' and 'dropship_edit_id' parameters in all versions up to, and including, 2.2.10 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.
</code>

- [RandomRobbieBF/CVE-2024-13483](https://github.com/RandomRobbieBF/CVE-2024-13483)

### CVE-2024-13485 (2025-02-19)

<code>The LTL Freight Quotes – ABF Freight Edition plugin for WordPress is vulnerable to SQL Injection via the 'edit_id' and 'dropship_edit_id' parameters in all versions up to, and including, 3.3.7 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.
</code>

- [RandomRobbieBF/CVE-2024-13485](https://github.com/RandomRobbieBF/CVE-2024-13485)

### CVE-2024-13488 (2025-02-15)

<code>The LTL Freight Quotes – Estes Edition plugin for WordPress is vulnerable to SQL Injection via the 'dropship_edit_id' and 'edit_id' parameters in all versions up to, and including, 3.3.7 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.
</code>

- [RandomRobbieBF/CVE-2024-13488](https://github.com/RandomRobbieBF/CVE-2024-13488)

### CVE-2024-13489 (2025-02-19)

<code>The LTL Freight Quotes – Old Dominion Edition plugin for WordPress is vulnerable to SQL Injection via the 'edit_id' and 'dropship_edit_id' parameters in all versions up to, and including, 4.2.10 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.
</code>

- [RandomRobbieBF/CVE-2024-13489](https://github.com/RandomRobbieBF/CVE-2024-13489)

### CVE-2024-13869 (2025-02-22)

<code>The Migration, Backup, Staging – WPvivid Backup &amp; Migration plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'upload_files' function in all versions up to, and including, 0.9.112. This makes it possible for authenticated attackers, with Administrator-level access and above, to upload arbitrary files on the affected site's server which may make remote code execution possible. NOTE: Uploaded files are only accessible on WordPress instances running on the NGINX web server as the existing .htaccess within the target file upload folder prevents access on Apache servers.
</code>

- [d0n601/CVE-2024-13869](https://github.com/d0n601/CVE-2024-13869)

### CVE-2024-20137 (2024-12-02)

<code>In wlan driver, there is a possible client disconnection due to improper handling of exceptional conditions. This could lead to remote denial of service with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: WCNCR00384543; Issue ID: MSV-1727.
</code>

- [takistmr/CVE-2024-20137](https://github.com/takistmr/CVE-2024-20137)

### CVE-2024-20767 (2024-03-18)

<code>ColdFusion versions 2023.6, 2021.12 and earlier are affected by an Improper Access Control vulnerability that could result in arbitrary file system read. An attacker could leverage this vulnerability to access or modify restricted files. Exploitation of this issue does not require user interaction. Exploitation of this issue requires the admin panel be exposed to the internet.
</code>

- [yoryio/CVE-2024-20767](https://github.com/yoryio/CVE-2024-20767)

### CVE-2024-21182 (2024-07-16)

<code>Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core).  Supported versions that are affected are 12.2.1.4.0 and  14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle WebLogic Server.  Successful attacks of this vulnerability can result in  unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).
</code>

- [kursadalsan/CVE-2024-21182](https://github.com/kursadalsan/CVE-2024-21182)

### CVE-2024-21306 (2024-01-09)

<code>Microsoft Bluetooth Driver Spoofing Vulnerability
</code>

- [PhucHauDeveloper/BadBlue](https://github.com/PhucHauDeveloper/BadBlue)
- [Danyw24/blueXploit](https://github.com/Danyw24/blueXploit)

### CVE-2024-21409 (2024-04-09)

<code>.NET, .NET Framework, and Visual Studio Remote Code Execution Vulnerability
</code>

- [vkairy/cve-2024-21409-repro](https://github.com/vkairy/cve-2024-21409-repro)

### CVE-2024-21413 (2024-02-13)

<code>Microsoft Outlook Remote Code Execution Vulnerability
</code>

- [olebris/CVE-2024-21413](https://github.com/olebris/CVE-2024-21413)
- [DerZiad/CVE-2024-21413](https://github.com/DerZiad/CVE-2024-21413)
- [ThemeHackers/CVE-2024-21413](https://github.com/ThemeHackers/CVE-2024-21413)
- [D1se0/CVE-2024-21413-Vulnerabilidad-Outlook-LAB](https://github.com/D1se0/CVE-2024-21413-Vulnerabilidad-Outlook-LAB)
- [Cyber-Trambon/CVE-2024-21413-exploit](https://github.com/Cyber-Trambon/CVE-2024-21413-exploit)

### CVE-2024-21513 (2024-07-15)

<code>Versions of the package langchain-experimental from 0.0.15 and before 0.0.21 are vulnerable to Arbitrary Code Execution when retrieving values from the database, the code will attempt to call 'eval' on all values. An attacker can exploit this vulnerability and execute arbitrary python code if they can control the input prompt and the server is configured with VectorSQLDatabaseChain.\r\r**Notes:**\r\rImpact on the Confidentiality, Integrity and Availability of the vulnerable component:\r\rConfidentiality: Code execution happens within the impacted component, in this case langchain-experimental, so all resources are necessarily accessible.\r\rIntegrity: There is nothing protected by the impacted component inherently. Although anything returned from the component counts as 'information' for which the trustworthiness can be compromised.\r\rAvailability: The loss of availability isn't caused by the attack itself, but it happens as a result during the attacker's post-exploitation steps.\r\r\rImpact on the Confidentiality, Integrity and Availability of the subsequent system:\r\rAs a legitimate low-privileged user of the package (PR:L) the attacker does not have more access to data owned by the package as a result of this vulnerability than they did with normal usage (e.g. can query the DB). The unintended action that one can perform by breaking out of the app environment and exfiltrating files, making remote connections etc. happens during the post exploitation phase in the subsequent system - in this case, the OS.\r\rAT:P: An attacker needs to be able to influence the input prompt, whilst the server is configured with the VectorSQLDatabaseChain plugin.
</code>

- [SavageSanta11/Reproduce-CVE-2024-21513](https://github.com/SavageSanta11/Reproduce-CVE-2024-21513)

### CVE-2024-21542 (2024-12-10)

<code>Versions of the package luigi before 3.6.0 are vulnerable to Arbitrary File Write via Archive Extraction (Zip Slip) due to improper destination file path validation in the _extract_packages_archive function.
</code>

- [L3ster1337/Poc-CVE-2024-21542](https://github.com/L3ster1337/Poc-CVE-2024-21542)

### CVE-2024-21626 (2024-01-31)

<code>runc is a CLI tool for spawning and running containers on Linux according to the OCI specification. In runc 1.1.11 and earlier, due to an internal file descriptor leak, an attacker could cause a newly-spawned container process (from runc exec) to have a working directory in the host filesystem namespace, allowing for a container escape by giving access to the host filesystem (&quot;attack 2&quot;). The same attack could be used by a malicious image to allow a container process to gain access to the host filesystem through runc run (&quot;attack 1&quot;). Variants of attacks 1 and 2 could be also be used to overwrite semi-arbitrary host binaries, allowing for complete container escapes (&quot;attack 3a&quot; and &quot;attack 3b&quot;). runc 1.1.12 includes patches for this issue.
</code>

- [Sk3pper/CVE-2024-21626](https://github.com/Sk3pper/CVE-2024-21626)

### CVE-2024-21754 (2024-06-11)

<code>A use of password hash with insufficient computational effort vulnerability [CWE-916] affecting FortiOS version 7.4.3 and below, 7.2 all versions, 7.0 all versions, 6.4 all versions and FortiProxy version 7.4.2 and below, 7.2 all versions, 7.0 all versions, 2.0 all versions may allow a privileged attacker with super-admin profile and CLI access to decrypting the backup file.
</code>

- [CyberSecuritist/CVE-2024-21754-Forti-RCE](https://github.com/CyberSecuritist/CVE-2024-21754-Forti-RCE)

### CVE-2024-21762 (2024-02-09)

<code>A out-of-bounds write in Fortinet FortiOS versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.6, 7.0.0 through 7.0.13, 6.4.0 through 6.4.14, 6.2.0 through 6.2.15, 6.0.0 through 6.0.17, FortiProxy versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.8, 7.0.0 through 7.0.14, 2.0.0 through 2.0.13, 1.2.0 through 1.2.13, 1.1.0 through 1.1.6, 1.0.0 through 1.0.7 allows attacker to execute unauthorized code or commands via specifically crafted requests
</code>

- [BishopFox/cve-2024-21762-check](https://github.com/BishopFox/cve-2024-21762-check)

### CVE-2024-21887 (2024-01-12)

<code>A command injection vulnerability in web components of Ivanti Connect Secure (9.x, 22.x) and Ivanti Policy Secure (9.x, 22.x)  allows an authenticated administrator to send specially crafted requests and execute arbitrary commands on the appliance.
</code>

- [rxwx/pulse-meter](https://github.com/rxwx/pulse-meter)

### CVE-2024-21978 (2024-08-05)

<code>Improper input validation in SEV-SNP could allow a malicious hypervisor to read or overwrite guest memory potentially leading to data leakage or data corruption.
</code>

- [Freax13/cve-2024-21978-poc](https://github.com/Freax13/cve-2024-21978-poc)

### CVE-2024-22243 (2024-02-23)

<code>Applications that use UriComponentsBuilder to parse an externally provided URL (e.g. through a query parameter) AND perform validation checks on the host of the parsed URL may be vulnerable to a  open redirect https://cwe.mitre.org/data/definitions/601.html  attack or to a SSRF attack if the URL is used after passing validation checks.
</code>

- [SeanPesce/CVE-2024-22243](https://github.com/SeanPesce/CVE-2024-22243)
- [Reivap/CVE-2024-22243](https://github.com/Reivap/CVE-2024-22243)

### CVE-2024-22734 (2024-04-12)

<code>An issue was discovered in AMCS Group Trux Waste Management Software before version 7.19.0018.26912, allows local attackers to obtain sensitive information via a static, hard-coded AES Key-IV pair in the TxUtilities.dll and TruxUser.cfg components.
</code>

- [securekomodo/CVE-2024-22734](https://github.com/securekomodo/CVE-2024-22734)

### CVE-2024-22853 (2024-02-06)

<code>D-LINK Go-RT-AC750 GORTAC750_A1_FW_v101b03 has a hardcoded password for the Alphanetworks account, which allows remote attackers to obtain root access via a telnet session.
</code>

- [FaLLenSKiLL1/CVE-2024-22853](https://github.com/FaLLenSKiLL1/CVE-2024-22853)

### CVE-2024-23298 (2024-03-15)

<code>A logic issue was addressed with improved state management.
</code>

- [p1tsi/CVE-2024-23298.app](https://github.com/p1tsi/CVE-2024-23298.app)

### CVE-2024-23334 (2024-01-29)

<code>aiohttp is an asynchronous HTTP client/server framework for asyncio and Python. When using aiohttp as a web server and configuring static routes, it is necessary to specify the root path for static files. Additionally, the option 'follow_symlinks' can be used to determine whether to follow symbolic links outside the static root directory. When 'follow_symlinks' is set to True, there is no validation to check if reading a file is within the root directory. This can lead to directory traversal vulnerabilities, resulting in unauthorized access to arbitrary files on the system, even when symlinks are not present.  Disabling follow_symlinks and using a reverse proxy are encouraged mitigations.  Version 3.9.2 fixes this issue.
</code>

- [TheRedP4nther/LFI-aiohttp-CVE-2024-23334-PoC](https://github.com/TheRedP4nther/LFI-aiohttp-CVE-2024-23334-PoC)
- [Betan423/CVE-2024-23334-PoC](https://github.com/Betan423/CVE-2024-23334-PoC)
- [BestDevOfc/CVE-2024-23334-PoC](https://github.com/BestDevOfc/CVE-2024-23334-PoC)

### CVE-2024-23346 (2024-02-21)

<code>Pymatgen (Python Materials Genomics) is an open-source Python library for materials analysis. A critical security vulnerability exists in the `JonesFaithfulTransformation.from_transformation_str()` method within the `pymatgen` library prior to version 2024.2.20. This method insecurely utilizes `eval()` for processing input, enabling execution of arbitrary code when parsing untrusted input. Version 2024.2.20 fixes this issue.
</code>

- [MAWK0235/CVE-2024-23346](https://github.com/MAWK0235/CVE-2024-23346)
- [Sanity-Archive/CVE-2024-23346](https://github.com/Sanity-Archive/CVE-2024-23346)
- [szyth/CVE-2024-23346-rust-exploit](https://github.com/szyth/CVE-2024-23346-rust-exploit)

### CVE-2024-23443 (2024-06-19)

<code>A high-privileged user, allowed to create custom osquery packs 17 could affect the availability of Kibana by uploading a maliciously crafted osquery pack.
</code>

- [zhazhalove/osquery_cve-2024-23443](https://github.com/zhazhalove/osquery_cve-2024-23443)

### CVE-2024-23653 (2024-01-31)

<code>BuildKit is a toolkit for converting source code to build artifacts in an efficient, expressive and repeatable manner. In addition to running containers as build steps, BuildKit also provides APIs for running interactive containers based on built images. It was possible to use these APIs to ask BuildKit to run a container with elevated privileges. Normally, running such containers is only allowed if special `security.insecure` entitlement is enabled both by buildkitd configuration and allowed by the user initializing the build request. The issue has been fixed in v0.12.5 . Avoid using BuildKit frontends from untrusted sources. \n
</code>

- [666asd/CVE-2024-23653](https://github.com/666asd/CVE-2024-23653)

### CVE-2024-23666 (2024-11-12)

<code>A client-side enforcement of server-side security in Fortinet FortiAnalyzer-BigData \r\nat least version 7.4.0 and 7.2.0 through 7.2.6 and 7.0.1 through 7.0.6 and 6.4.5 through 6.4.7 and 6.2.5, FortiManager version 7.4.0 through 7.4.1 and 7.2.0 through 7.2.4 and 7.0.0 through 7.0.11 and 6.4.0 through 6.4.14, FortiAnalyzer version 7.4.0 through 7.4.1 and 7.2.0 through 7.2.4 and 7.0.0 through 7.0.11 and 6.4.0 through 6.4.14 allows attacker to improper access control via crafted requests.
</code>

- [synacktiv/CVE-2023-42791_CVE-2024-23666](https://github.com/synacktiv/CVE-2023-42791_CVE-2024-23666)

### CVE-2024-23692 (2024-05-31)

<code>Rejetto HTTP File Server, up to and including version 2.3m, is vulnerable to a template injection vulnerability. This vulnerability allows a remote, unauthenticated attacker to execute arbitrary commands on the affected system by sending a specially crafted HTTP request. As of the CVE assignment date, Rejetto HFS 2.3m is no longer supported.
</code>

- [verylazytech/CVE-2024-23692](https://github.com/verylazytech/CVE-2024-23692)
- [NingXin2002/HFS2.3_poc](https://github.com/NingXin2002/HFS2.3_poc)
- [999gawkboyy/CVE-2024-23692_Exploit](https://github.com/999gawkboyy/CVE-2024-23692_Exploit)

### CVE-2024-23724 (2024-02-11)

<code>Ghost through 5.76.0 allows stored XSS, and resultant privilege escalation in which a contributor can take over any account, via an SVG profile picture that contains JavaScript code to interact with the API on localhost TCP port 3001. NOTE: The discoverer reports that &quot;The vendor does not view this as a valid vector.&quot;
</code>

- [gl1tch0x1/Ghost-CMS-Exploit](https://github.com/gl1tch0x1/Ghost-CMS-Exploit)

### CVE-2024-23733 (2025-01-29)

<code>The /WmAdmin/,/invoke/vm.server/login login page in the Integration Server in Software AG webMethods 10.15.0 before Core_Fix7 allows remote attackers to reach the administration panel and discover hostname and version information by sending an arbitrary username and a blank password to the /WmAdmin/#/login/ URI.
</code>

- [ekcrsm/CVE-2024-23733](https://github.com/ekcrsm/CVE-2024-23733)

### CVE-2024-23897 (2024-01-24)

<code>Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.
</code>

- [godylockz/CVE-2024-23897](https://github.com/godylockz/CVE-2024-23897)
- [pulentoski/CVE-2024-23897-Arbitrary-file-read](https://github.com/pulentoski/CVE-2024-23897-Arbitrary-file-read)
- [verylazytech/CVE-2024-23897](https://github.com/verylazytech/CVE-2024-23897)
- [D1se0/CVE-2024-23897-Vulnerabilidad-Jenkins](https://github.com/D1se0/CVE-2024-23897-Vulnerabilidad-Jenkins)

### CVE-2024-24401 (2024-02-26)

<code>SQL Injection vulnerability in Nagios XI 2024R1.01 allows a remote attacker to execute arbitrary code via a crafted payload to the monitoringwizard.php component.
</code>

- [MAWK0235/CVE-2024-24401](https://github.com/MAWK0235/CVE-2024-24401)

### CVE-2024-24409 (2024-11-08)

<code>Zohocorp ManageEngine ADManager Plus versions 7203 and prior are vulnerable to Privilege Escalation in the Modify Computers option.
</code>

- [passtheticket/CVE-2024-24409](https://github.com/passtheticket/CVE-2024-24409)

### CVE-2024-24549 (2024-03-13)

<code>Denial of Service due to improper input validation vulnerability for HTTP/2 requests in Apache Tomcat. When processing an HTTP/2 request, if the request exceeded any of the configured limits for headers, the associated HTTP/2 stream was not reset until after all of the headers had been processed.This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.0-M16, from 10.1.0-M1 through 10.1.18, from 9.0.0-M1 through 9.0.85, from 8.5.0 through 8.5.98.\n\nUsers are recommended to upgrade to version 11.0.0-M17, 10.1.19, 9.0.86 or 8.5.99 which fix the issue.
</code>

- [JFOZ1010/CVE-2024-24549](https://github.com/JFOZ1010/CVE-2024-24549)

### CVE-2024-24919 (2024-05-28)

<code>Potentially allowing an attacker to read certain information on Check Point Security Gateways once connected to the internet and enabled with remote Access VPN or Mobile Access Software Blades. A Security fix that mitigates this vulnerability is available.
</code>

- [0nin0hanz0/CVE-2024-24919-PoC](https://github.com/0nin0hanz0/CVE-2024-24919-PoC)
- [verylazytech/CVE-2024-24919](https://github.com/verylazytech/CVE-2024-24919)
- [0xlf/CVE-2024-24919](https://github.com/0xlf/CVE-2024-24919)
- [NingXin2002/Check-Point_poc](https://github.com/NingXin2002/Check-Point_poc)
- [hashdr1ft/SOC_287](https://github.com/hashdr1ft/SOC_287)
- [funixone/CVE-2024-24919---Exploit-Script](https://github.com/funixone/CVE-2024-24919---Exploit-Script)
- [spider00009/CVE-2024-24919-POC](https://github.com/spider00009/CVE-2024-24919-POC)

### CVE-2024-24926 (2024-02-12)

<code>Deserialization of Untrusted Data vulnerability in UnitedThemes Brooklyn | Creative Multi-Purpose Responsive WordPress Theme.This issue affects Brooklyn | Creative Multi-Purpose Responsive WordPress Theme: from n/a through 4.9.7.6.\n\n
</code>

- [moften/CVE-2024-24926](https://github.com/moften/CVE-2024-24926)

### CVE-2024-25292 (2024-02-29)

<code>Cross-site scripting (XSS) vulnerability in RenderTune v1.1.4 allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the Upload Title parameter.
</code>

- [EQSTLab/CVE-2024-25292](https://github.com/EQSTLab/CVE-2024-25292)

### CVE-2024-25731 (2024-03-04)

<code>The Elink Smart eSmartCam (com.cn.dq.ipc) application 2.1.5 for Android contains hardcoded AES encryption keys that can be extracted from a binary file. Thus, encryption can be defeated by an attacker who can observe packet data (e.g., over Wi-Fi).
</code>

- [actuator/com.cn.dq.ipc](https://github.com/actuator/com.cn.dq.ipc)

### CVE-2024-26144 (2024-02-27)

<code>Rails is a web-application framework. Starting with version 5.2.0, there is a possible sensitive session information leak in Active Storage. By default, Active Storage sends a Set-Cookie header along with the user's session cookie when serving blobs. It also sets Cache-Control to public. Certain proxies may cache the Set-Cookie, leading to an information leak. The vulnerability is fixed in 7.0.8.1 and 6.1.7.7.
</code>

- [gmo-ierae/CVE-2024-26144-test](https://github.com/gmo-ierae/CVE-2024-26144-test)

### CVE-2024-26229 (2024-04-09)

<code>Windows CSC Service Elevation of Privilege Vulnerability
</code>

- [varwara/CVE-2024-26229](https://github.com/varwara/CVE-2024-26229)

### CVE-2024-26230 (2024-04-09)

<code>Windows Telephony Server Elevation of Privilege Vulnerability
</code>

- [kiwids0220/CVE-2024-26230](https://github.com/kiwids0220/CVE-2024-26230)

### CVE-2024-27198 (2024-03-04)

<code>In JetBrains TeamCity before 2023.11.4 authentication bypass allowing to perform admin actions was possible
</code>

- [yoryio/CVE-2024-27198](https://github.com/yoryio/CVE-2024-27198)
- [Stuub/RCity-CVE-2024-27198](https://github.com/Stuub/RCity-CVE-2024-27198)

### CVE-2024-27292 (2024-02-29)

<code>Docassemble is an expert system for guided interviews and document assembly. The vulnerability allows attackers to gain unauthorized access to information on the system through URL manipulation. It affects versions 1.4.53 to 1.4.96. The vulnerability has been patched in version 1.4.97 of the master branch.
</code>

- [NingXin2002/Docassemble_poc](https://github.com/NingXin2002/Docassemble_poc)

### CVE-2024-27348 (2024-04-22)

<code>RCE-Remote Command Execution vulnerability in Apache HugeGraph-Server.This issue affects Apache HugeGraph-Server: from 1.0.0 before 1.3.0 in Java8 &amp; Java11\n\nUsers are recommended to upgrade to version 1.3.0 with Java11 &amp; enable the Auth system, which fixes the issue.
</code>

- [p0et08/CVE-2024-27348](https://github.com/p0et08/CVE-2024-27348)

### CVE-2024-27448 (2024-04-05)

<code>MailDev 2 through 2.1.0 allows Remote Code Execution via a crafted Content-ID header for an e-mail attachment, leading to lib/mailserver.js writing arbitrary code into the routes.js file.
</code>

- [rawtips/CVE-2024-27448-poc](https://github.com/rawtips/CVE-2024-27448-poc)

### CVE-2024-27766 (2024-10-17)

<code>An issue in MariaDB v.11.1 allows a remote attacker to execute arbitrary code via the lib_mysqludf_sys.so function. NOTE: this is disputed by the MariaDB Foundation because no privilege boundary is crossed.
</code>

- [Ant1sec-ops/CVE-2024-27766](https://github.com/Ant1sec-ops/CVE-2024-27766)

### CVE-2024-27956 (2024-03-21)

<code>Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in ValvePress Automatic allows SQL Injection.This issue affects Automatic: from n/a through 3.92.0.\n\n
</code>

- [AiGptCode/WordPress-Auto-Admin-Account-and-Reverse-Shell-cve-2024-27956](https://github.com/AiGptCode/WordPress-Auto-Admin-Account-and-Reverse-Shell-cve-2024-27956)
- [Cappricio-Securities/CVE-2024-27956](https://github.com/Cappricio-Securities/CVE-2024-27956)
- [7aRanchi/CVE-2024-27956-for-fscan](https://github.com/7aRanchi/CVE-2024-27956-for-fscan)

### CVE-2024-28085 (2024-03-27)

<code>wall in util-linux through 2.40, often installed with setgid tty permissions, allows escape sequences to be sent to other users' terminals through argv. (Specifically, escape sequences received from stdin are blocked, but escape sequences received from argv are not blocked.) There may be plausible scenarios where this leads to account takeover.
</code>

- [oditynet/sleepall](https://github.com/oditynet/sleepall)

### CVE-2024-28397 (2024-06-20)

<code>An issue in the component js2py.disable_pyimport() of js2py up to v0.74 allows attackers to execute arbitrary code via a crafted API call.
</code>

- [Marven11/CVE-2024-28397-js2py-Sandbox-Escape](https://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape)
- [CYBER-WARRIOR-SEC/CVE-2024-28397-js2py-Sandbox-Escape](https://github.com/CYBER-WARRIOR-SEC/CVE-2024-28397-js2py-Sandbox-Escape)

### CVE-2024-28995 (2024-06-06)

<code>\n\n\n\n\n\n\n\n\n\n\n\nSolarWinds Serv-U was susceptible to a directory transversal vulnerability that would allow access to read sensitive files on the host machine.    \n\n\n\n\n\n\n\n
</code>

- [Praison001/CVE-2024-28995-SolarWinds-Serv-U](https://github.com/Praison001/CVE-2024-28995-SolarWinds-Serv-U)

### CVE-2024-29269 (2024-04-10)

<code>An issue discovered in Telesquare TLR-2005Ksh 1.0.0 and 1.1.4 allows attackers to run arbitrary system commands via the Cmd parameter.
</code>

- [dream434/CVE-2024-29269](https://github.com/dream434/CVE-2024-29269)

### CVE-2024-29296 (2024-04-10)

<code>A user enumeration vulnerability was found in Portainer CE 2.19.4. This issue occurs during user authentication process, where a difference in response time could allow a remote unauthenticated user to determine if a username is valid or not.
</code>

- [ThaySolis/CVE-2024-29296](https://github.com/ThaySolis/CVE-2024-29296)
- [Lavender-exe/CVE-2024-29296-PoC](https://github.com/Lavender-exe/CVE-2024-29296-PoC)

### CVE-2024-29671 (2024-12-16)

<code>Buffer Overflow vulnerability in NEXTU FLATA AX1500 Router v.1.0.2 allows a remote attacker to execute arbitrary code via the POST request handler component.
</code>

- [laskdjlaskdj12/CVE-2024-29671-POC](https://github.com/laskdjlaskdj12/CVE-2024-29671-POC)

### CVE-2024-29868 (2024-06-24)

<code>Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) vulnerability in Apache StreamPipes user self-registration and password recovery mechanism.\nThis allows an attacker to guess the recovery token in a reasonable time and thereby to take over the attacked user's account.\nThis issue affects Apache StreamPipes: from 0.69.0 through 0.93.0.\n\nUsers are recommended to upgrade to version 0.95.0, which fixes the issue.\n\n
</code>

- [DEVisions/CVE-2024-29868](https://github.com/DEVisions/CVE-2024-29868)

### CVE-2024-29943 (2024-03-22)

<code>An attacker was able to perform an out-of-bounds read or write on a JavaScript object by fooling range-based bounds check elimination. This vulnerability affects Firefox &lt; 124.0.1.
</code>

- [bjrjk/CVE-2024-29943](https://github.com/bjrjk/CVE-2024-29943)

### CVE-2024-29972 (2024-06-04)

<code>** UNSUPPORTED WHEN ASSIGNED **\nThe command injection vulnerability in the CGI program &quot;remote_help-cgi&quot; in Zyxel NAS326 firmware versions before V5.21(AAZF.17)C0 and NAS542 firmware versions before V5.21(ABAG.14)C0 could allow an unauthenticated attacker to execute some operating system (OS) commands by sending a crafted HTTP POST request.
</code>

- [Pommaq/CVE-2024-29972-CVE-2024-29976-CVE-2024-29973-CVE-2024-29975-CVE-2024-29974-poc](https://github.com/Pommaq/CVE-2024-29972-CVE-2024-29976-CVE-2024-29973-CVE-2024-29975-CVE-2024-29974-poc)

### CVE-2024-29973 (2024-06-04)

<code>** UNSUPPORTED WHEN ASSIGNED **\nThe command injection vulnerability in the “setCookie” parameter in Zyxel NAS326 firmware versions before V5.21(AAZF.17)C0 and NAS542 firmware versions before V5.21(ABAG.14)C0 could allow an unauthenticated attacker to execute some operating system (OS) commands by sending a crafted HTTP POST request.
</code>

- [bigb0x/CVE-2024-29973](https://github.com/bigb0x/CVE-2024-29973)

### CVE-2024-30085 (2024-06-11)

<code>Windows Cloud Files Mini Filter Driver Elevation of Privilege Vulnerability
</code>

- [Adamkadaban/CVE-2024-30085](https://github.com/Adamkadaban/CVE-2024-30085)
- [murdok1982/Exploit-PoC-para-CVE-2024-30085](https://github.com/murdok1982/Exploit-PoC-para-CVE-2024-30085)

### CVE-2024-30088 (2024-06-11)

<code>Windows Kernel Elevation of Privilege Vulnerability
</code>

- [tykawaii98/CVE-2024-30088](https://github.com/tykawaii98/CVE-2024-30088)
- [NextGenPentesters/CVE-2024-30088-](https://github.com/NextGenPentesters/CVE-2024-30088-)

### CVE-2024-30896 (2024-11-21)

<code>InfluxDB OSS 2.x through 2.7.11 stores the administrative operator token under the default organization which allows authorized users with read access to the authorization resource of the default organization to retrieve the operator token. InfluxDB OSS 1.x, Enterprise, Cloud, Cloud Dedicated and Clustered are not affected. NOTE: The researcher states that InfluxDB allows allAccess administrators to retrieve all raw tokens via an &quot;influx auth ls&quot; command. The supplier indicates that the organizations feature is operating as intended and that users may choose to add users to non-default organizations. A future release of InfluxDB 2.x will remove the ability to retrieve tokens from the API.
</code>

- [XenoM0rph97/CVE-2024-30896](https://github.com/XenoM0rph97/CVE-2024-30896)

### CVE-2024-30956
- [leoCottret/CVE-2024-30956](https://github.com/leoCottret/CVE-2024-30956)

### CVE-2024-31317 (2024-07-09)

<code>In multiple functions of ZygoteProcess.java, there is a possible way to achieve code execution as any app via WRITE_SECURE_SETTINGS due to unsafe deserialization. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation.
</code>

- [fuhei/CVE-2024-31317](https://github.com/fuhei/CVE-2024-31317)

### CVE-2024-31320 (2024-07-09)

<code>In setSkipPrompt of AssociationRequest.java , there is a possible way to establish a companion device association without any confirmation due to CDM. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.
</code>

- [SpiralBL0CK/CVE-2024-31320-](https://github.com/SpiralBL0CK/CVE-2024-31320-)

### CVE-2024-31666 (2024-04-22)

<code>An issue in flusity-CMS v.2.33 allows a remote attacker to execute arbitrary code via a crafted script to the edit_addon_post.php component.
</code>

- [hapa3/CVE-2024-31666](https://github.com/hapa3/CVE-2024-31666)

### CVE-2024-31719
- [VoltaireYoung/CVE-2024-31719----AMI-Aptio-5-Vulnerability](https://github.com/VoltaireYoung/CVE-2024-31719----AMI-Aptio-5-Vulnerability)

### CVE-2024-31777 (2024-06-13)

<code>File Upload vulnerability in openeclass v.3.15 and before allows an attacker to execute arbitrary code via a crafted file to the certbadge.php endpoint.
</code>

- [FreySolarEye/Exploit-CVE-2024-31777](https://github.com/FreySolarEye/Exploit-CVE-2024-31777)

### CVE-2024-31819 (2024-04-10)

<code>An issue in WWBN AVideo v.12.4 through v.14.2 allows a remote attacker to execute arbitrary code via the systemRootPath parameter of the submitIndex.php component.
</code>

- [dream434/CVE-2024-31819](https://github.com/dream434/CVE-2024-31819)

### CVE-2024-31903 (2025-01-22)

<code>IBM Sterling B2B Integrator Standard Edition 6.0.0.0 through 6.1.2.5 and 6.2.0.0 through 6.2.0.2 allow an attacker on the local network to execute arbitrary code on the system, caused by the deserialization of untrusted data.
</code>

- [WithSecureLabs/ibm-sterling-b2b-integrator-poc](https://github.com/WithSecureLabs/ibm-sterling-b2b-integrator-poc)

### CVE-2024-32002 (2024-05-14)

<code>Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.
</code>

- [AD-Appledog/wakuwaku](https://github.com/AD-Appledog/wakuwaku)
- [Julian-gmz/hook_CVE-2024-32002](https://github.com/Julian-gmz/hook_CVE-2024-32002)
- [jolibb55/donald](https://github.com/jolibb55/donald)
- [razenkovv/captain](https://github.com/razenkovv/captain)
- [razenkovv/hook](https://github.com/razenkovv/hook)
- [ashutosh0408/CVE-2024-32002](https://github.com/ashutosh0408/CVE-2024-32002)
- [ashutosh0408/Cve-2024-32002-poc](https://github.com/ashutosh0408/Cve-2024-32002-poc)

### CVE-2024-32030 (2024-06-19)

<code>Kafka UI is an Open-Source Web UI for Apache Kafka Management. Kafka UI API allows users to connect to different Kafka brokers by specifying their network address and port. As a separate feature, it also provides the ability to monitor the performance of Kafka brokers by connecting to their JMX ports. JMX is based on the RMI protocol, so it is inherently susceptible to deserialization attacks. A potential attacker can exploit this feature by connecting Kafka UI backend to its own malicious broker. This vulnerability affects the deployments where one of the following occurs: 1. dynamic.config.enabled property is set in settings. It's not enabled by default, but it's suggested to be enabled in many tutorials for Kafka UI, including its own README.md. OR  2. an attacker has access to the Kafka cluster that is being connected to Kafka UI. In this scenario the attacker can exploit this vulnerability to expand their access and execute code on Kafka UI as well. Instead of setting up a legitimate JMX port, an attacker can create an RMI listener that returns a malicious serialized object for any RMI call. In the worst case it could lead to remote code execution as Kafka UI has the required gadget chains in its classpath. This issue may lead to post-auth remote code execution. This is particularly dangerous as Kafka-UI does not have authentication enabled by default. This issue has been addressed in version 0.7.2. All users are advised to upgrade. There are no known workarounds for this vulnerability. These issues were discovered and reported by the GitHub Security lab and is also tracked as GHSL-2023-230.
</code>

- [huseyinstif/CVE-2024-32030-Nuclei-Template](https://github.com/huseyinstif/CVE-2024-32030-Nuclei-Template)

### CVE-2024-32113 (2024-05-08)

<code>Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability in Apache OFBiz.This issue affects Apache OFBiz: before 18.12.13.\n\nUsers are recommended to upgrade to version 18.12.13, which fixes the issue.
</code>

- [RacerZ-fighting/CVE-2024-32113-POC](https://github.com/RacerZ-fighting/CVE-2024-32113-POC)
- [MikeyPPPPPPPP/CVE-2024-32113](https://github.com/MikeyPPPPPPPP/CVE-2024-32113)

### CVE-2024-32258 (2024-04-23)

<code>The network server of fceux 2.7.0 has a path traversal vulnerability, allowing attackers to overwrite any files on the server without authentication by fake ROM.
</code>

- [liyansong2018/CVE-2024-32258](https://github.com/liyansong2018/CVE-2024-32258)

### CVE-2024-33111 (2024-05-06)

<code>D-Link DIR-845L router &lt;=v1.01KRb03 is vulnerable to Cross Site Scripting (XSS) via /htdocs/webinc/js/bsc_sms_inbox.php.
</code>

- [FaLLenSKiLL1/CVE-2024-33111](https://github.com/FaLLenSKiLL1/CVE-2024-33111)

### CVE-2024-33113 (2024-05-06)

<code>D-LINK DIR-845L &lt;=v1.01KRb03 is vulnerable to Information disclosurey via bsc_sms_inbox.php.
</code>

- [FaLLenSKiLL1/CVE-2024-33113](https://github.com/FaLLenSKiLL1/CVE-2024-33113)
- [tekua/CVE-2024-33113](https://github.com/tekua/CVE-2024-33113)

### CVE-2024-33883 (2024-04-28)

<code>The ejs (aka Embedded JavaScript templates) package before 3.1.10 for Node.js lacks certain pollution protection.
</code>

- [Grantzile/PoC-CVE-2024-33883](https://github.com/Grantzile/PoC-CVE-2024-33883)

### CVE-2024-34102 (2024-06-13)

<code>Adobe Commerce versions 2.4.7, 2.4.6-p5, 2.4.5-p7, 2.4.4-p8 and earlier are affected by an Improper Restriction of XML External Entity Reference ('XXE') vulnerability that could result in arbitrary code execution. An attacker could exploit this vulnerability by sending a crafted XML document that references external entities. Exploitation of this issue does not require user interaction.
</code>

- [ArturArz1/TestCVE-2024-34102](https://github.com/ArturArz1/TestCVE-2024-34102)
- [th3gokul/CVE-2024-34102](https://github.com/th3gokul/CVE-2024-34102)
- [bigb0x/CVE-2024-34102](https://github.com/bigb0x/CVE-2024-34102)
- [11whoami99/CVE-2024-34102](https://github.com/11whoami99/CVE-2024-34102)
- [d0rb/CVE-2024-34102](https://github.com/d0rb/CVE-2024-34102)
- [Chocapikk/CVE-2024-34102](https://github.com/Chocapikk/CVE-2024-34102)
- [0x0d3ad/CVE-2024-34102](https://github.com/0x0d3ad/CVE-2024-34102)
- [SamJUK/cosmicsting-validator](https://github.com/SamJUK/cosmicsting-validator)
- [wubinworks/magento2-cosmic-sting-patch](https://github.com/wubinworks/magento2-cosmic-sting-patch)
- [EQSTLab/CVE-2024-34102](https://github.com/EQSTLab/CVE-2024-34102)
- [dream434/CVE-2024-34102](https://github.com/dream434/CVE-2024-34102)
- [wubinworks/magento2-encryption-key-manager-cli](https://github.com/wubinworks/magento2-encryption-key-manager-cli)

### CVE-2024-34313 (2024-06-24)

<code>An issue in VPL Jail System up to v4.0.2 allows attackers to execute a directory traversal via a crafted request to a public endpoint.
</code>

- [vincentscode/CVE-2024-34313](https://github.com/vincentscode/CVE-2024-34313)

### CVE-2024-34350 (2024-05-09)

<code>Next.js is a React framework that can provide building blocks to create web applications. Prior to 13.5.1, an inconsistent interpretation of a crafted HTTP request meant that requests are treated as both a single request, and two separate requests by Next.js, leading to desynchronized responses. This led to a response queue poisoning vulnerability in the affected Next.js versions. For a request to be exploitable, the affected route also had to be making use of the [rewrites](https://nextjs.org/docs/app/api-reference/next-config-js/rewrites) feature in Next.js. The vulnerability is resolved in Next.js `13.5.1` and newer.
</code>

- [Sudistark/rewrites-nextjs-CVE-2024-34350](https://github.com/Sudistark/rewrites-nextjs-CVE-2024-34350)

### CVE-2024-34351 (2024-05-09)

<code>Next.js is a React framework that can provide building blocks to create web applications. A Server-Side Request Forgery (SSRF) vulnerability was identified in Next.js Server Actions. If the `Host` header is modified, and the below conditions are also met, an attacker may be able to make requests that appear to be originating from the Next.js application server itself. The required conditions are 1) Next.js is running in a self-hosted manner; 2) the Next.js application makes use of Server Actions; and 3) the Server Action performs a redirect to a relative path which starts with a `/`. This vulnerability was fixed in Next.js `14.1.1`.
</code>

- [avergnaud/Next.js_exploit_CVE-2024-34351](https://github.com/avergnaud/Next.js_exploit_CVE-2024-34351)

### CVE-2024-34470 (2024-05-06)

<code>An issue was discovered in HSC Mailinspector 5.2.17-3 through v.5.2.18. An Unauthenticated Path Traversal vulnerability exists in the /public/loader.php file. The path parameter does not properly filter whether the file and directory passed are part of the webroot, allowing an attacker to read arbitrary files on the server.
</code>

- [th3gokul/CVE-2024-34470](https://github.com/th3gokul/CVE-2024-34470)

### CVE-2024-34716 (2024-05-14)

<code>PrestaShop is an open source e-commerce web application. A cross-site scripting (XSS) vulnerability that only affects PrestaShops with customer-thread feature flag enabled is present starting from PrestaShop 8.1.0 and prior to PrestaShop 8.1.6. When the customer thread feature flag is enabled through the front-office contact form, a hacker can upload a malicious file containing an XSS that will be executed when an admin opens the attached file in back office. The script injected can access the session and the security token, which allows it to perform any authenticated action in the scope of the administrator's right. This vulnerability is patched in 8.1.6. A workaround is to disable the customer-thread feature-flag.
</code>

- [aelmokhtar/CVE-2024-34716](https://github.com/aelmokhtar/CVE-2024-34716)
- [0xDTC/Prestashop-CVE-2024-34716](https://github.com/0xDTC/Prestashop-CVE-2024-34716)
- [TU-M/Trickster-HTB](https://github.com/TU-M/Trickster-HTB)

### CVE-2024-34833 (2024-06-17)

<code>Sourcecodester Payroll Management System v1.0 is vulnerable to File Upload. Users can upload images via the &quot;save_settings&quot; page. An unauthenticated attacker can leverage this functionality to upload a malicious PHP file instead. Successful exploitation of this vulnerability results in the ability to execute arbitrary code as the user running the web server.
</code>

- [ShellUnease/CVE-2024-34833-payroll-management-system-rce](https://github.com/ShellUnease/CVE-2024-34833-payroll-management-system-rce)

### CVE-2024-35106 (2025-02-07)

<code>NEXTU FLETA AX1500 WIFI6 v1.0.3 was discovered to contain a buffer overflow at /boafrm/formIpQoS. This vulnerability allows attackers to cause a Denial of Service (DoS) or potentially arbitrary code execution via a crafted POST request.
</code>

- [laskdjlaskdj12/CVE-2024-35106-POC](https://github.com/laskdjlaskdj12/CVE-2024-35106-POC)

### CVE-2024-35176 (2024-05-16)

<code> REXML is an XML toolkit for Ruby. The REXML gem before 3.2.6 has a denial of service vulnerability when it parses an XML that has many `&lt;`s in an attribute value. Those who need to parse untrusted XMLs may be impacted to this vulnerability. The REXML gem 3.2.7 or later include the patch to fix this vulnerability. As a workaround, don't parse untrusted XMLs.
</code>

- [SpiralBL0CK/CVE-2024-35176](https://github.com/SpiralBL0CK/CVE-2024-35176)

### CVE-2024-35205 (2024-05-13)

<code>The WPS Office (aka cn.wps.moffice_eng) application before 17.0.0 for Android fails to properly sanitize file names before processing them through external application interactions, leading to a form of path traversal. This potentially enables any application to dispatch a crafted library file, aiming to overwrite an existing native library utilized by WPS Office. Successful exploitation could result in the execution of arbitrary commands under the guise of WPS Office's application ID.
</code>

- [cyb3r-w0lf/Dirty_Stream-Android-POC](https://github.com/cyb3r-w0lf/Dirty_Stream-Android-POC)

### CVE-2024-35286 (2024-10-21)

<code>A vulnerability in NuPoint Messenger (NPM) of Mitel MiCollab through 9.8.0.33 allows an unauthenticated attacker to conduct a SQL injection attack due to insufficient sanitization of user input. A successful exploit could allow an attacker to access sensitive information and execute arbitrary database and management operations.
</code>

- [lu4m575/CVE-2024-35286_scan.nse](https://github.com/lu4m575/CVE-2024-35286_scan.nse)

### CVE-2024-36401 (2024-07-01)

<code>GeoServer is an open source server that allows users to share and edit geospatial data. Prior to versions 2.23.6, 2.24.4, and 2.25.2, multiple OGC request parameters allow Remote Code Execution (RCE) by unauthenticated users through specially crafted input against a default GeoServer installation due to unsafely evaluating property names as XPath expressions.\n\nThe GeoTools library API that GeoServer calls evaluates property/attribute names for feature types in a way that unsafely passes them to the commons-jxpath library which can execute arbitrary code when evaluating XPath expressions. This XPath evaluation is intended to be used only by complex feature types (i.e., Application Schema data stores) but is incorrectly being applied to simple feature types as well which makes this vulnerability apply to **ALL** GeoServer instances. No public PoC is provided but this vulnerability has been confirmed to be exploitable through WFS GetFeature, WFS GetPropertyValue, WMS GetMap, WMS GetFeatureInfo, WMS GetLegendGraphic and WPS Execute requests. This vulnerability can lead to executing arbitrary code.\n\nVersions 2.23.6, 2.24.4, and 2.25.2 contain a patch for the issue. A workaround exists by removing the `gt-complex-x.y.jar` file from the GeoServer where `x.y` is the GeoTools version (e.g., `gt-complex-31.1.jar` if running GeoServer 2.25.1). This will remove the vulnerable code from GeoServer but may break some GeoServer functionality or prevent GeoServer from deploying if the gt-complex module is needed.
</code>

- [netuseradministrator/CVE-2024-36401](https://github.com/netuseradministrator/CVE-2024-36401)
- [0x0d3ad/CVE-2024-36401](https://github.com/0x0d3ad/CVE-2024-36401)
- [unlinedvol/CVE-2024-36401](https://github.com/unlinedvol/CVE-2024-36401)

### CVE-2024-36837 (2024-06-05)

<code>SQL Injection vulnerability in CRMEB v.5.2.2 allows a remote attacker to obtain sensitive information via the getProductList function in the ProductController.php file.
</code>

- [phtcloud-dev/CVE-2024-36837](https://github.com/phtcloud-dev/CVE-2024-36837)

### CVE-2024-36842
- [abbiy/CVE-2024-36842-Backdooring-Oncord-Android-Sterio-](https://github.com/abbiy/CVE-2024-36842-Backdooring-Oncord-Android-Sterio-)

### CVE-2024-37032 (2024-05-31)

<code>Ollama before 0.1.34 does not validate the format of the digest (sha256 with 64 hex digits) when getting the model path, and thus mishandles the TestGetBlobsPath test cases such as fewer than 64 hex digits, more than 64 hex digits, or an initial ../ substring.
</code>

- [Bi0x/CVE-2024-37032](https://github.com/Bi0x/CVE-2024-37032)

### CVE-2024-37383 (2024-06-07)

<code>Roundcube Webmail before 1.5.7 and 1.6.x before 1.6.7 allows XSS via SVG animate attributes.
</code>

- [amirzargham/CVE-2024-37383-exploit](https://github.com/amirzargham/CVE-2024-37383-exploit)

### CVE-2024-37726 (2024-07-03)

<code>Insecure Permissions vulnerability in Micro-Star International Co., Ltd MSI Center v.2.0.36.0 allows a local attacker to escalate privileges via the Export System Info function in MSI.CentralServer.exe
</code>

- [carsonchan12345/CVE-2024-37726-MSI-Center-Local-Privilege-Escalation](https://github.com/carsonchan12345/CVE-2024-37726-MSI-Center-Local-Privilege-Escalation)

### CVE-2024-37888 (2024-06-14)

<code>The Open Link is a CKEditor plugin, extending context menu with a possibility to open link in a new tab. The vulnerability allowed to execute JavaScript code by abusing link href attribute. It affects all users using the Open Link plugin at version &lt; **1.0.5**.
</code>

- [7Ragnarok7/CVE-2024-37888](https://github.com/7Ragnarok7/CVE-2024-37888)

### CVE-2024-38014 (2024-09-10)

<code>Windows Installer Elevation of Privilege Vulnerability
</code>

- [Anurag-Chevendra/CVE-2024-38014](https://github.com/Anurag-Chevendra/CVE-2024-38014)

### CVE-2024-38063 (2024-08-13)

<code>Windows TCP/IP Remote Code Execution Vulnerability
</code>

- [ThemeHackers/CVE-2024-38063](https://github.com/ThemeHackers/CVE-2024-38063)
- [Laukage/Windows-CVE-2024-38063](https://github.com/Laukage/Windows-CVE-2024-38063)

### CVE-2024-38143 (2024-08-13)

<code>Windows WLAN AutoConfig Service Elevation of Privilege Vulnerability
</code>

- [redr0nin/CVE-2024-38143](https://github.com/redr0nin/CVE-2024-38143)

### CVE-2024-38200 (2024-08-08)

<code>Microsoft Office Spoofing Vulnerability
</code>

- [passtheticket/CVE-2024-38200](https://github.com/passtheticket/CVE-2024-38200)

### CVE-2024-38366 (2024-07-01)

<code>trunk.cocoapods.org is the authentication server for the CoacoaPods dependency manager. The part of trunk which verifies whether a user has a real email address on signup used a rfc-822 library which executes a shell command to validate the email domain MX records validity. It works via an DNS MX. This lookup could be manipulated to also execute a command on the trunk server, effectively giving root access to the server and the infrastructure. This issue was patched server-side with commit 001cc3a430e75a16307f5fd6cdff1363ad2f40f3 in September 2023. This RCE triggered a full user-session reset, as an attacker could have used this method to write to any Podspec in trunk.
</code>

- [ReeFSpeK/CocoaPods-RCE_CVE-2024-38366](https://github.com/ReeFSpeK/CocoaPods-RCE_CVE-2024-38366)

### CVE-2024-38475 (2024-07-01)

<code>Improper escaping of output in mod_rewrite in Apache HTTP Server 2.4.59 and earlier allows an attacker to map URLs to filesystem locations that are permitted to be served by the server but are not intentionally/directly reachable by any URL, resulting in code execution or source code disclosure. \n\nSubstitutions in server context that use a backreferences or variables as the first segment of the substitution are affected.  Some unsafe RewiteRules will be broken by this change and the rewrite flag &quot;UnsafePrefixStat&quot; can be used to opt back in once ensuring the substitution is appropriately constrained.
</code>

- [soltanali0/CVE-2024-38475](https://github.com/soltanali0/CVE-2024-38475)

### CVE-2024-38526 (2024-06-25)

<code>pdoc provides API Documentation for Python Projects. Documentation generated with `pdoc --math` linked to JavaScript files from polyfill.io. The polyfill.io CDN has been sold and now serves malicious code. This issue has been fixed in pdoc 14.5.1.
</code>

- [padayali-JD/pollyscan](https://github.com/padayali-JD/pollyscan)

### CVE-2024-38816 (2024-09-13)

<code>Applications serving static resources through the functional web frameworks WebMvc.fn or WebFlux.fn are vulnerable to path traversal attacks. An attacker can craft malicious HTTP requests and obtain any file on the file system that is also accessible to the process in which the Spring application is running.\n\nSpecifically, an application is vulnerable when both of the following are true:\n\n  *  the web application uses RouterFunctions to serve static resources\n  *  resource handling is explicitly configured with a FileSystemResource location\n\n\nHowever, malicious requests are blocked and rejected when any of the following is true:\n\n  *  the  Spring Security HTTP Firewall https://docs.spring.io/spring-security/reference/servlet/exploits/firewall.html  is in use\n  *  the application runs on Tomcat or Jetty
</code>

- [Anthony1078/App-vulnerable](https://github.com/Anthony1078/App-vulnerable)

### CVE-2024-38819 (2024-12-19)

<code>Applications serving static resources through the functional web frameworks WebMvc.fn or WebFlux.fn are vulnerable to path traversal attacks. An attacker can craft malicious HTTP requests and obtain any file on the file system that is also accessible to the process in which the Spring application is running.
</code>

- [masa42/CVE-2024-38819-POC](https://github.com/masa42/CVE-2024-38819-POC)
- [GhostS3c/CVE-2024-38819](https://github.com/GhostS3c/CVE-2024-38819)
- [skrkcb2/cve-2024-38819](https://github.com/skrkcb2/cve-2024-38819)

### CVE-2024-38856 (2024-08-05)

<code>Incorrect Authorization vulnerability in Apache OFBiz.\n\nThis issue affects Apache OFBiz: through 18.12.14.\n\nUsers are recommended to upgrade to version 18.12.15, which fixes the issue.\n\nUnauthenticated endpoints could allow execution of screen rendering code of screens if some preconditions are met (such as when the screen definitions don't explicitly check user's permissions because they rely on the configuration of their endpoints).
</code>

- [AlissonFaoli/Apache-OFBiz-Exploit](https://github.com/AlissonFaoli/Apache-OFBiz-Exploit)

### CVE-2024-38998
- [z3ldr1/PP_CVE-2024-38998](https://github.com/z3ldr1/PP_CVE-2024-38998)

### CVE-2024-39081 (2024-09-18)

<code>An issue in SMART TYRE CAR &amp; BIKE v4.2.0 allows attackers to perform a man-in-the-middle attack via Bluetooth communications.
</code>

- [Amirasaiyad/BLE-TPMS](https://github.com/Amirasaiyad/BLE-TPMS)

### CVE-2024-39199
- [phtcloud-dev/CVE-2024-39199](https://github.com/phtcloud-dev/CVE-2024-39199)

### CVE-2024-39248 (2024-07-03)

<code>A cross-site scripting (XSS) vulnerability in SimpCMS v0.1 allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the Title field at /admin.php.
</code>

- [jasonthename/CVE-2024-39248](https://github.com/jasonthename/CVE-2024-39248)

### CVE-2024-39689 (2024-07-05)

<code>Certifi is a curated collection of Root Certificates for validating the trustworthiness of SSL certificates while verifying the identity of TLS hosts. Certifi starting in 2021.5.30 and prior to 2024.7.4 recognized root certificates from `GLOBALTRUST`. Certifi 2024.7.04 removes root certificates from `GLOBALTRUST` from the root store. These are in the process of being removed from Mozilla's trust store. `GLOBALTRUST`'s root certificates are being removed pursuant to an investigation which identified &quot;long-running and unresolved compliance issues.&quot;
</code>

- [roy-aladin/InfraTest](https://github.com/roy-aladin/InfraTest)

### CVE-2024-39713 (2024-08-05)

<code>A Server-Side Request Forgery (SSRF) affects Rocket.Chat's Twilio webhook endpoint before version 6.10.1.
</code>

- [typical-pashochek/CVE-2024-39713](https://github.com/typical-pashochek/CVE-2024-39713)

### CVE-2024-39908 (2024-07-16)

<code> REXML is an XML toolkit for Ruby. The REXML gem before 3.3.1 has some DoS vulnerabilities when it parses an XML that has many specific characters such as `&lt;`, `0` and `%&gt;`. If you need to parse untrusted XMLs, you many be impacted to these vulnerabilities. The REXML gem 3.3.2 or later include the patches to fix these vulnerabilities. Users are advised to upgrade. Users unable to upgrade should avoid parsing untrusted XML strings.
</code>

- [SpiralBL0CK/CVE-2024-39908](https://github.com/SpiralBL0CK/CVE-2024-39908)

### CVE-2024-39914 (2024-07-12)

<code>FOG is a cloning/imaging/rescue suite/inventory management system. Prior to 1.5.10.34, packages/web/lib/fog/reportmaker.class.php in FOG was affected by a command injection via the filename parameter to /fog/management/export.php. This vulnerability is fixed in 1.5.10.34.
</code>

- [9874621368/FOG-Project](https://github.com/9874621368/FOG-Project)

### CVE-2024-40318 (2024-07-25)

<code>An arbitrary file upload vulnerability in Webkul Qloapps v1.6.0.0 allows attackers to execute arbitrary code via uploading a crafted file.
</code>

- [3v1lC0d3/RCE-QloApps-CVE-2024-40318](https://github.com/3v1lC0d3/RCE-QloApps-CVE-2024-40318)

### CVE-2024-40348 (2024-07-20)

<code>An issue in the component /api/swaggerui/static of Bazaar v1.4.3 allows unauthenticated attackers to execute a directory traversal.
</code>

- [NingXin2002/Bazaar_poc](https://github.com/NingXin2002/Bazaar_poc)

### CVE-2024-40725 (2024-07-18)

<code>A partial fix for  CVE-2024-39884 in the core of Apache HTTP Server 2.4.61 ignores some use of the legacy content-type based configuration of handlers. &quot;AddType&quot; and similar configuration, under some circumstances where files are requested indirectly, result in source code disclosure of local content. For example, PHP scripts may be served instead of interpreted.\n\nUsers are recommended to upgrade to version 2.4.62, which fixes this issue.\n\n
</code>

- [soltanali0/CVE-2024-40725](https://github.com/soltanali0/CVE-2024-40725)

### CVE-2024-40815 (2024-07-29)

<code>A race condition was addressed with additional validation. This issue is fixed in macOS Ventura 13.6.8, iOS 17.6 and iPadOS 17.6, watchOS 10.6, tvOS 17.6, macOS Sonoma 14.6. A malicious attacker with arbitrary read and write capability may be able to bypass Pointer Authentication.
</code>

- [w0wbox/CVE-2024-40815](https://github.com/w0wbox/CVE-2024-40815)

### CVE-2024-41319 (2024-07-23)

<code>TOTOLINK A6000R V1.0.1-B20201211.2000 was discovered to contain a command injection vulnerability via the cmd parameter in the webcmd function.
</code>

- [NingXin2002/TOTOLINK_poc](https://github.com/NingXin2002/TOTOLINK_poc)

### CVE-2024-41453 (2025-01-15)

<code>A cross-site scripting (XSS) vulnerability in Process Maker pm4core-docker 4.1.21-RC7 allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the Name parameter.
</code>

- [php-lover-boy/CVE-2024-41453_CVE-2024-41454](https://github.com/php-lover-boy/CVE-2024-41453_CVE-2024-41454)

### CVE-2024-41713 (2024-10-21)

<code>A vulnerability in the NuPoint Unified Messaging (NPM) component of Mitel MiCollab through 9.8 SP1 FP2 (9.8.1.201) could allow an unauthenticated attacker to conduct a path traversal attack, due to insufficient input validation. A successful exploit could allow unauthorized access, enabling the attacker to view, corrupt, or delete users' data and system configurations.
</code>

- [watchtowrlabs/Mitel-MiCollab-Auth-Bypass_CVE-2024-41713](https://github.com/watchtowrlabs/Mitel-MiCollab-Auth-Bypass_CVE-2024-41713)
- [zxj-hub/CVE-2024-41713POC](https://github.com/zxj-hub/CVE-2024-41713POC)
- [Sanandd/cve-2024-CVE-2024-41713](https://github.com/Sanandd/cve-2024-CVE-2024-41713)

### CVE-2024-42008 (2024-08-05)

<code>A Cross-Site Scripting vulnerability in rcmail_action_mail_get-&gt;run() in Roundcube through 1.5.7 and 1.6.x through 1.6.7 allows a remote attacker to steal and send emails of a victim via a malicious e-mail attachment served with a dangerous Content-Type header.
</code>

- [victoni/Roundcube-CVE-2024-42008-and-CVE-2024-42010-POC](https://github.com/victoni/Roundcube-CVE-2024-42008-and-CVE-2024-42010-POC)

### CVE-2024-42009 (2024-08-05)

<code>A Cross-Site Scripting vulnerability in Roundcube through 1.5.7 and 1.6.x through 1.6.7 allows a remote attacker to steal and send emails of a victim via a crafted e-mail message that abuses a Desanitization issue in message_body() in program/actions/mail/show.php.
</code>

- [0xbassiouny1337/CVE-2024-42009](https://github.com/0xbassiouny1337/CVE-2024-42009)
- [Bhanunamikaze/CVE-2024-42009](https://github.com/Bhanunamikaze/CVE-2024-42009)

### CVE-2024-42327 (2024-11-27)

<code>A non-admin user account on the Zabbix frontend with the default User role, or with any other role that gives API access can exploit this vulnerability. An SQLi exists in the CUser class in the addRelatedObjects function, this function is being called from the CUser.get function which is available for every user who has API access.
</code>

- [aramosf/cve-2024-42327](https://github.com/aramosf/cve-2024-42327)
- [compr00t/CVE-2024-42327](https://github.com/compr00t/CVE-2024-42327)
- [depers-rus/CVE-2024-42327](https://github.com/depers-rus/CVE-2024-42327)
- [watchdog1337/CVE-2024-42327_Zabbix_SQLI](https://github.com/watchdog1337/CVE-2024-42327_Zabbix_SQLI)
- [itform-fr/Zabbix---CVE-2024-42327](https://github.com/itform-fr/Zabbix---CVE-2024-42327)
- [igorbf495/CVE-2024-42327](https://github.com/igorbf495/CVE-2024-42327)
- [godylockz/CVE-2024-42327](https://github.com/godylockz/CVE-2024-42327)

### CVE-2024-42448 (2024-12-11)

<code>From the VSPC management agent machine, under condition that the management agent is authorized on the server, it is possible to perform Remote Code Execution (RCE) on the VSPC server machine.
</code>

- [h3lye/CVE-2024-42448-RCE](https://github.com/h3lye/CVE-2024-42448-RCE)

### CVE-2024-42845 (2024-08-23)

<code>An eval Injection vulnerability in the component invesalius/reader/dicom.py of InVesalius 3.1.99991 through 3.1.99998 allows attackers to execute arbitrary code via loading a crafted DICOM file.
</code>

- [partywavesec/invesalius3_vulnerabilities](https://github.com/partywavesec/invesalius3_vulnerabilities)

### CVE-2024-43088 (2024-11-13)

<code>In multiple functions in AppInfoBase.java, there is a possible way to manipulate app permission settings belonging to another user on the device due to a missing permission check. This could lead to local escalation of privilege across user boundaries with no additional execution privileges needed. User interaction is not needed for exploitation.
</code>

- [nidhihcl75/packages_apps_Settings_AOSP10_r33_CVE-2024-43088](https://github.com/nidhihcl75/packages_apps_Settings_AOSP10_r33_CVE-2024-43088)

### CVE-2024-43090 (2024-11-13)

<code>In multiple locations, there is a possible cross-user image read due to a missing permission check. This could lead to local information disclosure with User execution privileges needed. User interaction is needed for exploitation.
</code>

- [nidhihcl75/frameworks_base_AOSP10_r33_CVE-2024-43090](https://github.com/nidhihcl75/frameworks_base_AOSP10_r33_CVE-2024-43090)

### CVE-2024-43097 (2025-01-02)

<code>In resizeToAtLeast of SkRegion.cpp, there is a possible out of bounds write due to an integer overflow. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.
</code>

- [Mahesh-970/CVE-2024-43097](https://github.com/Mahesh-970/CVE-2024-43097)

### CVE-2024-43425 (2024-11-07)

<code>A flaw was found in Moodle. Additional restrictions are required to avoid a remote code execution risk in calculated question types. Note: This requires the capability to add/update questions.
</code>

- [Snizi/Moodle-CVE-2024-43425-Exploit](https://github.com/Snizi/Moodle-CVE-2024-43425-Exploit)

### CVE-2024-43468 (2024-10-08)

<code>Microsoft Configuration Manager Remote Code Execution Vulnerability
</code>

- [synacktiv/CVE-2024-43468](https://github.com/synacktiv/CVE-2024-43468)

### CVE-2024-43583 (2024-10-08)

<code>Winlogon Elevation of Privilege Vulnerability
</code>

- [Kvngtheta/CVE-2024-43583-PoC](https://github.com/Kvngtheta/CVE-2024-43583-PoC)

### CVE-2024-43762 (2025-01-02)

<code>In multiple locations, there is a possible way to avoid unbinding of a service from the system due to a logic error in the code. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.
</code>

- [Mahesh-970/CVE-2024-43762](https://github.com/Mahesh-970/CVE-2024-43762)

### CVE-2024-43768 (2025-01-02)

<code>In skia_alloc_func of SkDeflate.cpp, there is a possible out of bounds write due to an integer overflow. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.
</code>

- [Mahesh-970/CVE-2024-43768](https://github.com/Mahesh-970/CVE-2024-43768)

### CVE-2024-44133 (2024-09-16)

<code>This issue was addressed by removing the vulnerable code. This issue is fixed in macOS Sequoia 15. On MDM managed devices, an app may be able to bypass certain Privacy preferences.
</code>

- [yo-yo-yo-jbo/hm-surf](https://github.com/yo-yo-yo-jbo/hm-surf)

### CVE-2024-44285 (2024-10-28)

<code>A use-after-free issue was addressed with improved memory management. This issue is fixed in iOS 18.1 and iPadOS 18.1, watchOS 11.1, visionOS 2.1, tvOS 18.1. An app may be able to cause unexpected system termination or corrupt kernel memory.
</code>

- [slds1/explt](https://github.com/slds1/explt)

### CVE-2024-44378
- [aezdmr/CVE-2024-44378](https://github.com/aezdmr/CVE-2024-44378)

### CVE-2024-44541 (2024-09-11)

<code>evilnapsis Inventio Lite Versions v4 and before is vulnerable to SQL Injection via the &quot;username&quot; parameter in &quot;/?action=processlogin.&quot;
</code>

- [pointedsec/CVE-2024-44541](https://github.com/pointedsec/CVE-2024-44541)

### CVE-2024-44765 (2024-11-08)

<code>An Improper Authorization (Access Control Misconfiguration) vulnerability in MGT-COMMERCE GmbH CloudPanel v2.0.0 to v2.4.2 allows low-privilege users to bypass access controls and gain unauthorized access to sensitive configuration files and administrative functionality.
</code>

- [josephgodwinkimani/cloudpanel-2.4.2-CVE-2024-44765-recovery](https://github.com/josephgodwinkimani/cloudpanel-2.4.2-CVE-2024-44765-recovery)

### CVE-2024-45216 (2024-10-16)

<code>Improper Authentication vulnerability in Apache Solr.\n\nSolr instances using the PKIAuthenticationPlugin, which is enabled by default when Solr Authentication is used, are vulnerable to Authentication bypass.\nA fake ending at the end of any Solr API URL path, will allow requests to skip Authentication while maintaining the API contract with the original URL Path.\nThis fake ending looks like an unprotected API path, however it is stripped off internally after authentication but before API routing.\n\n\nThis issue affects Apache Solr: from 5.3.0 before 8.11.4, from 9.0.0 before 9.7.0.\n\nUsers are recommended to upgrade to version 9.7.0, or 8.11.4, which fix the issue.
</code>

- [congdong007/CVE-2024-45216-Poc](https://github.com/congdong007/CVE-2024-45216-Poc)

### CVE-2024-45241 (2024-08-26)

<code>A traversal vulnerability in GeneralDocs.aspx in CentralSquare CryWolf (False Alarm Management) through 2024-08-09 allows unauthenticated attackers to read files outside of the working web directory via the rpt parameter, leading to the disclosure of sensitive information.
</code>

- [verylazytech/CVE-2024-45241](https://github.com/verylazytech/CVE-2024-45241)

### CVE-2024-45244 (2024-08-25)

<code>Hyperledger Fabric through 2.5.9 does not verify that a request has a timestamp within the expected time window.
</code>

- [shanker-sec/HLF_TxTime_spoofing](https://github.com/shanker-sec/HLF_TxTime_spoofing)

### CVE-2024-45337 (2024-12-11)

<code>Applications and libraries which misuse connection.serverAuthenticate (via callback field ServerConfig.PublicKeyCallback) may be susceptible to an authorization bypass. The documentation for ServerConfig.PublicKeyCallback says that &quot;A call to this function does not guarantee that the key offered is in fact used to authenticate.&quot; Specifically, the SSH protocol allows clients to inquire about whether a public key is acceptable before proving control of the corresponding private key. PublicKeyCallback may be called with multiple keys, and the order in which the keys were provided cannot be used to infer which key the client successfully authenticated with, if any. Some applications, which store the key(s) passed to PublicKeyCallback (or derived information) and make security relevant determinations based on it once the connection is established, may make incorrect assumptions. For example, an attacker may send public keys A and B, and then authenticate with A. PublicKeyCallback would be called only twice, first with A and then with B. A vulnerable application may then make authorization decisions based on key B for which the attacker does not actually control the private key. Since this API is widely misused, as a partial mitigation golang.org/x/cry...@v0.31.0 enforces the property that, when successfully authenticating via public key, the last key passed to ServerConfig.PublicKeyCallback will be the key used to authenticate the connection. PublicKeyCallback will now be called multiple times with the same key, if necessary. Note that the client may still not control the last key passed to PublicKeyCallback if the connection is then authenticated with a different method, such as PasswordCallback, KeyboardInteractiveCallback, or NoClientAuth. Users should be using the Extensions field of the Permissions return value from the various authentication callbacks to record data associated with the authentication attempt instead of referencing external state. Once the connection is established the state corresponding to the successful authentication attempt can be retrieved via the ServerConn.Permissions field. Note that some third-party libraries misuse the Permissions type by sharing it across authentication attempts; users of third-party libraries should refer to the relevant projects for guidance.
</code>

- [NHAS/CVE-2024-45337-POC](https://github.com/NHAS/CVE-2024-45337-POC)
- [NHAS/VULNERABLE-CVE-2024-45337](https://github.com/NHAS/VULNERABLE-CVE-2024-45337)

### CVE-2024-45440 (2024-08-29)

<code>core/authorize.php in Drupal 11.x-dev allows Full Path Disclosure (even when error logging is None) if the value of hash_salt is file_get_contents of a file that does not exist.
</code>

- [w0r1i0g1ht/CVE-2024-45440](https://github.com/w0r1i0g1ht/CVE-2024-45440)

### CVE-2024-45870 (2024-10-03)

<code>Bandisoft BandiView 7.05 is vulnerable to Incorrect Access Control in sub_0x3d80fc via a crafted POC file.
</code>

- [bshyuunn/Bandiview-7.05-Vuln-PoC](https://github.com/bshyuunn/Bandiview-7.05-Vuln-PoC)

### CVE-2024-46383 (2024-11-15)

<code>Hathway Skyworth Router CM5100-511 v4.1.1.24 was discovered to store sensitive information about USB and Wifi connected devices in plaintext.
</code>

- [nitinronge91/Sensitive-Information-disclosure-via-SPI-flash-firmware-for-Hathway-router-CVE-2024-46383](https://github.com/nitinronge91/Sensitive-Information-disclosure-via-SPI-flash-firmware-for-Hathway-router-CVE-2024-46383)

### CVE-2024-46507
- [Somchandra17/CVE-2024-46507](https://github.com/Somchandra17/CVE-2024-46507)

### CVE-2024-46538 (2024-10-22)

<code>A cross-site scripting (XSS) vulnerability in pfsense v2.5.2 allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the $pconfig variable at interfaces_groups_edit.php.
</code>

- [EQSTLab/CVE-2024-46538](https://github.com/EQSTLab/CVE-2024-46538)
- [LauLeysen/CVE-2024-46538](https://github.com/LauLeysen/CVE-2024-46538)

### CVE-2024-46542 (2024-12-30)

<code>Veritas / Arctera Data Insight before 7.1.1 allows Application Administrators to conduct SQL injection attacks.
</code>

- [MarioTesoro/CVE-2024-46542](https://github.com/MarioTesoro/CVE-2024-46542)

### CVE-2024-46982 (2024-09-17)

<code>Next.js is a React framework for building full-stack web applications. By sending a crafted HTTP request, it is possible to poison the cache of a non-dynamic server-side rendered route in the pages router (this does not affect the app router). When this crafted request is sent it could coerce Next.js to cache a route that is meant to not be cached and send a `Cache-Control: s-maxage=1, stale-while-revalidate` header which some upstream CDNs may cache as well. To be potentially affected all of the following must apply: 1. Next.js between 13.5.1 and 14.2.9, 2. Using pages router, &amp; 3. Using non-dynamic server-side rendered routes e.g. `pages/dashboard.tsx` not `pages/blog/[slug].tsx`. This vulnerability was resolved in Next.js v13.5.7, v14.2.10, and later. We recommend upgrading regardless of whether you can reproduce the issue or not. There are no official or recommended workarounds for this issue, we recommend that users patch to a safe version.
</code>

- [CodePontiff/next_js_poisoning](https://github.com/CodePontiff/next_js_poisoning)
- [Lercas/CVE-2024-46982](https://github.com/Lercas/CVE-2024-46982)

### CVE-2024-47051 (2025-02-26)

<code>This advisory addresses two critical security vulnerabilities present in Mautic versions before 5.2.3. These vulnerabilities could be exploited by authenticated users.\n\n  *  Remote Code Execution (RCE) via Asset Upload: A Remote Code Execution vulnerability has been identified in the asset upload functionality. Insufficient enforcement of allowed file extensions allows an attacker to bypass restrictions and upload executable files, such as PHP scripts.\n\n\n  *  Path Traversal File Deletion: A Path Traversal vulnerability exists in the upload validation process. Due to improper handling of path components, an authenticated user can manipulate the file deletion process to delete arbitrary files on the host system.
</code>

- [mallo-m/CVE-2024-47051](https://github.com/mallo-m/CVE-2024-47051)

### CVE-2024-47062 (2024-09-20)

<code>Navidrome is an open source web-based music collection server and streamer. Navidrome automatically adds parameters in the URL to SQL queries. This can be exploited to access information by adding parameters like `password=...` in the URL (ORM Leak). Furthermore, the names of the parameters are not properly escaped, leading to SQL Injections. Finally, the username is used in a `LIKE` statement, allowing people to log in with `%` instead of their username. When adding parameters to the URL, they are automatically included in an SQL `LIKE` statement (depending on the parameter's name). This allows attackers to potentially retrieve arbitrary information. For example, attackers can use the following request to test whether some encrypted passwords start with `AAA`. This results in an SQL query like `password LIKE 'AAA%'`, allowing attackers to slowly brute-force passwords. When adding parameters to the URL, they are automatically added to an SQL query. The names of the parameters are not properly escaped. This behavior can be used to inject arbitrary SQL code (SQL Injection). These vulnerabilities can be used to leak information and dump the contents of the database and have been addressed in release version 0.53.0. Users are advised to upgrade. There are no known workarounds for this vulnerability.
</code>

- [saisathvik1/CVE-2024-47062](https://github.com/saisathvik1/CVE-2024-47062)

### CVE-2024-47875 (2024-10-11)

<code>DOMPurify is a DOM-only, super-fast, uber-tolerant XSS sanitizer for HTML, MathML and SVG. DOMpurify was vulnerable to nesting-based mXSS. This vulnerability is fixed in 2.5.0 and 3.1.3.
</code>

- [daikinitanda/-CVE-2024-47875-](https://github.com/daikinitanda/-CVE-2024-47875-)

### CVE-2024-48197 (2025-01-02)

<code>Cross Site Scripting vulnerability in Audiocodes MP-202b v.4.4.3 allows a remote attacker to escalate privileges via the login page of the web interface.
</code>

- [GCatt-AS/CVE-2024-48197](https://github.com/GCatt-AS/CVE-2024-48197)

### CVE-2024-48245 (2025-01-07)

<code>Vehicle Management System 1.0 is vulnerable to SQL Injection. A guest user can exploit vulnerable POST parameters in various administrative actions, such as booking a vehicle or confirming a booking. The affected parameters include &quot;Booking ID&quot;, &quot;Action Name&quot;, and &quot;Payment Confirmation ID&quot;, which are present in /newvehicle.php and /newdriver.php.
</code>

- [ShadowByte1/CVE-2024-48245](https://github.com/ShadowByte1/CVE-2024-48245)

### CVE-2024-48246 (2025-03-05)

<code>Vehicle Management System 1.0 contains a Stored Cross-Site Scripting (XSS) vulnerability in the &quot;Name&quot; parameter of /vehicle-management/booking.php.
</code>

- [ShadowByte1/CVE-2024-48246](https://github.com/ShadowByte1/CVE-2024-48246)

### CVE-2024-48248 (2025-03-04)

<code>NAKIVO Backup &amp; Replication before 11.0.0.88174 allows absolute path traversal for reading files via getImageByPath to /c/router (this may lead to remote code execution across the enterprise because PhysicalDiscovery has cleartext credentials).
</code>

- [watchtowrlabs/nakivo-arbitrary-file-read-poc-CVE-2024-48248](https://github.com/watchtowrlabs/nakivo-arbitrary-file-read-poc-CVE-2024-48248)

### CVE-2024-48336 (2024-11-04)

<code>The install() function of ProviderInstaller.java in Magisk App before canary version 27007 does not verify the GMS app before loading it, which allows a local untrusted app with no additional privileges to silently execute arbitrary code in the Magisk app and escalate privileges to root via a crafted package, aka Bug #8279. User interaction is not needed for exploitation.
</code>

- [canyie/MagiskEoP](https://github.com/canyie/MagiskEoP)

### CVE-2024-48589 (2025-02-06)

<code>Cross Site Scripting vulnerability in Gilnei Moraes phpABook v.0.9 allows a remote attacker to execute arbitrary code via the rol parameter in index.php
</code>

- [Exek1el/CVE-2024-48589](https://github.com/Exek1el/CVE-2024-48589)

### CVE-2024-48705
- [L41KAA/CVE-2024-48705](https://github.com/L41KAA/CVE-2024-48705)

### CVE-2024-48762
- [YZS17/CVE-2024-48762](https://github.com/YZS17/CVE-2024-48762)

### CVE-2024-48990 (2024-11-19)

<code>Qualys discovered that needrestart, before version 3.8, allows local attackers to execute arbitrary code as root by tricking needrestart into running the Python interpreter with an attacker-controlled PYTHONPATH environment variable.
</code>

- [r0xdeadbeef/CVE-2024-48990](https://github.com/r0xdeadbeef/CVE-2024-48990)
- [CyberCrowCC/CVE-2024-48990](https://github.com/CyberCrowCC/CVE-2024-48990)
- [NullByte-7w7/CVE-2024-48990](https://github.com/NullByte-7w7/CVE-2024-48990)
- [ten-ops/CVE-2024-48990_needrestart](https://github.com/ten-ops/CVE-2024-48990_needrestart)

### CVE-2024-49019 (2024-11-12)

<code>Active Directory Certificate Services Elevation of Privilege Vulnerability
</code>

- [rayngnpc/CVE-2024-49019-rayng](https://github.com/rayngnpc/CVE-2024-49019-rayng)

### CVE-2024-49039 (2024-11-12)

<code>Windows Task Scheduler Elevation of Privilege Vulnerability
</code>

- [Alexandr-bit253/CVE-2024-49039](https://github.com/Alexandr-bit253/CVE-2024-49039)

### CVE-2024-49112 (2024-12-10)

<code>Windows Lightweight Directory Access Protocol (LDAP) Remote Code Execution Vulnerability
</code>

- [tnkr/poc_monitor](https://github.com/tnkr/poc_monitor)

### CVE-2024-49113 (2024-12-10)

<code>Windows Lightweight Directory Access Protocol (LDAP) Denial of Service Vulnerability
</code>

- [0xMetr0/metasploit-ldapnightmare](https://github.com/0xMetr0/metasploit-ldapnightmare)

### CVE-2024-49117 (2024-12-10)

<code>Windows Hyper-V Remote Code Execution Vulnerability
</code>

- [mutkus/Microsoft-2024-December-Update-Control](https://github.com/mutkus/Microsoft-2024-December-Update-Control)

### CVE-2024-49138 (2024-12-10)

<code>Windows Common Log File System Driver Elevation of Privilege Vulnerability
</code>

- [MrAle98/CVE-2024-49138-POC](https://github.com/MrAle98/CVE-2024-49138-POC)

### CVE-2024-49369 (2024-11-12)

<code>Icinga is a monitoring system which checks the availability of network resources, notifies users of outages, and generates performance data for reporting. The TLS certificate validation in all Icinga 2 versions starting from 2.4.0 was flawed, allowing an attacker to impersonate both trusted cluster nodes as well as any API users that use TLS client certificates for authentication (ApiUser objects with the client_cn attribute set). This vulnerability has been fixed in v2.14.3, v2.13.10, v2.12.11, and v2.11.12.
</code>

- [Quantum-Sicarius/CVE-2024-49369](https://github.com/Quantum-Sicarius/CVE-2024-49369)

### CVE-2024-50379 (2024-12-17)

<code>Time-of-check Time-of-use (TOCTOU) Race Condition vulnerability during JSP compilation in Apache Tomcat permits an RCE on case insensitive file systems when the default servlet is enabled for write (non-default configuration).\n\nThis issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.1, from 10.1.0-M1 through 10.1.33, from 9.0.0.M1 through 9.0.97.\n\nUsers are recommended to upgrade to version 11.0.2, 10.1.34 or 9.0.98, which fixes the issue.
</code>

- [v3153/CVE-2024-50379-POC](https://github.com/v3153/CVE-2024-50379-POC)
- [yiliufeng168/CVE-2024-50379-POC](https://github.com/yiliufeng168/CVE-2024-50379-POC)
- [JFOZ1010/Nuclei-Template-CVE-2024-50379](https://github.com/JFOZ1010/Nuclei-Template-CVE-2024-50379)
- [iSee857/CVE-2024-50379-PoC](https://github.com/iSee857/CVE-2024-50379-PoC)
- [Alchemist3dot14/CVE-2024-50379](https://github.com/Alchemist3dot14/CVE-2024-50379)
- [ph0ebus/Tomcat-CVE-2024-50379-Poc](https://github.com/ph0ebus/Tomcat-CVE-2024-50379-Poc)
- [SleepingBag945/CVE-2024-50379](https://github.com/SleepingBag945/CVE-2024-50379)
- [dear-cell/CVE-2024-50379](https://github.com/dear-cell/CVE-2024-50379)
- [lizhianyuguangming/CVE-2024-50379-exp](https://github.com/lizhianyuguangming/CVE-2024-50379-exp)
- [dragonked2/CVE-2024-50379-POC](https://github.com/dragonked2/CVE-2024-50379-POC)
- [dkstar11q/CVE-2024-50379-nuclei](https://github.com/dkstar11q/CVE-2024-50379-nuclei)

### CVE-2024-50498 (2024-10-28)

<code>Improper Control of Generation of Code ('Code Injection') vulnerability in LUBUS WP Query Console allows Code Injection.This issue affects WP Query Console: from n/a through 1.0.
</code>

- [p0et08/CVE-2024-50498](https://github.com/p0et08/CVE-2024-50498)

### CVE-2024-50507 (2024-10-30)

<code>Deserialization of Untrusted Data vulnerability in Daniel Schmitzer DS.DownloadList allows Object Injection.This issue affects DS.DownloadList: from n/a through 1.3.
</code>

- [RandomRobbieBF/CVE-2024-50507](https://github.com/RandomRobbieBF/CVE-2024-50507)

### CVE-2024-50508 (2024-10-30)

<code>Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability in Chetan Khandla Woocommerce Product Design allows Path Traversal.This issue affects Woocommerce Product Design: from n/a through 1.0.0.
</code>

- [RandomRobbieBF/CVE-2024-50508](https://github.com/RandomRobbieBF/CVE-2024-50508)

### CVE-2024-50509 (2024-10-30)

<code>Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability in Chetan Khandla Woocommerce Product Design allows Path Traversal.This issue affects Woocommerce Product Design: from n/a through 1.0.0.
</code>

- [RandomRobbieBF/CVE-2024-50509](https://github.com/RandomRobbieBF/CVE-2024-50509)

### CVE-2024-50510 (2024-10-30)

<code>Unrestricted Upload of File with Dangerous Type vulnerability in Web and Print Design AR For Woocommerce allows Upload a Web Shell to a Web Server.This issue affects AR For Woocommerce: from n/a through 6.2.
</code>

- [RandomRobbieBF/CVE-2024-50510](https://github.com/RandomRobbieBF/CVE-2024-50510)

### CVE-2024-50623 (2024-10-27)

<code>In Cleo Harmony before 5.8.0.21, VLTrader before 5.8.0.21, and LexiCom before 5.8.0.21, there is an unrestricted file upload and download that could lead to remote code execution.
</code>

- [watchtowrlabs/CVE-2024-50623](https://github.com/watchtowrlabs/CVE-2024-50623)
- [verylazytech/CVE-2024-50623](https://github.com/verylazytech/CVE-2024-50623)
- [iSee857/Cleo-CVE-2024-50623-PoC](https://github.com/iSee857/Cleo-CVE-2024-50623-PoC)

### CVE-2024-50677 (2024-12-06)

<code>A cross-site scripting (XSS) vulnerability in OroPlatform CMS v5.1 allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the Search parameter.
</code>

- [ZumiYumi/CVE-2024-50677](https://github.com/ZumiYumi/CVE-2024-50677)

### CVE-2024-50944 (2024-12-27)

<code>Integer overflow vulnerability exists in SimplCommerce at commit 230310c8d7a0408569b292c5a805c459d47a1d8f in the shopping cart functionality. The issue lies in the quantity parameter in the CartController's AddToCart method.
</code>

- [AbdullahAlmutawa/CVE-2024-50944](https://github.com/AbdullahAlmutawa/CVE-2024-50944)

### CVE-2024-50945 (2024-12-27)

<code>An improper access control vulnerability exists in SimplCommerce at commit 230310c8d7a0408569b292c5a805c459d47a1d8f, allowing users to submit reviews without verifying if they have purchased the product.
</code>

- [AbdullahAlmutawa/CVE-2024-50945](https://github.com/AbdullahAlmutawa/CVE-2024-50945)

### CVE-2024-50986 (2024-11-15)

<code>An issue in Clementine v.1.3.1 allows a local attacker to execute arbitrary code via a crafted DLL file.
</code>

- [riftsandroses/CVE-2024-50986](https://github.com/riftsandroses/CVE-2024-50986)

### CVE-2024-51144 (2025-03-05)

<code>Cross Site Request Forgery (CSRF) vulnerability exists in the 'pvmsg.php?action=add_message', pvmsg.php?action=confirm_delete , and ajax.server.php?page=user&amp;action=flip_follow endpoints in Ampache &lt;= 6.6.0.
</code>

- [nitipoom-jar/CVE-2024-51144](https://github.com/nitipoom-jar/CVE-2024-51144)

### CVE-2024-51179 (2024-11-12)

<code>An issue in Open 5GS v.2.7.1 allows a remote attacker to cause a denial of service via the Network Function Virtualizations (NFVs) such as the User Plane Function (UPF) and the Session Management Function (SMF), The Packet Data Unit (PDU) session establishment process.
</code>

- [Lakshmirnr/CVE-2024-51179](https://github.com/Lakshmirnr/CVE-2024-51179)

### CVE-2024-51378 (2024-10-29)

<code>getresetstatus in dns/views.py and ftp/views.py in CyberPanel (aka Cyber Panel) before 1c0c6cb allows remote attackers to bypass authentication and execute arbitrary commands via /dns/getresetstatus or /ftp/getresetstatus by bypassing secMiddleware (which is only for a POST request) and using shell metacharacters in the statusfile property, as exploited in the wild in October 2024 by PSAUX. Versions through 2.3.6 and (unpatched) 2.3.7 are affected.
</code>

- [qnole000/CVE-2024-51378](https://github.com/qnole000/CVE-2024-51378)

### CVE-2024-51442 (2025-01-08)

<code>Command Injection in Minidlna version v1.3.3 and before allows an attacker to execute arbitrary OS commands via a specially crafted minidlna.conf configuration file.
</code>

- [mselbrede/CVE-2024-51442](https://github.com/mselbrede/CVE-2024-51442)

### CVE-2024-52002 (2024-11-08)

<code>Combodo iTop is a simple, web based IT Service Management tool. Several url endpoints are subject to a Cross-Site Request Forgery (CSRF) vulnerability. Please refer to the linked GHSA for the complete list. This issue has been addressed in version 3.2.0 and all users are advised to upgrade. There are no known workarounds for this vulnerability.
</code>

- [Harshit-Mashru/iTop-CVEs-exploit](https://github.com/Harshit-Mashru/iTop-CVEs-exploit)

### CVE-2024-52940 (2024-11-18)

<code>AnyDesk through 8.1.0 on Windows, when Allow Direct Connections is enabled, inadvertently exposes a public IP address within network traffic. The attacker must know the victim's AnyDesk ID.
</code>

- [MKultra6969/AnySniff](https://github.com/MKultra6969/AnySniff)

### CVE-2024-53259 (2024-12-02)

<code>quic-go is an implementation of the QUIC protocol in Go. An off-path attacker can inject an ICMP Packet Too Large packet. Since affected quic-go versions used IP_PMTUDISC_DO, the kernel would then return a &quot;message too large&quot; error on sendmsg, i.e. when quic-go attempts to send a packet that exceeds the MTU claimed in that ICMP packet. By setting this value to smaller than 1200 bytes (the minimum MTU for QUIC), the attacker can disrupt a QUIC connection. Crucially, this can be done after completion of the handshake, thereby circumventing any TCP fallback that might be implemented on the application layer (for example, many browsers fall back to HTTP over TCP if they're unable to establish a QUIC connection). The attacker needs to at least know the client's IP and port tuple to mount an attack. This vulnerability is fixed in 0.48.2.
</code>

- [kota-yata/cve-2024-53259](https://github.com/kota-yata/cve-2024-53259)

### CVE-2024-53345 (2025-01-07)

<code>An authenticated arbitrary file upload vulnerability in Car Rental Management System v1.0 to v1.3 allows attackers to execute arbitrary code via uploading a crafted file.
</code>

- [ShadowByte1/CVE-2024-53345](https://github.com/ShadowByte1/CVE-2024-53345)

### CVE-2024-53375 (2024-12-02)

<code>An Authenticated Remote Code Execution (RCE) vulnerability affects the TP-Link Archer router series. A vulnerability exists in the &quot;tmp_get_sites&quot; function of the HomeShield functionality provided by TP-Link. This vulnerability is still exploitable without the activation of the HomeShield functionality.
</code>

- [ThottySploity/CVE-2024-53375](https://github.com/ThottySploity/CVE-2024-53375)

### CVE-2024-53376 (2024-12-16)

<code>CyberPanel before 2.3.8 allows remote authenticated users to execute arbitrary commands via shell metacharacters in the phpSelection field to the websites/submitWebsiteCreation URI.
</code>

- [ThottySploity/CVE-2024-53376](https://github.com/ThottySploity/CVE-2024-53376)

### CVE-2024-53393
- [alirezac0/CVE-2024-53393](https://github.com/alirezac0/CVE-2024-53393)

### CVE-2024-53476 (2024-12-27)

<code>A race condition vulnerability in SimplCommerce at commit 230310c8d7a0408569b292c5a805c459d47a1d8f allows attackers to bypass inventory restrictions by simultaneously submitting purchase requests from multiple accounts for the same product. This can lead to overselling when stock is limited, as the system fails to accurately track inventory under high concurrency, resulting in potential loss and unfulfilled orders.
</code>

- [AbdullahAlmutawa/CVE-2024-53476](https://github.com/AbdullahAlmutawa/CVE-2024-53476)

### CVE-2024-53615 (2025-01-30)

<code>A command injection vulnerability in the video thumbnail rendering component of Karl Ward's files.gallery v0.3.0 through 0.11.0 allows remote attackers to execute arbitrary code via a crafted video file.
</code>

- [beune/CVE-2024-53615](https://github.com/beune/CVE-2024-53615)

### CVE-2024-53677 (2024-12-11)

<code>File upload logic in Apache Struts is flawed. An attacker can manipulate file upload params to enable paths traversal and under some circumstances this can lead to uploading a malicious file which can be used to perform Remote Code Execution.\n\nThis issue affects Apache Struts: from 2.0.0 before 6.4.0.\n\nUsers are recommended to upgrade to version 6.4.0 at least and migrate to the new  file upload mechanism https://struts.apache.org/core-developers/file-upload . If you are not using an old file upload logic based on FileuploadInterceptor your application is safe.\n\nYou can find more details in  https://cwiki.apache.org/confluence/display/WW/S2-067
</code>

- [cloudwafs/s2-067-CVE-2024-53677](https://github.com/cloudwafs/s2-067-CVE-2024-53677)
- [TAM-K592/CVE-2024-53677-S2-067](https://github.com/TAM-K592/CVE-2024-53677-S2-067)
- [yangyanglo/CVE-2024-53677](https://github.com/yangyanglo/CVE-2024-53677)
- [c4oocO/CVE-2024-53677-Docker](https://github.com/c4oocO/CVE-2024-53677-Docker)
- [XiaomingX/CVE-2024-53677-S2-067](https://github.com/XiaomingX/CVE-2024-53677-S2-067)
- [dustblessnotdust/CVE-2024-53677-S2-067-thread](https://github.com/dustblessnotdust/CVE-2024-53677-S2-067-thread)
- [0xdeviner/CVE-2024-53677](https://github.com/0xdeviner/CVE-2024-53677)
- [SeanRickerd/CVE-2024-53677](https://github.com/SeanRickerd/CVE-2024-53677)
- [hopsypopsy8/CVE-2024-53677-Exploitation](https://github.com/hopsypopsy8/CVE-2024-53677-Exploitation)
- [shishirghimir/CVE-2024-53677-Exploit](https://github.com/shishirghimir/CVE-2024-53677-Exploit)

### CVE-2024-53704 (2025-01-09)

<code>An Improper Authentication vulnerability in the SSLVPN authentication mechanism allows a remote attacker to bypass authentication.
</code>

- [istagmbh/CVE-2024-53704](https://github.com/istagmbh/CVE-2024-53704)

### CVE-2024-54152 (2024-12-10)

<code>Angular Expressions provides expressions for the Angular.JS web framework as a standalone module. Prior to version 1.4.3, an attacker can write a malicious expression that escapes the sandbox to execute arbitrary code on the system. With a more complex (undisclosed) payload, one can get full access to Arbitrary code execution on the system. The problem has been patched in version 1.4.3 of Angular Expressions. Two possible workarounds are available. One may either disable access to `__proto__` globally or make sure that one uses the function with just one argument.
</code>

- [math-x-io/CVE-2024-54152-poc](https://github.com/math-x-io/CVE-2024-54152-poc)

### CVE-2024-54160 (2025-02-12)

<code>dashboards-reporting (aka Dashboards Reports) before 2.19.0.0, as shipped in OpenSearch before 2.19, allows XSS because Markdown is not sanitized when previewing a header or footer.
</code>

- [Jflye/CVE-2024-54160-Opensearch-HTML-And-Injection-Stored-XSS](https://github.com/Jflye/CVE-2024-54160-Opensearch-HTML-And-Injection-Stored-XSS)

### CVE-2024-54262 (2024-12-13)

<code>Unrestricted Upload of File with Dangerous Type vulnerability in Siddharth Nagar Import Export For WooCommerce allows Upload a Web Shell to a Web Server.This issue affects Import Export For WooCommerce: from n/a through 1.5.
</code>

- [RandomRobbieBF/CVE-2024-54262](https://github.com/RandomRobbieBF/CVE-2024-54262)

### CVE-2024-54369 (2024-12-16)

<code>Missing Authorization vulnerability in ThemeHunk Zita Site Builder allows Accessing Functionality Not Properly Constrained by ACLs.This issue affects Zita Site Builder: from n/a through 1.0.2.
</code>

- [RandomRobbieBF/CVE-2024-54369](https://github.com/RandomRobbieBF/CVE-2024-54369)

### CVE-2024-54378 (2024-12-16)

<code>Missing Authorization vulnerability in Quietly Quietly Insights allows Privilege Escalation.This issue affects Quietly Insights: from n/a through 1.2.2.
</code>

- [RandomRobbieBF/CVE-2024-54378](https://github.com/RandomRobbieBF/CVE-2024-54378)

### CVE-2024-54379 (2024-12-16)

<code>Missing Authorization vulnerability in Blokhaus Minterpress allows Privilege Escalation.This issue affects Minterpress: from n/a through 1.0.5.
</code>

- [RandomRobbieBF/CVE-2024-54379](https://github.com/RandomRobbieBF/CVE-2024-54379)

### CVE-2024-54679 (2024-12-05)

<code>CyberPanel (aka Cyber Panel) before 6778ad1 does not require the FilemanagerAdmin capability for restartMySQL actions.
</code>

- [hotplugin0x01/CVE-2024-54679](https://github.com/hotplugin0x01/CVE-2024-54679)

### CVE-2024-54761 (2025-01-09)

<code>BigAnt Office Messenger 5.6.06 is vulnerable to SQL Injection via the 'dev_code' parameter.
</code>

- [nscan9/CVE-2024-54761-BigAnt-Office-Messenger-5.6.06-RCE-via-SQL-Injection](https://github.com/nscan9/CVE-2024-54761-BigAnt-Office-Messenger-5.6.06-RCE-via-SQL-Injection)

### CVE-2024-54772 (2025-02-11)

<code>An issue was discovered in the Winbox service of MikroTik RouterOS long-term release v6.43.13 through v6.49.13 and stable v6.43 through v7.17.2. A patch is available in the stable release v6.49.18. A discrepancy in response size between connection attempts made with a valid username and those with an invalid username allows attackers to enumerate for valid accounts.
</code>

- [deauther890/CVE-2024-54772](https://github.com/deauther890/CVE-2024-54772)

### CVE-2024-54819 (2025-01-07)

<code>I, Librarian before and including 5.11.1 is vulnerable to Server-Side Request Forgery (SSRF) due to improper input validation in classes/security/validation.php
</code>

- [partywavesec/CVE-2024-54819](https://github.com/partywavesec/CVE-2024-54819)

### CVE-2024-54820 (2025-02-24)

<code>XOne Web Monitor v02.10.2024.530 framework 1.0.4.9 was discovered to contain a SQL injection vulnerability in the login page. This vulnerability allows attackers to extract all usernames and passwords via a crafted input.
</code>

- [jcarabantes/CVE-2024-54820](https://github.com/jcarabantes/CVE-2024-54820)

### CVE-2024-54916 (2025-02-11)

<code>An issue in the SharedConfig class of Telegram Android APK v.11.7.0 allows a physically proximate attacker to bypass authentication and escalate privileges by manipulating the return value of the checkPasscode method.
</code>

- [SAHALLL/CVE-2024-54916](https://github.com/SAHALLL/CVE-2024-54916)

### CVE-2024-54951 (2025-02-13)

<code>Monica 4.1.2 is vulnerable to Cross Site Scripting (XSS). A malicious user can create a malformed contact and use that contact in the &quot;HOW YOU MET&quot; customization options to trigger the XSS.
</code>

- [Allevon412/CVE-2024-54951](https://github.com/Allevon412/CVE-2024-54951)

### CVE-2024-55040
- [tcbutler320/CVE-2024-55040-Sensaphone-XSS](https://github.com/tcbutler320/CVE-2024-55040-Sensaphone-XSS)

### CVE-2024-55099 (2024-12-12)

<code>A SQL Injection vulnerability was found in /admin/index.php in phpgurukul Online Nurse Hiring System v1.0, which allows remote attackers to execute arbitrary SQL commands to get unauthorized database access via the username parameter.
</code>

- [ugurkarakoc1/CVE-2024-55099-Online-Nurse-Hiring-System-v1.0-SQL-Injection-Vulnerability-](https://github.com/ugurkarakoc1/CVE-2024-55099-Online-Nurse-Hiring-System-v1.0-SQL-Injection-Vulnerability-)

### CVE-2024-55215 (2025-02-07)

<code>An issue in trojan v.2.0.0 through v.2.15.3 allows a remote attacker to escalate privileges via the initialization interface /auth/register.
</code>

- [ainrm/Jrohy-trojan-unauth-poc](https://github.com/ainrm/Jrohy-trojan-unauth-poc)

### CVE-2024-55347
- [sahil3276/CVE-2024-55347](https://github.com/sahil3276/CVE-2024-55347)

### CVE-2024-55503 (2025-01-15)

<code>An issue in termius before v.9.9.0 allows a local attacker to execute arbitrary code via a crafted script to the DYLD_INSERT_LIBRARIES component.
</code>

- [SyFi/CVE-2024-55503](https://github.com/SyFi/CVE-2024-55503)

### CVE-2024-55511 (2025-01-16)

<code>A null pointer dereference vulnerability in Macrium Reflect prior to 8.1.8017 allows a local attacker to cause a system crash or potentially elevate their privileges via executing a specially crafted executable.
</code>

- [nikosecurity/CVE-2024-55511](https://github.com/nikosecurity/CVE-2024-55511)

### CVE-2024-55557 (2024-12-16)

<code>ui/pref/ProxyPrefView.java in weasis-core in Weasis 4.5.1 has a hardcoded key for symmetric encryption of proxy credentials.
</code>

- [partywavesec/CVE-2024-55557](https://github.com/partywavesec/CVE-2024-55557)

### CVE-2024-55587 (2024-12-11)

<code>python-libarchive through 4.2.1 allows directory traversal (to create files) in extract in zip.py for ZipFile.extractall and ZipFile.extract.
</code>

- [CSIRTTrizna/CVE-2024-55587](https://github.com/CSIRTTrizna/CVE-2024-55587)

### CVE-2024-55591 (2025-01-14)

<code>An Authentication Bypass Using an Alternate Path or Channel vulnerability [CWE-288] affecting FortiOS version 7.0.0 through 7.0.16 and FortiProxy version 7.0.0 through 7.0.19 and 7.2.0 through 7.2.12 allows a remote attacker to gain super-admin privileges via crafted requests to Node.js websocket module.
</code>

- [virus-or-not/CVE-2024-55591](https://github.com/virus-or-not/CVE-2024-55591)
- [exfil0/CVE-2024-55591-POC](https://github.com/exfil0/CVE-2024-55591-POC)
- [0x7556/CVE-2024-55591](https://github.com/0x7556/CVE-2024-55591)

### CVE-2024-55875 (2024-12-12)

<code>http4k is a functional toolkit for Kotlin HTTP applications. Prior to version 5.41.0.0, there is a potential XXE (XML External Entity Injection) vulnerability when http4k handling malicious XML contents within requests, which might allow attackers to read local sensitive information on server, trigger Server-side Request Forgery and even execute code under some circumstances. Version 5.41.0.0 contains a patch for the issue.
</code>

- [JAckLosingHeart/CVE-2024-55875](https://github.com/JAckLosingHeart/CVE-2024-55875)

### CVE-2024-55968 (2025-01-28)

<code>An issue was discovered in DTEX DEC-M (DTEX Forwarder) 6.1.1. The com.dtexsystems.helper service, responsible for handling privileged operations within the macOS DTEX Event Forwarder agent, fails to implement critical client validation during XPC interprocess communication (IPC). Specifically, the service does not verify the code requirements, entitlements, security flags, or version of any client attempting to establish a connection. This lack of proper logic validation allows malicious actors to exploit the service's methods via unauthorized client connections, and escalate privileges to root by abusing the DTConnectionHelperProtocol protocol's submitQuery method over an unauthorized XPC connection.
</code>

- [Wi1DN00B/CVE-2024-55968](https://github.com/Wi1DN00B/CVE-2024-55968)
- [null-event/CVE-2024-55968](https://github.com/null-event/CVE-2024-55968)

### CVE-2024-56115 (2024-12-18)

<code>A vulnerability in Amiro.CMS before 7.8.4 exists due to the failure to take measures to neutralize special elements. It allows remote attackers to conduct a Cross-Site Scripting (XSS) attack.
</code>

- [ComplianceControl/CVE-2024-56115](https://github.com/ComplianceControl/CVE-2024-56115)

### CVE-2024-56116 (2024-12-18)

<code>A Cross-Site Request Forgery vulnerability in Amiro.CMS before 7.8.4 allows remote attackers to create an administrator account.
</code>

- [ComplianceControl/CVE-2024-56116](https://github.com/ComplianceControl/CVE-2024-56116)

### CVE-2024-56145 (2024-12-18)

<code>Craft is a flexible, user-friendly CMS for creating custom digital experiences on the web and beyond. Users of affected versions are affected by this vulnerability if their php.ini configuration has `register_argc_argv` enabled. For these users an unspecified remote code execution vector is present. Users are advised to update to version 3.9.14, 4.13.2, or 5.5.2. Users unable to upgrade should disable `register_argc_argv` to mitigate the issue.
</code>

- [Chocapikk/CVE-2024-56145](https://github.com/Chocapikk/CVE-2024-56145)
- [Sachinart/CVE-2024-56145-craftcms-rce](https://github.com/Sachinart/CVE-2024-56145-craftcms-rce)

### CVE-2024-56264 (2025-01-02)

<code>Unrestricted Upload of File with Dangerous Type vulnerability in Beee ACF City Selector allows Upload a Web Shell to a Web Server.This issue affects ACF City Selector: from n/a through 1.14.0.
</code>

- [Nxploited/CVE-2024-56264](https://github.com/Nxploited/CVE-2024-56264)
- [dpakmrya/CVE-2024-56264](https://github.com/dpakmrya/CVE-2024-56264)

### CVE-2024-56331 (2024-12-20)

<code>Uptime Kuma is an open source, self-hosted monitoring tool. An **Improper URL Handling Vulnerability** allows an attacker to access sensitive local files on the server by exploiting the `file:///` protocol. This vulnerability is triggered via the **&quot;real-browser&quot;** request type, which takes a screenshot of the URL provided by the attacker. By supplying local file paths, such as `file:///etc/passwd`, an attacker can read sensitive data from the server. This vulnerability arises because the system does not properly validate or sanitize the user input for the URL field. Specifically: 1. The URL input (`&lt;input data-v-5f5c86d7=&quot;&quot; id=&quot;url&quot; type=&quot;url&quot; class=&quot;form-control&quot; pattern=&quot;https?://.+&quot; required=&quot;&quot;&gt;`) allows users to input arbitrary file paths, including those using the `file:///` protocol, without server-side validation. 2. The server then uses the user-provided URL to make a request, passing it to a browser instance that performs the &quot;real-browser&quot; request, which takes a screenshot of the content at the given URL. If a local file path is entered (e.g., `file:///etc/passwd`), the browser fetches and captures the file’s content. Since the user input is not validated, an attacker can manipulate the URL to request local files (e.g., `file:///etc/passwd`), and the system will capture a screenshot of the file's content, potentially exposing sensitive data. Any **authenticated user** who can submit a URL in &quot;real-browser&quot; mode is at risk of exposing sensitive data through screenshots of these files. This issue has been addressed in version 1.23.16 and all users are advised to upgrade. There are no known workarounds for this vulnerability.
</code>

- [griisemine/CVE-2024-56331](https://github.com/griisemine/CVE-2024-56331)

### CVE-2024-56340 (2025-02-28)

<code>IBM Cognos Analytics 11.2.0 through 11.2.4 FP5 is vulnerable to local file inclusion vulnerability, allowing an attacker to access sensitive files by inserting path traversal payloads inside the deficon parameter.
</code>

- [MarioTesoro/CVE-2024-56340](https://github.com/MarioTesoro/CVE-2024-56340)

### CVE-2024-56431 (2024-12-25)

<code>oc_huff_tree_unpack in huffdec.c in libtheora in Theora through 1.0 7180717 has an invalid negative left shift.
</code>

- [UnionTech-Software/libtheora-CVE-2024-56431-PoC](https://github.com/UnionTech-Software/libtheora-CVE-2024-56431-PoC)

### CVE-2024-56801 (2024-12-30)

<code>Tasklists provides plugin tasklists for GLPI. Versions prior to 2.0.4 have a blind SQL injection vulnerability. Version 2.0.4 contains a patch for the vulnerability.
</code>

- [kz0xpwn/CVE-2024-56801](https://github.com/kz0xpwn/CVE-2024-56801)

### CVE-2024-56882 (2025-02-18)

<code>Sage DPW before 2024_12_000 is vulnerable to Cross Site Scripting (XSS). Low-privileged Sage users with employee role privileges can permanently store JavaScript code in the Kurstitel and Kurzinfo input fields. The injected payload is executed for each authenticated user who views and interacts with the modified data elements.
</code>

- [trustcves/CVE-2024-56882](https://github.com/trustcves/CVE-2024-56882)

### CVE-2024-56883 (2025-02-18)

<code>Sage DPW before 2024_12_001 is vulnerable to Incorrect Access Control. The implemented role-based access controls are not always enforced on the server side. Low-privileged Sage users with employee role privileges can create external courses for other employees, even though they do not have the option to do so in the user interface. To do this, a valid request to create a course simply needs to be modified, so that the current user ID in the &quot;id&quot; parameter is replaced with the ID of another user.
</code>

- [trustcves/CVE-2024-56883](https://github.com/trustcves/CVE-2024-56883)

### CVE-2024-56889 (2025-02-06)

<code>Incorrect access control in the endpoint /admin/m_delete.php of CodeAstro Complaint Management System v1.0 allows unauthorized attackers to arbitrarily delete complaints via modification of the id parameter.
</code>

- [vigneshr232/CVE-2024-56889](https://github.com/vigneshr232/CVE-2024-56889)

### CVE-2024-56898 (2025-02-03)

<code>Broken access control vulnerability in Geovision GV-ASWeb with version v6.1.0.0 or less. This vulnerability allows low privilege users perform actions that they aren't authorized to, which can be leveraged to escalate privileges, create, modify or delete accounts.
</code>

- [DRAGOWN/CVE-2024-56898](https://github.com/DRAGOWN/CVE-2024-56898)

### CVE-2024-56901 (2025-02-03)

<code>A Cross-Site Request Forgery (CSRF) vulnerability in Geovision GV-ASWeb application with the version 6.1.1.0 or less that allows attackers to arbitrarily create Administrator accounts via a crafted GET request method. This vulnerability is used in chain with CVE-2024-56903 for a successful CSRF attack.
</code>

- [DRAGOWN/CVE-2024-56901](https://github.com/DRAGOWN/CVE-2024-56901)

### CVE-2024-56902 (2025-02-03)

<code>Information disclosure vulnerability in Geovision GV-ASManager web application with the version v6.1.0.0 or less, which discloses account information, including cleartext password.
</code>

- [DRAGOWN/CVE-2024-56902](https://github.com/DRAGOWN/CVE-2024-56902)

### CVE-2024-56903 (2025-02-03)

<code>Geovision GV-ASWeb with the version 6.1.1.0 or less allows attackers to modify POST request method with the GET against critical functionalities, such as account management. This vulnerability is used in chain with CVE-2024-56901 for a successful CSRF attack.
</code>

- [DRAGOWN/CVE-2024-56903](https://github.com/DRAGOWN/CVE-2024-56903)

### CVE-2024-57175 (2025-02-03)

<code>A Stored Cross-Site Scripting (XSS) vulnerability was identified in the PHPGURUKUL Online Birth Certificate System v1.0 via the profile name to /user/certificate-form.php.
</code>

- [Ajmal101/CVE-2024-57175](https://github.com/Ajmal101/CVE-2024-57175)

### CVE-2024-57241 (2025-02-11)

<code>Dedecms 5.71sp1 and earlier is vulnerable to URL redirect. In the web application, a logic error does not judge the input GET request resulting in URL redirection.
</code>

- [woshidaheike/CVE-2024-57241](https://github.com/woshidaheike/CVE-2024-57241)

### CVE-2024-57373 (2025-01-27)

<code>Cross Site Request Forgery (CSRF) vulnerability in LifestyleStore v1.0 allows a remote attacker to execute unauthorized actions on behalf of an authenticated user, potentially leading to account modifications or data compromise.
</code>

- [cypherdavy/CVE-2024-57373](https://github.com/cypherdavy/CVE-2024-57373)

### CVE-2024-57427 (2025-02-06)

<code>PHPJabbers Cinema Booking System v2.0 is vulnerable to reflected cross-site scripting (XSS). Multiple endpoints improperly handle user input, allowing malicious scripts to execute in a victim’s browser. Attackers can craft malicious links to steal session cookies or conduct phishing attacks.
</code>

- [ahrixia/CVE-2024-57427](https://github.com/ahrixia/CVE-2024-57427)

### CVE-2024-57428 (2025-02-06)

<code>A stored cross-site scripting (XSS) vulnerability in PHPJabbers Cinema Booking System v2.0 exists due to unsanitized input in file upload fields (event_img, seat_maps) and seat number configurations (number[new_X] in pjActionCreate). Attackers can inject persistent JavaScript, leading to phishing, malware injection, and session hijacking.
</code>

- [ahrixia/CVE-2024-57428](https://github.com/ahrixia/CVE-2024-57428)

### CVE-2024-57429 (2025-02-06)

<code>A cross-site request forgery (CSRF) vulnerability in the pjActionUpdate function of PHPJabbers Cinema Booking System v2.0 allows remote attackers to escalate privileges by tricking an authenticated admin into submitting an unauthorized request.
</code>

- [ahrixia/CVE-2024-57429](https://github.com/ahrixia/CVE-2024-57429)

### CVE-2024-57430 (2025-02-06)

<code>An SQL injection vulnerability in the pjActionGetUser function of PHPJabbers Cinema Booking System v2.0 allows attackers to manipulate database queries via the column parameter. Exploiting this flaw can lead to unauthorized information disclosure, privilege escalation, or database manipulation.
</code>

- [ahrixia/CVE-2024-57430](https://github.com/ahrixia/CVE-2024-57430)

### CVE-2024-57484
- [yogeswaran6383/CVE-2024-57484](https://github.com/yogeswaran6383/CVE-2024-57484)

### CVE-2024-57514 (2025-01-28)

<code>The TP-Link Archer A20 v3 router is vulnerable to Cross-site Scripting (XSS) due to improper handling of directory listing paths in the web interface. When a specially crafted URL is visited, the router's web page renders the directory listing and executes arbitrary JavaScript embedded in the URL. This allows the attacker to inject malicious code into the page, executing JavaScript on the victim's browser, which could then be used for further malicious actions. The vulnerability was identified in the 1.0.6 Build 20231011 rel.85717(5553) version.
</code>

- [rvizx/CVE-2024-57514](https://github.com/rvizx/CVE-2024-57514)

### CVE-2024-57609 (2025-02-06)

<code>An issue in Kanaries Inc Pygwalker before v.0.4.9.9 allows a remote attacker to obtain sensitive information and execute arbitrary code via the redirect_path parameter of the login redirection function.
</code>

- [nca785/CVE-2024-57609](https://github.com/nca785/CVE-2024-57609)

### CVE-2024-57610 (2025-02-06)

<code>A rate limiting issue in Sylius v2.0.2 allows a remote attacker to perform unrestricted brute-force attacks on user accounts, significantly increasing the risk of account compromise and denial of service for legitimate users. The Supplier's position is that the Sylius core software is not intended to address brute-force attacks; instead, customers deploying a Sylius-based system are supposed to use &quot;firewalls, rate-limiting middleware, or authentication providers&quot; for that functionality.
</code>

- [nca785/CVE-2024-57610](https://github.com/nca785/CVE-2024-57610)

### CVE-2024-57725 (2025-02-14)

<code>An issue in the Arcadyan Livebox Fibra PRV3399B_B_LT allows a remote or local attacker to modify the GPON link value without authentication, causing an internet service disruption via the /firstconnection.cgi endpoint.
</code>

- [pointedsec/CVE-2024-57725](https://github.com/pointedsec/CVE-2024-57725)

### CVE-2024-57778 (2025-02-14)

<code>An issue in Orbe ONetView Roeador Onet-1200 Orbe 1680210096 allows a remote attacker to escalate privileges via the servers response from status code 500 to status code 200.
</code>

- [KUK3N4N/CVE-2024-57778](https://github.com/KUK3N4N/CVE-2024-57778)


## 2023
### CVE-2023-0099 (2023-02-13)

<code>The Simple URLs WordPress plugin before 115 does not sanitise and escape some parameters before outputting them back in some pages, leading to Reflected Cross-Site Scripting which could be used against high privilege users such as admin.
</code>

- [amirzargham/CVE-2023-0099-exploit](https://github.com/amirzargham/CVE-2023-0099-exploit)

### CVE-2023-0179 (2023-03-27)

<code>A buffer overflow vulnerability was found in the Netfilter subsystem in the Linux Kernel. This issue could allow the leakage of both stack and heap addresses, and potentially allow Local Privilege Escalation to the root user via arbitrary code execution.
</code>

- [TurtleARM/CVE-2023-0179-PoC](https://github.com/TurtleARM/CVE-2023-0179-PoC)

### CVE-2023-0669 (2023-02-06)

<code>Fortra (formerly, HelpSystems) GoAnywhere MFT suffers from a pre-authentication command injection vulnerability in the License Response Servlet due to deserializing an arbitrary attacker-controlled object. This issue was patched in version 7.1.2.
</code>

- [0xf4n9x/CVE-2023-0669](https://github.com/0xf4n9x/CVE-2023-0669)

### CVE-2023-08
- [amirzargham/CVE-2023-08-21-exploit](https://github.com/amirzargham/CVE-2023-08-21-exploit)

### CVE-2023-1177 (2023-03-24)

<code>Path Traversal: '\..\filename' in GitHub repository mlflow/mlflow prior to 2.2.1.\n\n
</code>

- [hh-hunter/ml-CVE-2023-1177](https://github.com/hh-hunter/ml-CVE-2023-1177)

### CVE-2023-1389 (2023-03-15)

<code>TP-Link Archer AX21 (AX1800) firmware versions before 1.1.4 Build 20230219 contained a command injection vulnerability in the country form of the /cgi-bin/luci;stok=/locale endpoint on the web management interface. Specifically, the country parameter of the write operation was not sanitized before being used in a call to popen(), allowing an unauthenticated attacker to inject commands, which would be run as root, with a simple POST request.
</code>

- [Voyag3r-Security/CVE-2023-1389](https://github.com/Voyag3r-Security/CVE-2023-1389)

### CVE-2023-1430 (2023-06-09)

<code>The FluentCRM - Marketing Automation For WordPress  plugin for WordPress is vulnerable to unauthorized modification of data in versions up to, and including, 2.7.40 due to the use of an MD5 hash without a salt to control subscriptions. This makes it possible for unauthenticated attackers to unsubscribe users from lists and manage subscriptions, granted they gain access to any targeted subscribers email address.
</code>

- [karlemilnikka/CVE-2023-1430](https://github.com/karlemilnikka/CVE-2023-1430)

### CVE-2023-1498 (2023-03-19)

<code>Es wurde eine kritische Schwachstelle in code-projects Responsive Hotel Site 1.0 entdeckt. Dabei betrifft es einen unbekannter Codeteil der Datei messages.php der Komponente Newsletter Log Handler. Durch Beeinflussen des Arguments title mit unbekannten Daten kann eine sql injection-Schwachstelle ausgenutzt werden. Die Umsetzung des Angriffs kann dabei über das Netzwerk erfolgen. Der Exploit steht zur öffentlichen Verfügung.
</code>

- [Decemberus/BugHub](https://github.com/Decemberus/BugHub)

### CVE-2023-1545 (2023-03-21)

<code>SQL Injection in GitHub repository nilsteampassnet/teampass prior to 3.0.0.23.
</code>

- [HarshRajSinghania/CVE-2023-1545-Exploit](https://github.com/HarshRajSinghania/CVE-2023-1545-Exploit)
- [zer0-dave/CVE-2023-1545-POC](https://github.com/zer0-dave/CVE-2023-1545-POC)
- [sternstundes/CVE-2023-1545-POC-python](https://github.com/sternstundes/CVE-2023-1545-POC-python)

### CVE-2023-1698 (2023-05-15)

<code>In multiple products of WAGO a vulnerability allows an unauthenticated, remote attacker to create new users and change the device configuration which can result in unintended behaviour, Denial of Service and full system compromise.
</code>

- [X3RX3SSec/CVE-2023-1698](https://github.com/X3RX3SSec/CVE-2023-1698)

### CVE-2023-1829 (2023-04-12)

<code>A use-after-free vulnerability in the Linux Kernel traffic control index filter (tcindex) can be exploited to achieve local privilege escalation. The tcindex_delete function which does not properly deactivate filters in case of a perfect hashes while deleting the underlying structure which can later lead to double freeing the structure. A local attacker user can use this vulnerability to elevate its privileges to root.\nWe recommend upgrading past commit 8c710f75256bb3cf05ac7b1672c82b92c43f3d28.
</code>

- [lanleft/CVE-2023-1829](https://github.com/lanleft/CVE-2023-1829)

### CVE-2023-2033 (2023-04-14)

<code>Type confusion in V8 in Google Chrome prior to 112.0.5615.121 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
</code>

- [sandumjacob/CVE-2023-2033-Analysis](https://github.com/sandumjacob/CVE-2023-2033-Analysis)

### CVE-2023-2245 (2023-04-22)

<code>In hansunCMS 1.4.3 wurde eine Schwachstelle ausgemacht. Sie wurde als kritisch eingestuft. Es geht um eine nicht näher bekannte Funktion der Datei /ueditor/net/controller.ashx?action=catchimage. Durch die Manipulation mit unbekannten Daten kann eine unrestricted upload-Schwachstelle ausgenutzt werden. Der Angriff kann über das Netzwerk erfolgen. Der Exploit steht zur öffentlichen Verfügung.
</code>

- [chihyeonwon/2023-2245](https://github.com/chihyeonwon/2023-2245)

### CVE-2023-2645 (2023-05-11)

<code>Es wurde eine Schwachstelle in USR USR-G806 1.0.41 gefunden. Sie wurde als kritisch eingestuft. Betroffen hiervon ist ein unbekannter Ablauf der Komponente Web Management Page. Durch das Manipulieren des Arguments username/password mit der Eingabe root mit unbekannten Daten kann eine use of hard-coded password-Schwachstelle ausgenutzt werden. Umgesetzt werden kann der Angriff über das Netzwerk. Der Exploit steht zur öffentlichen Verfügung. Als bestmögliche Massnahme werden Anpassungen an der Konfiguration empfohlen.
</code>

- [xymbiot-solution/CVE-2023-2645](https://github.com/xymbiot-solution/CVE-2023-2645)

### CVE-2023-2825 (2023-05-26)

<code>An issue has been discovered in GitLab CE/EE affecting only version 16.0.0. An unauthenticated malicious user can use a path traversal vulnerability to read arbitrary files on the server when an attachment exists in a public project nested within at least five groups.
</code>

- [alej6/MassCyberCenter-Mentorship-Project-](https://github.com/alej6/MassCyberCenter-Mentorship-Project-)

### CVE-2023-2986 (2023-06-08)

<code>The Abandoned Cart Lite for WooCommerce plugin for WordPress is vulnerable to authentication bypass in versions up to, and including, 5.14.2. This is due to insufficient encryption on the user being supplied during the abandoned cart link decode through the plugin. This allows unauthenticated attackers to log in as users who have abandoned the cart, who are typically customers. Further security hardening was introduced in version 5.15.1 that ensures sites are no longer vulnerable through historical check-out links, and additional hardening was introduced in version 5.15.2 that ensured null key values wouldn't permit the authentication bypass.
</code>

- [Ayantaker/CVE-2023-2986](https://github.com/Ayantaker/CVE-2023-2986)

### CVE-2023-3280 (2023-09-13)

<code>A problem with a protection mechanism in the Palo Alto Networks Cortex XDR agent on Windows devices allows a local user to disable the agent.\n\n
</code>

- [ig-labs/EDR-ALPC-Block-POC](https://github.com/ig-labs/EDR-ALPC-Block-POC)

### CVE-2023-3460 (2023-07-04)

<code>The Ultimate Member WordPress plugin before 2.6.7 does not prevent visitors from creating user accounts with arbitrary capabilities, effectively allowing attackers to create administrator accounts at will. This is actively being exploited in the wild.
</code>

- [Rajneeshkarya/CVE-2023-3460](https://github.com/Rajneeshkarya/CVE-2023-3460)
- [TranKuBao/CVE-2023-3460_FIX](https://github.com/TranKuBao/CVE-2023-3460_FIX)

### CVE-2023-3824 (2023-08-11)

<code>In PHP version 8.0.* before 8.0.30,  8.1.* before 8.1.22, and 8.2.* before 8.2.8, when loading phar file, while reading PHAR directory entries, insufficient length checking may lead to a stack buffer overflow, leading potentially to memory corruption or RCE.
</code>

- [fr33c0d3/poc-cve-2023-3824](https://github.com/fr33c0d3/poc-cve-2023-3824)
- [bluefish3r/poc-cve](https://github.com/bluefish3r/poc-cve)

### CVE-2023-4147 (2023-08-07)

<code>A use-after-free flaw was found in the Linux kernel’s Netfilter functionality when adding a rule with NFTA_RULE_CHAIN_ID. This flaw allows a local user to crash or escalate their privileges on the system.
</code>

- [murdok1982/Exploit-en-Python-para-CVE-2023-4147](https://github.com/murdok1982/Exploit-en-Python-para-CVE-2023-4147)

### CVE-2023-4220 (2023-11-28)

<code>Unrestricted file upload in big file upload functionality in `/main/inc/lib/javascript/bigupload/inc/bigUpload.php` in Chamilo LMS &lt;= v1.11.24 allows unauthenticated attackers to perform stored cross-site scripting attacks and obtain remote code execution via uploading of web shell.
</code>

- [0xDTC/Chamilo-LMS-CVE-2023-4220-Exploit](https://github.com/0xDTC/Chamilo-LMS-CVE-2023-4220-Exploit)
- [zora-beep/CVE-2023-4220](https://github.com/zora-beep/CVE-2023-4220)

### CVE-2023-4542 (2023-08-25)

<code>Es wurde eine Schwachstelle in D-Link DAR-8000-10 bis 20230809 ausgemacht. Sie wurde als kritisch eingestuft. Es geht dabei um eine nicht klar definierte Funktion der Datei /app/sys1.php. Durch das Manipulieren des Arguments cmd mit der Eingabe id mit unbekannten Daten kann eine os command injection-Schwachstelle ausgenutzt werden. Der Angriff kann über das Netzwerk passieren. Der Exploit steht zur öffentlichen Verfügung.
</code>

- [PumpkinBridge/CVE-2023-4542](https://github.com/PumpkinBridge/CVE-2023-4542)

### CVE-2023-4596 (2023-08-30)

<code>The Forminator plugin for WordPress is vulnerable to arbitrary file uploads due to file type validation occurring after a file has been uploaded to the server in the upload_post_image() function in versions up to, and including, 1.24.6. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.
</code>

- [E1A/CVE-2023-4596](https://github.com/E1A/CVE-2023-4596)

### CVE-2023-4863 (2023-09-12)

<code>Heap buffer overflow in libwebp in Google Chrome prior to 116.0.5845.187 and libwebp 1.3.2 allowed a remote attacker to perform an out of bounds memory write via a crafted HTML page. (Chromium security severity: Critical)
</code>

- [mistymntncop/CVE-2023-4863](https://github.com/mistymntncop/CVE-2023-4863)

### CVE-2023-4911 (2023-10-03)

<code>A buffer overflow was discovered in the GNU C Library's dynamic loader ld.so while processing the GLIBC_TUNABLES environment variable. This issue could allow a local attacker to use maliciously crafted GLIBC_TUNABLES environment variables when launching binaries with SUID permission to execute code with elevated privileges.
</code>

- [Billar42/CVE-2023-4911](https://github.com/Billar42/CVE-2023-4911)
- [shacojx/CVE-2023-4911-Exploit](https://github.com/shacojx/CVE-2023-4911-Exploit)

### CVE-2023-4966 (2023-10-10)

<code>Sensitive information disclosure in NetScaler ADC and NetScaler Gateway when configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) or AAA  virtual server.
</code>

- [akshthejo/CVE-2023-4966-exploit](https://github.com/akshthejo/CVE-2023-4966-exploit)

### CVE-2023-5965 (2023-11-30)

<code>An authenticated privileged attacker could upload a specially crafted zip to the EspoCRM server in version 7.2.5, via the update form, which could lead to arbitrary PHP code execution.
</code>

- [pedrojosenavasperez/cve-2023-5965](https://github.com/pedrojosenavasperez/cve-2023-5965)

### CVE-2023-5966 (2023-11-30)

<code>An authenticated privileged attacker could upload a specially crafted zip to the EspoCRM server in version 7.2.5, via the extension deployment form, which could lead to arbitrary PHP code execution.
</code>

- [pedrojosenavasperez/cve-2023-5966](https://github.com/pedrojosenavasperez/cve-2023-5966)

### CVE-2023-6000 (2024-01-01)

<code>The Popup Builder WordPress plugin before 4.2.3 does not prevent simple visitors from updating existing popups, and injecting raw JavaScript in them, which could lead to Stored XSS attacks.
</code>

- [RonF98/CVE-2023-6000-POC](https://github.com/RonF98/CVE-2023-6000-POC)

### CVE-2023-6199 (2023-11-20)

<code>Book Stack version 23.10.2 allows filtering local files on the server. This is possible because the application is vulnerable to SSRF.\n
</code>

- [AbdrrahimDahmani/php_filter_chains_oracle_exploit_for_CVE-2023-6199](https://github.com/AbdrrahimDahmani/php_filter_chains_oracle_exploit_for_CVE-2023-6199)
- [4xura/php_filter_chain_oracle_poc](https://github.com/4xura/php_filter_chain_oracle_poc)

### CVE-2023-6546 (2023-12-21)

<code>A race condition was found in the GSM 0710 tty multiplexor in the Linux kernel. This issue occurs when two threads execute the GSMIOC_SETCONF ioctl on the same tty file descriptor with the gsm line discipline enabled, and can lead to a use-after-free problem on a struct gsm_dlci while restarting the gsm mux. This could allow a local unprivileged user to escalate their privileges on the system.
</code>

- [harithlab/CVE-2023-6546](https://github.com/harithlab/CVE-2023-6546)

### CVE-2023-6931 (2023-12-19)

<code>A heap out-of-bounds write vulnerability in the Linux kernel's Performance Events system component can be exploited to achieve local privilege escalation.\n\nA perf_event's read_size can overflow, leading to an heap out-of-bounds increment or write in perf_read_group().\n\nWe recommend upgrading past commit 382c27f4ed28f803b1f1473ac2d8db0afc795a1b.
</code>

- [K0n9-log/CVE-2023-6931](https://github.com/K0n9-log/CVE-2023-6931)

### CVE-2023-7028 (2024-01-12)

<code>An issue has been discovered in GitLab CE/EE affecting all versions from 16.1 prior to 16.1.6, 16.2 prior to 16.2.9, 16.3 prior to 16.3.7, 16.4 prior to 16.4.5, 16.5 prior to 16.5.6, 16.6 prior to 16.6.4, and 16.7 prior to 16.7.2 in which user account password reset emails could be delivered to an unverified email address.
</code>

- [yoryio/CVE-2023-7028](https://github.com/yoryio/CVE-2023-7028)
- [sariamubeen/CVE-2023-7028](https://github.com/sariamubeen/CVE-2023-7028)

### CVE-2023-20573 (2024-01-11)

<code>A privileged attacker\ncan prevent delivery of debug exceptions to SEV-SNP guests potentially\nresulting in guests not receiving expected debug information.\n\n\n\n
</code>

- [Freax13/cve-2023-20573-poc](https://github.com/Freax13/cve-2023-20573-poc)

### CVE-2023-20963 (2023-03-24)

<code>In WorkSource, there is a possible parcel mismatch. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-11 Android-12 Android-12L Android-13Android ID: A-220302519
</code>

- [pwnipc/BadParcel](https://github.com/pwnipc/BadParcel)

### CVE-2023-21537 (2023-01-10)

<code>Microsoft Message Queuing (MSMQ) Elevation of Privilege Vulnerability
</code>

- [stevenjoezhang/CVE-2023-21537](https://github.com/stevenjoezhang/CVE-2023-21537)

### CVE-2023-21554 (2023-04-11)

<code>Microsoft Message Queuing (MSMQ) Remote Code Execution Vulnerability
</code>

- [Rahul-Thakur7/CVE-2023-21554](https://github.com/Rahul-Thakur7/CVE-2023-21554)

### CVE-2023-21608 (2023-01-18)

<code>Adobe Acrobat Reader versions 22.003.20282 (and earlier), 22.003.20281 (and earlier) and 20.005.30418 (and earlier) are affected by a Use After Free vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.
</code>

- [hacksysteam/CVE-2023-21608](https://github.com/hacksysteam/CVE-2023-21608)

### CVE-2023-21768 (2023-01-10)

<code>Windows Ancillary Function Driver for WinSock Elevation of Privilege Vulnerability
</code>

- [Malwareman007/CVE-2023-21768](https://github.com/Malwareman007/CVE-2023-21768)
- [IlanDudnik/CVE-2023-21768](https://github.com/IlanDudnik/CVE-2023-21768)

### CVE-2023-21839 (2023-01-17)

<code>Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core).  Supported versions that are affected are 12.2.1.3.0, 12.2.1.4.0 and  14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle WebLogic Server.  Successful attacks of this vulnerability can result in  unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).
</code>

- [juniorinter/CVE-2023-21839](https://github.com/juniorinter/CVE-2023-21839)

### CVE-2023-22515 (2023-10-04)

<code>Atlassian has been made aware of an issue reported by a handful of customers where external attackers may have exploited a previously unknown vulnerability in publicly accessible Confluence Data Center and Server instances to create unauthorized Confluence administrator accounts and access Confluence instances. \r\n\r\nAtlassian Cloud sites are not affected by this vulnerability. If your Confluence site is accessed via an atlassian.net domain, it is hosted by Atlassian and is not vulnerable to this issue. 
</code>

- [Onedy1703/CVE-2023-22515-Confluence](https://github.com/Onedy1703/CVE-2023-22515-Confluence)
- [vivigotnotime/CVE-2023-22515-Exploit-Script](https://github.com/vivigotnotime/CVE-2023-22515-Exploit-Script)

### CVE-2023-22527 (2024-01-16)

<code>A template injection vulnerability on older versions of Confluence Data Center and Server allows an unauthenticated attacker to achieve RCE on an affected instance. Customers using an affected version must take immediate action.\n\nMost recent supported versions of Confluence Data Center and Server are not affected by this vulnerability as it was ultimately mitigated during regular version updates. However, Atlassian recommends that customers take care to install the latest version to protect their instances from non-critical vulnerabilities outlined in Atlassian’s January Security Bulletin.
</code>

- [vulncheck-oss/cve-2023-22527](https://github.com/vulncheck-oss/cve-2023-22527)

### CVE-2023-22960 (2023-01-23)

<code>Lexmark products through 2023-01-10 have Improper Control of Interaction Frequency.
</code>

- [t3l3machus/CVE-2023-22960](https://github.com/t3l3machus/CVE-2023-22960)

### CVE-2023-23638 (2023-03-08)

<code>A deserialization vulnerability existed when dubbo generic invoke, which could lead to malicious code execution. \n\nThis issue affects Apache Dubbo 2.7.x version 2.7.21 and prior versions; Apache Dubbo 3.0.x version 3.0.13 and prior versions; Apache Dubbo 3.1.x version 3.1.5 and prior versions. 
</code>

- [X1r0z/Dubbo-RCE](https://github.com/X1r0z/Dubbo-RCE)
- [YYHYlh/Apache-Dubbo-CVE-2023-23638-exp](https://github.com/YYHYlh/Apache-Dubbo-CVE-2023-23638-exp)

### CVE-2023-23752 (2023-02-16)

<code>An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.
</code>

- [Acceis/exploit-CVE-2023-23752](https://github.com/Acceis/exploit-CVE-2023-23752)

### CVE-2023-24278 (2023-03-18)

<code>Squidex before 7.4.0 was discovered to contain a squid.svg cross-site scripting (XSS) vulnerability.
</code>

- [NeCr00/CVE-2023-24278](https://github.com/NeCr00/CVE-2023-24278)

### CVE-2023-24317 (2023-02-23)

<code>Judging Management System 1.0 was discovered to contain an arbitrary file upload vulnerability via the component edit_organizer.php.
</code>

- [angelopioamirante/CVE-2023-24317](https://github.com/angelopioamirante/CVE-2023-24317)

### CVE-2023-24709 (2023-03-21)

<code>An issue found in Paradox Security Systems IPR512 allows attackers to cause a denial of service via the login.html and login.xml parameters.
</code>

- [DRAGOWN/CVE-2023-24709-PoC](https://github.com/DRAGOWN/CVE-2023-24709-PoC)

### CVE-2023-24932 (2023-05-09)

<code>Secure Boot Security Feature Bypass Vulnerability
</code>

- [helleflo1312/Orchestrated-Powershell-for-CVE-2023-24932](https://github.com/helleflo1312/Orchestrated-Powershell-for-CVE-2023-24932)

### CVE-2023-25136 (2023-02-03)

<code>OpenSSH server (sshd) 9.1 introduced a double-free vulnerability during options.kex_algorithms handling. This is fixed in OpenSSH 9.2. The double free can be leveraged, by an unauthenticated remote attacker in the default configuration, to jump to any location in the sshd address space. One third-party report states &quot;remote code execution is theoretically possible.&quot;
</code>

- [mrmtwoj/CVE-2023-25136](https://github.com/mrmtwoj/CVE-2023-25136)

### CVE-2023-25157 (2023-02-21)

<code>GeoServer is an open source software server written in Java that allows users to share and edit geospatial data. GeoServer includes support for the OGC Filter expression language and the OGC Common Query Language (CQL) as part of the Web Feature Service (WFS) and Web Map Service (WMS) protocols.  CQL is also supported through the Web Coverage Service (WCS) protocol for ImageMosaic coverages. Users are advised to upgrade to either version 2.21.4, or version 2.22.2 to resolve this issue. Users unable to upgrade should disable the PostGIS Datastore *encode functions* setting to mitigate ``strEndsWith``, ``strStartsWith`` and ``PropertyIsLike `` misuse and enable the PostGIS DataStore *preparedStatements* setting to mitigate the ``FeatureId`` misuse.
</code>

- [7imbitz/CVE-2023-25157-checker](https://github.com/7imbitz/CVE-2023-25157-checker)

### CVE-2023-25292 (2023-04-27)

<code>Reflected Cross Site Scripting (XSS) in Intermesh BV Group-Office version 6.6.145, allows attackers to gain escalated privileges and gain sensitive information via the GO_LANGUAGE cookie.
</code>

- [brainkok/CVE-2023-25292](https://github.com/brainkok/CVE-2023-25292)

### CVE-2023-25690 (2023-03-07)

<code>Some mod_proxy configurations on Apache HTTP Server versions 2.4.0 through 2.4.55 allow a HTTP Request Smuggling attack.\n\n\n\n\nConfigurations are affected when mod_proxy is enabled along with some form of RewriteRule\n or ProxyPassMatch in which a non-specific pattern matches\n some portion of the user-supplied request-target (URL) data and is then\n re-inserted into the proxied request-target using variable \nsubstitution. For example, something like:\n\n\n\n\nRewriteEngine on\nRewriteRule &quot;^/here/(.*)&quot; &quot;http://example.com:8080/elsewhere?$1&quot;; [P]\nProxyPassReverse /here/ http://example.com:8080/\n\n\nRequest splitting/smuggling could result in bypass of access controls in the proxy server, proxying unintended URLs to existing origin servers, and cache poisoning. Users are recommended to update to at least version 2.4.56 of Apache HTTP Server.
</code>

- [dhmosfunk/CVE-2023-25690-POC](https://github.com/dhmosfunk/CVE-2023-25690-POC)

### CVE-2023-25950 (2023-04-11)

<code>HTTP request/response smuggling vulnerability in HAProxy version 2.7.0, and 2.6.1 to 2.6.7 allows a remote attacker to alter a legitimate user's request. As a result, the attacker may obtain sensitive information or cause a denial-of-service (DoS) condition.
</code>

- [dhmosfunk/HTTP3ONSTEROIDS](https://github.com/dhmosfunk/HTTP3ONSTEROIDS)

### CVE-2023-26049 (2023-04-18)

<code>Jetty is a java based web server and servlet engine. Nonstandard cookie parsing in Jetty may allow an attacker to smuggle cookies within other cookies, or otherwise perform unintended behavior by tampering with the cookie parsing mechanism. If Jetty sees a cookie VALUE that starts with `&quot;` (double quote), it will continue to read the cookie string until it sees a closing quote -- even if a semicolon is encountered. So, a cookie header such as: `DISPLAY_LANGUAGE=&quot;b; JSESSIONID=1337; c=d&quot;` will be parsed as one cookie, with the name DISPLAY_LANGUAGE and a value of b; JSESSIONID=1337; c=d instead of 3 separate cookies. This has security implications because if, say, JSESSIONID is an HttpOnly cookie, and the DISPLAY_LANGUAGE cookie value is rendered on the page, an attacker can smuggle the JSESSIONID cookie into the DISPLAY_LANGUAGE cookie and thereby exfiltrate it. This is significant when an intermediary is enacting some policy based on cookies, so a smuggled cookie can bypass that policy yet still be seen by the Jetty server or its logging system. This issue has been addressed in versions 9.4.51, 10.0.14, 11.0.14, and 12.0.0.beta0 and users are advised to upgrade. There are no known workarounds for this issue.
</code>

- [nidhihcl75/jetty-9.4.31.v20200723_G3_CVE-2023-26049](https://github.com/nidhihcl75/jetty-9.4.31.v20200723_G3_CVE-2023-26049)

### CVE-2023-26136 (2023-07-01)

<code>Versions of the package tough-cookie before 4.1.3 are vulnerable to Prototype Pollution due to improper handling of Cookies when using CookieJar in rejectPublicSuffixes=false mode. This issue arises from the manner in which the objects are initialized.
</code>

- [dani33339/Tough-Cookie-v2.5.0-Patched](https://github.com/dani33339/Tough-Cookie-v2.5.0-Patched)
- [morrisel/CVE-2023-26136](https://github.com/morrisel/CVE-2023-26136)

### CVE-2023-26144 (2023-09-20)

<code>Versions of the package graphql from 16.3.0 and before 16.8.1 are vulnerable to Denial of Service (DoS) due to insufficient checks in the OverlappingFieldsCanBeMergedRule.ts file when parsing large queries. This vulnerability allows an attacker to degrade system performance.\r\r**Note:** It was not proven that this vulnerability can crash the process.
</code>

- [tadhglewis/apollo-koa-minimal](https://github.com/tadhglewis/apollo-koa-minimal)

### CVE-2023-26258 (2023-07-03)

<code>Arcserve UDP through 9.0.6034 allows authentication bypass. The method getVersionInfo at WebServiceImpl/services/FlashServiceImpl leaks the AuthUUID token. This token can be used at /WebServiceImpl/services/VirtualStandbyServiceImpl to obtain a valid session. This session can be used to execute any task as administrator.
</code>

- [mdsecactivebreach/CVE-2023-26258-ArcServe](https://github.com/mdsecactivebreach/CVE-2023-26258-ArcServe)

### CVE-2023-26326 (2023-02-23)

<code>The BuddyForms WordPress plugin, in versions prior to 2.7.8, was affected by an unauthenticated insecure deserialization issue. An unauthenticated attacker could leverage this issue to call files using a PHAR wrapper that will deserialize the data and call arbitrary PHP Objects that can be used to perform a variety of malicious actions granted a POP chain is also present.
</code>

- [omarelshopky/exploit_cve-2023-26326_using_cve-2024-2961](https://github.com/omarelshopky/exploit_cve-2023-26326_using_cve-2024-2961)
- [mesudmammad1/CVE-2023-26326_Buddyform_exploit](https://github.com/mesudmammad1/CVE-2023-26326_Buddyform_exploit)

### CVE-2023-26818 (2023-05-19)

<code>Telegram 9.3.1 and 9.4.0 allows attackers to access restricted files, microphone ,or video recording via the DYLD_INSERT_LIBRARIES flag.
</code>

- [Zeyad-Azima/CVE-2023-26818](https://github.com/Zeyad-Azima/CVE-2023-26818)

### CVE-2023-26976 (2023-04-04)

<code>Tenda AC6 v15.03.05.09_multi was discovered to contain a stack overflow via the ssid parameter in the form_fast_setting_wifi_set function.
</code>

- [FzBacon/CVE-2023-26976_tenda_AC6_stack_overflow](https://github.com/FzBacon/CVE-2023-26976_tenda_AC6_stack_overflow)

### CVE-2023-27326 (2024-05-03)

<code>Parallels Desktop Toolgate Directory Traversal Local Privilege Escalation Vulnerability. This vulnerability allows local attackers to escalate privileges on affected installations of Parallels Desktop. An attacker must first obtain the ability to execute high-privileged code on the target guest system in order to exploit this vulnerability.\n\nThe specific flaw exists within the Toolgate component. The issue results from the lack of proper validation of a user-supplied path prior to using it in file operations. An attacker can leverage this vulnerability to escalate privileges and execute arbitrary code in the context of the current user on the host system.\n. Was ZDI-CAN-18933.
</code>

- [Impalabs/CVE-2023-27326](https://github.com/Impalabs/CVE-2023-27326)

### CVE-2023-27350 (2023-04-20)

<code>This vulnerability allows remote attackers to bypass authentication on affected installations of PaperCut NG 22.0.5 (Build 63914). Authentication is not required to exploit this vulnerability. The specific flaw exists within the SetupCompleted class. The issue results from improper access control. An attacker can leverage this vulnerability to bypass authentication and execute arbitrary code in the context of SYSTEM. Was ZDI-CAN-18987.
</code>

- [imancybersecurity/CVE-2023-27350-POC](https://github.com/imancybersecurity/CVE-2023-27350-POC)

### CVE-2023-27363 (2024-05-03)

<code>Foxit PDF Reader exportXFAData Exposed Dangerous Method Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Foxit PDF Reader. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.\n\nThe specific flaw exists within the exportXFAData method. The application exposes a JavaScript interface that allows writing arbitrary files. An attacker can leverage this vulnerability to execute code in the context of the current user. Was ZDI-CAN-19697.
</code>

- [qwqdanchun/CVE-2023-27363](https://github.com/qwqdanchun/CVE-2023-27363)

### CVE-2023-27372 (2023-02-28)

<code>SPIP before 4.2.1 allows Remote Code Execution via form values in the public area because serialization is mishandled. The fixed versions are 3.2.18, 4.0.10, 4.1.8, and 4.2.1.
</code>

- [nuts7/CVE-2023-27372](https://github.com/nuts7/CVE-2023-27372)
- [Chocapikk/CVE-2023-27372](https://github.com/Chocapikk/CVE-2023-27372)
- [dream434/CVE-2023-27372](https://github.com/dream434/CVE-2023-27372)

### CVE-2023-27524 (2023-04-24)

<code>Session Validation attacks in Apache Superset versions up to and including 2.0.1. Installations that have not altered the default configured SECRET_KEY according to installation instructions allow for an attacker to authenticate and access unauthorized resources. This does not affect Superset administrators who have changed the default value for SECRET_KEY config.\n\nAll superset installations should always set a unique secure random SECRET_KEY. Your SECRET_KEY is used to securely sign all session cookies and encrypting sensitive information on the database.\nAdd a strong SECRET_KEY to your `superset_config.py` file like:\n\nSECRET_KEY = &lt;YOUR_OWN_RANDOM_GENERATED_SECRET_KEY&gt;\n\nAlternatively you can set it with `SUPERSET_SECRET_KEY` environment variable.\n
</code>

- [horizon3ai/CVE-2023-27524](https://github.com/horizon3ai/CVE-2023-27524)

### CVE-2023-27566 (2023-03-03)

<code>Cubism Core in Live2D Cubism Editor 4.2.03 allows out-of-bounds write via a crafted Section Offset Table or Count Info Table in an MOC3 file.
</code>

- [OpenL2D/moc3ingbird](https://github.com/OpenL2D/moc3ingbird)

### CVE-2023-27746 (2023-04-13)

<code>BlackVue DR750-2CH LTE v.1.012_2022.10.26 was discovered to contain a weak default passphrase which can be easily cracked via a brute force attack if the WPA2 handshake is intercepted.
</code>

- [eyJhb/blackvue-cve-2023](https://github.com/eyJhb/blackvue-cve-2023)

### CVE-2023-27997 (2023-06-13)

<code>A heap-based buffer overflow vulnerability [CWE-122] in FortiOS version 7.2.4 and below, version 7.0.11 and below, version 6.4.12 and below, version 6.0.16 and below and FortiProxy version 7.2.3 and below, version 7.0.9 and below, version 2.0.12 and below, version 1.2 all versions, version 1.1 all versions SSL-VPN may allow a remote attacker to execute arbitrary code or commands via specifically crafted requests.
</code>

- [BishopFox/CVE-2023-27997-check](https://github.com/BishopFox/CVE-2023-27997-check)

### CVE-2023-28121 (2023-04-12)

<code>An issue in WooCommerce Payments plugin for WordPress (versions 5.6.1 and lower) allows an unauthenticated attacker to send requests on behalf of an elevated user, like administrator. This allows a remote, unauthenticated attacker to gain admin access on a site that has the affected version of the plugin activated.
</code>

- [sug4r-wr41th/CVE-2023-28121](https://github.com/sug4r-wr41th/CVE-2023-28121)

### CVE-2023-28229 (2023-04-11)

<code>Windows CNG Key Isolation Service Elevation of Privilege Vulnerability
</code>

- [Y3A/CVE-2023-28229](https://github.com/Y3A/CVE-2023-28229)

### CVE-2023-28293 (2023-04-11)

<code>Windows Kernel Elevation of Privilege Vulnerability
</code>

- [CrazyDaveX86/CVE-2023-28293](https://github.com/CrazyDaveX86/CVE-2023-28293)

### CVE-2023-28432 (2023-03-22)

<code>Minio is a Multi-Cloud Object Storage framework. In a cluster deployment starting with RELEASE.2019-12-17T23-16-33Z and prior to RELEASE.2023-03-20T20-16-18Z, MinIO returns all environment variables, including `MINIO_SECRET_KEY`\nand `MINIO_ROOT_PASSWORD`, resulting in information disclosure. All users of distributed deployment are impacted. All users are advised to upgrade to RELEASE.2023-03-20T20-16-18Z.
</code>

- [BitWiz4rd/CVE-2023-28432](https://github.com/BitWiz4rd/CVE-2023-28432)

### CVE-2023-29357 (2023-06-13)

<code>Microsoft SharePoint Server Elevation of Privilege Vulnerability
</code>

- [LuemmelSec/CVE-2023-29357](https://github.com/LuemmelSec/CVE-2023-29357)

### CVE-2023-29360 (2023-06-13)

<code>Microsoft Streaming Service Elevation of Privilege Vulnerability
</code>

- [Nero22k/cve-2023-29360](https://github.com/Nero22k/cve-2023-29360)

### CVE-2023-29478 (2023-04-07)

<code>BiblioCraft before 2.4.6 does not sanitize path-traversal characters in filenames, allowing restricted write access to almost anywhere on the filesystem. This includes the Minecraft mods folder, which results in code execution.
</code>

- [Exopteron/BiblioRCE](https://github.com/Exopteron/BiblioRCE)

### CVE-2023-29489 (2023-04-27)

<code>An issue was discovered in cPanel before 11.109.9999.116. XSS can occur on the cpsrvd error page via an invalid webcall ID, aka SEC-669. The fixed versions are 11.109.9999.116, 11.108.0.13, 11.106.0.18, and 11.102.0.31.
</code>

- [0-d3y/CVE-2023-29489](https://github.com/0-d3y/CVE-2023-29489)
- [Abdullah7-ma/CVE-2023-29489](https://github.com/Abdullah7-ma/CVE-2023-29489)

### CVE-2023-29929 (2024-08-21)

<code>Buffer Overflow vulnerability found in Kemptechnologies Loadmaster before v.7.2.60.0 allows a remote attacker to casue a denial of service via the libkemplink.so, isreverse library.
</code>

- [YSaxon/CVE-2023-29929](https://github.com/YSaxon/CVE-2023-29929)

### CVE-2023-30367 (2023-07-26)

<code>Multi-Remote Next Generation Connection Manager (mRemoteNG) is free software that enables users to store and manage multi-protocol connection configurations to remotely connect to systems. mRemoteNG configuration files can be stored in an encrypted state on disk. mRemoteNG version &lt;= v1.76.20 and &lt;= 1.77.3-dev loads configuration files in plain text into memory (after decrypting them if necessary) at application start-up, even if no connection has been established yet. This allows attackers to access contents of configuration files in plain text through a memory dump and thus compromise user credentials when no custom password encryption key has been set. This also bypasses the connection configuration file encryption setting by dumping already decrypted configurations from memory.
</code>

- [S1lkys/CVE-2023-30367-mRemoteNG-password-dumper](https://github.com/S1lkys/CVE-2023-30367-mRemoteNG-password-dumper)

### CVE-2023-30943 (2023-05-02)

<code>The vulnerability was found Moodle which exists because the application allows a user to control path of the older to create in TinyMCE loaders. A remote user can send a specially crafted HTTP request and create arbitrary folders on the system.
</code>

- [d0rb/CVE-2023-30943](https://github.com/d0rb/CVE-2023-30943)

### CVE-2023-31320 (2023-11-14)

<code>Improper input validation in the AMD RadeonTM Graphics display driver may allow an attacker to corrupt the display potentially resulting in denial of service.\n\n\n\n\n\n\n\n\n\n\n\n\n
</code>

- [whypet/CVE-2023-31320](https://github.com/whypet/CVE-2023-31320)

### CVE-2023-31497 (2023-05-11)

<code>Incorrect access control in Quick Heal Technologies Limited Seqrite Endpoint Security (EPS) all versions prior to v8.0 allows attackers to escalate privileges to root via supplying a crafted binary to the target system.
</code>

- [0xInfection/EPScalate](https://github.com/0xInfection/EPScalate)

### CVE-2023-31714 (2023-08-30)

<code>Chitor-CMS before v1.1.2 was discovered to contain multiple SQL injection vulnerabilities.
</code>

- [msd0pe-1/CVE-2023-31714](https://github.com/msd0pe-1/CVE-2023-31714)

### CVE-2023-32243 (2023-05-12)

<code>Improper Authentication vulnerability in WPDeveloper Essential Addons for Elementor allows Privilege Escalation. This issue affects Essential Addons for Elementor: from 5.4.0 through 5.7.1.
</code>

- [Jenderal92/WP-CVE-2023-32243](https://github.com/Jenderal92/WP-CVE-2023-32243)

### CVE-2023-32315 (2023-05-26)

<code>Openfire is an XMPP server licensed under the Open Source Apache License. Openfire's administrative console, a web-based application, was found to be vulnerable to a path traversal attack via the setup environment. This permitted an unauthenticated user to use the unauthenticated Openfire Setup Environment in an already configured Openfire environment to access restricted pages in the Openfire Admin Console reserved for administrative users. This vulnerability affects all versions of Openfire that have been released since April 2015, starting with version 3.10.0. The problem has been patched in Openfire release 4.7.5 and 4.6.8, and further improvements will be included in the yet-to-be released first version on the 4.8 branch (which is expected to be version 4.8.0). Users are advised to upgrade. If an Openfire upgrade isn’t available for a specific release, or isn’t quickly actionable, users may see the linked github advisory (GHSA-gw42-f939-fhvm) for mitigation advice.
</code>

- [miko550/CVE-2023-32315](https://github.com/miko550/CVE-2023-32315)
- [asepsaepdin/CVE-2023-32315](https://github.com/asepsaepdin/CVE-2023-32315)

### CVE-2023-32434 (2023-06-23)

<code>An integer overflow was addressed with improved input validation. This issue is fixed in watchOS 9.5.2, macOS Big Sur 11.7.8, iOS 15.7.7 and iPadOS 15.7.7, macOS Monterey 12.6.7, watchOS 8.8.1, iOS 16.5.1 and iPadOS 16.5.1, macOS Ventura 13.4.1. An app may be able to execute arbitrary code with kernel privileges. Apple is aware of a report that this issue may have been actively exploited against versions of iOS released before iOS 15.7.
</code>

- [alfiecg24/Trigon](https://github.com/alfiecg24/Trigon)

### CVE-2023-32590 (2023-12-20)

<code>Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Daniel Söderström / Sidney van de Stouwe Subscribe to Category.This issue affects Subscribe to Category: from n/a through 2.7.4.\n\n
</code>

- [RandomRobbieBF/CVE-2023-32590](https://github.com/RandomRobbieBF/CVE-2023-32590)

### CVE-2023-32629 (2023-07-26)

<code>Local privilege escalation vulnerability in Ubuntu Kernels overlayfs ovl_copy_up_meta_inode_data skip permission checks when calling ovl_do_setxattr on Ubuntu kernels
</code>

- [kaotickj/Check-for-CVE-2023-32629-GameOver-lay](https://github.com/kaotickj/Check-for-CVE-2023-32629-GameOver-lay)

### CVE-2023-32784 (2023-05-15)

<code>In KeePass 2.x before 2.54, it is possible to recover the cleartext master password from a memory dump, even when a workspace is locked or no longer running. The memory dump can be a KeePass process dump, swap file (pagefile.sys), hibernation file (hiberfil.sys), or RAM dump of the entire system. The first character cannot be recovered. In 2.54, there is different API usage and/or random string insertion for mitigation.
</code>

- [vdohney/keepass-password-dumper](https://github.com/vdohney/keepass-password-dumper)
- [CTM1/CVE-2023-32784-keepass-linux](https://github.com/CTM1/CVE-2023-32784-keepass-linux)
- [z-jxy/keepass_dump](https://github.com/z-jxy/keepass_dump)

### CVE-2023-33246 (2023-05-24)

<code>For RocketMQ versions 5.1.0 and below, under certain conditions, there is a risk of remote command execution. \n\nSeveral components of RocketMQ, including NameServer, Broker, and Controller, are leaked on the extranet and lack permission verification, an attacker can exploit this vulnerability by using the update configuration function to execute commands as the system users that RocketMQ is running as. Additionally, an attacker can achieve the same effect by forging the RocketMQ protocol content. \n\nTo prevent these attacks, users are recommended to upgrade to version 5.1.1 or above for using RocketMQ 5.x or 4.9.6 or above for using RocketMQ 4.x .
</code>

- [vulncheck-oss/fetch-broker-conf](https://github.com/vulncheck-oss/fetch-broker-conf)

### CVE-2023-33580 (2023-06-26)

<code>Phpgurukul Student Study Center Management System V1.0 is vulnerable to Cross Site Scripting (XSS) in the &quot;Admin Name&quot; field on Admin Profile page.
</code>

- [sudovivek/Published-CVE](https://github.com/sudovivek/Published-CVE)

### CVE-2023-33669 (2023-06-02)

<code>Tenda AC8V4.0-V16.03.34.06 was discovered to contain a stack overflow via the timeZone parameter in the sub_44db3c function.
</code>

- [retr0reg/tenda-ac8v4-rop](https://github.com/retr0reg/tenda-ac8v4-rop)

### CVE-2023-33733 (2023-06-05)

<code>Reportlab up to v3.6.12 allows attackers to execute arbitrary code via supplying a crafted PDF file.
</code>

- [c53elyas/CVE-2023-33733](https://github.com/c53elyas/CVE-2023-33733)

### CVE-2023-33831 (2023-09-18)

<code>A remote command execution (RCE) vulnerability in the /api/runscript endpoint of FUXA 1.1.13 allows attackers to execute arbitrary commands via a crafted POST request.
</code>

- [rodolfomarianocy/Unauthenticated-RCE-FUXA-CVE-2023-33831](https://github.com/rodolfomarianocy/Unauthenticated-RCE-FUXA-CVE-2023-33831)

### CVE-2023-33977 (2023-06-06)

<code>Kiwi TCMS is an open source test management system for both manual and automated testing. Kiwi TCMS allows users to upload attachments to test plans, test cases, etc. Earlier versions of Kiwi TCMS had introduced upload validators in order to prevent potentially dangerous files from being uploaded and Content-Security-Policy definition to prevent cross-site-scripting attacks. The upload validation checks were not 100% robust which left the possibility to circumvent them and upload a potentially dangerous file which allows execution of arbitrary JavaScript in the browser. Additionally we've discovered that Nginx's `proxy_pass` directive will strip some headers negating protections built into Kiwi TCMS when served behind a reverse proxy. This issue has been addressed in version 12.4. Users are advised to upgrade. Users unable to upgrade who are serving Kiwi TCMS behind a reverse proxy should make sure that additional header values are still passed to the client browser. If they aren't redefining them inside the proxy configuration.
</code>

- [mnqazi/CVE-2023-33977](https://github.com/mnqazi/CVE-2023-33977)

### CVE-2023-34040 (2023-08-24)

<code>In Spring for Apache Kafka 3.0.9 and earlier and versions 2.9.10 and earlier, a possible deserialization attack vector existed, but only if unusual configuration was applied. An attacker would have to construct a malicious serialized object in one of the deserialization exception record headers.\n\nSpecifically, an application is vulnerable when all of the following are true:\n\n  *  The user does not configure an ErrorHandlingDeserializer for the key and/or value of the record\n  *  The user explicitly sets container properties checkDeserExWhenKeyNull and/or checkDeserExWhenValueNull container properties to true.\n  *  The user allows untrusted sources to publish to a Kafka topic\n\n\nBy default, these properties are false, and the container only attempts to deserialize the headers if an ErrorHandlingDeserializer is configured. The ErrorHandlingDeserializer prevents the vulnerability by removing any such malicious headers before processing the record.\n\n\n
</code>

- [pyn3rd/CVE-2023-34040](https://github.com/pyn3rd/CVE-2023-34040)

### CVE-2023-34362 (2023-06-02)

<code>In Progress MOVEit Transfer before 2021.0.6 (13.0.6), 2021.1.4 (13.1.4), 2022.0.4 (14.0.4), 2022.1.5 (14.1.5), and 2023.0.1 (15.0.1), a SQL injection vulnerability has been found in the MOVEit Transfer web application that could allow an unauthenticated attacker to gain access to MOVEit Transfer's database. Depending on the database engine being used (MySQL, Microsoft SQL Server, or Azure SQL), an attacker may be able to infer information about the structure and contents of the database, and execute SQL statements that alter or delete database elements. NOTE: this is exploited in the wild in May and June 2023; exploitation of unpatched systems can occur via HTTP or HTTPS. All versions (e.g., 2020.0 and 2019x) before the five explicitly mentioned versions are affected, including older unsupported versions.
</code>

- [sfewer-r7/CVE-2023-34362](https://github.com/sfewer-r7/CVE-2023-34362)

### CVE-2023-34537 (2023-06-13)

<code>A Reflected XSS was discovered in HotelDruid version 3.0.5, an attacker can issue malicious code/command on affected webpage's parameter to trick user on browser and/or exfiltrate data.
</code>

- [leekenghwa/CVE-2023-34537---XSS-reflected--found-in-HotelDruid-3.0.5](https://github.com/leekenghwa/CVE-2023-34537---XSS-reflected--found-in-HotelDruid-3.0.5)

### CVE-2023-34600 (2023-06-20)

<code>Adiscon LogAnalyzer v4.1.13 and before is vulnerable to SQL Injection.
</code>

- [costacoco/Adiscon](https://github.com/costacoco/Adiscon)

### CVE-2023-34960 (2023-08-01)

<code>A command injection vulnerability in the wsConvertPpt component of Chamilo v1.11.* up to v1.11.18 allows attackers to execute arbitrary commands via a SOAP API call with a crafted PowerPoint name.
</code>

- [Jenderal92/CHAMILO-CVE-2023-34960](https://github.com/Jenderal92/CHAMILO-CVE-2023-34960)

### CVE-2023-35001 (2023-07-05)

<code>Linux Kernel nftables Out-Of-Bounds Read/Write Vulnerability; nft_byteorder poorly handled vm register contents when CAP_NET_ADMIN is in any user or network namespace
</code>

- [synacktiv/CVE-2023-35001](https://github.com/synacktiv/CVE-2023-35001)

### CVE-2023-35078 (2023-07-25)

<code>An authentication bypass vulnerability in Ivanti EPMM allows unauthorized users to access restricted functionality or resources of the application without proper authentication.
</code>

- [0nsec/CVE-2023-35078](https://github.com/0nsec/CVE-2023-35078)

### CVE-2023-35671 (2023-09-11)

<code>In onHostEmulationData of HostEmulationManager.java, there is a possible way for a general purpose NFC reader to read the full card number and expiry details when the device is in locked screen mode due to a logic error in the code. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.
</code>

- [MrTiz/CVE-2023-35671](https://github.com/MrTiz/CVE-2023-35671)

### CVE-2023-36123 (2023-10-06)

<code>Directory Traversal vulnerability in Hex-Dragon Plain Craft Launcher 2 version Alpha 1.3.9, allows local attackers to execute arbitrary code and gain sensitive information.
</code>

- [9Bakabaka/CVE-2023-36123](https://github.com/9Bakabaka/CVE-2023-36123)

### CVE-2023-36723 (2023-10-10)

<code>Windows Container Manager Service Elevation of Privilege Vulnerability
</code>

- [Wh04m1001/CVE-2023-36723](https://github.com/Wh04m1001/CVE-2023-36723)

### CVE-2023-36845 (2023-08-17)

<code>A PHP External Variable Modification vulnerability in J-Web of Juniper Networks Junos OS on EX Series \n\nand SRX Series \n\nallows an unauthenticated, network-based attacker to remotely execute code.\n\nUsing a crafted request which sets the variable PHPRC an attacker is able to modify the PHP execution environment allowing the injection und execution of code.\n\n\nThis issue affects Juniper Networks Junos OS on EX Series\n\n\nand \n\n\nSRX Series:\n\n\n\n  *  All versions prior to \n\n20.4R3-S9;\n  *  21.1 versions 21.1R1 and later;\n  *  21.2 versions prior to 21.2R3-S7;\n  *  21.3 versions prior to 21.3R3-S5;\n  *  21.4 versions prior to 21.4R3-S5;\n  *  22.1 versions \n\nprior to \n\n22.1R3-S4;\n  *  22.2 versions \n\nprior to \n\n22.2R3-S2;\n  *  22.3 versions \n\nprior to \n\n22.3R2-S2, 22.3R3-S1;\n  *  22.4 versions \n\nprior to \n\n22.4R2-S1, 22.4R3;\n  *  23.2 versions prior to 23.2R1-S1, 23.2R2.
</code>

- [vulncheck-oss/cve-2023-36845-scanner](https://github.com/vulncheck-oss/cve-2023-36845-scanner)
- [kljunowsky/CVE-2023-36845](https://github.com/kljunowsky/CVE-2023-36845)
- [zaenhaxor/CVE-2023-36845](https://github.com/zaenhaxor/CVE-2023-36845)

### CVE-2023-36874 (2023-07-11)

<code>Windows Error Reporting Service Elevation of Privilege Vulnerability
</code>

- [d0rb/CVE-2023-36874](https://github.com/d0rb/CVE-2023-36874)

### CVE-2023-36884 (2023-07-11)

<code>Windows Search Remote Code Execution Vulnerability
</code>

- [jakabakos/CVE-2023-36884-MS-Office-HTML-RCE](https://github.com/jakabakos/CVE-2023-36884-MS-Office-HTML-RCE)

### CVE-2023-37250 (2023-08-20)

<code>Unity Parsec has a TOCTOU race condition that permits local attackers to escalate privileges to SYSTEM if Parsec was installed in &quot;Per User&quot; mode. The application intentionally launches DLLs from a user-owned directory but intended to always perform integrity verification of those DLLs. This affects Parsec Loader versions through 8. Parsec Loader 9 is a fixed version.
</code>

- [ewilded/CVE-2023-37250-POC](https://github.com/ewilded/CVE-2023-37250-POC)

### CVE-2023-37456 (2023-07-12)

<code>The session restore helper crashed whenever there was no parameter sent to the message handler. This vulnerability affects Firefox for iOS &lt; 115.
</code>

- [SpiralBL0CK/cve-2023-37456](https://github.com/SpiralBL0CK/cve-2023-37456)

### CVE-2023-37621
- [MY0723/CNVD-2022-27366__CVE-2023-37621](https://github.com/MY0723/CNVD-2022-27366__CVE-2023-37621)

### CVE-2023-38408 (2023-07-20)

<code>The PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2 has an insufficiently trustworthy search path, leading to remote code execution if an agent is forwarded to an attacker-controlled system. (Code in /usr/lib is not necessarily safe for loading into ssh-agent.) NOTE: this issue exists because of an incomplete fix for CVE-2016-10009.
</code>

- [kali-mx/CVE-2023-38408](https://github.com/kali-mx/CVE-2023-38408)
- [wxrdnx/CVE-2023-38408](https://github.com/wxrdnx/CVE-2023-38408)

### CVE-2023-38646 (2023-07-21)

<code>Metabase open source before 0.46.6.1 and Metabase Enterprise before 1.46.6.1 allow attackers to execute arbitrary commands on the server, at the server's privilege level. Authentication is not required for exploitation. The other fixed versions are 0.45.4.1, 1.45.4.1, 0.44.7.1, 1.44.7.1, 0.43.7.2, and 1.43.7.2.
</code>

- [securezeron/CVE-2023-38646](https://github.com/securezeron/CVE-2023-38646)
- [Zenmovie/CVE-2023-38646](https://github.com/Zenmovie/CVE-2023-38646)

### CVE-2023-38829 (2023-09-11)

<code>An issue in NETIS SYSTEMS WF2409E v.3.6.42541 allows a remote attacker to execute arbitrary code via the ping and traceroute functions of the diagnostic tools component in the admin management interface.
</code>

- [Victorique-123/CVE-2023-38829-NETIS-WF2409E_Report](https://github.com/Victorique-123/CVE-2023-38829-NETIS-WF2409E_Report)

### CVE-2023-38831 (2023-08-23)

<code>RARLAB WinRAR before 6.23 allows attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive. The issue occurs because a ZIP archive may include a benign file (such as an ordinary .JPG file) and also a folder that has the same name as the benign file, and the contents of the folder (which may include executable content) are processed during an attempt to access only the benign file. This was exploited in the wild in April through October 2023.
</code>

- [b1tg/CVE-2023-38831-winrar-exploit](https://github.com/b1tg/CVE-2023-38831-winrar-exploit)
- [HDCE-inc/CVE-2023-38831](https://github.com/HDCE-inc/CVE-2023-38831)
- [RonF98/CVE-2023-38831-POC](https://github.com/RonF98/CVE-2023-38831-POC)
- [VictoriousKnight/CVE-2023-38831_Exploit](https://github.com/VictoriousKnight/CVE-2023-38831_Exploit)
- [kuyrathdaro/winrar-cve-2023-38831](https://github.com/kuyrathdaro/winrar-cve-2023-38831)

### CVE-2023-38836 (2023-08-21)

<code>File Upload vulnerability in BoidCMS v.2.0.0 allows a remote attacker to execute arbitrary code by adding a GIF header to bypass MIME type checks.
</code>

- [1337kid/CVE-2023-38836](https://github.com/1337kid/CVE-2023-38836)

### CVE-2023-38840 (2023-08-15)

<code>Bitwarden Desktop 2023.7.0 and below allows an attacker with local access to obtain sensitive information via the Bitwarden.exe process.
</code>

- [markuta/bw-dump](https://github.com/markuta/bw-dump)

### CVE-2023-39362 (2023-09-05)

<code>Cacti is an open source operational monitoring and fault management framework. In Cacti 1.2.24, under certain conditions, an authenticated privileged user, can use a malicious string in the SNMP options of a Device, performing command injection and obtaining remote code execution on the underlying server. The `lib/snmp.php` file has a set of functions, with similar behavior, that accept in input some variables and place them into an `exec` call without a proper escape or validation. This issue has been addressed in version 1.2.25. Users are advised to upgrade. There are no known workarounds for this vulnerability.
</code>

- [m3ssap0/cacti-rce-snmp-options-vulnerable-application](https://github.com/m3ssap0/cacti-rce-snmp-options-vulnerable-application)

### CVE-2023-39593 (2024-10-17)

<code>Insecure permissions in the sys_exec function of MariaDB v10.5 allows authenticated attackers to execute arbitrary commands with elevated privileges. NOTE: this is disputed by the MariaDB Foundation because no privilege boundary is crossed.
</code>

- [Ant1sec-ops/CVE-2023-39593](https://github.com/Ant1sec-ops/CVE-2023-39593)

### CVE-2023-40028 (2023-08-15)

<code>Ghost is an open source content management system. Versions prior to 5.59.1 are subject to a vulnerability which allows authenticated users to upload files that are symlinks. This can be exploited to perform an arbitrary file read of any file on the host operating system. Site administrators can check for exploitation of this issue by looking for unknown symlinks within Ghost's `content/` folder. Version 5.59.1 contains a fix for this issue. All users are advised to upgrade. There are no known workarounds for this vulnerability.
</code>

- [0xDTC/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028](https://github.com/0xDTC/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028)
- [monke443/CVE-2023-40028-Ghost-Arbitrary-File-Read](https://github.com/monke443/CVE-2023-40028-Ghost-Arbitrary-File-Read)
- [rvizx/CVE-2023-40028](https://github.com/rvizx/CVE-2023-40028)
- [godylockz/CVE-2023-40028](https://github.com/godylockz/CVE-2023-40028)
- [rehan6658/CVE-2023-40028](https://github.com/rehan6658/CVE-2023-40028)

### CVE-2023-40029 (2023-09-07)

<code>Argo CD is a declarative continuous deployment for Kubernetes. Argo CD Cluster secrets might be managed declaratively using Argo CD / kubectl apply. As a result, the full secret body is stored in`kubectl.kubernetes.io/last-applied-configuration` annotation. pull request #7139 introduced the ability to manage cluster labels and annotations. Since clusters are stored as secrets it also exposes the `kubectl.kubernetes.io/last-applied-configuration` annotation which includes full secret body. In order to view the cluster annotations via the Argo CD API, the user must have `clusters, get` RBAC access. **Note:** In many cases, cluster secrets do not contain any actually-secret information. But sometimes, as in bearer-token auth, the contents might be very sensitive. The bug has been patched in versions 2.8.3, 2.7.14, and 2.6.15. Users are advised to upgrade. Users unable to upgrade should update/deploy cluster secret with `server-side-apply` flag which does not use or rely on `kubectl.kubernetes.io/last-applied-configuration` annotation. Note: annotation for existing secrets will require manual removal.\n\n
</code>

- [guobei233/CVE-2023-40029](https://github.com/guobei233/CVE-2023-40029)

### CVE-2023-40167 (2023-09-15)

<code>Jetty is a Java based web server and servlet engine. Prior to versions 9.4.52, 10.0.16, 11.0.16, and 12.0.1, Jetty accepts the `+` character proceeding the content-length value in a HTTP/1 header field.  This is more permissive than allowed by the RFC and other servers routinely reject such requests with 400 responses.  There is no known exploit scenario, but it is conceivable that request smuggling could result if jetty is used in combination with a server that does not close the connection after sending such a 400 response. Versions 9.4.52, 10.0.16, 11.0.16, and 12.0.1 contain a patch for this issue. There is no workaround as there is no known exploit scenario.
</code>

- [uthrasri/Jetty-v9.4.31_CVE-2023-40167](https://github.com/uthrasri/Jetty-v9.4.31_CVE-2023-40167)

### CVE-2023-40297 (2024-05-15)

<code>Stakater Forecastle 1.0.139 and before allows %5C../ directory traversal in the website component.
</code>

- [sahar042/CVE-2023-40297](https://github.com/sahar042/CVE-2023-40297)

### CVE-2023-40362 (2024-01-12)

<code>An issue was discovered in CentralSquare Click2Gov Building Permit before October 2023. Lack of access control protections allows remote attackers to arbitrarily delete the contractors from any user's account when the user ID and contractor information is known.
</code>

- [ally-petitt/CVE-2023-40362](https://github.com/ally-petitt/CVE-2023-40362)

### CVE-2023-40448 (2023-09-26)

<code>The issue was addressed with improved handling of protocols. This issue is fixed in tvOS 17, iOS 16.7 and iPadOS 16.7, watchOS 10, iOS 17 and iPadOS 17, macOS Sonoma 14. A remote attacker may be able to break out of Web Content sandbox.
</code>

- [w0wbox/CVE-2023-40448](https://github.com/w0wbox/CVE-2023-40448)

### CVE-2023-40931 (2023-09-19)

<code>A SQL injection vulnerability in Nagios XI from version 5.11.0 up to and including 5.11.1 allows authenticated attackers to execute arbitrary SQL commands via the ID parameter in the POST request to /nagiosxi/admin/banner_message-ajaxhelper.php
</code>

- [datboi6942/Nagios-XI-s-CVE-2023-40931-Exploit](https://github.com/datboi6942/Nagios-XI-s-CVE-2023-40931-Exploit)

### CVE-2023-41425 (2023-11-07)

<code>Cross Site Scripting vulnerability in Wonder CMS v.3.2.0 thru v.3.4.2 allows a remote attacker to execute arbitrary code via a crafted script uploaded to the installModule component.
</code>

- [0xDTC/WonderCMS-4.3.2-XSS-to-RCE-Exploits-CVE-2023-41425](https://github.com/0xDTC/WonderCMS-4.3.2-XSS-to-RCE-Exploits-CVE-2023-41425)
- [Diegomjx/CVE-2023-41425-WonderCMS-Authenticated-RCE](https://github.com/Diegomjx/CVE-2023-41425-WonderCMS-Authenticated-RCE)
- [xpltive/CVE-2023-41425](https://github.com/xpltive/CVE-2023-41425)
- [KGorbakon/CVE-2023-41425](https://github.com/KGorbakon/CVE-2023-41425)

### CVE-2023-42442 (2023-09-15)

<code>JumpServer is an open source bastion host and a professional operation and maintenance security audit system. Starting in version 3.0.0 and prior to versions 3.5.5 and 3.6.4, session replays can download without authentication. Session replays stored in S3, OSS, or other cloud storage are not affected. The api `/api/v1/terminal/sessions/` permission control is broken and can be accessed anonymously. SessionViewSet permission classes set to `[RBACPermission | IsSessionAssignee]`, relation is or, so any permission matched will be allowed. Versions 3.5.5 and 3.6.4 have a fix. After upgrading, visit the api `$HOST/api/v1/terminal/sessions/?limit=1`. The expected http response code is 401 (`not_authenticated`).\n
</code>

- [HolyGu/CVE-2023-42442](https://github.com/HolyGu/CVE-2023-42442)

### CVE-2023-42468 (2023-09-13)

<code>The com.cutestudio.colordialer application through 2.1.8-2 for Android allows a remote attacker to initiate phone calls without user consent, because of improper export of the com.cutestudio.dialer.activities.DialerActivity component. A third-party application (without any permissions) can craft an intent targeting com.cutestudio.dialer.activities.DialerActivity via the android.intent.action.CALL action in conjunction with a tel: URI, thereby placing a phone call.
</code>

- [actuator/com.cutestudio.colordialer](https://github.com/actuator/com.cutestudio.colordialer)

### CVE-2023-42469 (2023-09-13)

<code>The com.full.dialer.top.secure.encrypted application through 1.0.1 for Android enables any installed application (with no permissions) to place phone calls without user interaction by sending a crafted intent via the com.full.dialer.top.secure.encrypted.activities.DialerActivity component.
</code>

- [actuator/com.full.dialer.top.secure.encrypted](https://github.com/actuator/com.full.dialer.top.secure.encrypted)

### CVE-2023-42470 (2023-09-11)

<code>The Imou Life com.mm.android.smartlifeiot application through 6.8.0 for Android allows Remote Code Execution via a crafted intent to an exported component. This relates to the com.mm.android.easy4ip.MainActivity activity. JavaScript execution is enabled in the WebView, and direct web content loading occurs.
</code>

- [actuator/imou](https://github.com/actuator/imou)

### CVE-2023-42471 (2023-09-11)

<code>The wave.ai.browser application through 1.0.35 for Android allows a remote attacker to execute arbitrary JavaScript code via a crafted intent. It contains a manifest entry that exports the wave.ai.browser.ui.splash.SplashScreen activity. This activity uses a WebView component to display web content and doesn't adequately validate or sanitize the URI or any extra data passed in the intent by a third party application (with no permissions).
</code>

- [actuator/wave.ai.browser](https://github.com/actuator/wave.ai.browser)

### CVE-2023-42791 (2024-02-20)

<code>A relative path traversal in Fortinet FortiManager version 7.4.0 and 7.2.0 through 7.2.3 and 7.0.0 through 7.0.8 and 6.4.0 through 6.4.12 and 6.2.0 through 6.2.11 allows attacker to execute unauthorized code or commands via crafted HTTP requests.
</code>

- [synacktiv/CVE-2023-42791_CVE-2024-23666](https://github.com/synacktiv/CVE-2023-42791_CVE-2024-23666)

### CVE-2023-42793 (2023-09-19)

<code>In JetBrains TeamCity before 2023.05.4 authentication bypass leading to RCE on TeamCity Server was possible
</code>

- [H454NSec/CVE-2023-42793](https://github.com/H454NSec/CVE-2023-42793)

### CVE-2023-42829 (2024-01-10)

<code>The issue was addressed with additional restrictions on the observability of app states. This issue is fixed in macOS Big Sur 11.7.9, macOS Monterey 12.6.8, macOS Ventura 13.5. An app may be able to access SSH passphrases.
</code>

- [JamesD4/CVE-2023-42829](https://github.com/JamesD4/CVE-2023-42829)

### CVE-2023-43115 (2023-09-18)

<code>In Artifex Ghostscript through 10.01.2, gdevijs.c in GhostPDL can lead to remote code execution via crafted PostScript documents because they can switch to the IJS device, or change the IjsServer parameter, after SAFER has been activated. NOTE: it is a documented risk that the IJS server can be specified on a gs command line (the IJS device inherently must execute a command to start the IJS server).
</code>

- [jostaub/ghostscript-CVE-2023-43115](https://github.com/jostaub/ghostscript-CVE-2023-43115)

### CVE-2023-43148 (2023-10-12)

<code>SPA-Cart 1.9.0.3 has a Cross Site Request Forgery (CSRF) vulnerability that allows a remote attacker to delete all accounts.
</code>

- [MinoTauro2020/CVE-2023-43148](https://github.com/MinoTauro2020/CVE-2023-43148)

### CVE-2023-43263 (2023-09-26)

<code>A Cross-site scripting (XSS) vulnerability in Froala Editor v.4.1.1 allows attackers to execute arbitrary code via the Markdown component.
</code>

- [b0marek/CVE-2023-43263](https://github.com/b0marek/CVE-2023-43263)

### CVE-2023-43481 (2023-12-27)

<code>An issue in Shenzhen TCL Browser TV Web BrowseHere (aka com.tcl.browser) 6.65.022_dab24cc6_231221_gp allows a remote attacker to execute arbitrary JavaScript code via the com.tcl.browser.portal.browse.activity.BrowsePageActivity component.
</code>

- [actuator/com.tcl.browser](https://github.com/actuator/com.tcl.browser)

### CVE-2023-43955 (2023-12-27)

<code>The com.phlox.tvwebbrowser TV Bro application through 2.0.0 for Android mishandles external intents through WebView. This allows attackers to execute arbitrary code, create arbitrary files. and perform arbitrary downloads via JavaScript that uses takeBlobDownloadData.
</code>

- [actuator/com.phlox.tvwebbrowser](https://github.com/actuator/com.phlox.tvwebbrowser)

### CVE-2023-44487 (2023-10-10)

<code>The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023.
</code>

- [aulauniversal/CVE-2023-44487](https://github.com/aulauniversal/CVE-2023-44487)
- [BMG-Black-Magic/CVE-2023-44487](https://github.com/BMG-Black-Magic/CVE-2023-44487)

### CVE-2023-44812 (2023-10-09)

<code>Cross Site Scripting (XSS) vulnerability in mooSocial v.3.1.8 allows a remote attacker to execute arbitrary code via a crafted payload to the admin_redirect_url parameter of the user login function.
</code>

- [ahrixia/CVE-2023-44812](https://github.com/ahrixia/CVE-2023-44812)

### CVE-2023-44813 (2023-10-09)

<code>Cross Site Scripting (XSS) vulnerability in mooSocial v.3.1.8 allows a remote attacker to execute arbitrary code via a crafted payload to the mode parameter of the invite friend login function.
</code>

- [ahrixia/CVE-2023-44813](https://github.com/ahrixia/CVE-2023-44813)

### CVE-2023-45542 (2023-10-16)

<code>Cross Site Scripting vulnerability in mooSocial 3.1.8 allows a remote attacker to obtain sensitive information via a crafted script to the q parameter in the Search function.
</code>

- [ahrixia/CVE-2023-45542](https://github.com/ahrixia/CVE-2023-45542)

### CVE-2023-45866 (2023-12-08)

<code>Bluetooth HID Hosts in BlueZ may permit an unauthenticated Peripheral role HID Device to initiate and establish an encrypted connection, and accept HID keyboard reports, potentially permitting injection of HID messages when no user interaction has occurred in the Central role to authorize such access. An example affected package is bluez 5.64-0ubuntu1 in Ubuntu 22.04LTS. NOTE: in some cases, a CVE-2020-0556 mitigation would have already addressed this Bluetooth HID Hosts issue.
</code>

- [xG3nesis/RustyInjector](https://github.com/xG3nesis/RustyInjector)

### CVE-2023-46303 (2023-10-22)

<code>link_to_local_path in ebooks/conversion/plugins/html_input.py in calibre before 6.19.0 can, by default, add resources outside of the document root.
</code>

- [0x1717/ssrf-via-img](https://github.com/0x1717/ssrf-via-img)

### CVE-2023-46442 (2024-05-24)

<code>An infinite loop in the retrieveActiveBody function of Soot before v4.4.1 under Java 8 allows attackers to cause a Denial of Service (DoS).
</code>

- [JAckLosingHeart/CVE-2023-46442_POC](https://github.com/JAckLosingHeart/CVE-2023-46442_POC)

### CVE-2023-46447 (2024-01-20)

<code>The POPS! Rebel application 5.0 for Android, in POPS! Rebel Bluetooth Glucose Monitoring System, sends unencrypted glucose measurements over BLE.
</code>

- [actuator/rebel](https://github.com/actuator/rebel)

### CVE-2023-46604 (2023-10-27)

<code>The Java OpenWire protocol marshaller is vulnerable to Remote Code \nExecution. This vulnerability may allow a remote attacker with network \naccess to either a Java-based OpenWire broker or client to run arbitrary\n shell commands by manipulating serialized class types in the OpenWire \nprotocol to cause either the client or the broker (respectively) to \ninstantiate any class on the classpath.\n\nUsers are recommended to upgrade\n both brokers and clients to version 5.15.16, 5.16.7, 5.17.6, or 5.18.3 \nwhich fixes this issue.
</code>

- [skrkcb2/CVE-2023-46604](https://github.com/skrkcb2/CVE-2023-46604)

### CVE-2023-46805 (2024-01-12)

<code>An authentication bypass vulnerability in the web component of Ivanti ICS 9.x, 22.x and Ivanti Policy Secure allows a remote attacker to access restricted resources by bypassing control checks.
</code>

- [rxwx/pulse-meter](https://github.com/rxwx/pulse-meter)
- [Hexastrike/Ivanti-Connect-Secure-Logs-Parser](https://github.com/Hexastrike/Ivanti-Connect-Secure-Logs-Parser)

### CVE-2023-46813 (2023-10-27)

<code>An issue was discovered in the Linux kernel before 6.5.9, exploitable by local users with userspace access to MMIO registers. Incorrect access checking in the #VC handler and instruction emulation of the SEV-ES emulation of MMIO accesses could lead to arbitrary write access to kernel memory (and thus privilege escalation). This depends on a race condition through which userspace can replace an instruction before the #VC handler reads it.
</code>

- [Freax13/cve-2023-46813-poc](https://github.com/Freax13/cve-2023-46813-poc)

### CVE-2023-47268
- [TU-M/Trickster-HTB](https://github.com/TU-M/Trickster-HTB)

### CVE-2023-47668 (2023-11-23)

<code>Exposure of Sensitive Information to an Unauthorized Actor vulnerability in StellarWP Membership Plugin – Restrict Content plugin &lt;= 3.2.7 versions.
</code>

- [Nxploited/CVE-2023-47668](https://github.com/Nxploited/CVE-2023-47668)

### CVE-2023-47883 (2023-12-27)

<code>The com.altamirano.fabricio.tvbrowser TV browser application through 4.5.1 for Android is vulnerable to JavaScript code execution via an explicit intent due to an exposed MainActivity.
</code>

- [actuator/com.altamirano.fabricio.tvbrowser](https://github.com/actuator/com.altamirano.fabricio.tvbrowser)

### CVE-2023-48795 (2023-12-18)

<code>The SSH transport protocol with certain OpenSSH extensions, found in OpenSSH before 9.6 and other products, allows remote attackers to bypass integrity checks such that some packets are omitted (from the extension negotiation message), and a client and server may consequently end up with a connection for which some security features have been downgraded or disabled, aka a Terrapin attack. This occurs because the SSH Binary Packet Protocol (BPP), implemented by these extensions, mishandles the handshake phase and mishandles use of sequence numbers. For example, there is an effective attack against SSH's use of ChaCha20-Poly1305 (and CBC with Encrypt-then-MAC). The bypass occurs in chacha20-poly1305@openssh.com and (if CBC is used) the -etm@openssh.com MAC algorithms. This also affects Maverick Synergy Java SSH API before 3.1.0-SNAPSHOT, Dropbear through 2022.83, Ssh before 5.1.1 in Erlang/OTP, PuTTY before 0.80, AsyncSSH before 2.14.2, golang.org/x/crypto before 0.17.0, libssh before 0.10.6, libssh2 through 1.11.0, Thorn Tech SFTP Gateway before 3.4.6, Tera Term before 5.1, Paramiko before 3.4.0, jsch before 0.2.15, SFTPGo before 2.5.6, Netgate pfSense Plus through 23.09.1, Netgate pfSense CE through 2.7.2, HPN-SSH through 18.2.0, ProFTPD before 1.3.8b (and before 1.3.9rc2), ORYX CycloneSSH before 2.3.4, NetSarang XShell 7 before Build 0144, CrushFTP before 10.6.0, ConnectBot SSH library before 2.2.22, Apache MINA sshd through 2.11.0, sshj through 0.37.0, TinySSH through 20230101, trilead-ssh2 6401, LANCOM LCOS and LANconfig, FileZilla before 3.66.4, Nova before 11.8, PKIX-SSH before 14.4, SecureCRT before 9.4.3, Transmit5 before 5.10.4, Win32-OpenSSH before 9.5.0.0p1-Beta, WinSCP before 6.2.2, Bitvise SSH Server before 9.32, Bitvise SSH Client before 9.33, KiTTY through 0.76.1.13, the net-ssh gem 7.2.0 for Ruby, the mscdex ssh2 module before 1.15.0 for Node.js, the thrussh library before 0.35.1 for Rust, and the Russh crate before 0.40.2 for Rust.
</code>

- [TrixSec/CVE-2023-48795](https://github.com/TrixSec/CVE-2023-48795)

### CVE-2023-49031 (2025-03-03)

<code>Directory Traversal (Local File Inclusion) vulnerability in Tikit (now Advanced) eMarketing platform 6.8.3.0 allows a remote attacker to read arbitrary files and obtain sensitive information via a crafted payload to the filename parameter to the OpenLogFile endpoint.
</code>

- [Yoshik0xF6/CVE-2023-49031](https://github.com/Yoshik0xF6/CVE-2023-49031)

### CVE-2023-49070 (2023-12-05)

<code>Pre-auth RCE in Apache Ofbiz 18.12.09.\n\nIt's due to XML-RPC no longer maintained still present.\nThis issue affects Apache OFBiz: before 18.12.10. \nUsers are recommended to upgrade to version 18.12.10
</code>

- [UserConnecting/Exploit-CVE-2023-49070-and-CVE-2023-51467-Apache-OFBiz](https://github.com/UserConnecting/Exploit-CVE-2023-49070-and-CVE-2023-51467-Apache-OFBiz)

### CVE-2023-50164 (2023-12-07)

<code>An attacker can manipulate file upload params to enable paths traversal and under some circumstances this can lead to uploading a malicious file which can be used to perform Remote Code Execution.\nUsers are recommended to upgrade to versions Struts 2.5.33 or Struts 6.3.0.2 or greater to fix this issue.
</code>

- [minhbao15677/CVE-2023-50164](https://github.com/minhbao15677/CVE-2023-50164)
- [Pixel-DefaultBR/CVE-2023-50164](https://github.com/Pixel-DefaultBR/CVE-2023-50164)
- [heavyyeast/cve-2023-50164-poc](https://github.com/heavyyeast/cve-2023-50164-poc)

### CVE-2023-50564 (2023-12-14)

<code>An arbitrary file upload vulnerability in the component /inc/modules_install.php of Pluck-CMS v4.7.18 allows attackers to execute arbitrary code via uploading a crafted ZIP file.
</code>

- [0xDTC/Pluck-CMS-v4.7.18-Remote-Code-Execution-CVE-2023-50564](https://github.com/0xDTC/Pluck-CMS-v4.7.18-Remote-Code-Execution-CVE-2023-50564)
- [xpltive/CVE-2023-50564](https://github.com/xpltive/CVE-2023-50564)

### CVE-2023-50780 (2024-10-14)

<code>Apache ActiveMQ Artemis allows access to diagnostic information and controls through MBeans, which are also exposed through the authenticated Jolokia endpoint. Before version 2.29.0, this also included the Log4J2 MBean. This MBean is not meant for exposure to non-administrative users. This could eventually allow an authenticated attacker to write arbitrary files to the filesystem and indirectly achieve RCE.\n\n\nUsers are recommended to upgrade to version 2.29.0 or later, which fixes the issue.
</code>

- [mbadanoiu/CVE-2023-50780](https://github.com/mbadanoiu/CVE-2023-50780)

### CVE-2023-51385 (2023-12-18)

<code>In ssh in OpenSSH before 9.6, OS command injection might occur if a user name or host name has shell metacharacters, and this name is referenced by an expansion token in certain situations. For example, an untrusted Git repository can have a submodule with shell metacharacters in a user name or host name.
</code>

- [vin01/poc-proxycommand-vulnerable](https://github.com/vin01/poc-proxycommand-vulnerable)
- [GroundCTL2MajorTom/CVE-2023-51385POC](https://github.com/GroundCTL2MajorTom/CVE-2023-51385POC)
- [GroundCTL2MajorTom/CVE-2023-51385P-POC](https://github.com/GroundCTL2MajorTom/CVE-2023-51385P-POC)

### CVE-2023-51409 (2024-04-12)

<code>Unrestricted Upload of File with Dangerous Type vulnerability in Jordy Meow AI Engine: ChatGPT Chatbot.This issue affects AI Engine: ChatGPT Chatbot: from n/a through 1.9.98.\n\n
</code>

- [Nxploited/CVE-2023-51409](https://github.com/Nxploited/CVE-2023-51409)


## 2022
### CVE-2022-0155 (2022-01-10)

<code>follow-redirects is vulnerable to Exposure of Private Personal Information to an Unauthorized Actor
</code>

- [coana-tech/CVE-2022-0155-PoC](https://github.com/coana-tech/CVE-2022-0155-PoC)

### CVE-2022-0165 (2022-03-14)

<code>The Page Builder KingComposer WordPress plugin through 2.9.6 does not validate the id parameter before redirecting the user to it via the kc_get_thumbn AJAX action available to both unauthenticated and authenticated users
</code>

- [K3ysTr0K3R/CVE-2022-0165-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2022-0165-EXPLOIT)
- [Cappricio-Securities/CVE-2022-0165](https://github.com/Cappricio-Securities/CVE-2022-0165)

### CVE-2022-0185 (2022-02-11)

<code>A heap-based buffer overflow flaw was found in the way the legacy_parse_param function in the Filesystem Context functionality of the Linux kernel verified the supplied parameters length. An unprivileged (in case of unprivileged user namespaces enabled, otherwise needs namespaced CAP_SYS_ADMIN privilege) local user able to open a filesystem that does not support the Filesystem Context API (and thus fallbacks to legacy handling) could use this flaw to escalate their privileges on the system.
</code>

- [featherL/CVE-2022-0185-exploit](https://github.com/featherL/CVE-2022-0185-exploit)
- [dcheng69/CVE-2022-0185-Case-Study](https://github.com/dcheng69/CVE-2022-0185-Case-Study)

### CVE-2022-0337 (2023-01-02)

<code>Inappropriate implementation in File System API in Google Chrome on Windows prior to 97.0.4692.71 allowed a remote attacker to obtain potentially sensitive information via a crafted HTML page. (Chrome security severity: High)
</code>

- [Puliczek/CVE-2022-0337-PoC-Google-Chrome-Microsoft-Edge-Opera](https://github.com/Puliczek/CVE-2022-0337-PoC-Google-Chrome-Microsoft-Edge-Opera)
- [zer0ne1/CVE-2022-0337-RePoC](https://github.com/zer0ne1/CVE-2022-0337-RePoC)

### CVE-2022-0412 (2022-02-28)

<code>The TI WooCommerce Wishlist WordPress plugin before 1.40.1, TI WooCommerce Wishlist Pro WordPress plugin before 1.40.1 do not sanitise and escape the item_id parameter before using it in a SQL statement via the wishlist/remove_product REST endpoint, allowing unauthenticated attackers to perform SQL injection attacks
</code>

- [TcherB31/CVE-2022-0412_Exploit](https://github.com/TcherB31/CVE-2022-0412_Exploit)

### CVE-2022-0441 (2022-03-07)

<code>The MasterStudy LMS WordPress plugin before 2.7.6 does to validate some parameters given when registering a new account, allowing unauthenticated users to register as an admin
</code>

- [kyukazamiqq/CVE-2022-0441](https://github.com/kyukazamiqq/CVE-2022-0441)

### CVE-2022-0482 (2022-03-09)

<code>Exposure of Private Personal Information to an Unauthorized Actor in GitHub repository alextselegidis/easyappointments prior to 1.4.3.
</code>

- [mija-pilkaite/CVE-2022-0482_exploit](https://github.com/mija-pilkaite/CVE-2022-0482_exploit)

### CVE-2022-0543 (2022-02-18)

<code>It was discovered, that redis, a persistent key-value database, due to a packaging issue, is prone to a (Debian-specific) Lua sandbox escape, which could result in remote code execution.
</code>

- [0x7eTeam/CVE-2022-0543](https://github.com/0x7eTeam/CVE-2022-0543)
- [JacobEbben/CVE-2022-0543](https://github.com/JacobEbben/CVE-2022-0543)

### CVE-2022-0591 (2022-03-21)

<code>The FormCraft WordPress plugin before 3.8.28 does not validate the URL parameter in the formcraft3_get AJAX action, leading to SSRF issues exploitable by unauthenticated users
</code>

- [im-hanzou/FC3er](https://github.com/im-hanzou/FC3er)

### CVE-2022-0778 (2022-03-15)

<code>The BN_mod_sqrt() function, which computes a modular square root, contains a bug that can cause it to loop forever for non-prime moduli. Internally this function is used when parsing certificates that contain elliptic curve public keys in compressed form or explicit elliptic curve parameters with a base point encoded in compressed form. It is possible to trigger the infinite loop by crafting a certificate that has invalid explicit curve parameters. Since certificate parsing happens prior to verification of the certificate signature, any process that parses an externally supplied certificate may thus be subject to a denial of service attack. The infinite loop can also be reached when parsing crafted private keys as they can contain explicit elliptic curve parameters. Thus vulnerable situations include: - TLS clients consuming server certificates - TLS servers consuming client certificates - Hosting providers taking certificates or private keys from customers - Certificate authorities parsing certification requests from subscribers - Anything else which parses ASN.1 elliptic curve parameters Also any other applications that use the BN_mod_sqrt() where the attacker can control the parameter values are vulnerable to this DoS issue. In the OpenSSL 1.0.2 version the public key is not parsed during initial parsing of the certificate which makes it slightly harder to trigger the infinite loop. However any operation which requires the public key from the certificate will trigger the infinite loop. In particular the attacker can use a self-signed certificate to trigger the loop during verification of the certificate signature. This issue affects OpenSSL versions 1.0.2, 1.1.1 and 3.0. It was addressed in the releases of 1.1.1n and 3.0.2 on the 15th March 2022. Fixed in OpenSSL 3.0.2 (Affected 3.0.0,3.0.1). Fixed in OpenSSL 1.1.1n (Affected 1.1.1-1.1.1m). Fixed in OpenSSL 1.0.2zd (Affected 1.0.2-1.0.2zc).
</code>

- [Trinadh465/openssl-1.1.1g_CVE-2022-0778](https://github.com/Trinadh465/openssl-1.1.1g_CVE-2022-0778)
- [jeongjunsoo/CVE-2022-0778](https://github.com/jeongjunsoo/CVE-2022-0778)
- [hshivhare67/OpenSSL_1.0.1g_CVE-2022-0778](https://github.com/hshivhare67/OpenSSL_1.0.1g_CVE-2022-0778)

### CVE-2022-0847 (2022-03-07)

<code>A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.
</code>

- [r1is/CVE-2022-0847](https://github.com/r1is/CVE-2022-0847)
- [basharkey/CVE-2022-0847-dirty-pipe-checker](https://github.com/basharkey/CVE-2022-0847-dirty-pipe-checker)
- [arttnba3/CVE-2022-0847](https://github.com/arttnba3/CVE-2022-0847)
- [AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits](https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits)
- [tmoneypenny/CVE-2022-0847](https://github.com/tmoneypenny/CVE-2022-0847)
- [ih3na/debian11-dirty_pipe-patcher](https://github.com/ih3na/debian11-dirty_pipe-patcher)
- [Asbatel/CBDS_CVE-2022-0847_POC](https://github.com/Asbatel/CBDS_CVE-2022-0847_POC)
- [notl0cal/dpipe](https://github.com/notl0cal/dpipe)
- [Gustavo-Nogueira/Dirty-Pipe-Exploits](https://github.com/Gustavo-Nogueira/Dirty-Pipe-Exploits)
- [mutur4/CVE-2022-0847](https://github.com/mutur4/CVE-2022-0847)
- [h4ckm310n/CVE-2022-0847-eBPF](https://github.com/h4ckm310n/CVE-2022-0847-eBPF)
- [pashayogi/DirtyPipe](https://github.com/pashayogi/DirtyPipe)
- [n3rada/DirtyPipe](https://github.com/n3rada/DirtyPipe)
- [ayushx007/CVE-2022-0847-dirty-pipe-checker](https://github.com/ayushx007/CVE-2022-0847-dirty-pipe-checker)
- [ayushx007/CVE-2022-0847-DirtyPipe-Exploits](https://github.com/ayushx007/CVE-2022-0847-DirtyPipe-Exploits)
- [solomon12354/LockingGirl-----CVE-2022-0847-Dirty_Pipe_virus](https://github.com/solomon12354/LockingGirl-----CVE-2022-0847-Dirty_Pipe_virus)
- [letsr00t/CVE-2022-0847](https://github.com/letsr00t/CVE-2022-0847)
- [xsxtw/CVE-2022-0847](https://github.com/xsxtw/CVE-2022-0847)
- [muhammad1596/CVE-2022-0847-dirty-pipe-checker](https://github.com/muhammad1596/CVE-2022-0847-dirty-pipe-checker)
- [muhammad1596/CVE-2022-0847-DirtyPipe-Exploits](https://github.com/muhammad1596/CVE-2022-0847-DirtyPipe-Exploits)
- [JustinYe377/CTF-CVE-2022-0847](https://github.com/JustinYe377/CTF-CVE-2022-0847)
- [mithunmadhukuttan/Dirty-Pipe-Exploit](https://github.com/mithunmadhukuttan/Dirty-Pipe-Exploit)
- [Mephierr/DirtyPipe_exploit](https://github.com/Mephierr/DirtyPipe_exploit)
- [RogelioPumajulca/CVE-2022-0847](https://github.com/RogelioPumajulca/CVE-2022-0847)

### CVE-2022-0944 (2022-03-15)

<code>Template injection in connection test endpoint leads to RCE in GitHub repository sqlpad/sqlpad prior to 6.10.1.
</code>

- [shhrew/CVE-2022-0944](https://github.com/shhrew/CVE-2022-0944)
- [Philip-Otter/CVE-2022-0944_RCE_Automation](https://github.com/Philip-Otter/CVE-2022-0944_RCE_Automation)
- [FlojBoj/CVE-2022-0944](https://github.com/FlojBoj/CVE-2022-0944)
- [0xRoqeeb/sqlpad-rce-exploit-CVE-2022-0944](https://github.com/0xRoqeeb/sqlpad-rce-exploit-CVE-2022-0944)
- [Robocopsita/CVE-2022-0944_RCE_POC](https://github.com/Robocopsita/CVE-2022-0944_RCE_POC)
- [toneillcodes/CVE-2022-0944](https://github.com/toneillcodes/CVE-2022-0944)
- [LipeOzyy/SQLPad-RCE-Exploit-CVE-2022-0944](https://github.com/LipeOzyy/SQLPad-RCE-Exploit-CVE-2022-0944)
- [0xDTC/SQLPad-6.10.0-Exploit-CVE-2022-0944](https://github.com/0xDTC/SQLPad-6.10.0-Exploit-CVE-2022-0944)

### CVE-2022-0952 (2022-05-02)

<code>The Sitemap by click5 WordPress plugin before 1.0.36 does not have authorisation and CSRF checks when updating options via a REST endpoint, and does not ensure that the option to be updated belongs to the plugin. As a result, unauthenticated attackers could change arbitrary blog options, such as the users_can_register and default_role, allowing them to create a new admin account and take over the blog.
</code>

- [RandomRobbieBF/CVE-2022-0952](https://github.com/RandomRobbieBF/CVE-2022-0952)

### CVE-2022-0995 (2022-03-25)

<code>An out-of-bounds (OOB) memory write flaw was found in the Linux kernel’s watch_queue event notification subsystem. This flaw can overwrite parts of the kernel state, potentially allowing a local user to gain privileged access or cause a denial of service on the system.
</code>

- [1nzag/CVE-2022-0995](https://github.com/1nzag/CVE-2022-0995)

### CVE-2022-1015 (2022-04-29)

<code>A flaw was found in the Linux kernel in linux/net/netfilter/nf_tables_api.c of the netfilter subsystem. This flaw allows a local user to cause an out-of-bounds write issue.
</code>

- [more-kohii/CVE-2022-1015](https://github.com/more-kohii/CVE-2022-1015)
- [0range1337/CVE-2022-1015](https://github.com/0range1337/CVE-2022-1015)
- [seadragnol/CVE-2022-1015](https://github.com/seadragnol/CVE-2022-1015)

### CVE-2022-1026 (2022-04-04)

<code>Kyocera multifunction printers running vulnerable versions of Net View unintentionally expose sensitive user information, including usernames and passwords, through an insufficiently protected address book export function.
</code>

- [r0lh/kygocera](https://github.com/r0lh/kygocera)

### CVE-2022-1040 (2022-03-25)

<code>An authentication bypass vulnerability in the User Portal and Webadmin allows a remote attacker to execute code in Sophos Firewall version v18.5 MR3 and older.
</code>

- [jam620/Sophos-Vulnerability](https://github.com/jam620/Sophos-Vulnerability)
- [Cyb3rEnthusiast/CVE-2022-1040](https://github.com/Cyb3rEnthusiast/CVE-2022-1040)
- [xMr110/CVE-2022-1040](https://github.com/xMr110/CVE-2022-1040)

### CVE-2022-1077 (2022-03-29)

<code>A vulnerability was found in TEM FLEX-1080 and FLEX-1085 1.6.0. It has been declared as problematic. This vulnerability log.cgi of the component Log Handler. A direct request leads to information disclosure of hardware information. The attack can be initiated remotely and does not require any form of authentication.
</code>

- [brosck/CVE-2022-1077](https://github.com/brosck/CVE-2022-1077)

### CVE-2022-1292 (2022-05-03)

<code>The c_rehash script does not properly sanitise shell metacharacters to prevent command injection. This script is distributed by some operating systems in a manner where it is automatically executed. On such operating systems, an attacker could execute arbitrary commands with the privileges of the script. Use of the c_rehash script is considered obsolete and should be replaced by the OpenSSL rehash command line tool. Fixed in OpenSSL 3.0.3 (Affected 3.0.0,3.0.1,3.0.2). Fixed in OpenSSL 1.1.1o (Affected 1.1.1-1.1.1n). Fixed in OpenSSL 1.0.2ze (Affected 1.0.2-1.0.2zd).
</code>

- [alcaparra/CVE-2022-1292](https://github.com/alcaparra/CVE-2022-1292)
- [greek0x0/CVE-2022-1292](https://github.com/greek0x0/CVE-2022-1292)
- [und3sc0n0c1d0/CVE-2022-1292](https://github.com/und3sc0n0c1d0/CVE-2022-1292)

### CVE-2022-1329 (2022-04-19)

<code>The Elementor Website Builder plugin for WordPress is vulnerable to unauthorized execution of several AJAX actions due to a missing capability check in the ~/core/app/modules/onboarding/module.php file that make it possible for attackers to modify site data in addition to uploading malicious files that can be used to obtain remote code execution, in versions 3.6.0 to 3.6.2.
</code>

- [phanthibichtram12/CVE-2022-1329](https://github.com/phanthibichtram12/CVE-2022-1329)
- [AgustinESI/CVE-2022-1329](https://github.com/AgustinESI/CVE-2022-1329)

### CVE-2022-1364 (2022-07-26)

<code>Type confusion in V8 Turbofan in Google Chrome prior to 100.0.4896.127 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.
</code>

- [A1Lin/cve-2022-1364](https://github.com/A1Lin/cve-2022-1364)

### CVE-2022-1386 (2022-05-16)

<code>The Fusion Builder WordPress plugin before 3.6.2, used in the Avada theme, does not validate a parameter in its forms which could be used to initiate arbitrary HTTP requests. The data returned is then reflected back in the application's response. This could be used to interact with hosts on the server's local network bypassing firewalls and access control measures.
</code>

- [zycoder0day/CVE-2022-1386-Mass_Vulnerability](https://github.com/zycoder0day/CVE-2022-1386-Mass_Vulnerability)
- [satyasai1460/CVE-2022-1386](https://github.com/satyasai1460/CVE-2022-1386)
- [lamcodeofpwnosec/CVE-2022-1386](https://github.com/lamcodeofpwnosec/CVE-2022-1386)

### CVE-2022-1388 (2022-05-05)

<code>On F5 BIG-IP 16.1.x versions prior to 16.1.2.2, 15.1.x versions prior to 15.1.5.1, 14.1.x versions prior to 14.1.4.6, 13.1.x versions prior to 13.1.5, and all 12.1.x and 11.6.x versions, undisclosed requests may bypass iControl REST authentication. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated
</code>

- [Vulnmachines/F5-Big-IP-CVE-2022-1388](https://github.com/Vulnmachines/F5-Big-IP-CVE-2022-1388)
- [Henry4E36/CVE-2022-1388](https://github.com/Henry4E36/CVE-2022-1388)
- [EvilLizard666/CVE-2022-1388](https://github.com/EvilLizard666/CVE-2022-1388)
- [Zeyad-Azima/CVE-2022-1388](https://github.com/Zeyad-Azima/CVE-2022-1388)
- [west9b/F5-BIG-IP-POC](https://github.com/west9b/F5-BIG-IP-POC)
- [Chocapikk/CVE-2022-1388](https://github.com/Chocapikk/CVE-2022-1388)
- [forktheplanet/CVE-2022-1388](https://github.com/forktheplanet/CVE-2022-1388)
- [battleofthebots/refresh](https://github.com/battleofthebots/refresh)
- [nvk0x/CVE-2022-1388-exploit](https://github.com/nvk0x/CVE-2022-1388-exploit)
- [nico989/CVE-2022-1388](https://github.com/nico989/CVE-2022-1388)
- [gotr00t0day/CVE-2022-1388](https://github.com/gotr00t0day/CVE-2022-1388)
- [impost0r/CVE-2022-1388](https://github.com/impost0r/CVE-2022-1388)
- [XiaomingX/cve-2022-1388-poc](https://github.com/XiaomingX/cve-2022-1388-poc)

### CVE-2022-1421 (2022-06-06)

<code>The Discy WordPress theme before 5.2 lacks CSRF checks in some AJAX actions, allowing an attacker to make a logged in admin change arbitrary 's settings including payment methods via a CSRF attack
</code>

- [nb1b3k/CVE-2022-1421](https://github.com/nb1b3k/CVE-2022-1421)

### CVE-2022-1471 (2022-12-01)

<code>SnakeYaml's Constructor() class does not restrict types which can be instantiated during deserialization. Deserializing yaml content provided by an attacker can lead to remote code execution. We recommend using SnakeYaml's SafeConsturctor when parsing untrusted content to restrict deserialization. We recommend upgrading to version 2.0 and beyond.
</code>

- [falconkei/snakeyaml_cve_poc](https://github.com/falconkei/snakeyaml_cve_poc)

### CVE-2022-1565 (2022-07-18)

<code>The plugin WP All Import is vulnerable to arbitrary file uploads due to missing file type validation via the wp_all_import_get_gz.php file in versions up to, and including, 3.6.7. This makes it possible for authenticated attackers, with administrator level permissions and above, to upload arbitrary files on the affected sites server which may make remote code execution possible.
</code>

- [phanthibichtram12/CVE-2022-1565](https://github.com/phanthibichtram12/CVE-2022-1565)

### CVE-2022-1679 (2022-05-16)

<code>A use-after-free flaw was found in the Linux kernel’s Atheros wireless adapter driver in the way a user forces the ath9k_htc_wait_for_target function to fail with some input messages. This flaw allows a local user to crash or potentially escalate their privileges on the system.
</code>

- [ov3rwatch/Detection-and-Mitigation-for-CVE-2022-1679](https://github.com/ov3rwatch/Detection-and-Mitigation-for-CVE-2022-1679)

### CVE-2022-1802 (2022-12-22)

<code>If an attacker was able to corrupt the methods of an Array object in JavaScript via prototype pollution, they could have achieved execution of attacker-controlled JavaScript code in a privileged context. This vulnerability affects Firefox ESR &lt; 91.9.1, Firefox &lt; 100.0.2, Firefox for Android &lt; 100.3.0, and Thunderbird &lt; 91.9.1.
</code>

- [mistymntncop/CVE-2022-1802](https://github.com/mistymntncop/CVE-2022-1802)

### CVE-2022-2274 (2022-07-01)

<code>The OpenSSL 3.0.4 release introduced a serious bug in the RSA implementation for X86_64 CPUs supporting the AVX512IFMA instructions. This issue makes the RSA implementation with 2048 bit private keys incorrect on such machines and memory corruption will happen during the computation. As a consequence of the memory corruption an attacker may be able to trigger a remote code execution on the machine performing the computation. SSL/TLS servers or other servers using 2048 bit RSA private keys running on machines supporting AVX512IFMA instructions of the X86_64 architecture are affected by this issue.
</code>

- [Malwareman007/CVE-2022-2274](https://github.com/Malwareman007/CVE-2022-2274)

### CVE-2022-2414 (2022-07-29)

<code>Access to external entities when parsing XML documents can lead to XML external entity (XXE) attacks. This flaw allows a remote attacker to potentially retrieve the content of arbitrary files by sending specially crafted HTTP requests.
</code>

- [amitlttwo/CVE-2022-2414-Proof-Of-Concept](https://github.com/amitlttwo/CVE-2022-2414-Proof-Of-Concept)
- [satyasai1460/CVE-2022-2414](https://github.com/satyasai1460/CVE-2022-2414)
- [geniuszly/CVE-2022-2414](https://github.com/geniuszly/CVE-2022-2414)

### CVE-2022-2546 (2023-02-02)

<code>The All-in-One WP Migration WordPress plugin before 7.63 uses the wrong content type, and does not properly escape the response from the ai1wm_export AJAX action, allowing an attacker to craft a request that when submitted by any visitor will inject arbitrary html or javascript into the response that will be executed in the victims session. Note: This requires knowledge of a static secret key
</code>

- [OpenXP-Research/CVE-2022-2546](https://github.com/OpenXP-Research/CVE-2022-2546)

### CVE-2022-2586 (2024-01-08)

<code>It was discovered that a nft object or expression could reference a nft set on a different nft table, leading to a use-after-free once that table was deleted.
</code>

- [aels/CVE-2022-2586-LPE](https://github.com/aels/CVE-2022-2586-LPE)

### CVE-2022-2588 (2024-01-08)

<code>It was discovered that the cls_route filter implementation in the Linux kernel would not remove an old filter from the hashtable before freeing it if its handle had the value 0.
</code>

- [Markakd/CVE-2022-2588](https://github.com/Markakd/CVE-2022-2588)
- [PolymorphicOpcode/CVE-2022-2588](https://github.com/PolymorphicOpcode/CVE-2022-2588)
- [veritas501/CVE-2022-2588](https://github.com/veritas501/CVE-2022-2588)

### CVE-2022-2590 (2022-08-31)

<code>A race condition was found in the way the Linux kernel's memory subsystem handled the copy-on-write (COW) breakage of private read-only shared memory mappings. This flaw allows an unprivileged, local user to gain write access to read-only memory mappings, increasing their privileges on the system.
</code>

- [hyeonjun17/CVE-2022-2590-analysis](https://github.com/hyeonjun17/CVE-2022-2590-analysis)

### CVE-2022-2639 (2022-09-01)

<code>An integer coercion error was found in the openvswitch kernel module. Given a sufficiently large number of actions, while copying and reserving memory for a new action of a new flow, the reserve_sfa_size() function does not return -EMSGSIZE as expected, potentially leading to an out-of-bounds write access. This flaw allows a local user to crash or potentially escalate their privileges on the system.
</code>

- [bb33bb/CVE-2022-2639-PipeVersion](https://github.com/bb33bb/CVE-2022-2639-PipeVersion)
- [letsr00t/-2022-LOCALROOT-CVE-2022-2639](https://github.com/letsr00t/-2022-LOCALROOT-CVE-2022-2639)
- [devetop/CVE-2022-2639-PipeVersion](https://github.com/devetop/CVE-2022-2639-PipeVersion)

### CVE-2022-3168
- [irsl/CVE-2022-3168-adb-unexpected-reverse-forwards](https://github.com/irsl/CVE-2022-3168-adb-unexpected-reverse-forwards)

### CVE-2022-3172 (2023-11-03)

<code>A security issue was discovered in kube-apiserver that allows an \naggregated API server to redirect client traffic to any URL.  This could\n lead to the client performing unexpected actions as well as forwarding \nthe client's API server credentials to third parties.
</code>

- [UgOrange/CVE-2022-3172](https://github.com/UgOrange/CVE-2022-3172)

### CVE-2022-3357 (2022-10-31)

<code>The Smart Slider 3 WordPress plugin before 3.5.1.11 unserialises the content of an imported file, which could lead to PHP object injection issues when a user import (intentionally or not) a malicious file, and a suitable gadget chain is present on the site.
</code>

- [iamz24/CVE-2021-3493_CVE-2022-3357](https://github.com/iamz24/CVE-2021-3493_CVE-2022-3357)

### CVE-2022-3368 (2022-10-17)

<code>A vulnerability within the Software Updater functionality of Avira Security for Windows allowed an attacker with write access to the filesystem, to escalate his privileges in certain scenarios. The issue was fixed with Avira Security version 1.1.72.30556.
</code>

- [byt3n33dl3/CrackAVFee](https://github.com/byt3n33dl3/CrackAVFee)

### CVE-2022-3546 (2022-10-17)

<code>A vulnerability was found in SourceCodester Simple Cold Storage Management System 1.0 and classified as problematic. Affected by this issue is some unknown functionality of the file /csms/admin/?page=user/list of the component Create User Handler. The manipulation of the argument First Name/Last Name leads to cross site scripting. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. VDB-211046 is the identifier assigned to this vulnerability.
</code>

- [thehackingverse/CVE-2022-3546](https://github.com/thehackingverse/CVE-2022-3546)

### CVE-2022-3564 (2022-10-17)

<code>A vulnerability classified as critical was found in Linux Kernel. Affected by this vulnerability is the function l2cap_reassemble_sdu of the file net/bluetooth/l2cap_core.c of the component Bluetooth. The manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-211087.
</code>

- [Trinadh465/linux-4.1.15_CVE-2022-3564](https://github.com/Trinadh465/linux-4.1.15_CVE-2022-3564)

### CVE-2022-3590 (2022-12-14)

<code>WordPress is affected by an unauthenticated blind SSRF in the pingback feature. Because of a TOCTOU race condition between the validation checks and the HTTP request, attackers can reach internal hosts that are explicitly forbidden.
</code>

- [huynhvanphuc/CVE-2022-3590-WordPress-Vulnerability-Scanner](https://github.com/huynhvanphuc/CVE-2022-3590-WordPress-Vulnerability-Scanner)

### CVE-2022-3699 (2023-10-24)

<code>\nA privilege escalation vulnerability was reported in the Lenovo HardwareScanPlugin prior to version 1.3.1.2 and Lenovo Diagnostics prior to version 4.45\n\n\n\n that could allow a local user to execute code with elevated privileges.
</code>

- [Eap2468/CVE-2022-3699](https://github.com/Eap2468/CVE-2022-3699)

### CVE-2022-3910 (2022-11-22)

<code>Use After Free vulnerability in Linux Kernel allows Privilege Escalation. An improper Update of Reference Count in io_uring leads to Use-After-Free and Local Privilege Escalation.\nWhen io_msg_ring was invoked with a fixed file, it called io_fput_file() which improperly decreased its reference count (leading to Use-After-Free and Local Privilege Escalation). Fixed files are permanently registered to the ring, and should not be put separately.\n\nWe recommend upgrading past commit  https://github.com/torvalds/linux/commit/fc7222c3a9f56271fba02aabbfbae999042f1679 https://github.com/torvalds/linux/commit/fc7222c3a9f56271fba02aabbfbae999042f1679 \n
</code>

- [TLD1027/CVE-2022-3910](https://github.com/TLD1027/CVE-2022-3910)

### CVE-2022-4047 (2022-12-26)

<code>The Return Refund and Exchange For WooCommerce WordPress plugin before 4.0.9 does not validate attachment files to be uploaded via an AJAX action available to unauthenticated users, which could allow them to upload arbitrary files such as PHP and lead to RCE
</code>

- [im-hanzou/WooRefer](https://github.com/im-hanzou/WooRefer)
- [entroychang/CVE-2022-4047](https://github.com/entroychang/CVE-2022-4047)

### CVE-2022-4060 (2023-01-16)

<code>The User Post Gallery WordPress plugin through 2.19 does not limit what callback functions can be called by users, making it possible to any visitors to run code on sites running it.
</code>

- [im-hanzou/UPGer](https://github.com/im-hanzou/UPGer)

### CVE-2022-4061 (2022-12-19)

<code>The JobBoardWP WordPress plugin before 1.2.2 does not properly validate file names and types in its file upload functionalities, allowing unauthenticated users to upload arbitrary files such as PHP.
</code>

- [im-hanzou/JBWPer](https://github.com/im-hanzou/JBWPer)

### CVE-2022-4063 (2022-12-19)

<code>The InPost Gallery WordPress plugin before 2.1.4.1 insecurely uses PHP's extract() function when rendering HTML views, allowing attackers to force the inclusion of malicious files &amp; URLs, which may enable them to run code on servers.
</code>

- [im-hanzou/INPGer](https://github.com/im-hanzou/INPGer)

### CVE-2022-4174 (2022-11-29)

<code>Type confusion in V8 in Google Chrome prior to 108.0.5359.71 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
</code>

- [moften/CVE-2022-4174_CVE-2022-41742](https://github.com/moften/CVE-2022-4174_CVE-2022-41742)

### CVE-2022-4262 (2022-12-02)

<code>Type confusion in V8 in Google Chrome prior to 108.0.5359.94 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
</code>

- [bjrjk/CVE-2022-4262](https://github.com/bjrjk/CVE-2022-4262)
- [mistymntncop/CVE-2022-4262](https://github.com/mistymntncop/CVE-2022-4262)
- [quangnh89/CVE-2022-4262](https://github.com/quangnh89/CVE-2022-4262)

### CVE-2022-4539 (2024-08-31)

<code>The Web Application Firewall plugin for WordPress is vulnerable to IP Address Spoofing in versions up to, and including, 2.1.2. This is due to insufficient restrictions on where the IP Address information is being retrieved for request logging and login restrictions. Attackers can supply the X-Forwarded-For header with with a different IP Address that will be logged and can be used to bypass settings that may have blocked out an IP address or country from logging in.
</code>

- [Abdurahmon3236/CVE-2022-4539](https://github.com/Abdurahmon3236/CVE-2022-4539)

### CVE-2022-4543 (2023-01-11)

<code>A flaw named &quot;EntryBleed&quot; was found in the Linux Kernel Page Table Isolation (KPTI). This issue could allow a local attacker to leak KASLR base via prefetch side-channels based on TLB timing for Intel systems.
</code>

- [sunichi/cve-2022-4543-wrapper](https://github.com/sunichi/cve-2022-4543-wrapper)

### CVE-2022-4944 (2023-04-22)

<code>Eine problematische Schwachstelle wurde in kalcaddle KodExplorer bis 4.49 entdeckt. Davon betroffen ist unbekannter Code. Durch Manipulation mit unbekannten Daten kann eine cross-site request forgery-Schwachstelle ausgenutzt werden. Der Angriff kann über das Netzwerk erfolgen. Der Exploit steht zur öffentlichen Verfügung. Ein Aktualisieren auf die Version 4.50 vermag dieses Problem zu lösen. Als bestmögliche Massnahme wird das Einspielen eines Upgrades empfohlen.
</code>

- [brosck/CVE-2022-4944](https://github.com/brosck/CVE-2022-4944)

### CVE-2022-20009 (2022-05-10)

<code>In various functions of the USB gadget subsystem, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-213172319References: Upstream kernel
</code>

- [szymonh/android-gadget](https://github.com/szymonh/android-gadget)

### CVE-2022-20120 (2022-05-10)

<code>Product: AndroidVersions: Android kernelAndroid ID: A-203213034References: N/A
</code>

- [boredpentester/ABL_ROP](https://github.com/boredpentester/ABL_ROP)

### CVE-2022-20126 (2022-06-15)

<code>In setScanMode of AdapterService.java, there is a possible way to enable Bluetooth discovery mode without user interaction due to a missing permission check. This could lead to local escalation of privilege with User execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-203431023
</code>

- [Trinadh465/packages_apps_Bluetooth_AOSP10_r33_CVE-2022-20126](https://github.com/Trinadh465/packages_apps_Bluetooth_AOSP10_r33_CVE-2022-20126)

### CVE-2022-20128
- [irsl/CVE-2022-20128](https://github.com/irsl/CVE-2022-20128)

### CVE-2022-20140 (2022-06-15)

<code>In read_multi_rsp of gatt_sr.cc, there is a possible out of bounds write due to an incorrect bounds check. This could lead to remote escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-12 Android-12LAndroid ID: A-227618988
</code>

- [RenukaSelvar/system_bt_aosp10_cve-2022-20140](https://github.com/RenukaSelvar/system_bt_aosp10_cve-2022-20140)

### CVE-2022-20186 (2022-06-15)

<code>In kbase_mem_alias of mali_kbase_mem_linux.c, there is a possible arbitrary code execution due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-215001024References: N/A
</code>

- [SmileTabLabo/CVE-2022-20186](https://github.com/SmileTabLabo/CVE-2022-20186)

### CVE-2022-20223 (2022-07-13)

<code>In assertSafeToStartCustomActivity of AppRestrictionsFragment.java, there is a possible way to start a phone call without permissions due to a confused deputy. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-223578534
</code>

- [xbee9/cve-2022-20223](https://github.com/xbee9/cve-2022-20223)

### CVE-2022-20338 (2022-08-11)

<code>In HierarchicalUri.readFrom of Uri.java, there is a possible way to craft a malformed Uri object due to improper input validation. This could lead to a local escalation of privilege, preventing processes from validating URIs correctly, with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-11 Android-12 Android-12LAndroid ID: A-171966843
</code>

- [Satheesh575555/frameworks_base_AOSP_06_r22_CVE-2022-20338](https://github.com/Satheesh575555/frameworks_base_AOSP_06_r22_CVE-2022-20338)
- [Trinadh465/frameworks_base_AOSP10_r33_CVE-2022-20338](https://github.com/Trinadh465/frameworks_base_AOSP10_r33_CVE-2022-20338)
- [Trinadh465/frameworks_base_AOSP_10_r33_CVE-2022-20338](https://github.com/Trinadh465/frameworks_base_AOSP_10_r33_CVE-2022-20338)

### CVE-2022-20347 (2022-08-09)

<code>In onAttach of ConnectedDeviceDashboardFragment.java, there is a possible permission bypass due to a confused deputy. This could lead to remote escalation of privilege in Bluetooth settings with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-228450811
</code>

- [ShaikUsaf/packages_apps_settings_AOSP10_r33_CVE-2022-20347](https://github.com/ShaikUsaf/packages_apps_settings_AOSP10_r33_CVE-2022-20347)
- [Trinadh465/packages_apps_Settings_AOSP10_r33_CVE-2022-20347](https://github.com/Trinadh465/packages_apps_Settings_AOSP10_r33_CVE-2022-20347)

### CVE-2022-20409 (2022-10-11)

<code>In io_identity_cow of io_uring.c, there is a possible way to corrupt memory due to a use after free. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-238177383References: Upstream kernel
</code>

- [Markakd/bad_io_uring](https://github.com/Markakd/bad_io_uring)

### CVE-2022-20474 (2022-12-13)

<code>In readLazyValue of Parcel.java, there is a possible loading of arbitrary code into the System Settings app due to a confused deputy. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12L Android-13Android ID: A-240138294
</code>

- [cxxsheng/CVE-2022-20474](https://github.com/cxxsheng/CVE-2022-20474)

### CVE-2022-20818 (2022-09-30)

<code>Multiple vulnerabilities in the CLI of Cisco SD-WAN Software could allow an authenticated, local attacker to gain elevated privileges. These vulnerabilities are due to improper access controls on commands within the application CLI. An attacker could exploit these vulnerabilities by running a malicious command on the application CLI. A successful exploit could allow the attacker to execute arbitrary commands as the root user.
</code>

- [mbadanoiu/CVE-2022-20818](https://github.com/mbadanoiu/CVE-2022-20818)

### CVE-2022-20829 (2022-06-24)

<code>A vulnerability in the packaging of Cisco Adaptive Security Device Manager (ASDM) images and the validation of those images by Cisco Adaptive Security Appliance (ASA) Software could allow an authenticated, remote attacker with administrative privileges to upload an ASDM image that contains malicious code to a device that is running Cisco ASA Software. This vulnerability is due to insufficient validation of the authenticity of an ASDM image during its installation on a device that is running Cisco ASA Software. An attacker could exploit this vulnerability by installing a crafted ASDM image on the device that is running Cisco ASA Software and then waiting for a targeted user to access that device using ASDM. A successful exploit could allow the attacker to execute arbitrary code on the machine of the targeted user with the privileges of that user on that machine. Notes: To successfully exploit this vulnerability, the attacker must have administrative privileges on the device that is running Cisco ASA Software. Potential targets are limited to users who manage the same device that is running Cisco ASA Software using ASDM. Cisco has released and will release software updates that address this vulnerability.
</code>

- [jbaines-r7/theway](https://github.com/jbaines-r7/theway)

### CVE-2022-21340 (2022-01-19)

<code>Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Libraries). Supported versions that are affected are Oracle Java SE: 7u321, 8u311, 11.0.13, 17.0.1; Oracle GraalVM Enterprise Edition: 20.3.4 and 21.3.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM Enterprise Edition. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. CVSS 3.1 Base Score 5.3 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L).
</code>

- [Alexandre-Bartel/CVE-2022-21340](https://github.com/Alexandre-Bartel/CVE-2022-21340)

### CVE-2022-21350 (2022-01-19)

<code>Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle WebLogic Server accessible data and unauthorized ability to cause a partial denial of service (partial DOS) of Oracle WebLogic Server. CVSS 3.1 Base Score 6.5 (Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L).
</code>

- [hktalent/CVE-2022-21350](https://github.com/hktalent/CVE-2022-21350)

### CVE-2022-21371 (2022-01-19)

<code>Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Web Container). Supported versions that are affected are 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).
</code>

- [Cappricio-Securities/CVE-2022-21371](https://github.com/Cappricio-Securities/CVE-2022-21371)

### CVE-2022-21392 (2022-01-19)

<code>Vulnerability in the Enterprise Manager Base Platform product of Oracle Enterprise Manager (component: Policy Framework). Supported versions that are affected are 13.4.0.0 and 13.5.0.0. Easily exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise Enterprise Manager Base Platform. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Enterprise Manager Base Platform accessible data as well as unauthorized update, insert or delete access to some of Enterprise Manager Base Platform accessible data. CVSS 3.1 Base Score 8.8 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H).
</code>

- [mbadanoiu/CVE-2022-21392](https://github.com/mbadanoiu/CVE-2022-21392)

### CVE-2022-21445 (2022-04-19)

<code>Vulnerability in the Oracle Application Development Framework (ADF) product of Oracle Fusion Middleware (component: ADF Faces).  Supported versions that are affected are 12.2.1.3.0 and  12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Application Development Framework (ADF).  Successful attacks of this vulnerability can result in takeover of Oracle Application Development Framework (ADF). Note: Oracle Application Development Framework (ADF) is downloaded via Oracle JDeveloper Product. Please refer to Fusion Middleware Patch Advisor for more details. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
</code>

- [hienkiet/CVE-2022-21445-for-12.2.1.3.0-Weblogic](https://github.com/hienkiet/CVE-2022-21445-for-12.2.1.3.0-Weblogic)

### CVE-2022-21449 (2022-04-19)

<code>Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Libraries). Supported versions that are affected are Oracle Java SE: 17.0.2 and 18; Oracle GraalVM Enterprise Edition: 21.3.1 and 22.0.0.2. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification access to critical data or all Oracle Java SE, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. CVSS 3.1 Base Score 7.5 (Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N).
</code>

- [davwwwx/CVE-2022-21449](https://github.com/davwwwx/CVE-2022-21449)
- [AlexanderZinoni/CVE-2022-21449](https://github.com/AlexanderZinoni/CVE-2022-21449)
- [HeyMrSalt/AIS3-2024-Project-D5Team](https://github.com/HeyMrSalt/AIS3-2024-Project-D5Team)

### CVE-2022-21500 (2022-05-19)

<code>Vulnerability in Oracle E-Business Suite (component: Manage Proxies). The supported version that is affected is 12.2. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle E-Business Suite. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle E-Business Suite accessible data. Note: Authentication is required for successful attack, however the user may be self-registered. &lt;br&gt; &lt;br&gt;Oracle E-Business Suite 12.1 is not impacted by this vulnerability. Customers should refer to the Patch Availability Document for details. CVSS 3.1 Base Score 7.5 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).
</code>

- [Cappricio-Securities/CVE-2022-21500](https://github.com/Cappricio-Securities/CVE-2022-21500)

### CVE-2022-21661 (2022-01-06)

<code>WordPress is a free and open-source content management system written in PHP and paired with a MariaDB database. Due to improper sanitization in WP_Query, there can be cases where SQL injection is possible through plugins or themes that use it in a certain way. This has been patched in WordPress version 5.8.3. Older affected versions are also fixed via security release, that go back till 3.7.37. We strongly recommend that you keep auto-updates enabled. There are no known workarounds for this vulnerability.
</code>

- [TAPESH-TEAM/CVE-2022-21661-WordPress-Core-5.8.2-WP_Query-SQL-Injection](https://github.com/TAPESH-TEAM/CVE-2022-21661-WordPress-Core-5.8.2-WP_Query-SQL-Injection)
- [z92g/CVE-2022-21661](https://github.com/z92g/CVE-2022-21661)
- [WellingtonEspindula/SSI-CVE-2022-21661](https://github.com/WellingtonEspindula/SSI-CVE-2022-21661)
- [p4ncontomat3/CVE-2022-21661](https://github.com/p4ncontomat3/CVE-2022-21661)
- [CharonDefalt/WordPress--CVE-2022-21661](https://github.com/CharonDefalt/WordPress--CVE-2022-21661)
- [w0r1i0g1ht/CVE-2022-21661](https://github.com/w0r1i0g1ht/CVE-2022-21661)
- [kittypurrnaz/cve-2022-21661](https://github.com/kittypurrnaz/cve-2022-21661)

### CVE-2022-21789 (2022-08-01)

<code>In audio ipi, there is a possible memory corruption due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06478101; Issue ID: ALPS06478101.
</code>

- [docfate111/CVE-2022-21789](https://github.com/docfate111/CVE-2022-21789)

### CVE-2022-21894 (2022-01-11)

<code>Secure Boot Security Feature Bypass Vulnerability
</code>

- [Wack0/CVE-2022-21894](https://github.com/Wack0/CVE-2022-21894)
- [ASkyeye/CVE-2022-21894-Payload](https://github.com/ASkyeye/CVE-2022-21894-Payload)
- [nova-master/CVE-2022-21894-Payload-New](https://github.com/nova-master/CVE-2022-21894-Payload-New)

### CVE-2022-21907 (2022-01-11)

<code>HTTP Protocol Stack Remote Code Execution Vulnerability
</code>

- [corelight/cve-2022-21907](https://github.com/corelight/cve-2022-21907)
- [p0dalirius/CVE-2022-21907-http.sys](https://github.com/p0dalirius/CVE-2022-21907-http.sys)
- [Malwareman007/CVE-2022-21907](https://github.com/Malwareman007/CVE-2022-21907)
- [asepsaepdin/CVE-2022-21907](https://github.com/asepsaepdin/CVE-2022-21907)
- [kamal-marouane/CVE-2022-21907](https://github.com/kamal-marouane/CVE-2022-21907)

### CVE-2022-22274 (2022-03-25)

<code>A Stack-based buffer overflow vulnerability in the SonicOS via HTTP request allows a remote unauthenticated attacker to cause Denial of Service (DoS) or potentially results in code execution in the firewall.
</code>

- [BishopFox/CVE-2022-22274_CVE-2023-0656](https://github.com/BishopFox/CVE-2022-22274_CVE-2023-0656)

### CVE-2022-22555 (2022-07-20)

<code>Dell EMC PowerStore, contains an OS command injection Vulnerability. A locally authenticated attacker could potentially exploit this vulnerability, leading to the execution of arbitrary OS commands on the PowerStore underlying OS, with the privileges of the vulnerable application. Exploitation may lead to an elevation of privilege.
</code>

- [colaoo123/cve-2022-22555](https://github.com/colaoo123/cve-2022-22555)

### CVE-2022-22620 (2022-03-18)

<code>A use after free issue was addressed with improved memory management. This issue is fixed in macOS Monterey 12.2.1, iOS 15.3.1 and iPadOS 15.3.1, Safari 15.3 (v. 16612.4.9.1.8 and 15612.4.9.1.8). Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been actively exploited..
</code>

- [kmeps4/CVE-2022-22620](https://github.com/kmeps4/CVE-2022-22620)

### CVE-2022-22629 (2022-09-23)

<code>A buffer overflow issue was addressed with improved memory handling. This issue is fixed in macOS Monterey 12.3, Safari 15.4, watchOS 8.5, iTunes 12.12.3 for Windows, iOS 15.4 and iPadOS 15.4, tvOS 15.4. Processing maliciously crafted web content may lead to arbitrary code execution.
</code>

- [lck0/CVE-2022-22629](https://github.com/lck0/CVE-2022-22629)

### CVE-2022-22720 (2022-03-14)

<code>Apache HTTP Server 2.4.52 and earlier fails to close inbound connection when errors are encountered discarding the request body, exposing the server to HTTP Request Smuggling
</code>

- [Benasin/CVE-2022-22720](https://github.com/Benasin/CVE-2022-22720)

### CVE-2022-22814 (2022-03-10)

<code>The System Diagnosis service of MyASUS before 3.1.2.0 allows privilege escalation.
</code>

- [DShankle/CVE-2022-22814_PoC](https://github.com/DShankle/CVE-2022-22814_PoC)

### CVE-2022-22818 (2022-02-03)

<code>The {% debug %} template tag in Django 2.2 before 2.2.27, 3.2 before 3.2.12, and 4.0 before 4.0.2 does not properly encode the current context. This may lead to XSS.
</code>

- [Prikalel/django-xss-example](https://github.com/Prikalel/django-xss-example)

### CVE-2022-22822 (2022-01-08)

<code>addBinding in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow.
</code>

- [nanopathi/external_expat_AOSP10_r33_CVE-2022-22822toCVE-2022-22827](https://github.com/nanopathi/external_expat_AOSP10_r33_CVE-2022-22822toCVE-2022-22827)

### CVE-2022-22885 (2022-02-16)

<code>Hutool v5.7.18's HttpRequest was discovered to ignore all TLS/SSL certificate validation.
</code>

- [miguelc49/CVE-2022-22885-2](https://github.com/miguelc49/CVE-2022-22885-2)
- [miguelc49/CVE-2022-22885-1](https://github.com/miguelc49/CVE-2022-22885-1)

### CVE-2022-22909 (2022-03-02)

<code>HotelDruid v3.0.3 was discovered to contain a remote code execution (RCE) vulnerability which is exploited via an attacker inserting a crafted payload into the name field under the Create New Room module.
</code>

- [0z09e/CVE-2022-22909](https://github.com/0z09e/CVE-2022-22909)

### CVE-2022-22947 (2022-03-03)

<code>In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.
</code>

- [Axx8/CVE-2022-22947_Rce_Exp](https://github.com/Axx8/CVE-2022-22947_Rce_Exp)
- [k3rwin/spring-cloud-gateway-rce](https://github.com/k3rwin/spring-cloud-gateway-rce)
- [4nNns/CVE-2022-22947](https://github.com/4nNns/CVE-2022-22947)
- [Sumitpathania03/CVE-2022-22947](https://github.com/Sumitpathania03/CVE-2022-22947)
- [cc3305/CVE-2022-22947](https://github.com/cc3305/CVE-2022-22947)

### CVE-2022-22948 (2022-03-29)

<code>The vCenter Server contains an information disclosure vulnerability due to improper permission of files. A malicious actor with non-administrative access to the vCenter Server may exploit this issue to gain access to sensitive information.
</code>

- [PenteraIO/CVE-2022-22948](https://github.com/PenteraIO/CVE-2022-22948)

### CVE-2022-22954 (2022-04-11)

<code>VMware Workspace ONE Access and Identity Manager contain a remote code execution vulnerability due to server-side template injection. A malicious actor with network access can trigger a server-side template injection that may result in remote code execution.
</code>

- [corelight/cve-2022-22954](https://github.com/corelight/cve-2022-22954)
- [tunelko/CVE-2022-22954-PoC](https://github.com/tunelko/CVE-2022-22954-PoC)
- [Schira4396/VcenterKiller](https://github.com/Schira4396/VcenterKiller)

### CVE-2022-22963 (2022-04-01)

<code>In Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions, when using routing functionality it is possible for a user to provide a specially crafted SpEL as a routing-expression that may result in remote code execution and access to local resources.
</code>

- [hktalent/spring-spel-0day-poc](https://github.com/hktalent/spring-spel-0day-poc)
- [G01d3nW01f/CVE-2022-22963](https://github.com/G01d3nW01f/CVE-2022-22963)
- [75ACOL/CVE-2022-22963](https://github.com/75ACOL/CVE-2022-22963)
- [BearClaw96/CVE-2022-22963-Poc-Bearcules](https://github.com/BearClaw96/CVE-2022-22963-Poc-Bearcules)
- [jrbH4CK/CVE-2022-22963](https://github.com/jrbH4CK/CVE-2022-22963)
- [Shayz614/CVE-2022-22963](https://github.com/Shayz614/CVE-2022-22963)

### CVE-2022-22965 (2022-04-01)

<code>A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.
</code>

- [BobTheShoplifter/Spring4Shell-POC](https://github.com/BobTheShoplifter/Spring4Shell-POC)
- [reznok/Spring4Shell-POC](https://github.com/reznok/Spring4Shell-POC)
- [DDuarte/springshell-rce-poc](https://github.com/DDuarte/springshell-rce-poc)
- [viniciuspereiras/CVE-2022-22965-poc](https://github.com/viniciuspereiras/CVE-2022-22965-poc)
- [likewhite/CVE-2022-22965](https://github.com/likewhite/CVE-2022-22965)
- [sunnyvale-it/CVE-2022-22965-PoC](https://github.com/sunnyvale-it/CVE-2022-22965-PoC)
- [0xrobiul/CVE-2022-22965](https://github.com/0xrobiul/CVE-2022-22965)
- [cxzero/CVE-2022-22965-spring4shell](https://github.com/cxzero/CVE-2022-22965-spring4shell)
- [tpt11fb/SpringVulScan](https://github.com/tpt11fb/SpringVulScan)
- [zangcc/CVE-2022-22965-rexbb](https://github.com/zangcc/CVE-2022-22965-rexbb)
- [bL34cHig0/Telstra-Cybersecurity-Virtual-Experience-](https://github.com/bL34cHig0/Telstra-Cybersecurity-Virtual-Experience-)
- [sohamsharma966/Spring4Shell-CVE-2022-22965](https://github.com/sohamsharma966/Spring4Shell-CVE-2022-22965)
- [LucasPDiniz/CVE-2022-22965](https://github.com/LucasPDiniz/CVE-2022-22965)
- [xsxtw/SpringFramework_CVE-2022-22965_RCE](https://github.com/xsxtw/SpringFramework_CVE-2022-22965_RCE)
- [Aur3ns/Block-Spring4Shell](https://github.com/Aur3ns/Block-Spring4Shell)
- [guigui237/Expoitation-de-la-vuln-rabilit-CVE-2022-22965](https://github.com/guigui237/Expoitation-de-la-vuln-rabilit-CVE-2022-22965)
- [jashan-lefty/Spring4Shell](https://github.com/jashan-lefty/Spring4Shell)

### CVE-2022-22970 (2022-05-12)

<code>In spring framework versions prior to 5.3.20+ , 5.2.22+ and old unsupported versions, applications that handle file uploads are vulnerable to DoS attack if they rely on data binding to set a MultipartFile or javax.servlet.Part to a field in a model object.
</code>

- [Performant-Labs/CVE-2022-22970](https://github.com/Performant-Labs/CVE-2022-22970)

### CVE-2022-22978 (2022-05-19)

<code>In spring security versions prior to 5.4.11+, 5.5.7+ , 5.6.4+ and older unsupported versions, RegexRequestMatcher can easily be misconfigured to be bypassed on some servlet containers. Applications using RegexRequestMatcher with `.` in the regular expression are possibly vulnerable to an authorization bypass.
</code>

- [Raghvendra1207/CVE-2022-22978](https://github.com/Raghvendra1207/CVE-2022-22978)
- [wan9xx/CVE-2022-22978-demo](https://github.com/wan9xx/CVE-2022-22978-demo)
- [BoB13-Opensource-Contribution-Team9/CVE-2022-22978](https://github.com/BoB13-Opensource-Contribution-Team9/CVE-2022-22978)

### CVE-2022-22980 (2022-06-22)

<code>A Spring Data MongoDB application is vulnerable to SpEL Injection when using @Query or @Aggregation-annotated query methods with SpEL expressions that contain query parameter placeholders for value binding if the input is not sanitized.
</code>

- [kuron3k0/Spring-Data-Mongodb-Example](https://github.com/kuron3k0/Spring-Data-Mongodb-Example)

### CVE-2022-23046 (2022-01-19)

<code>PhpIPAM v1.4.4 allows an authenticated admin user to inject SQL sentences in the &quot;subnet&quot; parameter while searching a subnet via app/admin/routing/edit-bgp-mapping-search.php
</code>

- [hadrian3689/phpipam_1.4.4](https://github.com/hadrian3689/phpipam_1.4.4)

### CVE-2022-23093 (2024-02-15)

<code>ping reads raw IP packets from the network to process responses in the pr_pack() function.  As part of processing a response ping has to reconstruct the IP header, the ICMP header and if present a &quot;quoted packet,&quot; which represents the packet that generated an ICMP error.  The quoted packet again has an IP header and an ICMP header.\n\nThe pr_pack() copies received IP and ICMP headers into stack buffers for further processing.  In so doing, it fails to take into account the possible presence of IP option headers following the IP header in either the response or the quoted packet.  When IP options are present, pr_pack() overflows the destination buffer by up to 40 bytes.\n\nThe memory safety bugs described above can be triggered by a remote host, causing the ping program to crash.\n\nThe ping process runs in a capability mode sandbox on all affected versions of FreeBSD and is thus very constrained in how it can interact with the rest of the system at the point where the bug can occur.
</code>

- [Symbolexe/DrayTek-Exploit](https://github.com/Symbolexe/DrayTek-Exploit)

### CVE-2022-23131 (2022-01-13)

<code>In the case of instances where the SAML SSO authentication is enabled (non-default), session data can be modified by a malicious actor, because a user login stored in the session was not verified. Malicious unauthenticated actor may exploit this issue to escalate privileges and gain admin access to Zabbix Frontend. To perform the attack, SAML authentication is required to be enabled and the actor has to know the username of Zabbix user (or use the guest account, which is disabled by default).
</code>

- [Mr-xn/cve-2022-23131](https://github.com/Mr-xn/cve-2022-23131)
- [Vulnmachines/Zabbix-CVE-2022-23131](https://github.com/Vulnmachines/Zabbix-CVE-2022-23131)
- [r10lab/CVE-2022-23131](https://github.com/r10lab/CVE-2022-23131)
- [fork-bombed/CVE-2022-23131](https://github.com/fork-bombed/CVE-2022-23131)
- [davidzzo23/CVE-2022-23131](https://github.com/davidzzo23/CVE-2022-23131)
- [dagowda/Zabbix-cve-2022-23131-SSO-bypass](https://github.com/dagowda/Zabbix-cve-2022-23131-SSO-bypass)
- [worstundersh/CVE-2022-23131](https://github.com/worstundersh/CVE-2022-23131)

### CVE-2022-23305 (2022-01-18)

<code>By design, the JDBCAppender in Log4j 1.2.x accepts an SQL statement as a configuration parameter where the values to be inserted are converters from PatternLayout. The message converter, %m, is likely to always be included. This allows attackers to manipulate the SQL by entering crafted strings into input fields or headers of an application that are logged allowing unintended SQL queries to be executed. Note this issue only affects Log4j 1.x when specifically configured to use the JDBCAppender, which is not the default. Beginning in version 2.0-beta8, the JDBCAppender was re-introduced with proper support for parameterized SQL queries and further customization over the columns written to in logs. Apache Log4j 1.2 reached end of life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the previous versions.
</code>

- [HynekPetrak/log4shell-finder](https://github.com/HynekPetrak/log4shell-finder)

### CVE-2022-23773 (2022-02-11)

<code>cmd/go in Go before 1.16.14 and 1.17.x before 1.17.7 can misinterpret branch names that falsely appear to be version tags. This can lead to incorrect access control if an actor is supposed to be able to create branches but not tags.
</code>

- [danbudris/CVE-2022-23773-repro](https://github.com/danbudris/CVE-2022-23773-repro)
- [danbudris/CVE-2022-23773-repro-target](https://github.com/danbudris/CVE-2022-23773-repro-target)

### CVE-2022-23779 (2022-03-02)

<code>Zoho ManageEngine Desktop Central before 10.1.2137.8 exposes the installed server name to anyone. The internal hostname can be discovered by reading HTTP redirect responses.
</code>

- [Vulnmachines/Zoho_CVE-2022-23779](https://github.com/Vulnmachines/Zoho_CVE-2022-23779)

### CVE-2022-23808 (2022-01-22)

<code>An issue was discovered in phpMyAdmin 5.1 before 5.1.2. An attacker can inject malicious code into aspects of the setup script, which can allow XSS or HTML injection.
</code>

- [dipakpanchal05/CVE-2022-23808](https://github.com/dipakpanchal05/CVE-2022-23808)

### CVE-2022-23861 (2024-10-22)

<code>Multiple Stored Cross-Site Scripting vulnerabilities were discovered in Y Soft SAFEQ 6 Build 53. Multiple fields in the YSoft SafeQ web application can be used to inject malicious inputs that, due to a lack of output sanitization, result in the execution of arbitrary JS code. These fields can be leveraged to perform XSS attacks on legitimate users accessing the SafeQ web interface.
</code>

- [mbadanoiu/CVE-2022-23861](https://github.com/mbadanoiu/CVE-2022-23861)

### CVE-2022-23862 (2024-10-22)

<code>A Local Privilege Escalation issue was discovered in Y Soft SAFEQ 6 Build 53. The SafeQ JMX service running on port 9696 is vulnerable to JMX MLet attacks. Because the service did not enforce authentication and was running under the &quot;NT Authority\System&quot; user, an attacker is able to use the vulnerability to execute arbitrary code and elevate to the system user.
</code>

- [mbadanoiu/CVE-2022-23862](https://github.com/mbadanoiu/CVE-2022-23862)

### CVE-2022-23988 (2022-02-28)

<code>The WS Form LITE and Pro WordPress plugins before 1.8.176 do not sanitise and escape submitted form data, allowing unauthenticated attacker to submit XSS payloads which will get executed when a privileged user will view the related submission
</code>

- [simonepetruzzi/WebSecurityProject](https://github.com/simonepetruzzi/WebSecurityProject)

### CVE-2022-24086 (2022-02-16)

<code>Adobe Commerce versions 2.4.3-p1 (and earlier) and 2.3.7-p2 (and earlier) are affected by an improper input validation vulnerability during the checkout process. Exploitation of this issue does not require user interaction and could result in arbitrary code execution.
</code>

- [Mr-xn/CVE-2022-24086](https://github.com/Mr-xn/CVE-2022-24086)
- [oK0mo/CVE-2022-24086-RCE-PoC](https://github.com/oK0mo/CVE-2022-24086-RCE-PoC)
- [BurpRoot/CVE-2022-24086](https://github.com/BurpRoot/CVE-2022-24086)
- [wubinworks/magento2-template-filter-patch](https://github.com/wubinworks/magento2-template-filter-patch)

### CVE-2022-24112 (2022-02-11)

<code>An attacker can abuse the batch-requests plugin to send requests to bypass the IP restriction of Admin API. A default configuration of Apache APISIX (with default API key) is vulnerable to remote code execution. When the admin key was changed or the port of Admin API was changed to a port different from the data panel, the impact is lower. But there is still a risk to bypass the IP restriction of Apache APISIX's data panel. There is a check in the batch-requests plugin which overrides the client IP with its real remote IP. But due to a bug in the code, this check can be bypassed.
</code>

- [btar1gan/exploit_CVE-2022-24112](https://github.com/btar1gan/exploit_CVE-2022-24112)

### CVE-2022-24124 (2022-01-29)

<code>The query API in Casdoor before 1.13.1 has a SQL injection vulnerability related to the field and value parameters, as demonstrated by api/get-organizations.
</code>

- [b1gdog/CVE-2022-24124](https://github.com/b1gdog/CVE-2022-24124)

### CVE-2022-24125 (2022-03-20)

<code>The matchmaking servers of Bandai Namco FromSoftware Dark Souls III through 2022-03-19 allow remote attackers to send arbitrary push requests to clients via a RequestSendMessageToPlayers request. For example, ability to send a push message to hundreds of thousands of machines is only restricted on the client side, and can thus be bypassed with a modified client.
</code>

- [tremwil/ds3-nrssr-rce](https://github.com/tremwil/ds3-nrssr-rce)

### CVE-2022-24181 (2022-04-01)

<code>Cross-site scripting (XSS) via Host Header injection in PKP Open Journals System 2.4.8 &gt;= 3.3 allows remote attackers to inject arbitary code via the X-Forwarded-Host Header.
</code>

- [cyberhawk000/CVE-2022-24181](https://github.com/cyberhawk000/CVE-2022-24181)

### CVE-2022-24227 (2022-02-15)

<code>A cross-site scripting (XSS) vulnerability in BoltWire v7.10 and v 8.00 allows attackers to execute arbitrary web scripts or HTML via a crafted payload in the name and lastname parameters.
</code>

- [Cyber-Wo0dy/CVE-2022-24227-updated](https://github.com/Cyber-Wo0dy/CVE-2022-24227-updated)

### CVE-2022-24348 (2022-02-04)

<code>Argo CD before 2.1.9 and 2.2.x before 2.2.4 allows directory traversal related to Helm charts because of an error in helmTemplate in repository.go. For example, an attacker may be able to discover credentials stored in a YAML file.
</code>

- [jkroepke/CVE-2022-24348-2](https://github.com/jkroepke/CVE-2022-24348-2)

### CVE-2022-24439 (2022-12-12)

<code>All versions of package gitpython are vulnerable to Remote Code Execution (RCE) due to improper user input validation, which makes it possible to inject a maliciously crafted remote URL into the clone command. Exploiting this vulnerability is possible because the library makes external calls to git without sufficient sanitization of input arguments.
</code>

- [muhammadhendro/CVE-2022-24439](https://github.com/muhammadhendro/CVE-2022-24439)

### CVE-2022-24442 (2022-02-25)

<code>JetBrains YouTrack before 2021.4.40426 was vulnerable to SSTI (Server-Side Template Injection) via FreeMarker templates.
</code>

- [mbadanoiu/CVE-2022-24442](https://github.com/mbadanoiu/CVE-2022-24442)

### CVE-2022-24491 (2022-04-15)

<code>Windows Network File System Remote Code Execution Vulnerability
</code>

- [corelight/CVE-2022-24491](https://github.com/corelight/CVE-2022-24491)

### CVE-2022-24497 (2022-04-15)

<code>Windows Network File System Remote Code Execution Vulnerability
</code>

- [corelight/CVE-2022-24497](https://github.com/corelight/CVE-2022-24497)

### CVE-2022-24637 (2022-03-18)

<code>Open Web Analytics (OWA) before 1.7.4 allows an unauthenticated remote attacker to obtain sensitive user information, which can be used to gain admin privileges by leveraging cache hashes. This occurs because files generated with '&lt;?php (instead of the intended &quot;&lt;?php sequence) aren't handled by the PHP interpreter.
</code>

- [JacobEbben/CVE-2022-24637](https://github.com/JacobEbben/CVE-2022-24637)
- [0xRyuk/CVE-2022-24637](https://github.com/0xRyuk/CVE-2022-24637)

### CVE-2022-24644 (2022-03-07)

<code>ZZ Inc. KeyMouse Windows 3.08 and prior is affected by a remote code execution vulnerability during an unauthenticated update. To exploit this vulnerability, a user must trigger an update of an affected installation of KeyMouse.
</code>

- [gerr-re/cve-2022-24644](https://github.com/gerr-re/cve-2022-24644)

### CVE-2022-24693 (2022-03-30)

<code>Baicells Nova436Q and Neutrino 430 devices with firmware through QRTB 2.7.8 have hardcoded credentials that are easily discovered, and can be used by remote attackers to authenticate via ssh. (The credentials are stored in the firmware, encrypted by the crypt function.)
</code>

- [lukejenkins/CVE-2022-24693](https://github.com/lukejenkins/CVE-2022-24693)

### CVE-2022-24715 (2022-03-08)

<code>Icinga Web 2 is an open source monitoring web interface, framework and command-line interface. Authenticated users, with access to the configuration, can create SSH resource files in unintended directories, leading to the execution of arbitrary code. This issue has been resolved in versions 2.8.6, 2.9.6 and 2.10 of Icinga Web 2. Users unable to upgrade should limit access to the Icinga Web 2 configuration.
</code>

- [d4rkb0n3/CVE-2022-24715-go](https://github.com/d4rkb0n3/CVE-2022-24715-go)

### CVE-2022-24716 (2022-03-08)

<code>Icinga Web 2 is an open source monitoring web interface, framework and command-line interface. Unauthenticated users can leak the contents of files of the local system accessible to the web-server user, including `icingaweb2` configuration files with database credentials. This issue has been resolved in versions 2.9.6 and 2.10 of Icinga Web 2. Database credentials should be rotated.
</code>

- [joaoviictorti/CVE-2022-24716](https://github.com/joaoviictorti/CVE-2022-24716)

### CVE-2022-24780 (2022-04-05)

<code>Combodo iTop is a web based IT Service Management tool. In versions prior to 2.7.6 and 3.0.0, users of the iTop user portal can send TWIG code to the server by forging specific http queries, and execute arbitrary code on the server using http server user privileges. This issue is fixed in versions 2.7.6 and 3.0.0. There are currently no known workarounds.
</code>

- [Acceis/exploit-CVE-2022-24780](https://github.com/Acceis/exploit-CVE-2022-24780)

### CVE-2022-24816 (2022-04-13)

<code>JAI-EXT is an open-source project which aims to extend the Java Advanced Imaging (JAI) API. Programs allowing Jiffle script to be provided via network request can lead to a Remote Code Execution as the Jiffle script is compiled into Java code via Janino, and executed. In particular, this affects the downstream GeoServer project. Version 1.2.22 will contain a patch that disables the ability to inject malicious code into the resulting script. Users unable to upgrade may negate the ability to compile Jiffle scripts from the final application, by removing janino-x.y.z.jar from the classpath.
</code>

- [c1ph3rbyt3/CVE-2022-24816](https://github.com/c1ph3rbyt3/CVE-2022-24816)

### CVE-2022-24818 (2022-04-13)

<code>GeoTools is an open source Java library that provides tools for geospatial data. The GeoTools library has a number of data sources that can perform unchecked JNDI lookups, which in turn can be used to perform class deserialization and result in arbitrary code execution. Similar to the Log4J case, the vulnerability can be triggered if the JNDI names are user-provided, but requires admin-level login to be triggered. The lookups are now restricted in GeoTools 26.4, GeoTools 25.6, and GeoTools 24.6. Users unable to upgrade should ensure that any downstream application should not allow usage of remotely provided JNDI strings.
</code>

- [mbadanoiu/CVE-2022-24818](https://github.com/mbadanoiu/CVE-2022-24818)

### CVE-2022-24834 (2023-07-13)

<code>Redis is an in-memory database that persists on disk. A specially crafted Lua script executing in Redis can trigger a heap overflow in the cjson library, and result with heap corruption and potentially remote code execution. The problem exists in all versions of Redis with Lua scripting support, starting from 2.6, and affects only authenticated and authorized users. The problem is fixed in versions 7.0.12, 6.2.13, and 6.0.20.
</code>

- [DukeSec97/CVE-2022-24834-](https://github.com/DukeSec97/CVE-2022-24834-)

### CVE-2022-24853 (2022-04-14)

<code>Metabase is an open source business intelligence and analytics application. Metabase has a proxy to load arbitrary URLs for JSON maps as part of our GeoJSON support. While we do validation to not return contents of arbitrary URLs, there is a case where a particularly crafted request could result in file access on windows, which allows enabling an `NTLM relay attack`, potentially allowing an attacker to receive the system password hash. If you use Windows and are on this version of Metabase, please upgrade immediately. The following patches (or greater versions) are available: 0.42.4 and 1.42.4, 0.41.7 and 1.41.7, 0.40.8 and 1.40.8.
</code>

- [secure-77/CVE-2022-24853](https://github.com/secure-77/CVE-2022-24853)

### CVE-2022-24934 (2022-03-23)

<code>wpsupdater.exe in Kingsoft WPS Office through 11.2.0.10382 allows remote code execution by modifying HKEY_CURRENT_USER in the registry.
</code>

- [webraybtl/CVE-2022-24934](https://github.com/webraybtl/CVE-2022-24934)

### CVE-2022-24999 (2022-11-26)

<code>qs before 6.10.3, as used in Express before 4.17.3 and other products, allows attackers to cause a Node process hang for an Express application because an __ proto__ key can be used. In many typical Express use cases, an unauthenticated remote attacker can place the attack payload in the query string of the URL that is used to visit the application, such as a[__proto__]=b&amp;a[__proto__]&amp;a[length]=100000000. The fix was backported to qs 6.9.7, 6.8.3, 6.7.3, 6.6.1, 6.5.3, 6.4.1, 6.3.3, and 6.2.4 (and therefore Express 4.17.3, which has &quot;deps: qs@6.9.7&quot; in its release description, is not vulnerable).
</code>

- [n8tz/CVE-2022-24999](https://github.com/n8tz/CVE-2022-24999)

### CVE-2022-25260 (2022-02-25)

<code>JetBrains Hub before 2021.1.14276 was vulnerable to blind Server-Side Request Forgery (SSRF).
</code>

- [yuriisanin/CVE-2022-25260](https://github.com/yuriisanin/CVE-2022-25260)

### CVE-2022-25262 (2022-02-25)

<code>In JetBrains Hub before 2022.1.14434, SAML request takeover was possible.
</code>

- [yuriisanin/CVE-2022-25262](https://github.com/yuriisanin/CVE-2022-25262)

### CVE-2022-25479 (2024-07-02)

<code>Vulnerability in Realtek RtsPer driver for PCIe Card Reader (RtsPer.sys) before 10.0.22000.21355 and Realtek RtsUer driver for USB Card Reader (RtsUer.sys) before 10.0.22000.31274 allows for the leakage of kernel memory from both the stack and the heap.
</code>

- [SpiralBL0CK/CVE-2024-40431-CVE-2022-25479-EOP-CHAIN](https://github.com/SpiralBL0CK/CVE-2024-40431-CVE-2022-25479-EOP-CHAIN)

### CVE-2022-25765 (2022-09-09)

<code>The package pdfkit from 0.0.0 are vulnerable to Command Injection where the URL is not properly sanitized.
</code>

- [UNICORDev/exploit-CVE-2022-25765](https://github.com/UNICORDev/exploit-CVE-2022-25765)
- [lowercasenumbers/CVE-2022-25765](https://github.com/lowercasenumbers/CVE-2022-25765)

### CVE-2022-25813 (2022-09-02)

<code>In Apache OFBiz, versions 18.12.05 and earlier, an attacker acting as an anonymous user of the ecommerce plugin, can insert a malicious content in a message “Subject” field from the &quot;Contact us&quot; page. Then a party manager needs to list the communications in the party component to activate the SSTI. A RCE is then possible.
</code>

- [mbadanoiu/CVE-2022-25813](https://github.com/mbadanoiu/CVE-2022-25813)

### CVE-2022-25845 (2022-06-10)

<code>The package com.alibaba:fastjson before 1.2.83 are vulnerable to Deserialization of Untrusted Data by bypassing the default autoType shutdown restrictions, which is possible under certain conditions. Exploiting this vulnerability allows attacking remote servers. Workaround: If upgrading is not possible, you can enable [safeMode](https://github.com/alibaba/fastjson/wiki/fastjson_safemode).
</code>

- [hosch3n/FastjsonVulns](https://github.com/hosch3n/FastjsonVulns)
- [scabench/fastjson-tp1fn1](https://github.com/scabench/fastjson-tp1fn1)
- [luelueking/CVE-2022-25845-In-Spring](https://github.com/luelueking/CVE-2022-25845-In-Spring)
- [ph0ebus/CVE-2022-25845-In-Spring](https://github.com/ph0ebus/CVE-2022-25845-In-Spring)

### CVE-2022-25943 (2022-03-09)

<code>The installer of WPS Office for Windows versions prior to v11.2.0.10258 fails to configure properly the ACL for the directory where the service program is installed.
</code>

- [webraybtl/CVE-2022-25943](https://github.com/webraybtl/CVE-2022-25943)

### CVE-2022-26134 (2022-06-03)

<code>In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are from 1.3.0 before 7.4.17, from 7.13.0 before 7.13.7, from 7.14.0 before 7.14.3, from 7.15.0 before 7.15.2, from 7.16.0 before 7.16.4, from 7.17.0 before 7.17.4, and from 7.18.0 before 7.18.1.
</code>

- [W01fh4cker/Serein](https://github.com/W01fh4cker/Serein)
- [Vulnmachines/Confluence-CVE-2022-26134](https://github.com/Vulnmachines/Confluence-CVE-2022-26134)
- [whokilleddb/CVE-2022-26134-Confluence-RCE](https://github.com/whokilleddb/CVE-2022-26134-Confluence-RCE)
- [redhuntlabs/ConfluentPwn](https://github.com/redhuntlabs/ConfluentPwn)
- [Chocapikk/CVE-2022-26134](https://github.com/Chocapikk/CVE-2022-26134)
- [Luchoane/CVE-2022-26134_conFLU](https://github.com/Luchoane/CVE-2022-26134_conFLU)
- [nxtexploit/CVE-2022-26134](https://github.com/nxtexploit/CVE-2022-26134)
- [p4b3l1t0/confusploit](https://github.com/p4b3l1t0/confusploit)
- [Muhammad-Ali007/Atlassian_CVE-2022-26134](https://github.com/Muhammad-Ali007/Atlassian_CVE-2022-26134)
- [acfirthh/CVE-2022-26134](https://github.com/acfirthh/CVE-2022-26134)
- [yTxZx/CVE-2022-26134](https://github.com/yTxZx/CVE-2022-26134)
- [DARKSTUFF-LAB/-CVE-2022-26134](https://github.com/DARKSTUFF-LAB/-CVE-2022-26134)
- [404fu/CVE-2022-26134-POC](https://github.com/404fu/CVE-2022-26134-POC)
- [xsxtw/CVE-2022-26134](https://github.com/xsxtw/CVE-2022-26134)
- [BBD-YZZ/Confluence-RCE](https://github.com/BBD-YZZ/Confluence-RCE)
- [cc3305/CVE-2022-26134](https://github.com/cc3305/CVE-2022-26134)
- [Agentgilspy/CVE-2022-26134](https://github.com/Agentgilspy/CVE-2022-26134)
- [XiaomingX/cve-2022-26134-poc](https://github.com/XiaomingX/cve-2022-26134-poc)
- [Khalidhaimur/CVE-2022-26134](https://github.com/Khalidhaimur/CVE-2022-26134)

### CVE-2022-26135 (2022-06-30)

<code>A vulnerability in Mobile Plugin for Jira Data Center and Server allows a remote, authenticated user (including a user who joined via the sign-up feature) to perform a full read server-side request forgery via a batch endpoint. This affects Atlassian Jira Server and Data Center from version 8.0.0 before version 8.13.22, from version 8.14.0 before 8.20.10, from version 8.21.0 before 8.22.4. This also affects Jira Management Server and Data Center versions from version 4.0.0 before 4.13.22, from version 4.14.0 before 4.20.10 and from version 4.21.0 before 4.22.4.
</code>

- [assetnote/jira-mobile-ssrf-exploit](https://github.com/assetnote/jira-mobile-ssrf-exploit)

### CVE-2022-26318 (2022-03-04)

<code>On WatchGuard Firebox and XTM appliances, an unauthenticated user can execute arbitrary code, aka FBX-22786. This vulnerability impacts Fireware OS before 12.7.2_U2, 12.x before 12.1.3_U8, and 12.2.x through 12.5.x before 12.5.9_U2.
</code>

- [egilas/Watchguard-RCE-POC-CVE-2022-26318](https://github.com/egilas/Watchguard-RCE-POC-CVE-2022-26318)

### CVE-2022-26377 (2022-06-08)

<code>Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling') vulnerability in mod_proxy_ajp of Apache HTTP Server allows an attacker to smuggle requests to the AJP server it forwards requests to. This issue affects Apache HTTP Server Apache HTTP Server 2.4 version 2.4.53 and prior versions.
</code>

- [watchtowrlabs/ibm-qradar-ajp_smuggling_CVE-2022-26377_poc](https://github.com/watchtowrlabs/ibm-qradar-ajp_smuggling_CVE-2022-26377_poc)

### CVE-2022-26726 (2022-05-26)

<code>This issue was addressed with improved checks. This issue is fixed in Security Update 2022-004 Catalina, watchOS 8.6, macOS Monterey 12.4, macOS Big Sur 11.6.6. An app may be able to capture a user's screen.
</code>

- [acheong08/CVE-2022-26726-POC](https://github.com/acheong08/CVE-2022-26726-POC)

### CVE-2022-26809 (2022-04-15)

<code>Remote Procedure Call Runtime Remote Code Execution Vulnerability
</code>

- [corelight/cve-2022-26809](https://github.com/corelight/cve-2022-26809)

### CVE-2022-26923 (2022-05-10)

<code>Active Directory Domain Services Elevation of Privilege Vulnerability
</code>

- [evilashz/PIGADVulnScanner](https://github.com/evilashz/PIGADVulnScanner)
- [Gh-Badr/CVE-2022-26923](https://github.com/Gh-Badr/CVE-2022-26923)
- [Yowise/CVE-2022-26923](https://github.com/Yowise/CVE-2022-26923)
- [rayngnpc/CVE-2022-26923-rayng](https://github.com/rayngnpc/CVE-2022-26923-rayng)

### CVE-2022-26937 (2022-05-10)

<code>Windows Network File System Remote Code Execution Vulnerability
</code>

- [corelight/CVE-2022-26937](https://github.com/corelight/CVE-2022-26937)

### CVE-2022-26965 (2022-03-18)

<code>In Pluck 4.7.16, an admin user can use the theme upload functionality at /admin.php?action=themeinstall to perform remote code execution.
</code>

- [SkDevilS/Pluck-Exploitation-by-skdevils](https://github.com/SkDevilS/Pluck-Exploitation-by-skdevils)

### CVE-2022-27438 (2022-06-06)

<code>Caphyon Ltd Advanced Installer 19.3 and earlier and many products that use the updater from Advanced Installer (Advanced Updater) are affected by a remote code execution vulnerability via the CustomDetection parameter in the update check function. To exploit this vulnerability, a user must start an affected installation to trigger the update check.
</code>

- [gerr-re/cve-2022-27438](https://github.com/gerr-re/cve-2022-27438)

### CVE-2022-27646 (2023-03-29)

<code>This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations of NETGEAR R6700v3 1.0.4.120_10.0.91 routers. Although authentication is required to exploit this vulnerability, the existing authentication mechanism can be bypassed. The specific flaw exists within the circled daemon. A crafted circleinfo.txt file can trigger an overflow of a fixed-length stack-based buffer. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-15879.
</code>

- [cyber-defence-campus/netgear_r6700v3_circled](https://github.com/cyber-defence-campus/netgear_r6700v3_circled)

### CVE-2022-27665 (2023-04-03)

<code>Reflected XSS (via AngularJS sandbox escape expressions) exists in Progress Ipswitch WS_FTP Server 8.6.0. This can lead to execution of malicious code and commands on the client due to improper handling of user-provided input. By inputting malicious payloads in the subdirectory searchbar or Add folder filename boxes, it is possible to execute client-side commands. For example, there is Client-Side Template Injection via subFolderPath to the ThinClient/WtmApiService.asmx/GetFileSubTree URI.
</code>

- [dievus/CVE-2022-27665](https://github.com/dievus/CVE-2022-27665)

### CVE-2022-27925 (2022-04-20)

<code>Zimbra Collaboration (aka ZCS) 8.8.15 and 9.0 has mboximport functionality that receives a ZIP archive and extracts files from it. An authenticated user with administrator rights has the ability to upload arbitrary files to the system, leading to directory traversal.
</code>

- [mohamedbenchikh/CVE-2022-27925](https://github.com/mohamedbenchikh/CVE-2022-27925)
- [Chocapikk/CVE-2022-27925-Revshell](https://github.com/Chocapikk/CVE-2022-27925-Revshell)
- [akincibor/CVE-2022-27925](https://github.com/akincibor/CVE-2022-27925)
- [touchmycrazyredhat/CVE-2022-27925-Revshell](https://github.com/touchmycrazyredhat/CVE-2022-27925-Revshell)
- [jam620/Zimbra](https://github.com/jam620/Zimbra)
- [Inplex-sys/CVE-2022-27925](https://github.com/Inplex-sys/CVE-2022-27925)
- [sanan2004/CVE-2022-27925](https://github.com/sanan2004/CVE-2022-27925)

### CVE-2022-27997
- [Cyb3rEnthusiast/CVE-2023-27997](https://github.com/Cyb3rEnthusiast/CVE-2023-27997)

### CVE-2022-28108 (2022-04-19)

<code>Selenium Server (Grid) before 4 allows CSRF because it permits non-JSON content types such as application/x-www-form-urlencoded, multipart/form-data, and text/plain.
</code>

- [ZeroEthical/CVE-2022-28108](https://github.com/ZeroEthical/CVE-2022-28108)

### CVE-2022-28117 (2022-04-28)

<code>A Server-Side Request Forgery (SSRF) in feed_parser class of Navigate CMS v2.9.4 allows remote attackers to force the application to make arbitrary requests via injection of arbitrary URLs into the feed parameter.
</code>

- [cheshireca7/CVE-2022-28117](https://github.com/cheshireca7/CVE-2022-28117)
- [kimstars/POC-CVE-2022-28117](https://github.com/kimstars/POC-CVE-2022-28117)

### CVE-2022-28171 (2022-06-27)

<code>The web module in some Hikvision Hybrid SAN/Cluster Storage products have the following security vulnerability. Due to the insufficient input validation, attacker can exploit the vulnerability to execute restricted commands by sending messages with malicious commands to the affected device.
</code>

- [Sapphire2017/CVE-2022-28171-POC](https://github.com/Sapphire2017/CVE-2022-28171-POC)
- [aengussong/hikvision_probe](https://github.com/aengussong/hikvision_probe)

### CVE-2022-28219 (2022-04-05)

<code>Cewolf in Zoho ManageEngine ADAudit Plus before 7060 is vulnerable to an unauthenticated XXE attack that leads to Remote Code Execution.
</code>

- [aeifkz/CVE-2022-28219-Like](https://github.com/aeifkz/CVE-2022-28219-Like)

### CVE-2022-28282 (2022-12-22)

<code>By using a link with &lt;code&gt;rel=&quot;localization&quot;&lt;/code&gt; a use-after-free could have been triggered by destroying an object during JavaScript execution and then referencing the object through a freed pointer, leading to a potential exploitable crash. This vulnerability affects Thunderbird &lt; 91.8, Firefox &lt; 99, and Firefox ESR &lt; 91.8.
</code>

- [bb33bb/CVE-2022-28282-firefox](https://github.com/bb33bb/CVE-2022-28282-firefox)

### CVE-2022-28346 (2022-04-12)

<code>An issue was discovered in Django 2.2 before 2.2.28, 3.2 before 3.2.13, and 4.0 before 4.0.4. QuerySet.annotate(), aggregate(), and extra() methods are subject to SQL injection in column aliases via a crafted dictionary (with dictionary expansion) as the passed **kwargs.
</code>

- [kamal-marouane/CVE-2022-28346](https://github.com/kamal-marouane/CVE-2022-28346)

### CVE-2022-28368 (2022-04-03)

<code>Dompdf 1.2.1 allows remote code execution via a .php file in the src:url field of an @font-face Cascading Style Sheets (CSS) statement (within an HTML input file).
</code>

- [rvizx/CVE-2022-28368](https://github.com/rvizx/CVE-2022-28368)

### CVE-2022-28598 (2022-08-22)

<code>Frappe ERPNext 12.29.0 is vulnerable to XSS where the software does not neutralize or incorrectly neutralize user-controllable input before it is placed in output that is used as a web page that is served to other users.
</code>

- [patrickdeanramos/CVE-2022-28598](https://github.com/patrickdeanramos/CVE-2022-28598)

### CVE-2022-28672 (2022-07-18)

<code>This vulnerability allows remote attackers to execute arbitrary code on affected installations of Foxit PDF Reader 11.2.1.53537. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the handling of Doc objects. The issue results from the lack of validating the existence of an object prior to performing operations on the object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-16640.
</code>

- [hacksysteam/CVE-2022-28672](https://github.com/hacksysteam/CVE-2022-28672)

### CVE-2022-28944 (2022-05-23)

<code>Certain EMCO Software products are affected by: CWE-494: Download of Code Without Integrity Check. This affects MSI Package Builder for Windows 9.1.4 and Remote Installer for Windows 6.0.13 and Ping Monitor for Windows 8.0.18 and Remote Shutdown for Windows 7.2.2 and WakeOnLan 2.0.8 and Network Inventory for Windows 5.8.22 and Network Software Scanner for Windows 2.0.8 and UnLock IT for Windows 6.1.1. The impact is: execute arbitrary code (remote). The component is: Updater. The attack vector is: To exploit this vulnerability, a user must trigger an update of an affected installation of EMCO Software. ¶¶ Multiple products from EMCO Software are affected by a remote code execution vulnerability during the update process.
</code>

- [gerr-re/cve-2022-28944](https://github.com/gerr-re/cve-2022-28944)

### CVE-2022-29063 (2022-09-02)

<code>The Solr plugin of Apache OFBiz is configured by default to automatically make a RMI request on localhost, port 1099. In version 18.12.05 and earlier, by hosting a malicious RMI server on localhost, an attacker may exploit this behavior, at server start-up or on a server restart, in order to run arbitrary code. Upgrade to at least 18.12.06 or apply patches at https://issues.apache.org/jira/browse/OFBIZ-12646.
</code>

- [mbadanoiu/CVE-2022-29063](https://github.com/mbadanoiu/CVE-2022-29063)

### CVE-2022-29072 (2022-04-15)

<code>7-Zip through 21.07 on Windows allows privilege escalation and command execution when a file with the .7z extension is dragged to the Help&gt;Contents area. This is caused by misconfiguration of 7z.dll and a heap overflow. The command runs in a child process under the 7zFM.exe process. NOTE: multiple third parties have reported that no privilege escalation can occur
</code>

- [rasan2001/CVE-2022-29072](https://github.com/rasan2001/CVE-2022-29072)

### CVE-2022-29078 (2022-04-25)

<code>The ejs (aka Embedded JavaScript templates) package 3.1.6 for Node.js allows server-side template injection in settings[view options][outputFunctionName]. This is parsed as an internal option, and overwrites the outputFunctionName option with an arbitrary OS command (which is executed upon template compilation).
</code>

- [miko550/CVE-2022-29078](https://github.com/miko550/CVE-2022-29078)
- [l0n3m4n/CVE-2022-29078](https://github.com/l0n3m4n/CVE-2022-29078)
- [chuckdu21/CVE-2022-29078](https://github.com/chuckdu21/CVE-2022-29078)

### CVE-2022-29154 (2022-08-02)

<code>An issue was discovered in rsync before 3.2.5 that allows malicious remote servers to write arbitrary files inside the directories of connecting peers. The server chooses which files/directories are sent to the client. However, the rsync client performs insufficient validation of file names. A malicious rsync server (or Man-in-The-Middle attacker) can overwrite arbitrary files in the rsync client target directory and subdirectories (for example, overwrite the .ssh/authorized_keys file).
</code>

- [EgeBalci/CVE-2022-29154](https://github.com/EgeBalci/CVE-2022-29154)

### CVE-2022-29361 (2022-05-24)

<code>Improper parsing of HTTP requests in Pallets Werkzeug v2.1.0 and below allows attackers to perform HTTP Request Smuggling using a crafted HTTP request with multiple requests included inside the body. NOTE: the vendor's position is that this behavior can only occur in unsupported configurations involving development mode and an HTTP server from outside the Werkzeug project
</code>

- [l3ragio/CVE-2022-29361_Werkzeug_Client-Side-Desync-to-XSS](https://github.com/l3ragio/CVE-2022-29361_Werkzeug_Client-Side-Desync-to-XSS)

### CVE-2022-29380 (2022-05-25)

<code>Academy-LMS v4.3 was discovered to contain a stored cross-site scripting (XSS) vulnerability in the SEO panel.
</code>

- [OpenXP-Research/CVE-2022-29380](https://github.com/OpenXP-Research/CVE-2022-29380)

### CVE-2022-29455 (2022-06-13)

<code>DOM-based Reflected Cross-Site Scripting (XSS) vulnerability in Elementor's Elementor Website Builder plugin &lt;= 3.5.5 versions.
</code>

- [GULL2100/Wordpress_xss-CVE-2022-29455](https://github.com/GULL2100/Wordpress_xss-CVE-2022-29455)
- [akhilkoradiya/CVE-2022-29455](https://github.com/akhilkoradiya/CVE-2022-29455)

### CVE-2022-29464 (2022-04-18)

<code>Certain WSO2 products allow unrestricted file upload with resultant remote code execution. The attacker must use a /fileupload endpoint with a Content-Disposition directory traversal sequence to reach a directory under the web root, such as a ../../../../repository/deployment/server/webapps directory. This affects WSO2 API Manager 2.2.0 up to 4.0.0, WSO2 Identity Server 5.2.0 up to 5.11.0, WSO2 Identity Server Analytics 5.4.0, 5.4.1, 5.5.0 and 5.6.0, WSO2 Identity Server as Key Manager 5.3.0 up to 5.11.0, WSO2 Enterprise Integrator 6.2.0 up to 6.6.0, WSO2 Open Banking AM 1.4.0 up to 2.0.0 and WSO2 Open Banking KM 1.4.0, up to 2.0.0.
</code>

- [oppsec/WSOB](https://github.com/oppsec/WSOB)
- [Inplex-sys/CVE-2022-29464-loader](https://github.com/Inplex-sys/CVE-2022-29464-loader)
- [Pasch0/WSO2RCE](https://github.com/Pasch0/WSO2RCE)
- [r4x0r1337/-CVE-2022-29464](https://github.com/r4x0r1337/-CVE-2022-29464)
- [hupe1980/CVE-2022-29464](https://github.com/hupe1980/CVE-2022-29464)
- [Pushkarup/CVE-2022-29464](https://github.com/Pushkarup/CVE-2022-29464)
- [SynixCyberCrimeMy/CVE-2022-29464](https://github.com/SynixCyberCrimeMy/CVE-2022-29464)
- [cc3305/CVE-2022-29464](https://github.com/cc3305/CVE-2022-29464)
- [c1ph3rbyt3/CVE-2022-29464](https://github.com/c1ph3rbyt3/CVE-2022-29464)

### CVE-2022-29469
- [S4muraiMelayu1337/CVE-2022-29469](https://github.com/S4muraiMelayu1337/CVE-2022-29469)

### CVE-2022-29551
- [ComparedArray/printix-CVE-2022-29551](https://github.com/ComparedArray/printix-CVE-2022-29551)

### CVE-2022-29552
- [ComparedArray/printix-CVE-2022-29552](https://github.com/ComparedArray/printix-CVE-2022-29552)

### CVE-2022-29553
- [ComparedArray/printix-CVE-2022-29553](https://github.com/ComparedArray/printix-CVE-2022-29553)

### CVE-2022-29554
- [ComparedArray/printix-CVE-2022-29554](https://github.com/ComparedArray/printix-CVE-2022-29554)

### CVE-2022-29581 (2022-05-17)

<code>Improper Update of Reference Count vulnerability in net/sched of Linux Kernel allows local attacker to cause privilege escalation to root. This issue affects: Linux Kernel versions prior to 5.18; version 4.14 and later versions.
</code>

- [Nidhi77777/linux-4.19.72_CVE-2022-29581](https://github.com/Nidhi77777/linux-4.19.72_CVE-2022-29581)
- [nidhihcl/linux-4.19.72_CVE-2022-29581](https://github.com/nidhihcl/linux-4.19.72_CVE-2022-29581)

### CVE-2022-29593 (2022-07-14)

<code>relay_cgi.cgi on Dingtian DT-R002 2CH relay devices with firmware 3.1.276A allows an attacker to replay HTTP post requests without the need for authentication or a valid signed/authorized request.
</code>

- [9lyph/CVE-2022-29593](https://github.com/9lyph/CVE-2022-29593)

### CVE-2022-29622 (2022-05-16)

<code>An arbitrary file upload vulnerability in formidable v3.1.4 allows attackers to execute arbitrary code via a crafted filename. NOTE: some third parties dispute this issue because the product has common use cases in which uploading arbitrary files is the desired behavior. Also, there are configuration options in all versions that can change the default behavior of how files are handled. Strapi does not consider this to be a valid vulnerability.
</code>

- [keymandll/CVE-2022-29622](https://github.com/keymandll/CVE-2022-29622)

### CVE-2022-29856 (2022-04-29)

<code>A hardcoded cryptographic key in Automation360 22 allows an attacker to decrypt exported RPA packages.
</code>

- [Flo451/CVE-2022-29856-PoC](https://github.com/Flo451/CVE-2022-29856-PoC)

### CVE-2022-29968 (2022-05-02)

<code>An issue was discovered in the Linux kernel through 5.17.5. io_rw_init_file in fs/io_uring.c lacks initialization of kiocb-&gt;private.
</code>

- [jprx/CVE-2022-29968](https://github.com/jprx/CVE-2022-29968)

### CVE-2022-30006
- [ComparedArray/printix-CVE-2022-30006](https://github.com/ComparedArray/printix-CVE-2022-30006)

### CVE-2022-30075 (2022-06-09)

<code>In TP-Link Router AX50 firmware 210730 and older, import of a malicious backup file via web interface can lead to remote code execution due to improper validation.
</code>

- [aaronsvk/CVE-2022-30075](https://github.com/aaronsvk/CVE-2022-30075)
- [SAJIDAMINE/CVE-2022-30075](https://github.com/SAJIDAMINE/CVE-2022-30075)
- [M4fiaB0y/CVE-2022-30075](https://github.com/M4fiaB0y/CVE-2022-30075)

### CVE-2022-30190 (2022-06-01)

<code>A remote code execution vulnerability exists when MSDT is called using the URL protocol from a calling application such as Word. An attacker who successfully exploits this vulnerability can run arbitrary code with the privileges of the calling application. The attacker can then install programs, view, change, or delete data, or create new accounts in the context allowed by the user’s rights.\nPlease see the MSRC Blog Entry for important information about steps you can take to protect your system from this vulnerability.
</code>

- [drgreenthumb93/CVE-2022-30190-follina](https://github.com/drgreenthumb93/CVE-2022-30190-follina)
- [Cosmo121/Follina-Remediation](https://github.com/Cosmo121/Follina-Remediation)
- [ErrorNoInternet/FollinaScanner](https://github.com/ErrorNoInternet/FollinaScanner)
- [komomon/CVE-2022-30190-follina-Office-MSDT-Fixed](https://github.com/komomon/CVE-2022-30190-follina-Office-MSDT-Fixed)
- [swaiist/CVE-2022-30190-Fix](https://github.com/swaiist/CVE-2022-30190-Fix)
- [arozx/CVE-2022-30190](https://github.com/arozx/CVE-2022-30190)
- [Noxtal/follina](https://github.com/Noxtal/follina)
- [AbdulRKB/Follina](https://github.com/AbdulRKB/Follina)
- [DerZiad/CVE-2022-30190](https://github.com/DerZiad/CVE-2022-30190)
- [ItsNee/Follina-CVE-2022-30190-POC](https://github.com/ItsNee/Follina-CVE-2022-30190-POC)
- [Malwareman007/Deathnote](https://github.com/Malwareman007/Deathnote)
- [sentrium-security/Follina-Workaround-CVE-2022-30190](https://github.com/sentrium-security/Follina-Workaround-CVE-2022-30190)
- [Zitchev/go_follina](https://github.com/Zitchev/go_follina)
- [Gra3s/CVE-2022-30190_EXP_PowerPoint](https://github.com/Gra3s/CVE-2022-30190_EXP_PowerPoint)
- [winstxnhdw/CVE-2022-30190](https://github.com/winstxnhdw/CVE-2022-30190)
- [ToxicEnvelope/FOLLINA-CVE-2022-30190](https://github.com/ToxicEnvelope/FOLLINA-CVE-2022-30190)
- [hycheng15/CVE-2022-30190](https://github.com/hycheng15/CVE-2022-30190)
- [Jump-Wang-111/AmzWord](https://github.com/Jump-Wang-111/AmzWord)
- [shri142/ZipScan](https://github.com/shri142/ZipScan)
- [alien-keric/CVE-2022-30190](https://github.com/alien-keric/CVE-2022-30190)
- [ethicalblue/Follina-CVE-2022-30190-Sample](https://github.com/ethicalblue/Follina-CVE-2022-30190-Sample)
- [Potato-9257/CVE-2022-30190_page](https://github.com/Potato-9257/CVE-2022-30190_page)
- [yeep1115/ICT287_CVE-2022-30190_Exploit](https://github.com/yeep1115/ICT287_CVE-2022-30190_Exploit)

### CVE-2022-30203 (2022-07-12)

<code>Windows Boot Manager Security Feature Bypass Vulnerability
</code>

- [Wack0/dubiousdisk](https://github.com/Wack0/dubiousdisk)

### CVE-2022-30206 (2022-07-12)

<code>Windows Print Spooler Elevation of Privilege Vulnerability
</code>

- [MagicPwnrin/CVE-2022-30206](https://github.com/MagicPwnrin/CVE-2022-30206)
- [Malwareman007/CVE-2022-30206](https://github.com/Malwareman007/CVE-2022-30206)

### CVE-2022-30216 (2022-07-12)

<code>Windows Server Service Tampering Vulnerability
</code>

- [corelight/CVE-2022-30216](https://github.com/corelight/CVE-2022-30216)

### CVE-2022-30333 (2022-05-09)

<code>RARLAB UnRAR before 6.12 on Linux and UNIX allows directory traversal to write to files during an extract (aka unpack) operation, as demonstrated by creating a ~/.ssh/authorized_keys file. NOTE: WinRAR and Android RAR are unaffected.
</code>

- [paradox0909/cve-2022-30333_online_rar_extracor](https://github.com/paradox0909/cve-2022-30333_online_rar_extracor)

### CVE-2022-30507
- [yosef0x01/CVE-2022-30507-PoC](https://github.com/yosef0x01/CVE-2022-30507-PoC)

### CVE-2022-30525 (2022-05-12)

<code>A OS command injection vulnerability in the CGI program of Zyxel USG FLEX 100(W) firmware versions 5.00 through 5.21 Patch 1, USG FLEX 200 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 500 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 700 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 50(W) firmware versions 5.10 through 5.21 Patch 1, USG20(W)-VPN firmware versions 5.10 through 5.21 Patch 1, ATP series firmware versions 5.10 through 5.21 Patch 1, VPN series firmware versions 4.60 through 5.21 Patch 1, which could allow an attacker to modify specific files and then execute some OS commands on a vulnerable device.
</code>

- [arajsingh-infosec/CVE-2022-30525_Exploit](https://github.com/arajsingh-infosec/CVE-2022-30525_Exploit)

### CVE-2022-30526 (2022-07-19)

<code>A privilege escalation vulnerability was identified in the CLI command of Zyxel USG FLEX 100(W) firmware versions 4.50 through 5.30, USG FLEX 200 firmware versions 4.50 through 5.30, USG FLEX 500 firmware versions 4.50 through 5.30, USG FLEX 700 firmware versions 4.50 through 5.30, USG FLEX 50(W) firmware versions 4.16 through 5.30, USG20(W)-VPN firmware versions 4.16 through 5.30, ATP series firmware versions 4.32 through 5.30, VPN series firmware versions 4.30 through 5.30, USG/ZyWALL series firmware versions 4.09 through 4.72, which could allow a local attacker to execute some OS commands with root privileges in some directories on a vulnerable device.
</code>

- [greek0x0/CVE-2022-30526](https://github.com/greek0x0/CVE-2022-30526)

### CVE-2022-30591 (2022-07-06)

<code>quic-go through 0.27.0 allows remote attackers to cause a denial of service (CPU consumption) via a Slowloris variant in which incomplete QUIC or HTTP/3 requests are sent. This occurs because mtu_discoverer.go misparses the MTU Discovery service and consequently overflows the probe timer. NOTE: the vendor's position is that this behavior should not be listed as a vulnerability on the CVE List
</code>

- [efchatz/QUIC-attacks](https://github.com/efchatz/QUIC-attacks)

### CVE-2022-30592 (2022-05-11)

<code>liblsquic/lsquic_qenc_hdl.c in LiteSpeed QUIC (aka LSQUIC) before 3.1.0 mishandles MAX_TABLE_CAPACITY.
</code>

- [efchatz/HTTP3-attacks](https://github.com/efchatz/HTTP3-attacks)

### CVE-2022-30778
- [kang8/CVE-2022-30778](https://github.com/kang8/CVE-2022-30778)

### CVE-2022-30780 (2022-06-11)

<code>Lighttpd 1.4.56 through 1.4.58 allows a remote attacker to cause a denial of service (CPU consumption from stuck connections) because connection_read_header_more in connections.c has a typo that disrupts use of multiple read operations on large headers.
</code>

- [p0dalirius/CVE-2022-30780-lighttpd-denial-of-service](https://github.com/p0dalirius/CVE-2022-30780-lighttpd-denial-of-service)
- [xiw1ll/CVE-2022-30780_Checker](https://github.com/xiw1ll/CVE-2022-30780_Checker)

### CVE-2022-31144 (2022-07-19)

<code>Redis is an in-memory database that persists on disk. A specially crafted `XAUTOCLAIM` command on a stream key in a specific state may result with heap overflow, and potentially remote code execution. This problem affects versions on the 7.x branch prior to 7.0.4. The patch is released in version 7.0.4.
</code>

- [SpiralBL0CK/CVE-2022-31144](https://github.com/SpiralBL0CK/CVE-2022-31144)

### CVE-2022-31188 (2022-08-01)

<code>CVAT is an opensource interactive video and image annotation tool for computer vision. Versions prior to 2.0.0 were found to be subject to a Server-side request forgery (SSRF) vulnerability. Validation has been added to urls used in the affected code path in version 2.0.0. Users are advised to upgrade. There are no known workarounds for this issue.
</code>

- [emirpolatt/CVE-2022-31188](https://github.com/emirpolatt/CVE-2022-31188)

### CVE-2022-31245 (2022-05-20)

<code>mailcow before 2022-05d allows a remote authenticated user to inject OS commands and escalate privileges to domain admin via the --debug option in conjunction with the ---PIPEMESS option in Sync Jobs.
</code>

- [ly1g3/Mailcow-CVE-2022-31245](https://github.com/ly1g3/Mailcow-CVE-2022-31245)

### CVE-2022-31269 (2022-08-25)

<code>Nortek Linear eMerge E3-Series devices through 0.32-09c place admin credentials in /test.txt that allow an attacker to open a building's doors. (This occurs in situations where the CVE-2019-7271 default credentials have been changed.)
</code>

- [omarhashem123/CVE-2022-31269](https://github.com/omarhashem123/CVE-2022-31269)

### CVE-2022-31403 (2022-06-14)

<code>ITOP v3.0.1 was discovered to contain a cross-site scripting (XSS) vulnerability via /itop/pages/ajax.render.php.
</code>

- [IbrahimEkimIsik/CVE-2022-31403](https://github.com/IbrahimEkimIsik/CVE-2022-31403)

### CVE-2022-31499 (2022-08-25)

<code>Nortek Linear eMerge E3-Series devices before 0.32-08f allow an unauthenticated attacker to inject OS commands via ReaderNo. NOTE: this issue exists because of an incomplete fix for CVE-2019-7256.
</code>

- [omarhashem123/CVE-2022-31499](https://github.com/omarhashem123/CVE-2022-31499)

### CVE-2022-31626 (2022-06-16)

<code>In PHP versions 7.4.x below 7.4.30, 8.0.x below 8.0.20, and 8.1.x below 8.1.7, when pdo_mysql extension with mysqlnd driver, if the third party is allowed to supply host to connect to and the password for the connection, password of excessive length can trigger a buffer overflow in PHP, which can lead to a remote code execution vulnerability.
</code>

- [amitlttwo/CVE-2022-31626](https://github.com/amitlttwo/CVE-2022-31626)

### CVE-2022-31692 (2022-10-31)

<code>Spring Security, versions 5.7 prior to 5.7.5 and 5.6 prior to 5.6.9 could be susceptible to authorization rules bypass via forward or include dispatcher types. Specifically, an application is vulnerable when all of the following are true: The application expects that Spring Security applies security to forward and include dispatcher types. The application uses the AuthorizationFilter either manually or via the authorizeHttpRequests() method. The application configures the FilterChainProxy to apply to forward and/or include requests (e.g. spring.security.filter.dispatcher-types = request, error, async, forward, include). The application may forward or include the request to a higher privilege-secured endpoint.The application configures Spring Security to apply to every dispatcher type via authorizeHttpRequests().shouldFilterAllDispatcherTypes(true)
</code>

- [hotblac/cve-2022-31692](https://github.com/hotblac/cve-2022-31692)

### CVE-2022-31798 (2022-08-25)

<code>Nortek Linear eMerge E3-Series 0.32-07p devices are vulnerable to /card_scan.php?CardFormatNo= XSS with session fixation (via PHPSESSID) when they are chained together. This would allow an attacker to take over an admin account or a user account.
</code>

- [omarhashem123/CVE-2022-31798](https://github.com/omarhashem123/CVE-2022-31798)

### CVE-2022-31814 (2022-09-05)

<code>pfSense pfBlockerNG through 2.1.4_26 allows remote attackers to execute arbitrary OS commands as root via shell metacharacters in the HTTP Host header. NOTE: 3.x is unaffected.
</code>

- [EvergreenCartoons/SenselessViolence](https://github.com/EvergreenCartoons/SenselessViolence)
- [Laburity/CVE-2022-31814](https://github.com/Laburity/CVE-2022-31814)
- [ArunHAtter/CVE-2022-31814](https://github.com/ArunHAtter/CVE-2022-31814)
- [Inplex-sys/CVE-2022-31814](https://github.com/Inplex-sys/CVE-2022-31814)

### CVE-2022-31901 (2023-01-19)

<code>Buffer overflow in function Notepad_plus::addHotSpot in Notepad++ v8.4.3 and earlier allows attackers to crash the application via two crafted files.
</code>

- [CDACesec/CVE-2022-31901](https://github.com/CDACesec/CVE-2022-31901)

### CVE-2022-31902 (2023-02-01)

<code>Notepad++ v8.4.1 was discovered to contain a stack overflow via the component Finder::add().
</code>

- [CDACesec/CVE-2022-31902](https://github.com/CDACesec/CVE-2022-31902)

### CVE-2022-32114 (2022-07-13)

<code>An unrestricted file upload vulnerability in the Add New Assets function of Strapi 4.1.12 allows attackers to conduct XSS attacks via a crafted PDF file. NOTE: the project documentation suggests that a user with the Media Library &quot;Create (upload)&quot; permission is supposed to be able to upload PDF files containing JavaScript, and that all files in a public assets folder are accessible to the outside world (unless the filename begins with a dot character). The administrator can choose to allow only image, video, and audio files (i.e., not PDF) if desired.
</code>

- [bypazs/CVE-2022-32114](https://github.com/bypazs/CVE-2022-32114)

### CVE-2022-32118 (2022-07-15)

<code>Arox School ERP Pro v1.0 was discovered to contain a cross-site scripting (XSS) vulnerability via the dispatchcategory parameter in backoffice.inc.php.
</code>

- [JC175/CVE-2022-32118](https://github.com/JC175/CVE-2022-32118)

### CVE-2022-32119 (2022-07-15)

<code>Arox School ERP Pro v1.0 was discovered to contain multiple arbitrary file upload vulnerabilities via the Add Photo function at photogalleries.inc.php and the import staff excel function at 1finance_master.inc.php.
</code>

- [JC175/CVE-2022-32119](https://github.com/JC175/CVE-2022-32119)

### CVE-2022-32250 (2022-06-02)

<code>net/netfilter/nf_tables_api.c in the Linux kernel through 5.18.1 allows a local user (able to create user/net namespaces) to escalate privileges to root because an incorrect NFT_STATEFUL_EXPR check leads to a use-after-free.
</code>

- [theori-io/CVE-2022-32250-exploit](https://github.com/theori-io/CVE-2022-32250-exploit)
- [Decstor5/2022-32250LPE](https://github.com/Decstor5/2022-32250LPE)
- [Kristal-g/CVE-2022-32250](https://github.com/Kristal-g/CVE-2022-32250)
- [seadragnol/CVE-2022-32250](https://github.com/seadragnol/CVE-2022-32250)

### CVE-2022-32548 (2022-08-29)

<code>An issue was discovered on certain DrayTek Vigor routers before July 2022 such as the Vigor3910 before 4.3.1.1. /cgi-bin/wlogin.cgi has a buffer overflow via the username or password to the aa or ab field.
</code>

- [MosaedH/CVE-2022-32548-RCE-POC](https://github.com/MosaedH/CVE-2022-32548-RCE-POC)

### CVE-2022-32862 (2022-11-01)

<code>This issue was addressed with improved data protection. This issue is fixed in macOS Big Sur 11.7.1, macOS Ventura 13, macOS Monterey 12.6.1. An app with root privileges may be able to access private information.
</code>

- [rohitc33/CVE-2022-32862](https://github.com/rohitc33/CVE-2022-32862)

### CVE-2022-32883 (2022-09-20)

<code>A logic issue was addressed with improved restrictions. This issue is fixed in macOS Monterey 12.6, iOS 15.7 and iPadOS 15.7, iOS 16, macOS Big Sur 11.7. An app may be able to read sensitive location information.
</code>

- [breakpointHQ/CVE-2022-32883](https://github.com/breakpointHQ/CVE-2022-32883)

### CVE-2022-32898 (2022-11-01)

<code>The issue was addressed with improved memory handling. This issue is fixed in iOS 15.7 and iPadOS 15.7, iOS 16, macOS Ventura 13, watchOS 9. An app may be able to execute arbitrary code with kernel privileges.
</code>

- [ox1111/CVE-2022-32898](https://github.com/ox1111/CVE-2022-32898)

### CVE-2022-32932 (2022-11-01)

<code>The issue was addressed with improved memory handling. This issue is fixed in iOS 15.7.1 and iPadOS 15.7.1, iOS 16.1 and iPadOS 16, watchOS 9.1. An app may be able to execute arbitrary code with kernel privileges.
</code>

- [ox1111/CVE-2022-32932](https://github.com/ox1111/CVE-2022-32932)

### CVE-2022-32947 (2022-11-01)

<code>The issue was addressed with improved memory handling. This issue is fixed in iOS 16.1 and iPadOS 16, macOS Ventura 13, watchOS 9.1. An app may be able to execute arbitrary code with kernel privileges.
</code>

- [asahilina/agx-exploit](https://github.com/asahilina/agx-exploit)

### CVE-2022-32981 (2022-06-10)

<code>An issue was discovered in the Linux kernel through 5.18.3 on powerpc 32-bit platforms. There is a buffer overflow in ptrace PEEKUSER and POKEUSER (aka PEEKUSR and POKEUSR) when accessing floating point registers.
</code>

- [SpiralBL0CK/CVE-2022-32981](https://github.com/SpiralBL0CK/CVE-2022-32981)

### CVE-2022-33174 (2022-06-13)

<code>Power Distribution Units running on Powertek firmware (multiple brands) before 3.30.30 allows remote authorization bypass in the web interface. To exploit the vulnerability, an attacker must send an HTTP packet to the data retrieval interface (/cgi/get_param.cgi) with the tmpToken cookie set to an empty string followed by a semicolon. This bypasses an active session authorization check. This can be then used to fetch the values of protected sys.passwd and sys.su.name fields that contain the username and password in cleartext.
</code>

- [Henry4E36/CVE-2022-33174](https://github.com/Henry4E36/CVE-2022-33174)

### CVE-2022-33679 (2022-09-13)

<code>Windows Kerberos Elevation of Privilege Vulnerability
</code>

- [Bdenneu/CVE-2022-33679](https://github.com/Bdenneu/CVE-2022-33679)

### CVE-2022-33891 (2022-07-18)

<code>The Apache Spark UI offers the possibility to enable ACLs via the configuration option spark.acls.enable. With an authentication filter, this checks whether a user has access permissions to view or modify the application. If ACLs are enabled, a code path in HttpSecurityFilter can allow someone to perform impersonation by providing an arbitrary user name. A malicious user might then be able to reach a permission check function that will ultimately build a Unix shell command based on their input, and execute it. This will result in arbitrary shell command execution as the user Spark is currently running as. This affects Apache Spark versions 3.0.3 and earlier, versions 3.1.1 to 3.1.2, and versions 3.2.0 to 3.2.1.
</code>

- [HuskyHacks/cve-2022-33891](https://github.com/HuskyHacks/cve-2022-33891)
- [ps-interactive/lab_security_apache_spark_emulation_detection](https://github.com/ps-interactive/lab_security_apache_spark_emulation_detection)
- [elsvital/cve-2022-33891-fix](https://github.com/elsvital/cve-2022-33891-fix)
- [K3ysTr0K3R/CVE-2022-33891-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2022-33891-EXPLOIT)
- [asepsaepdin/CVE-2022-33891](https://github.com/asepsaepdin/CVE-2022-33891)

### CVE-2022-33980 (2022-07-06)

<code>Apache Commons Configuration performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.configuration2.interpol.Lookup that performs the interpolation. Starting with version 2.4 and continuing through 2.7, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Configuration 2.8.0, which disables the problematic interpolators by default.
</code>

- [HKirito/CVE-2022-33980](https://github.com/HKirito/CVE-2022-33980)

### CVE-2022-34169 (2022-07-19)

<code>The Apache Xalan Java XSLT library is vulnerable to an integer truncation issue when processing malicious XSLT stylesheets. This can be used to corrupt Java class files generated by the internal XSLTC compiler and execute arbitrary Java bytecode. Users are recommended to update to version 2.7.3 or later. Note: Java runtimes (such as OpenJDK) include repackaged copies of Xalan.
</code>

- [bor8/CVE-2022-34169](https://github.com/bor8/CVE-2022-34169)
- [Disnaming/CVE-2022-34169](https://github.com/Disnaming/CVE-2022-34169)

### CVE-2022-34265 (2022-07-04)

<code>An issue was discovered in Django 3.2 before 3.2.14 and 4.0 before 4.0.6. The Trunc() and Extract() database functions are subject to SQL injection if untrusted data is used as a kind/lookup_name value. Applications that constrain the lookup name and kind choice to a known safe list are unaffected.
</code>

- [lnwza0x0a/CTF_Django_CVE-2022-34265](https://github.com/lnwza0x0a/CTF_Django_CVE-2022-34265)

### CVE-2022-34715 (2022-08-09)

<code>Windows Network File System Remote Code Execution Vulnerability
</code>

- [Starssgo/CVE-2022-34715-POC](https://github.com/Starssgo/CVE-2022-34715-POC)

### CVE-2022-34753 (2022-07-13)

<code>A CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') vulnerability exists that could cause remote root exploit when the command is compromised. Affected Products: SpaceLogic C-Bus Home Controller (5200WHC2), formerly known as C-Bus Wiser Homer Controller MK2 (V1.31.460 and prior)
</code>

- [K3ysTr0K3R/CVE-2022-34753-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2022-34753-EXPLOIT)

### CVE-2022-34918 (2022-07-04)

<code>An issue was discovered in the Linux kernel through 5.18.9. A type confusion bug in nft_set_elem_init (leading to a buffer overflow) could be used by a local attacker to escalate privileges, a different vulnerability than CVE-2022-32250. (The attacker can obtain root access, but must start with an unprivileged user namespace to obtain CAP_NET_ADMIN access.) This can be fixed in nft_setelem_parse_data in net/netfilter/nf_tables_api.c.
</code>

- [randorisec/CVE-2022-34918-LPE-PoC](https://github.com/randorisec/CVE-2022-34918-LPE-PoC)
- [veritas501/CVE-2022-34918](https://github.com/veritas501/CVE-2022-34918)

### CVE-2022-34961 (2022-07-25)

<code>OpenTeknik LLC OSSN OPEN SOURCE SOCIAL NETWORK v6.3 LTS was discovered to contain a stored cross-site scripting (XSS) vulnerability via the Users Timeline module.
</code>

- [bypazs/CVE-2022-34961](https://github.com/bypazs/CVE-2022-34961)

### CVE-2022-34962 (2022-07-25)

<code>OpenTeknik LLC OSSN OPEN SOURCE SOCIAL NETWORK v6.3 LTS was discovered to contain a stored cross-site scripting (XSS) vulnerability via the Group Timeline module.
</code>

- [bypazs/CVE-2022-34962](https://github.com/bypazs/CVE-2022-34962)

### CVE-2022-34963 (2022-07-25)

<code>OpenTeknik LLC OSSN OPEN SOURCE SOCIAL NETWORK v6.3 LTS was discovered to contain a stored cross-site scripting (XSS) vulnerability via the News Feed module.
</code>

- [bypazs/CVE-2022-34963](https://github.com/bypazs/CVE-2022-34963)

### CVE-2022-35405 (2022-07-19)

<code>Zoho ManageEngine Password Manager Pro before 12101 and PAM360 before 5510 are vulnerable to unauthenticated remote code execution. (This also affects ManageEngine Access Manager Plus before 4303 with authentication.)
</code>

- [viniciuspereiras/CVE-2022-35405](https://github.com/viniciuspereiras/CVE-2022-35405)

### CVE-2022-35411 (2022-07-08)

<code>rpc.py through 0.6.0 allows Remote Code Execution because an unpickle occurs when the &quot;serializer: pickle&quot; HTTP header is sent. In other words, although JSON (not Pickle) is the default data format, an unauthenticated client can cause the data to be processed with unpickle.
</code>

- [fuzzlove/CVE-2022-35411](https://github.com/fuzzlove/CVE-2022-35411)

### CVE-2022-35698 (2022-10-14)

<code>Adobe Commerce versions 2.4.4-p1 (and earlier) and 2.4.5 (and earlier) are affected by a Stored Cross-site Scripting vulnerability. Exploitation of this issue does not require user interaction and could result in a post-authentication arbitrary code execution.
</code>

- [EmicoEcommerce/Magento-APSB22-48-Security-Patches](https://github.com/EmicoEcommerce/Magento-APSB22-48-Security-Patches)

### CVE-2022-35841 (2022-09-13)

<code>Windows Enterprise App Management Service Remote Code Execution Vulnerability
</code>

- [Wack0/CVE-2022-35841](https://github.com/Wack0/CVE-2022-35841)

### CVE-2022-35914 (2022-09-19)

<code>/vendor/htmlawed/htmlawed/htmLawedTest.php in the htmlawed module for GLPI through 10.0.2 allows PHP code injection.
</code>

- [cosad3s/CVE-2022-35914-poc](https://github.com/cosad3s/CVE-2022-35914-poc)
- [senderend/CVE-2022-35914](https://github.com/senderend/CVE-2022-35914)
- [noxlumens/CVE-2022-35914_poc](https://github.com/noxlumens/CVE-2022-35914_poc)
- [btar1gan/exploit_CVE-2022-35914](https://github.com/btar1gan/exploit_CVE-2022-35914)

### CVE-2022-35919 (2022-08-01)

<code>MinIO is a High Performance Object Storage released under GNU Affero General Public License v3.0. In affected versions all 'admin' users authorized for `admin:ServerUpdate` can selectively trigger an error that in response, returns the content of the path requested. Any normal OS system would allow access to contents at any arbitrary paths that are readable by MinIO process. Users are advised to upgrade. Users unable to upgrade may disable ServerUpdate API by denying the `admin:ServerUpdate` action for your admin users via IAM policies.
</code>

- [ifulxploit/Minio-Security-Vulnerability-Checker](https://github.com/ifulxploit/Minio-Security-Vulnerability-Checker)

### CVE-2022-35978 (2022-08-15)

<code>Minetest is a free open-source voxel game engine with easy modding and game creation. In **single player**, a mod can set a global setting that controls the Lua script loaded to display the main menu. The script is then loaded as soon as the game session is exited. The Lua environment the menu runs in is not sandboxed and can directly interfere with the user's system. There are currently no known workarounds.
</code>

- [CanVo/CVE-2022-35978-POC](https://github.com/CanVo/CVE-2022-35978-POC)

### CVE-2022-36200 (2022-08-29)

<code>In FiberHome VDSL2 Modem HG150-Ub_V3.0, Credentials of Admin are submitted in URL, which can be logged/sniffed.
</code>

- [afaq1337/CVE-2022-36200](https://github.com/afaq1337/CVE-2022-36200)

### CVE-2022-36267 (2022-08-08)

<code>In Airspan AirSpot 5410 version 0.3.4.1-4 and under there exists a Unauthenticated remote command injection vulnerability. The ping functionality can be called without user authentication when crafting a malicious http request by injecting code in one of the parameters allowing for remote code execution. This vulnerability is exploited via the binary file /home/www/cgi-bin/diagnostics.cgi that accepts unauthenticated requests and unsanitized data. As a result, a malicious actor can craft a specific request and interact remotely with the device.
</code>

- [0xNslabs/CVE-2022-36267-PoC](https://github.com/0xNslabs/CVE-2022-36267-PoC)

### CVE-2022-36271 (2022-09-07)

<code>Outbyte PC Repair Installation File 1.7.112.7856 is vulnerable to Dll Hijacking. iertutil.dll is missing so an attacker can use a malicious dll with same name and can get admin privileges.
</code>

- [SaumyajeetDas/POC-of-CVE-2022-36271](https://github.com/SaumyajeetDas/POC-of-CVE-2022-36271)

### CVE-2022-36446 (2022-07-25)

<code>software/apt-lib.pl in Webmin before 1.997 lacks HTML escaping for a UI command.
</code>

- [p0dalirius/CVE-2022-36446-Webmin-Software-Package-Updates-RCE](https://github.com/p0dalirius/CVE-2022-36446-Webmin-Software-Package-Updates-RCE)
- [emirpolatt/CVE-2022-36446](https://github.com/emirpolatt/CVE-2022-36446)
- [Kang3639/CVE-2022-36446](https://github.com/Kang3639/CVE-2022-36446)

### CVE-2022-36532 (2022-09-16)

<code>Bolt CMS contains a vulnerability in version 5.1.12 and below that allows an authenticated user with the ROLE_EDITOR privileges to upload and rename a malicious file to achieve remote code execution.
</code>

- [lutrasecurity/CVE-2022-36532](https://github.com/lutrasecurity/CVE-2022-36532)

### CVE-2022-36537 (2022-08-26)

<code>ZK Framework v9.6.1, 9.6.0.1, 9.5.1.3, 9.0.1.2 and 8.6.4.1 allows attackers to access sensitive information via a crafted POST request sent to the component AuUploader.
</code>

- [Malwareman007/CVE-2022-36537](https://github.com/Malwareman007/CVE-2022-36537)

### CVE-2022-36539 (2022-09-07)

<code>WeDayCare B.V Ouderapp before v1.1.22 allows attackers to alter the ID value within intercepted calls to gain access to data of other parents and children.
</code>

- [Fopje/CVE-2022-36539](https://github.com/Fopje/CVE-2022-36539)

### CVE-2022-36553 (2022-08-29)

<code>Hytec Inter HWL-2511-SS v1.05 and below was discovered to contain a command injection vulnerability via the component /www/cgi-bin/popen.cgi.
</code>

- [0xNslabs/CVE-2022-36553-PoC](https://github.com/0xNslabs/CVE-2022-36553-PoC)

### CVE-2022-36779 (2022-09-13)

<code>PROSCEND - PROSCEND / ADVICE .Ltd - G/5G Industrial Cellular Router (with GPS)4 Unauthenticated OS Command Injection Proscend M330-w / M33-W5 / M350-5G / M350-W5G / M350-6 / M350-W6 / M301-G / M301-GW ADVICE ICR 111WG / https://www.proscend.com/en/category/industrial-Cellular-Router/industrial-Cellular-Router.html https://cdn.shopify.com/s/files/1/0036/9413/3297/files/ADVICE_Industrial_4G_LTE_Cellular_Router_ICR111WG.pdf?v=1620814301
</code>

- [rootDR/CVE-2022-36779](https://github.com/rootDR/CVE-2022-36779)
- [EmadYaY/CVE-2022-36779](https://github.com/EmadYaY/CVE-2022-36779)

### CVE-2022-36804 (2022-08-25)

<code>Multiple API endpoints in Atlassian Bitbucket Server and Data Center 7.0.0 before version 7.6.17, from version 7.7.0 before version 7.17.10, from version 7.18.0 before version 7.21.4, from version 8.0.0 before version 8.0.3, from version 8.1.0 before version 8.1.3, and from version 8.2.0 before version 8.2.2, and from version 8.3.0 before 8.3.1 allows remote attackers with read permissions to a public or private Bitbucket repository to execute arbitrary code by sending a malicious HTTP request. This vulnerability was reported via our Bug Bounty Program by TheGrandPew.
</code>

- [notdls/CVE-2022-36804](https://github.com/notdls/CVE-2022-36804)
- [notxesh/CVE-2022-36804-PoC](https://github.com/notxesh/CVE-2022-36804-PoC)
- [JRandomSage/CVE-2022-36804-MASS-RCE](https://github.com/JRandomSage/CVE-2022-36804-MASS-RCE)
- [benjaminhays/CVE-2022-36804-PoC-Exploit](https://github.com/benjaminhays/CVE-2022-36804-PoC-Exploit)
- [Vulnmachines/bitbucket-cve-2022-36804](https://github.com/Vulnmachines/bitbucket-cve-2022-36804)
- [kljunowsky/CVE-2022-36804-POC](https://github.com/kljunowsky/CVE-2022-36804-POC)
- [Chocapikk/CVE-2022-36804-ReverseShell](https://github.com/Chocapikk/CVE-2022-36804-ReverseShell)
- [khal4n1/CVE-2022-36804](https://github.com/khal4n1/CVE-2022-36804)
- [0xEleven/CVE-2022-36804-ReverseShell](https://github.com/0xEleven/CVE-2022-36804-ReverseShell)
- [tahtaciburak/cve-2022-36804](https://github.com/tahtaciburak/cve-2022-36804)
- [Inplex-sys/CVE-2022-36804](https://github.com/Inplex-sys/CVE-2022-36804)
- [asepsaepdin/CVE-2022-36804](https://github.com/asepsaepdin/CVE-2022-36804)

### CVE-2022-36946 (2022-07-27)

<code>nfqnl_mangle in net/netfilter/nfnetlink_queue.c in the Linux kernel through 5.18.14 allows remote attackers to cause a denial of service (panic) because, in the case of an nf_queue verdict with a one-byte nfta_payload attribute, an skb_pull can encounter a negative skb-&gt;len.
</code>

- [Pwnzer0tt1/CVE-2022-36946](https://github.com/Pwnzer0tt1/CVE-2022-36946)

### CVE-2022-37017 (2022-12-01)

<code>Symantec Endpoint Protection (Windows) agent, prior to 14.3 RU6/14.3 RU5 Patch 1, may be susceptible to a Security Control Bypass vulnerability, which is a type of issue that can potentially allow a threat actor to circumvent existing security controls. This CVE applies narrowly to the Client User Interface Password protection and Policy Import/Export Password protection, if it has been enabled.
</code>

- [apeppels/CVE-2022-37017](https://github.com/apeppels/CVE-2022-37017)

### CVE-2022-37201 (2022-09-15)

<code>JFinal CMS 5.1.0 is vulnerable to SQL Injection.
</code>

- [AgainstTheLight/CVE-2022-37201](https://github.com/AgainstTheLight/CVE-2022-37201)

### CVE-2022-37202 (2022-10-26)

<code>JFinal CMS 5.1.0 is vulnerable to SQL Injection via /admin/advicefeedback/list
</code>

- [AgainstTheLight/CVE-2022-37202](https://github.com/AgainstTheLight/CVE-2022-37202)

### CVE-2022-37203 (2022-09-19)

<code>JFinal CMS 5.1.0 is vulnerable to SQL Injection. These interfaces do not use the same component, nor do they have filters, but each uses its own SQL concatenation method, resulting in SQL injection.
</code>

- [AgainstTheLight/CVE-2022-37203](https://github.com/AgainstTheLight/CVE-2022-37203)

### CVE-2022-37204 (2022-09-20)

<code>Final CMS 5.1.0 is vulnerable to SQL Injection.
</code>

- [AgainstTheLight/CVE-2022-37204](https://github.com/AgainstTheLight/CVE-2022-37204)

### CVE-2022-37205 (2022-09-20)

<code>JFinal CMS 5.1.0 is affected by: SQL Injection. These interfaces do not use the same component, nor do they have filters, but each uses its own SQL concatenation method, resulting in SQL injection.
</code>

- [AgainstTheLight/CVE-2022-37205](https://github.com/AgainstTheLight/CVE-2022-37205)

### CVE-2022-37206
- [AgainstTheLight/CVE-2022-37206](https://github.com/AgainstTheLight/CVE-2022-37206)

### CVE-2022-37207 (2022-09-15)

<code>JFinal CMS 5.1.0 is affected by: SQL Injection. These interfaces do not use the same component, nor do they have filters, but each uses its own SQL concatenation method, resulting in SQL injection
</code>

- [AgainstTheLight/CVE-2022-37207](https://github.com/AgainstTheLight/CVE-2022-37207)

### CVE-2022-37208 (2022-10-13)

<code>JFinal CMS 5.1.0 is vulnerable to SQL Injection. These interfaces do not use the same component, nor do they have filters, but each uses its own SQL concatenation method, resulting in SQL injection.
</code>

- [AgainstTheLight/CVE-2022-37208](https://github.com/AgainstTheLight/CVE-2022-37208)

### CVE-2022-37209 (2022-09-27)

<code>JFinal CMS 5.1.0 is affected by: SQL Injection. These interfaces do not use the same component, nor do they have filters, but each uses its own SQL concatenation method, resulting in SQL injection.
</code>

- [AgainstTheLight/CVE-2022-37209](https://github.com/AgainstTheLight/CVE-2022-37209)

### CVE-2022-37210
- [AgainstTheLight/CVE-2022-37210](https://github.com/AgainstTheLight/CVE-2022-37210)

### CVE-2022-37434 (2022-08-05)

<code>zlib through 1.2.12 has a heap-based buffer over-read or buffer overflow in inflate in inflate.c via a large gzip header extra field. NOTE: only applications that call inflateGetHeader are affected. Some common applications bundle the affected zlib source code but may be unable to call inflateGetHeader (e.g., see the nodejs/node reference).
</code>

- [Trinadh465/external_zlib_android-6.0.1_r22_CVE-2022-37434](https://github.com/Trinadh465/external_zlib_android-6.0.1_r22_CVE-2022-37434)
- [Trinadh465/external_zlib_CVE-2022-37434](https://github.com/Trinadh465/external_zlib_CVE-2022-37434)

### CVE-2022-37703 (2022-09-13)

<code>In Amanda 3.5.1, an information leak vulnerability was found in the calcsize SUID binary. An attacker can abuse this vulnerability to know if a directory exists or not anywhere in the fs. The binary will use `opendir()` as root directly without checking the path, letting the attacker provide an arbitrary path.
</code>

- [MaherAzzouzi/CVE-2022-37703](https://github.com/MaherAzzouzi/CVE-2022-37703)

### CVE-2022-37706 (2022-12-25)

<code>enlightenment_sys in Enlightenment before 0.25.4 allows local users to gain privileges because it is setuid root, and the system library function mishandles pathnames that begin with a /dev/.. substring.
</code>

- [MaherAzzouzi/CVE-2022-37706-LPE-exploit](https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit)
- [ECU-10525611-Xander/CVE-2022-37706](https://github.com/ECU-10525611-Xander/CVE-2022-37706)
- [junnythemarksman/CVE-2022-37706](https://github.com/junnythemarksman/CVE-2022-37706)
- [TACTICAL-HACK/CVE-2022-37706-SUID](https://github.com/TACTICAL-HACK/CVE-2022-37706-SUID)
- [sanan2004/CVE-2022-37706](https://github.com/sanan2004/CVE-2022-37706)
- [KaoXx/CVE-2022-37706](https://github.com/KaoXx/CVE-2022-37706)
- [d3ndr1t30x/CVE-2022-37706](https://github.com/d3ndr1t30x/CVE-2022-37706)

### CVE-2022-37708
- [thekevinday/docker_lightman_exploit](https://github.com/thekevinday/docker_lightman_exploit)

### CVE-2022-38029 (2022-10-11)

<code>Windows ALPC Elevation of Privilege Vulnerability
</code>

- [SpiralBL0CK/SIDECHANNEL-CVE-2022-38029](https://github.com/SpiralBL0CK/SIDECHANNEL-CVE-2022-38029)

### CVE-2022-38181 (2022-10-25)

<code>The Arm Mali GPU kernel driver allows unprivileged users to access freed memory because GPU memory operations are mishandled. This affects Bifrost r0p0 through r38p1, and r39p0; Valhall r19p0 through r38p1, and r39p0; and Midgard r4p0 through r32p0.
</code>

- [Pro-me3us/CVE_2022_38181_Raven](https://github.com/Pro-me3us/CVE_2022_38181_Raven)

### CVE-2022-38532 (2022-09-19)

<code>Micro-Star International Co., Ltd MSI Center 1.0.50.0 was discovered to contain a vulnerability in the component C_Features of MSI.CentralServer.exe. This vulnerability allows attackers to escalate privileges via running a crafted executable.
</code>

- [nam3lum/msi-central_privesc](https://github.com/nam3lum/msi-central_privesc)

### CVE-2022-38553 (2022-09-26)

<code>Academy Learning Management System before v5.9.1 was discovered to contain a reflected cross-site scripting (XSS) vulnerability via the Search parameter.
</code>

- [4websecurity/CVE-2022-38553](https://github.com/4websecurity/CVE-2022-38553)

### CVE-2022-38577 (2022-09-19)

<code>ProcessMaker before v3.5.4 was discovered to contain insecure permissions in the user profile page. This vulnerability allows attackers to escalate normal users to Administrators.
</code>

- [sornram9254/CVE-2022-38577-Processmaker](https://github.com/sornram9254/CVE-2022-38577-Processmaker)

### CVE-2022-38601
- [jet-pentest/CVE-2022-38601](https://github.com/jet-pentest/CVE-2022-38601)

### CVE-2022-38604 (2023-04-11)

<code>Wacom Driver 6.3.46-1 for Windows and lower was discovered to contain an arbitrary file deletion vulnerability.
</code>

- [LucaBarile/CVE-2022-38604](https://github.com/LucaBarile/CVE-2022-38604)

### CVE-2022-38691
- [TomKing062/CVE-2022-38691_38692](https://github.com/TomKing062/CVE-2022-38691_38692)

### CVE-2022-38694
- [TomKing062/CVE-2022-38694_unlock_bootloader](https://github.com/TomKing062/CVE-2022-38694_unlock_bootloader)
- [TheGammaSqueeze/Bootloader_Unlock_Anbernic_T820](https://github.com/TheGammaSqueeze/Bootloader_Unlock_Anbernic_T820)
- [Seriousattempts/Bootloader_Unlock_Retroid_Pocket_3Plus](https://github.com/Seriousattempts/Bootloader_Unlock_Retroid_Pocket_3Plus)

### CVE-2022-38725 (2023-01-23)

<code>An integer overflow in the RFC3164 parser in One Identity syslog-ng 3.0 through 3.37 allows remote attackers to cause a Denial of Service via crafted syslog input that is mishandled by the tcp or network function. syslog-ng Premium Edition 7.0.30 and syslog-ng Store Box 6.10.0 are also affected.
</code>

- [wdahlenburg/CVE-2022-38725](https://github.com/wdahlenburg/CVE-2022-38725)

### CVE-2022-38766 (2023-01-03)

<code>The remote keyless system on Renault ZOE 2021 vehicles sends 433.92 MHz RF signals from the same Rolling Codes set for each door-open request, which allows for a replay attack.
</code>

- [MalHyuk/CVE-2022-38766](https://github.com/MalHyuk/CVE-2022-38766)

### CVE-2022-38789 (2022-09-15)

<code>An issue was discovered in Airties Smart Wi-Fi before 2020-08-04. It allows attackers to change the main/guest SSID and the PSK to arbitrary values, and map the LAN, because of Insecure Direct Object Reference.
</code>

- [ProxyStaffy/Airties-CVE-2022-38789](https://github.com/ProxyStaffy/Airties-CVE-2022-38789)

### CVE-2022-39196 (2022-09-04)

<code>Blackboard Learn 1.10.1 allows remote authenticated users to read unintended files by entering student credentials and then directly visiting a certain webapps/bbcms/execute/ URL. Note: The vendor disputes this stating this cannot be reproduced.
</code>

- [DayiliWaseem/CVE-2022-39196-](https://github.com/DayiliWaseem/CVE-2022-39196-)

### CVE-2022-39197 (2022-09-22)

<code>An XSS (Cross Site Scripting) vulnerability was found in HelpSystems Cobalt Strike through 4.7 that allowed a remote attacker to execute HTML on the Cobalt Strike teamserver. To exploit the vulnerability, one must first inspect a Cobalt Strike payload, and then modify the username field in the payload (or create a new payload with the extracted information and then modify that username field to be malformed).
</code>

- [safe3s/CVE-2022-39197](https://github.com/safe3s/CVE-2022-39197)
- [zeoday/cobaltstrike4.5_cdf-1](https://github.com/zeoday/cobaltstrike4.5_cdf-1)
- [burpheart/cve-2022-39197](https://github.com/burpheart/cve-2022-39197)
- [xzajyjs/CVE-2022-39197-POC](https://github.com/xzajyjs/CVE-2022-39197-POC)
- [yqcs/CSPOC](https://github.com/yqcs/CSPOC)
- [purple-WL/Cobaltstrike-RCE-CVE-2022-39197](https://github.com/purple-WL/Cobaltstrike-RCE-CVE-2022-39197)
- [lovechoudoufu/about_cobaltstrike4.5_cdf](https://github.com/lovechoudoufu/about_cobaltstrike4.5_cdf)
- [burpheart/CVE-2022-39197-patch](https://github.com/burpheart/CVE-2022-39197-patch)
- [hluwa/cobaltstrike_swing_xss2rce](https://github.com/hluwa/cobaltstrike_swing_xss2rce)
- [Romanc9/Gui-poc-test](https://github.com/Romanc9/Gui-poc-test)

### CVE-2022-39227 (2022-09-23)

<code>python-jwt is a module for generating and verifying JSON Web Tokens. Versions prior to 3.3.4 are subject to Authentication Bypass by Spoofing, resulting in identity spoofing, session hijacking or authentication bypass. An attacker who obtains a JWT can arbitrarily forge its contents without knowing the secret key. Depending on the application, this may for example enable the attacker to spoof other user's identities, hijack their sessions, or bypass authentication. Users should upgrade to version 3.3.4. There are no known workarounds.
</code>

- [user0x1337/CVE-2022-39227](https://github.com/user0x1337/CVE-2022-39227)
- [NoSpaceAvailable/CVE-2022-39227](https://github.com/NoSpaceAvailable/CVE-2022-39227)

### CVE-2022-39275 (2022-10-06)

<code>Saleor is a headless, GraphQL commerce platform. In affected versions some GraphQL mutations were not properly checking the ID type input which allowed to access database objects that the authenticated user may not be allowed to access. This vulnerability can be used to expose the following information: Estimating database row counts from tables with a sequential primary key or Exposing staff user and customer email addresses and full name through the `assignNavigation()` mutation. This issue has been patched in main and backported to multiple releases (3.7.17, 3.6.18, 3.5.23, 3.4.24, 3.3.26, 3.2.14, 3.1.24). Users are advised to upgrade. There are no known workarounds for this issue.
</code>

- [omar2535/CVE-2022-39275](https://github.com/omar2535/CVE-2022-39275)

### CVE-2022-39838 (2022-09-05)

<code>Systematic FIX Adapter (ALFAFX) 2.4.0.25 13/09/2017 allows remote file inclusion via a UNC share pathname, and also allows absolute path traversal to local pathnames.
</code>

- [jet-pentest/CVE-2022-39838](https://github.com/jet-pentest/CVE-2022-39838)

### CVE-2022-39841
- [stealthcopter/CVE-2022-39841](https://github.com/stealthcopter/CVE-2022-39841)

### CVE-2022-39986 (2023-08-01)

<code>A Command injection vulnerability in RaspAP 2.8.0 thru 2.8.7 allows unauthenticated attackers to execute arbitrary commands via the cfg_id parameter in /ajax/openvpn/activate_ovpncfg.php and /ajax/openvpn/del_ovpncfg.php.
</code>

- [mind2hex/CVE-2022-39986](https://github.com/mind2hex/CVE-2022-39986)
- [tucommenceapousser/RaspAP-CVE-2022-39986-PoC](https://github.com/tucommenceapousser/RaspAP-CVE-2022-39986-PoC)

### CVE-2022-39987 (2023-08-01)

<code>A Command injection vulnerability in RaspAP 2.8.0 thru 2.9.2 allows an authenticated attacker to execute arbitrary OS commands as root via the &quot;entity&quot; POST parameters in /ajax/networking/get_wgkey.php.
</code>

- [miguelc49/CVE-2022-39987-2](https://github.com/miguelc49/CVE-2022-39987-2)
- [miguelc49/CVE-2022-39987-1](https://github.com/miguelc49/CVE-2022-39987-1)
- [miguelc49/CVE-2022-39987-3](https://github.com/miguelc49/CVE-2022-39987-3)

### CVE-2022-40032 (2023-02-17)

<code>SQL Injection vulnerability in Simple Task Managing System version 1.0 in login.php in 'username' and 'password' parameters, allows attackers to execute arbitrary code and gain sensitive information.
</code>

- [h4md153v63n/CVE-2022-40032_Simple-Task-Managing-System-V1.0-SQL-Injection-Vulnerability-Unauthenticated](https://github.com/h4md153v63n/CVE-2022-40032_Simple-Task-Managing-System-V1.0-SQL-Injection-Vulnerability-Unauthenticated)

### CVE-2022-40126 (2022-09-29)

<code>A misconfiguration in the Service Mode profile directory of Clash for Windows v0.19.9 allows attackers to escalate privileges and execute arbitrary commands when Service Mode is activated.
</code>

- [LovelyWei/CVE-2022-40126](https://github.com/LovelyWei/CVE-2022-40126)

### CVE-2022-40140 (2022-09-19)

<code>An origin validation error vulnerability in Trend Micro Apex One and Apex One as a Service could allow a local attacker to cause a denial-of-service on affected installations. Please note: an attacker must first obtain the ability to execute low-privileged code on the target system in order to exploit this vulnerability.
</code>

- [ZephrFish/NotProxyShellScanner](https://github.com/ZephrFish/NotProxyShellScanner)

### CVE-2022-40146 (2022-09-22)

<code>Server-Side Request Forgery (SSRF) vulnerability in Batik of Apache XML Graphics allows an attacker to access files using a Jar url. This issue affects Apache XML Graphics Batik 1.14.
</code>

- [soulfoodisgood/CVE-2022-40146](https://github.com/soulfoodisgood/CVE-2022-40146)

### CVE-2022-40297 (2022-09-08)

<code>UBports Ubuntu Touch 16.04 allows the screen-unlock passcode to be used for a privileged shell via Sudo. This passcode is only four digits, far below typical length/complexity for a user account's password. NOTE: a third party states &quot;The described attack cannot be executed as demonstrated.
</code>

- [filipkarc/PoC-ubuntutouch-pin-privesc](https://github.com/filipkarc/PoC-ubuntutouch-pin-privesc)

### CVE-2022-40317 (2022-09-09)

<code>OpenKM 6.3.11 allows stored XSS related to the javascript&amp;colon; substring in an A element.
</code>

- [izdiwho/CVE-2022-40317](https://github.com/izdiwho/CVE-2022-40317)

### CVE-2022-40347 (2023-02-17)

<code>SQL Injection vulnerability in Intern Record System version 1.0 in /intern/controller.php in 'phone', 'email', 'deptType' and 'name' parameters, allows attackers to execute arbitrary code and gain sensitive information.
</code>

- [h4md153v63n/CVE-2022-40347_Intern-Record-System-phone-V1.0-SQL-Injection-Vulnerability-Unauthenticated](https://github.com/h4md153v63n/CVE-2022-40347_Intern-Record-System-phone-V1.0-SQL-Injection-Vulnerability-Unauthenticated)

### CVE-2022-40348 (2023-02-18)

<code>Cross Site Scripting (XSS) vulnerability in Intern Record System version 1.0 in /intern/controller.php in 'name' and 'email' parameters, allows attackers to execute arbitrary code.
</code>

- [h4md153v63n/CVE-2022-40348_Intern-Record-System-Cross-site-Scripting-V1.0-Vulnerability-Unauthenticated](https://github.com/h4md153v63n/CVE-2022-40348_Intern-Record-System-Cross-site-Scripting-V1.0-Vulnerability-Unauthenticated)

### CVE-2022-40490 (2025-02-06)

<code>Tiny File Manager v2.4.7 and below was discovered to contain a Cross Site Scripting (XSS) vulnerability. This vulnerability allows attackers to execute arbitrary code via a crafted payload injected into the name of an uploaded or already existing file.
</code>

- [whitej3rry/CVE-2022-40490](https://github.com/whitej3rry/CVE-2022-40490)

### CVE-2022-40624 (2022-12-20)

<code>pfSense pfBlockerNG through 2.1.4_27 allows remote attackers to execute arbitrary OS commands as root via the HTTP Host header, a different vulnerability than CVE-2022-31814.
</code>

- [dhammon/pfBlockerNg-CVE-2022-40624](https://github.com/dhammon/pfBlockerNg-CVE-2022-40624)

### CVE-2022-40634 (2022-09-13)

<code>Improper Control of Dynamically-Managed Code Resources vulnerability in Crafter Studio of Crafter CMS allows authenticated developers to execute OS commands via FreeMarker SSTI.
</code>

- [mbadanoiu/CVE-2022-40634](https://github.com/mbadanoiu/CVE-2022-40634)

### CVE-2022-40635 (2022-09-13)

<code>Improper Control of Dynamically-Managed Code Resources vulnerability in Crafter Studio of Crafter CMS allows authenticated developers to execute OS commands via Groovy Sandbox Bypass.
</code>

- [mbadanoiu/CVE-2022-40635](https://github.com/mbadanoiu/CVE-2022-40635)

### CVE-2022-40684 (2022-10-18)

<code>An authentication bypass using an alternate path or channel [CWE-288] in Fortinet FortiOS version 7.2.0 through 7.2.1 and 7.0.0 through 7.0.6, FortiProxy version 7.2.0 and version 7.0.0 through 7.0.6 and FortiSwitchManager version 7.2.0 and 7.0.0 allows an unauthenticated atttacker to perform operations on the administrative interface via specially crafted HTTP or HTTPS requests.
</code>

- [Filiplain/Fortinet-PoC-Auth-Bypass](https://github.com/Filiplain/Fortinet-PoC-Auth-Bypass)
- [Anthony1500/CVE-2022-40684](https://github.com/Anthony1500/CVE-2022-40684)
- [arsolutioner/fortigate-belsen-leak](https://github.com/arsolutioner/fortigate-belsen-leak)
- [Rofell0s/Fortigate-Leak-CVE-2022-40684](https://github.com/Rofell0s/Fortigate-Leak-CVE-2022-40684)
- [XalfiE/Fortigate-Belsen-Leak-Dump-CVE-2022-40684-](https://github.com/XalfiE/Fortigate-Belsen-Leak-Dump-CVE-2022-40684-)
- [niklasmato/fortileak-01-2025-Be](https://github.com/niklasmato/fortileak-01-2025-Be)
- [Yami0x777/Belsen_Group-et-exploitation-de-la-CVE-2022-40684](https://github.com/Yami0x777/Belsen_Group-et-exploitation-de-la-CVE-2022-40684)

### CVE-2022-40916 (2025-02-06)

<code>Tiny File Manager v2.4.7 and below is vulnerable to session fixation.
</code>

- [whitej3rry/CVE-2022-40916](https://github.com/whitej3rry/CVE-2022-40916)

### CVE-2022-41040 (2022-10-03)

<code>Microsoft Exchange Server Elevation of Privilege Vulnerability
</code>

- [0-Gram/CVE-2022-41040](https://github.com/0-Gram/CVE-2022-41040)

### CVE-2022-41082 (2022-10-03)

<code>Microsoft Exchange Server Remote Code Execution Vulnerability
</code>

- [notareaperbutDR34P3r/http-vuln-CVE-2022-41082](https://github.com/notareaperbutDR34P3r/http-vuln-CVE-2022-41082)
- [SUPRAAA-1337/CVE-2022-41082](https://github.com/SUPRAAA-1337/CVE-2022-41082)
- [soltanali0/CVE-2022-41082](https://github.com/soltanali0/CVE-2022-41082)

### CVE-2022-41099 (2022-11-09)

<code>BitLocker Security Feature Bypass Vulnerability
</code>

- [rhett-hislop/PatchWinRE](https://github.com/rhett-hislop/PatchWinRE)

### CVE-2022-41352 (2022-09-26)

<code>An issue was discovered in Zimbra Collaboration (ZCS) 8.8.15 and 9.0. An attacker can upload arbitrary files through amavis via a cpio loophole (extraction to /opt/zimbra/jetty/webapps/zimbra/public) that can lead to incorrect access to any other user accounts. Zimbra recommends pax over cpio. Also, pax is in the prerequisites of Zimbra on Ubuntu; however, pax is no longer part of a default Red Hat installation after RHEL 6 (or CentOS 6). Once pax is installed, amavis automatically prefers it over cpio.
</code>

- [qailanet/cve-2022-41352-zimbra-rce](https://github.com/qailanet/cve-2022-41352-zimbra-rce)

### CVE-2022-41540 (2022-10-18)

<code>The web app client of TP-Link AX10v1 V1_211117 uses hard-coded cryptographic keys when communicating with the router. Attackers who are able to intercept the communications between the web client and router through a man-in-the-middle attack can then obtain the sequence key via a brute-force attack, and access sensitive information.
</code>

- [efchatz/easy-exploits](https://github.com/efchatz/easy-exploits)

### CVE-2022-41544 (2022-10-18)

<code>GetSimple CMS v3.3.16 was discovered to contain a remote code execution (RCE) vulnerability via the edited_file parameter in admin/theme-edit.php.
</code>

- [n3rdh4x0r/CVE-2022-41544](https://github.com/n3rdh4x0r/CVE-2022-41544)

### CVE-2022-41622 (2022-12-07)

<code>In all versions, \n\nBIG-IP and BIG-IQ are vulnerable to cross-site request forgery (CSRF) attacks through iControl SOAP.  \n\nNote: Software versions which have reached End of Technical Support (EoTS) are not evaluated.\n\n
</code>

- [rbowes-r7/refreshing-soap-exploit](https://github.com/rbowes-r7/refreshing-soap-exploit)

### CVE-2022-41678 (2023-11-28)

<code>Once an user is authenticated on Jolokia, he can potentially trigger arbitrary code execution. \n\nIn details, in ActiveMQ configurations, jetty allows\norg.jolokia.http.AgentServlet to handler request to /api/jolokia\n\norg.jolokia.http.HttpRequestHandler#handlePostRequest is able to\ncreate JmxRequest through JSONObject. And calls to\norg.jolokia.http.HttpRequestHandler#executeRequest.\n\nInto deeper calling stacks,\norg.jolokia.handler.ExecHandler#doHandleRequest can be invoked\nthrough refection. This could lead to RCE through via\nvarious mbeans. One example is unrestricted deserialization in jdk.management.jfr.FlightRecorderMXBeanImpl which exists on Java version above 11.\n\n1 Call newRecording.\n\n2 Call setConfiguration. And a webshell data hides in it.\n\n3 Call startRecording.\n\n4 Call copyTo method. The webshell will be written to a .jsp file.\n\nThe mitigation is to restrict (by default) the actions authorized on Jolokia, or disable Jolokia.\nA more restrictive Jolokia configuration has been defined in default ActiveMQ distribution. We encourage users to upgrade to ActiveMQ distributions version including updated Jolokia configuration: 5.16.6, 5.17.4, 5.18.0, 6.0.0.\n
</code>

- [mbadanoiu/CVE-2022-41678](https://github.com/mbadanoiu/CVE-2022-41678)

### CVE-2022-41741 (2022-10-19)

<code>NGINX Open Source before versions 1.23.2 and 1.22.1, NGINX Open Source Subscription before versions R2 P1 and R1 P1, and NGINX Plus before versions R27 P1 and R26 P1 have a vulnerability in the module ngx_http_mp4_module that might allow a local attacker to corrupt NGINX worker memory, resulting in its termination or potential other impact using a specially crafted audio or video file. The issue affects only NGINX products that are built with the ngx_http_mp4_module, when the mp4 directive is used in the configuration file. Further, the attack is possible only if an attacker can trigger processing of a specially crafted audio or video file with the module ngx_http_mp4_module.
</code>

- [dumbbutt0/evilMP4](https://github.com/dumbbutt0/evilMP4)

### CVE-2022-41828 (2022-09-29)

<code>In Amazon AWS Redshift JDBC Driver (aka amazon-redshift-jdbc-driver or redshift-jdbc42) before 2.1.0.8, the Object Factory does not check the class type when instantiating an object from a class name.
</code>

- [murataydemir/CVE-2022-41828](https://github.com/murataydemir/CVE-2022-41828)

### CVE-2022-41852
- [xpectomas/CVE-2022-41852-Disable](https://github.com/xpectomas/CVE-2022-41852-Disable)

### CVE-2022-41853 (2022-10-06)

<code>Those using java.sql.Statement or java.sql.PreparedStatement in hsqldb (HyperSQL DataBase) to process untrusted input may be vulnerable to a remote code execution attack. By default it is allowed to call any static method of any Java class in the classpath resulting in code execution. The issue can be prevented by updating to 2.7.1 or by setting the system property &quot;hsqldb.method_class_names&quot; to classes which are allowed to be called. For example, System.setProperty(&quot;hsqldb.method_class_names&quot;, &quot;abc&quot;) or Java argument -Dhsqldb.method_class_names=&quot;abc&quot; can be used. From version 2.7.1 all classes by default are not accessible except those in java.lang.Math and need to be manually enabled.
</code>

- [mbadanoiu/CVE-2022-41853](https://github.com/mbadanoiu/CVE-2022-41853)

### CVE-2022-41924 (2022-11-23)

<code>A vulnerability identified in the Tailscale Windows client allows a malicious website to reconfigure the Tailscale daemon `tailscaled`, which can then be used to remotely execute code. In the Tailscale Windows client, the local API was bound to a local TCP socket, and communicated with the Windows client GUI in cleartext with no Host header verification. This allowed an attacker-controlled website visited by the node to rebind DNS to an attacker-controlled DNS server, and then make local API requests in the client, including changing the coordination server to an attacker-controlled coordination server. An attacker-controlled coordination server can send malicious URL responses to the client, including pushing executables or installing an SMB share. These allow the attacker to remotely execute code on the node. All Windows clients prior to version v.1.32.3 are affected. If you are running Tailscale on Windows, upgrade to v1.32.3 or later to remediate the issue.
</code>

- [oalieno/CVE-2022-41924](https://github.com/oalieno/CVE-2022-41924)

### CVE-2022-42045 (2023-07-13)

<code>Certain Zemana products are vulnerable to Arbitrary code injection. This affects Watchdog Anti-Malware 4.1.422 and Zemana AntiMalware 3.2.28.
</code>

- [ReCryptLLC/CVE-2022-42045](https://github.com/ReCryptLLC/CVE-2022-42045)

### CVE-2022-42046 (2022-12-20)

<code>wfshbr64.sys and wfshbr32.sys specially crafted IOCTL allows arbitrary user to perform local privilege escalation
</code>

- [kkent030315/CVE-2022-42046](https://github.com/kkent030315/CVE-2022-42046)

### CVE-2022-42094 (2022-11-22)

<code>Backdrop CMS version 1.23.0 was discovered to contain a stored cross-site scripting (XSS) vulnerability via the 'Card' content.
</code>

- [bypazs/CVE-2022-42094](https://github.com/bypazs/CVE-2022-42094)

### CVE-2022-42095 (2022-11-23)

<code>Backdrop CMS version 1.23.0 was discovered to contain a stored cross-site scripting (XSS) vulnerability via the Page content.
</code>

- [bypazs/CVE-2022-42095](https://github.com/bypazs/CVE-2022-42095)

### CVE-2022-42096 (2022-11-21)

<code>Backdrop CMS version 1.23.0 was discovered to contain a stored cross-site scripting (XSS) vulnerability via Post content.
</code>

- [bypazs/CVE-2022-42096](https://github.com/bypazs/CVE-2022-42096)

### CVE-2022-42097 (2022-11-22)

<code>Backdrop CMS version 1.23.0 was discovered to contain a stored cross-site scripting (XSS) vulnerability via 'Comment.' .
</code>

- [bypazs/CVE-2022-42097](https://github.com/bypazs/CVE-2022-42097)

### CVE-2022-42098 (2022-11-22)

<code>KLiK SocialMediaWebsite version v1.0.1 is vulnerable to SQL Injection via the profile.php.
</code>

- [bypazs/CVE-2022-42098](https://github.com/bypazs/CVE-2022-42098)

### CVE-2022-42176 (2022-10-20)

<code>In PCTechSoft PCSecure V5.0.8.xw, use of Hard-coded Credentials in configuration files leads to admin panel access.
</code>

- [soy-oreocato/CVE-2022-42176](https://github.com/soy-oreocato/CVE-2022-42176)

### CVE-2022-42703 (2022-10-09)

<code>mm/rmap.c in the Linux kernel before 5.19.7 has a use-after-free related to leaf anon_vma double reuse.
</code>

- [Satheesh575555/linux-4.1.15_CVE-2022-42703](https://github.com/Satheesh575555/linux-4.1.15_CVE-2022-42703)

### CVE-2022-42889 (2022-10-13)

<code>Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.
</code>

- [chainguard-dev/text4shell-policy](https://github.com/chainguard-dev/text4shell-policy)
- [tulhan/commons-text-goat](https://github.com/tulhan/commons-text-goat)
- [kljunowsky/CVE-2022-42889-text4shell](https://github.com/kljunowsky/CVE-2022-42889-text4shell)
- [aaronm-sysdig/text4shell-docker](https://github.com/aaronm-sysdig/text4shell-docker)
- [Sic4rio/CVE-2022-42889](https://github.com/Sic4rio/CVE-2022-42889)
- [34006133/CVE-2022-42889](https://github.com/34006133/CVE-2022-42889)
- [DimaMend/cve-2022-42889-text4shell](https://github.com/DimaMend/cve-2022-42889-text4shell)
- [joshbnewton31080/cve-2022-42889-text4shell](https://github.com/joshbnewton31080/cve-2022-42889-text4shell)
- [MendDemo-josh/cve-2022-42889-text4shell](https://github.com/MendDemo-josh/cve-2022-42889-text4shell)

### CVE-2022-43704 (2023-01-20)

<code>The Sinilink XY-WFT1 WiFi Remote Thermostat, running firmware 1.3.6, allows an attacker to bypass the intended requirement to communicate using MQTT. It is possible to replay Sinilink aka SINILINK521 protocol (udp/1024) commands interfacing directly with the target device. This, in turn, allows for an attack to control the onboard relay without requiring authentication via the mobile application. This might result in an unacceptable temperature within the target device's physical environment.
</code>

- [9lyph/CVE-2022-43704](https://github.com/9lyph/CVE-2022-43704)

### CVE-2022-44149 (2023-01-06)

<code>The web service on Nexxt Amp300 ARN02304U8 42.103.1.5095 and 80.103.2.5045 devices allows remote OS command execution by placing &amp;telnetd in the JSON host field to the ping feature of the goform/sysTools component. Authentication is required
</code>

- [geniuszly/CVE-2022-44149](https://github.com/geniuszly/CVE-2022-44149)

### CVE-2022-44268 (2023-02-06)

<code>ImageMagick 7.1.0-49 is vulnerable to Information Disclosure. When it parses a PNG image (e.g., for resize), the resulting image could have embedded the content of an arbitrary. file (if the magick binary has permissions to read it).
</code>

- [jnschaeffer/cve-2022-44268-detector](https://github.com/jnschaeffer/cve-2022-44268-detector)
- [Sybil-Scan/imagemagick-lfi-poc](https://github.com/Sybil-Scan/imagemagick-lfi-poc)
- [kljunowsky/CVE-2022-44268](https://github.com/kljunowsky/CVE-2022-44268)
- [chairat095/CVE-2022-44268_By_Kyokito](https://github.com/chairat095/CVE-2022-44268_By_Kyokito)
- [atici/Exploit-for-ImageMagick-CVE-2022-44268](https://github.com/atici/Exploit-for-ImageMagick-CVE-2022-44268)
- [Vagebondcur/IMAGE-MAGICK-CVE-2022-44268](https://github.com/Vagebondcur/IMAGE-MAGICK-CVE-2022-44268)
- [NataliSemi/-CVE-2022-44268](https://github.com/NataliSemi/-CVE-2022-44268)
- [CygnusX-26/CVE-2022-44268-fixed-PoC](https://github.com/CygnusX-26/CVE-2022-44268-fixed-PoC)
- [PanAdamski/CVE-2022-44268-automated](https://github.com/PanAdamski/CVE-2022-44268-automated)
- [FlojBoj/CVE-2022-44268](https://github.com/FlojBoj/CVE-2022-44268)

### CVE-2022-44312 (2022-11-08)

<code>PicoC Version 3.2.2 was discovered to contain a heap buffer overflow in the ExpressionCoerceInteger function in expression.c when called from ExpressionInfixOperator.
</code>

- [Halcy0nic/CVEs-for-picoc-3.2.2](https://github.com/Halcy0nic/CVEs-for-picoc-3.2.2)

### CVE-2022-44569 (2023-11-03)

<code>A locally authenticated attacker with low privileges can bypass authentication due to insecure inter-process communication.
</code>

- [rweijnen/ivanti-automationmanager-exploit](https://github.com/rweijnen/ivanti-automationmanager-exploit)

### CVE-2022-44877 (2023-01-05)

<code>login/index.php in CWP (aka Control Web Panel or CentOS Web Panel) 7 before 0.9.8.1147 allows remote attackers to execute arbitrary OS commands via shell metacharacters in the login parameter.
</code>

- [hotpotcookie/CVE-2022-44877-white-box](https://github.com/hotpotcookie/CVE-2022-44877-white-box)
- [rhymsc/CVE-2022-44877-RCE](https://github.com/rhymsc/CVE-2022-44877-RCE)
- [G01d3nW01f/CVE-2022-44877](https://github.com/G01d3nW01f/CVE-2022-44877)

### CVE-2022-45059 (2022-11-09)

<code>An issue was discovered in Varnish Cache 7.x before 7.1.2 and 7.2.x before 7.2.1. A request smuggling attack can be performed on Varnish Cache servers by requesting that certain headers are made hop-by-hop, preventing the Varnish Cache servers from forwarding critical headers to the backend.
</code>

- [martinvks/CVE-2022-45059-demo](https://github.com/martinvks/CVE-2022-45059-demo)

### CVE-2022-45460 (2023-03-28)

<code>Multiple Xiongmai NVR devices, including MBD6304T V4.02.R11.00000117.10001.131900.00000 and NBD6808T-PL V4.02.R11.C7431119.12001.130000.00000, allow an unauthenticated and remote user to exploit a stack-based buffer overflow and crash the web server, resulting in a system reboot. An unauthenticated and remote attacker can execute arbitrary code by sending a crafted HTTP request that triggers the overflow condition via a long URI passed to a sprintf call. NOTE: this is different than CVE-2018-10088, but this may overlap CVE-2017-16725.
</code>

- [born0monday/CVE-2022-45460](https://github.com/born0monday/CVE-2022-45460)

### CVE-2022-45477 (2022-12-05)

<code>Telepad allows remote unauthenticated users to send instructions to the server to execute arbitrary code without any previous authorization or authentication. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
</code>

- [M507/nmap-vulnerability-scan-scripts](https://github.com/M507/nmap-vulnerability-scan-scripts)

### CVE-2022-45688 (2022-12-13)

<code>A stack overflow in the XML.toJSONObject component of hutool-json v5.8.10 allows attackers to cause a Denial of Service (DoS) via crafted JSON or XML data.
</code>

- [scabench/jsonorg-tp1](https://github.com/scabench/jsonorg-tp1)
- [scabench/jsonorg-fp1](https://github.com/scabench/jsonorg-fp1)
- [scabench/jsonorg-fp2](https://github.com/scabench/jsonorg-fp2)
- [scabench/jsonorg-fp3](https://github.com/scabench/jsonorg-fp3)
- [scabench/jsonorg-fn1](https://github.com/scabench/jsonorg-fn1)

### CVE-2022-45701 (2023-02-17)

<code>Arris TG2482A firmware through 9.1.103GEM9 allow Remote Code Execution (RCE) via the ping utility feature.
</code>

- [geniuszly/CVE-2022-45701](https://github.com/geniuszly/CVE-2022-45701)

### CVE-2022-45771 (2022-12-05)

<code>An issue in the /api/audits component of Pwndoc v0.5.3 allows attackers to escalate privileges and execute arbitrary code via uploading a crafted audit file.
</code>

- [p0dalirius/CVE-2022-45771-Pwndoc-LFI-to-RCE](https://github.com/p0dalirius/CVE-2022-45771-Pwndoc-LFI-to-RCE)

### CVE-2022-45808 (2023-01-24)

<code>SQL Injection vulnerability in LearnPress – WordPress LMS Plugin &lt;= 4.1.7.3.2 versions.
</code>

- [RandomRobbieBF/CVE-2022-45808](https://github.com/RandomRobbieBF/CVE-2022-45808)

### CVE-2022-46080 (2023-07-06)

<code>Nexxt Nebula 1200-AC 15.03.06.60 allows authentication bypass and command execution by using the HTTPD service to enable TELNET.
</code>

- [geniuszly/CVE-2022-46080](https://github.com/geniuszly/CVE-2022-46080)

### CVE-2022-46169 (2022-12-05)

<code>Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: &lt;TARGETIP&gt;`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`.\n\nThis command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.
</code>

- [ruycr4ft/CVE-2022-46169](https://github.com/ruycr4ft/CVE-2022-46169)
- [FredBrave/CVE-2022-46169-CACTI-1.2.22](https://github.com/FredBrave/CVE-2022-46169-CACTI-1.2.22)
- [a1665454764/CVE-2022-46169](https://github.com/a1665454764/CVE-2022-46169)
- [0xZon/CVE-2022-46169-Exploit](https://github.com/0xZon/CVE-2022-46169-Exploit)
- [copyleftdev/PricklyPwn](https://github.com/copyleftdev/PricklyPwn)
- [0xN7y/CVE-2022-46169](https://github.com/0xN7y/CVE-2022-46169)
- [mind2hex/CVE-2022-46169](https://github.com/mind2hex/CVE-2022-46169)
- [HPT-Intern-Task-Submission/CVE-2022-46169](https://github.com/HPT-Intern-Task-Submission/CVE-2022-46169)
- [lof1sec/CVE-2022-46169](https://github.com/lof1sec/CVE-2022-46169)

### CVE-2022-46395 (2023-03-06)

<code>An issue was discovered in the Arm Mali GPU Kernel Driver. A non-privileged user can make improper GPU processing operations to gain access to already freed memory. This affects Midgard r0p0 through r32p0, Bifrost r0p0 through r41p0 before r42p0, Valhall r19p0 through r41p0 before r42p0, and Avalon r41p0 before r42p0.
</code>

- [Pro-me3us/CVE_2022_46395_Gazelle](https://github.com/Pro-me3us/CVE_2022_46395_Gazelle)
- [Pro-me3us/CVE_2022_46395_Raven](https://github.com/Pro-me3us/CVE_2022_46395_Raven)
- [SmileTabLabo/CVE-2022-46395](https://github.com/SmileTabLabo/CVE-2022-46395)

### CVE-2022-46463 (2023-01-12)

<code>An access control issue in Harbor v1.X.X to v2.5.3 allows attackers to access public and private image repositories without authentication. NOTE: the vendor's position is that this &quot;is clearly described in the documentation as a feature.&quot;
</code>

- [404tk/CVE-2022-46463](https://github.com/404tk/CVE-2022-46463)
- [CodeSecurityTeam/harbor](https://github.com/CodeSecurityTeam/harbor)

### CVE-2022-46638
- [naonymous101/CVE-2022-46638](https://github.com/naonymous101/CVE-2022-46638)

### CVE-2022-46689 (2022-12-15)

<code>A race condition was addressed with additional validation. This issue is fixed in tvOS 16.2, macOS Monterey 12.6.2, macOS Ventura 13.1, macOS Big Sur 11.7.2, iOS 15.7.2 and iPadOS 15.7.2, iOS 16.2 and iPadOS 16.2, watchOS 9.2. An app may be able to execute arbitrary code with kernel privileges.
</code>

- [straight-tamago/NoCameraSound](https://github.com/straight-tamago/NoCameraSound)
- [ginsudev/WDBFontOverwrite](https://github.com/ginsudev/WDBFontOverwrite)
- [tdquang266/MDC](https://github.com/tdquang266/MDC)

### CVE-2022-47130 (2023-02-03)

<code>A Cross-Site Request Forgery (CSRF) in Academy LMS before v5.10 allows a discount coupon to be arbitrarily created if an attacker with administrative privileges interacts on the CSRF page.
</code>

- [OpenXP-Research/CVE-2022-47130](https://github.com/OpenXP-Research/CVE-2022-47130)

### CVE-2022-47131 (2023-02-03)

<code>A Cross-Site Request Forgery (CSRF) in Academy LMS before v5.10 allows an attacker to arbitrarily create a page.
</code>

- [OpenXP-Research/CVE-2022-47131](https://github.com/OpenXP-Research/CVE-2022-47131)

### CVE-2022-47132 (2023-02-03)

<code>A Cross-Site Request Forgery (CSRF) in Academy LMS before v5.10 allows attackers to arbitrarily add Administrator users.
</code>

- [OpenXP-Research/CVE-2022-47132](https://github.com/OpenXP-Research/CVE-2022-47132)

### CVE-2022-47197 (2023-01-19)

<code>An insecure default vulnerability exists in the Post Creation functionality of Ghost Foundation Ghost 5.9.4. Default installations of Ghost allow non-administrator users to inject arbitrary Javascript in posts, which allow privilege escalation to administrator via XSS. To trigger this vulnerability, an attacker can send an HTTP request to inject Javascript in a post to trick an administrator into visiting the post.A stored XSS vulnerability exists in the `codeinjection_foot` for a post.
</code>

- [miguelc49/CVE-2022-47197-2](https://github.com/miguelc49/CVE-2022-47197-2)
- [miguelc49/CVE-2022-47197-1](https://github.com/miguelc49/CVE-2022-47197-1)

### CVE-2022-47373 (2023-02-15)

<code>Reflected Cross Site Scripting in Search Functionality of Module Library in Pandora FMS Console v766 and lower. This vulnerability arises on the forget password functionality in which parameter username does not proper input validation/sanitization thus results in executing malicious JavaScript payload.
</code>

- [Argonx21/CVE-2022-47373](https://github.com/Argonx21/CVE-2022-47373)

### CVE-2022-47522 (2023-04-15)

<code>The IEEE 802.11 specifications through 802.11ax allow physically proximate attackers to intercept (possibly cleartext) target-destined frames by spoofing a target's MAC address, sending Power Save frames to the access point, and then sending other frames to the access point (such as authentication frames or re-association frames) to remove the target's original security context. This behavior occurs because the specifications do not require an access point to purge its transmit queue before removing a client's pairwise encryption key.
</code>

- [toffeenutt/CVE-2022-47522-PoC](https://github.com/toffeenutt/CVE-2022-47522-PoC)

### CVE-2022-47615 (2023-01-24)

<code>Local File Inclusion vulnerability in LearnPress – WordPress LMS Plugin &lt;= 4.1.7.3.2 versions.
</code>

- [RandomRobbieBF/CVE-2022-47615](https://github.com/RandomRobbieBF/CVE-2022-47615)

### CVE-2022-48565 (2023-08-22)

<code>An XML External Entity (XXE) issue was discovered in Python through 3.9.1. The plistlib module no longer accepts entity declarations in XML plist files to avoid XML vulnerabilities.
</code>

- [Einstein2150/CVE-2022-48565-POC](https://github.com/Einstein2150/CVE-2022-48565-POC)

### CVE-2022-218882
- [Sausageinforest/CVE-2022-218882](https://github.com/Sausageinforest/CVE-2022-218882)


## 2021
### CVE-2021-1675 (2021-06-08)

<code>Windows Print Spooler Remote Code Execution Vulnerability
</code>

- [LaresLLC/CVE-2021-1675](https://github.com/LaresLLC/CVE-2021-1675)

### CVE-2021-1732 (2021-02-25)

<code>Windows Win32k Elevation of Privilege Vulnerability
</code>

- [Sausageinforest/CVE-2021-1732](https://github.com/Sausageinforest/CVE-2021-1732)

### CVE-2021-2394 (2021-07-20)

<code>Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
</code>

- [fasanhlieu/CVE-2021-2394](https://github.com/fasanhlieu/CVE-2021-2394)

### CVE-2021-3122 (2021-02-07)

<code>CMCAgent in NCR Command Center Agent 16.3 on Aloha POS/BOH servers permits the submission of a runCommand parameter (within an XML document sent to port 8089) that enables the remote, unauthenticated execution of an arbitrary command as SYSTEM, as exploited in the wild in 2020 and/or 2021. NOTE: the vendor's position is that exploitation occurs only on devices with a certain &quot;misconfiguration.&quot;
</code>

- [acquiredsecurity/CVE-2021-3122-Details](https://github.com/acquiredsecurity/CVE-2021-3122-Details)

### CVE-2021-3129 (2021-01-12)

<code>Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.
</code>

- [joshuavanderpoll/CVE-2021-3129](https://github.com/joshuavanderpoll/CVE-2021-3129)
- [0x0d3ad/CVE-2021-3129](https://github.com/0x0d3ad/CVE-2021-3129)
- [GodOfServer/CVE-2021-3129](https://github.com/GodOfServer/CVE-2021-3129)
- [Prabesh01/hoh4](https://github.com/Prabesh01/hoh4)
- [lukwagoasuman/CVE-2021-3129---Laravel-RCE](https://github.com/lukwagoasuman/CVE-2021-3129---Laravel-RCE)

### CVE-2021-3156 (2021-01-26)

<code>Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via &quot;sudoedit -s&quot; and a command-line argument that ends with a single backslash character.
</code>

- [stong/CVE-2021-3156](https://github.com/stong/CVE-2021-3156)
- [acidburn2049/CVE-2021-3156](https://github.com/acidburn2049/CVE-2021-3156)
- [Bad3r/CVE-2021-3156-without-ip-command](https://github.com/Bad3r/CVE-2021-3156-without-ip-command)
- [Sebastianbedoya25/CVE-2021-3156](https://github.com/Sebastianbedoya25/CVE-2021-3156)
- [ten-ops/baron-samedit](https://github.com/ten-ops/baron-samedit)

### CVE-2021-3490 (2021-06-04)

<code>The eBPF ALU32 bounds tracking for bitwise ops (AND, OR and XOR) in the Linux kernel did not properly update 32-bit bounds, which could be turned into out of bounds reads and writes in the Linux kernel and therefore, arbitrary code execution. This issue was fixed via commit 049c4e13714e (&quot;bpf: Fix alu32 const subreg bound tracking on bitwise operations&quot;) (v5.13-rc4) and backported to the stable kernels in v5.12.4, v5.11.21, and v5.10.37. The AND/OR issues were introduced by commit 3f50f132d840 (&quot;bpf: Verifier, do explicit ALU32 bounds tracking&quot;) (5.7-rc1) and the XOR variant was introduced by 2921c90d4718 (&quot;bpf:Fix a verifier failure with xor&quot;) ( 5.10-rc1).
</code>

- [chompie1337/Linux_LPE_eBPF_CVE-2021-3490](https://github.com/chompie1337/Linux_LPE_eBPF_CVE-2021-3490)

### CVE-2021-3493 (2021-04-17)

<code>The overlayfs implementation in the linux kernel did not properly validate with respect to user namespaces the setting of file capabilities on files in an underlying file system. Due to the combination of unprivileged user namespaces along with a patch carried in the Ubuntu kernel to allow unprivileged overlay mounts, an attacker could use this to gain elevated privileges.
</code>

- [briskets/CVE-2021-3493](https://github.com/briskets/CVE-2021-3493)
- [fathallah17/OverlayFS-CVE-2021-3493](https://github.com/fathallah17/OverlayFS-CVE-2021-3493)
- [Sornphut/OverlayFS---CVE-2021-3493](https://github.com/Sornphut/OverlayFS---CVE-2021-3493)

### CVE-2021-3560 (2022-02-16)

<code>It was found that polkit could be tricked into bypassing the credential checks for D-Bus requests, elevating the privileges of the requestor to the root user. This flaw could be used by an unprivileged local attacker to, for example, create a new local administrator. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.
</code>

- [secnigma/CVE-2021-3560-Polkit-Privilege-Esclation](https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation)
- [arcslash/exploit_CVE-2021-3560](https://github.com/arcslash/exploit_CVE-2021-3560)

### CVE-2021-3754 (2022-08-26)

<code>A flaw was found in keycloak where an attacker is able to register himself with the username same as the email ID of any existing user. This may cause trouble in getting password recovery email in case the user forgets the password.
</code>

- [7Ragnarok7/CVE-2021-3754](https://github.com/7Ragnarok7/CVE-2021-3754)

### CVE-2021-3831 (2021-12-14)

<code>gnuboard5 is vulnerable to Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
</code>

- [aratane/CVE-2021-3831](https://github.com/aratane/CVE-2021-3831)

### CVE-2021-4034 (2022-01-28)

<code>A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.
</code>

- [lsclsclsc/CVE-2021-4034](https://github.com/lsclsclsc/CVE-2021-4034)
- [EuJin03/CVE-2021-4034-PoC](https://github.com/EuJin03/CVE-2021-4034-PoC)
- [dh4r4/PwnKit-CVE-2021-4034-](https://github.com/dh4r4/PwnKit-CVE-2021-4034-)
- [12bijaya/CVE-2021-4034-PwnKit-](https://github.com/12bijaya/CVE-2021-4034-PwnKit-)

### CVE-2021-4044 (2021-12-14)

<code>Internally libssl in OpenSSL calls X509_verify_cert() on the client side to verify a certificate supplied by a server. That function may return a negative return value to indicate an internal error (for example out of memory). Such a negative return value is mishandled by OpenSSL and will cause an IO function (such as SSL_connect() or SSL_do_handshake()) to not indicate success and a subsequent call to SSL_get_error() to return the value SSL_ERROR_WANT_RETRY_VERIFY. This return value is only supposed to be returned by OpenSSL if the application has previously called SSL_CTX_set_cert_verify_callback(). Since most applications do not do this the SSL_ERROR_WANT_RETRY_VERIFY return value from SSL_get_error() will be totally unexpected and applications may not behave correctly as a result. The exact behaviour will depend on the application but it could result in crashes, infinite loops or other similar incorrect responses. This issue is made more serious in combination with a separate bug in OpenSSL 3.0 that will cause X509_verify_cert() to indicate an internal error when processing a certificate chain. This will occur where a certificate does not include the Subject Alternative Name extension but where a Certificate Authority has enforced name constraints. This issue can occur even with valid chains. By combining the two issues an attacker could induce incorrect, application dependent behaviour. Fixed in OpenSSL 3.0.1 (Affected 3.0.0).
</code>

- [phirojshah/CVE-2021-4044](https://github.com/phirojshah/CVE-2021-4044)

### CVE-2021-4045 (2022-03-07)

<code>TP-Link Tapo C200 IP camera, on its 1.1.15 firmware version and below, is affected by an unauthenticated RCE vulnerability, present in the uhttpd binary running by default as root. The exploitation of this vulnerability allows an attacker to take full control of the camera.
</code>

- [hacefresko/CVE-2021-4045](https://github.com/hacefresko/CVE-2021-4045)

### CVE-2021-20837 (2021-10-26)

<code>Movable Type 7 r.5002 and earlier (Movable Type 7 Series), Movable Type 6.8.2 and earlier (Movable Type 6 Series), Movable Type Advanced 7 r.5002 and earlier (Movable Type Advanced 7 Series), Movable Type Advanced 6.8.2 and earlier (Movable Type Advanced 6 Series), Movable Type Premium 1.46 and earlier, and Movable Type Premium Advanced 1.46 and earlier allow remote attackers to execute arbitrary OS commands via unspecified vectors. Note that all versions of Movable Type 4.0 or later including unsupported (End-of-Life, EOL) versions are also affected by this vulnerability.
</code>

- [lamcodeofpwnosec/CVE-2021-20837](https://github.com/lamcodeofpwnosec/CVE-2021-20837)

### CVE-2021-21380 (2021-03-23)

<code>XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. In affected versions of XWiki Platform (and only those with the Ratings API installed), the Rating Script Service expose an API to perform SQL requests without escaping the from and where search arguments. This might lead to an SQL script injection quite easily for any user having Script rights on XWiki. The problem has been patched in XWiki 12.9RC1. The only workaround besides upgrading XWiki would be to uninstall the Ratings API in XWiki from the Extension Manager.
</code>

- [rvermeulen/codeql-workshop-cve-2021-21380](https://github.com/rvermeulen/codeql-workshop-cve-2021-21380)

### CVE-2021-21389 (2021-03-26)

<code>BuddyPress is an open source WordPress plugin to build a community site. In releases of BuddyPress from 5.0.0 before 7.2.1 it's possible for a non-privileged, regular user to obtain administrator rights by exploiting an issue in the REST API members endpoint. The vulnerability has been fixed in BuddyPress 7.2.1. Existing installations of the plugin should be updated to this version to mitigate the issue.
</code>

- [mynameSumin/CVE-2021-21389](https://github.com/mynameSumin/CVE-2021-21389)

### CVE-2021-21401 (2021-03-23)

<code>Nanopb is a small code-size Protocol Buffers implementation in ansi C. In Nanopb before versions 0.3.9.8 and 0.4.5, decoding a specifically formed message can cause invalid `free()` or `realloc()` calls if the message type contains an `oneof` field, and the `oneof` directly contains both a pointer field and a non-pointer field. If the message data first contains the non-pointer field and then the pointer field, the data of the non-pointer field is incorrectly treated as if it was a pointer value. Such message data rarely occurs in normal messages, but it is a concern when untrusted data is parsed. This has been fixed in versions 0.3.9.8 and 0.4.5. See referenced GitHub Security Advisory for more information including workarounds.
</code>

- [uthrasri/CVE-2021-21401_nanopb-c_AOSP10_R33](https://github.com/uthrasri/CVE-2021-21401_nanopb-c_AOSP10_R33)

### CVE-2021-21425 (2021-04-07)

<code>Grav Admin Plugin is an HTML user interface that provides a way to configure Grav and create and modify pages. In versions 1.10.7 and earlier, an unauthenticated user can execute some methods of administrator controller without needing any credentials. Particular method execution will result in arbitrary YAML file creation or content change of existing YAML files on the system. Successfully exploitation of that vulnerability results in configuration changes, such as general site information change, custom scheduler job definition, etc. Due to the nature of the vulnerability, an adversary can change some part of the webpage, or hijack an administrator account, or execute operating system command under the context of the web-server user. This vulnerability is fixed in version 1.10.8. Blocking access to the `/admin` path from untrusted sources can be applied as a workaround.
</code>

- [CsEnox/CVE-2021-21425](https://github.com/CsEnox/CVE-2021-21425)
- [bluetoothStrawberry/cve-2021-21425](https://github.com/bluetoothStrawberry/cve-2021-21425)

### CVE-2021-21551 (2021-05-04)

<code>Dell dbutil_2_3.sys driver contains an insufficient access control vulnerability which may lead to escalation of privileges, denial of service, or information disclosure. Local authenticated user access is required.
</code>

- [IlanDudnik/CVE-2021-21551](https://github.com/IlanDudnik/CVE-2021-21551)
- [luke0x90/CVE-2021-21551](https://github.com/luke0x90/CVE-2021-21551)

### CVE-2021-21772 (2021-03-10)

<code>A use-after-free vulnerability exists in the NMR::COpcPackageReader::releaseZIP() functionality of 3MF Consortium lib3mf 2.0.0. A specially crafted 3MF file can lead to code execution. An attacker can provide a malicious file to trigger this vulnerability.
</code>

- [3dluvr/New-lib3mf.dll-for-MeshMixer](https://github.com/3dluvr/New-lib3mf.dll-for-MeshMixer)

### CVE-2021-21972 (2021-02-24)

<code>The vSphere Client (HTML5) contains a remote code execution vulnerability in a vCenter Server plugin. A malicious actor with network access to port 443 may exploit this issue to execute commands with unrestricted privileges on the underlying operating system that hosts vCenter Server. This affects VMware vCenter Server (7.x before 7.0 U1c, 6.7 before 6.7 U3l and 6.5 before 6.5 U3n) and VMware Cloud Foundation (4.x before 4.2 and 3.x before 3.10.1.2).
</code>

- [NS-Sp4ce/CVE-2021-21972](https://github.com/NS-Sp4ce/CVE-2021-21972)
- [pettyhacks/vSphereyeeter](https://github.com/pettyhacks/vSphereyeeter)

### CVE-2021-21974 (2021-02-24)

<code>OpenSLP as used in ESXi (7.0 before ESXi70U1c-17325551, 6.7 before ESXi670-202102401-SG, 6.5 before ESXi650-202102101-SG) has a heap-overflow vulnerability. A malicious actor residing within the same network segment as ESXi who has access to port 427 may be able to trigger the heap-overflow issue in OpenSLP service resulting in remote code execution.
</code>

- [mercylessghost/CVE-2021-21974](https://github.com/mercylessghost/CVE-2021-21974)

### CVE-2021-21985 (2021-05-26)

<code>The vSphere Client (HTML5) contains a remote code execution vulnerability due to lack of input validation in the Virtual SAN Health Check plug-in which is enabled by default in vCenter Server. A malicious actor with network access to port 443 may exploit this issue to execute commands with unrestricted privileges on the underlying operating system that hosts vCenter Server.
</code>

- [alt3kx/CVE-2021-21985_PoC](https://github.com/alt3kx/CVE-2021-21985_PoC)
- [daedalus/CVE-2021-21985](https://github.com/daedalus/CVE-2021-21985)

### CVE-2021-22192 (2021-03-24)

<code>An issue has been discovered in GitLab CE/EE affecting all versions starting from 13.2 allowing unauthorized authenticated users to execute arbitrary code on the server.
</code>

- [EXP-Docs/CVE-2021-22192](https://github.com/EXP-Docs/CVE-2021-22192)

### CVE-2021-22204 (2021-04-23)

<code>Improper neutralization of user data in the DjVu file format in ExifTool versions 7.44 and up allows arbitrary code execution when parsing the malicious image
</code>

- [UNICORDev/exploit-CVE-2021-22204](https://github.com/UNICORDev/exploit-CVE-2021-22204)
- [sameep0/CVE-2021-22204](https://github.com/sameep0/CVE-2021-22204)

### CVE-2021-22205 (2021-04-23)

<code>An issue has been discovered in GitLab CE/EE affecting all versions starting from 11.9. GitLab was not properly validating image files that were passed to a file parser which resulted in a remote command execution.
</code>

- [devdanqtuan/CVE-2021-22205](https://github.com/devdanqtuan/CVE-2021-22205)

### CVE-2021-22214 (2021-06-08)

<code>When requests to the internal network for webhooks are enabled, a server-side request forgery vulnerability in GitLab CE/EE affecting all versions starting from 10.5 was possible to exploit for an unauthenticated attacker even on a GitLab instance where registration is limited
</code>

- [Vulnmachines/gitlab-cve-2021-22214](https://github.com/Vulnmachines/gitlab-cve-2021-22214)

### CVE-2021-22911 (2021-05-27)

<code>A improper input sanitization vulnerability exists in Rocket.Chat server 3.11, 3.12 &amp; 3.13 that could lead to unauthenticated NoSQL injection, resulting potentially in RCE.
</code>

- [CsEnox/CVE-2021-22911](https://github.com/CsEnox/CVE-2021-22911)
- [Weisant/CVE-2021-22911-EXP](https://github.com/Weisant/CVE-2021-22911-EXP)
- [yoohhuu/Rocket-Chat-3.12.1-PoC-CVE-2021-22911-](https://github.com/yoohhuu/Rocket-Chat-3.12.1-PoC-CVE-2021-22911-)

### CVE-2021-23017 (2021-06-01)

<code>A security issue in nginx resolver was identified, which might allow an attacker who is able to forge UDP packets from the DNS server to cause 1-byte memory overwrite, resulting in worker process crash or potential other impact.
</code>

- [z3usx01/CVE-2021-23017-POC](https://github.com/z3usx01/CVE-2021-23017-POC)
- [lukwagoasuman/-home-lukewago-Downloads-CVE-2021-23017-Nginx-1.14](https://github.com/lukwagoasuman/-home-lukewago-Downloads-CVE-2021-23017-Nginx-1.14)

### CVE-2021-23369 (2021-04-12)

<code>The package handlebars before 4.7.7 are vulnerable to Remote Code Execution (RCE) when selecting certain compiling options to compile templates coming from an untrusted source.
</code>

- [fazilbaig1/CVE-2021-23369](https://github.com/fazilbaig1/CVE-2021-23369)

### CVE-2021-23383 (2021-05-04)

<code>The package handlebars before 4.7.7 are vulnerable to Prototype Pollution when selecting certain compiling options to compile templates coming from an untrusted source.
</code>

- [fazilbaig1/CVE-2021-23383](https://github.com/fazilbaig1/CVE-2021-23383)

### CVE-2021-23639 (2021-12-10)

<code>The package md-to-pdf before 5.0.0 are vulnerable to Remote Code Execution (RCE) due to utilizing the library gray-matter to parse front matter content, without disabling the JS engine.
</code>

- [MohandAcherir/CVE-2021-23639](https://github.com/MohandAcherir/CVE-2021-23639)

### CVE-2021-24959 (2022-03-14)

<code>The WP Email Users WordPress plugin through 1.7.6 does not escape the data_raw parameter in the weu_selected_users_1 AJAX action, available to any authenticated users, allowing them to perform SQL injection attacks.
</code>

- [RandomRobbieBF/CVE-2021-24959](https://github.com/RandomRobbieBF/CVE-2021-24959)

### CVE-2021-25374 (2021-04-09)

<code>An improper authorization vulnerability in Samsung Members &quot;samsungrewards&quot; scheme for deeplink in versions 2.4.83.9 in Android O(8.1) and below, and 3.9.00.9 in Android P(9.0) and above allows remote attackers to access a user data related with Samsung Account.
</code>

- [WithSecureLabs/CVE-2021-25374_Samsung-Account-Access](https://github.com/WithSecureLabs/CVE-2021-25374_Samsung-Account-Access)

### CVE-2021-25646 (2021-01-29)

<code>Apache Druid includes the ability to execute user-provided JavaScript code embedded in various types of requests. This functionality is intended for use in high-trust environments, and is disabled by default. However, in Druid 0.20.0 and earlier, it is possible for an authenticated user to send a specially-crafted request that forces Druid to run user-provided JavaScript code for that request, regardless of server configuration. This can be leveraged to execute code on the target machine with the privileges of the Druid server process.
</code>

- [1n7erface/PocList](https://github.com/1n7erface/PocList)
- [luobai8/CVE-2021-25646-exp](https://github.com/luobai8/CVE-2021-25646-exp)

### CVE-2021-26291 (2021-04-23)

<code>Apache Maven will follow repositories that are defined in a dependency’s Project Object Model (pom) which may be surprising to some users, resulting in potential risk if a malicious actor takes over that repository or is able to insert themselves into a position to pretend to be that repository. Maven is changing the default behavior in 3.8.1+ to no longer follow http (non-SSL) repository references by default. More details available in the referenced urls. If you are currently using a repository manager to govern the repositories used by your builds, you are unaffected by the risks present in the legacy behavior, and are unaffected by this vulnerability and change to default behavior. See this link for more information about repository management: https://maven.apache.org/repository-management.html
</code>

- [jpmartins/MinimalReproducer](https://github.com/jpmartins/MinimalReproducer)

### CVE-2021-26690 (2021-06-10)

<code>Apache HTTP Server versions 2.4.0 to 2.4.46 A specially crafted Cookie header handled by mod_session can cause a NULL pointer dereference and crash, leading to a possible Denial Of Service
</code>

- [7own/CVE-2021-26690---Apache-mod_session](https://github.com/7own/CVE-2021-26690---Apache-mod_session)
- [0xdeviner/CVE-2021-26690](https://github.com/0xdeviner/CVE-2021-26690)
- [danielduan2002/CVE-2021-26690](https://github.com/danielduan2002/CVE-2021-26690)

### CVE-2021-26855 (2021-03-02)

<code>Microsoft Exchange Server Remote Code Execution Vulnerability
</code>

- [dwisiswant0/proxylogscan](https://github.com/dwisiswant0/proxylogscan)
- [r0xdeadbeef/CVE-2021-26855](https://github.com/r0xdeadbeef/CVE-2021-26855)
- [hakivvi/proxylogon](https://github.com/hakivvi/proxylogon)
- [ZephrFish/Exch-CVE-2021-26855_Priv](https://github.com/ZephrFish/Exch-CVE-2021-26855_Priv)
- [hosch3n/ProxyVulns](https://github.com/hosch3n/ProxyVulns)

### CVE-2021-27180 (2021-04-14)

<code>An issue was discovered in MDaemon before 20.0.4. There is Reflected XSS in Webmail (aka WorldClient). It can be exploited via a GET request. It allows performing any action with the privileges of the attacked user.
</code>

- [chudyPB/MDaemon-Advisories](https://github.com/chudyPB/MDaemon-Advisories)

### CVE-2021-27285 (2025-01-06)

<code>An issue was discovered in Inspur ClusterEngine v4.0 that allows attackers to gain escalated Local privileges and execute arbitrary commands via /opt/tsce4/torque6/bin/getJobsByShell.
</code>

- [fjh1997/CVE-2021-27285](https://github.com/fjh1997/CVE-2021-27285)

### CVE-2021-27365 (2021-03-07)

<code>An issue was discovered in the Linux kernel through 5.11.3. Certain iSCSI data structures do not have appropriate length constraints or checks, and can exceed the PAGE_SIZE value. An unprivileged user can send a Netlink message that is associated with iSCSI, and has a length up to the maximum length of a Netlink message.
</code>

- [Iweisc/Kernel-CVE-2021-27365-hotfix](https://github.com/Iweisc/Kernel-CVE-2021-27365-hotfix)

### CVE-2021-27850 (2021-04-15)

<code>A critical unauthenticated remote code execution vulnerability was found all recent versions of Apache Tapestry. The affected versions include 5.4.5, 5.5.0, 5.6.2 and 5.7.0. The vulnerability I have found is a bypass of the fix for CVE-2019-0195. Recap: Before the fix of CVE-2019-0195 it was possible to download arbitrary class files from the classpath by providing a crafted asset file URL. An attacker was able to download the file `AppModule.class` by requesting the URL `http://localhost:8080/assets/something/services/AppModule.class` which contains a HMAC secret key. The fix for that bug was a blacklist filter that checks if the URL ends with `.class`, `.properties` or `.xml`. Bypass: Unfortunately, the blacklist solution can simply be bypassed by appending a `/` at the end of the URL: `http://localhost:8080/assets/something/services/AppModule.class/` The slash is stripped after the blacklist check and the file `AppModule.class` is loaded into the response. This class usually contains the HMAC secret key which is used to sign serialized Java objects. With the knowledge of that key an attacker can sign a Java gadget chain that leads to RCE (e.g. CommonsBeanUtils1 from ysoserial). Solution for this vulnerability: * For Apache Tapestry 5.4.0 to 5.6.1, upgrade to 5.6.2 or later. * For Apache Tapestry 5.7.0, upgrade to 5.7.1 or later.
</code>

- [kahla-sec/CVE-2021-27850_POC](https://github.com/kahla-sec/CVE-2021-27850_POC)

### CVE-2021-27928 (2021-03-19)

<code>A remote code execution issue was discovered in MariaDB 10.2 before 10.2.37, 10.3 before 10.3.28, 10.4 before 10.4.18, and 10.5 before 10.5.9; Percona Server through 2021-03-03; and the wsrep patch through 2021-03-03 for MySQL. An untrusted search path leads to eval injection, in which a database SUPER user can execute OS commands after modifying wsrep_provider and wsrep_notify_cmd. NOTE: this does not affect an Oracle product.
</code>

- [Al1ex/CVE-2021-27928](https://github.com/Al1ex/CVE-2021-27928)

### CVE-2021-28164 (2021-04-01)

<code>In Eclipse Jetty 9.4.37.v20210219 to 9.4.38.v20210224, the default compliance mode allows requests with URIs that contain %2e or %2e%2e segments to access protected resources within the WEB-INF directory. For example a request to /context/%2e/WEB-INF/web.xml can retrieve the web.xml file. This can reveal sensitive information regarding the implementation of a web application.
</code>

- [jammy0903/-jettyCVE-2021-28164-](https://github.com/jammy0903/-jettyCVE-2021-28164-)

### CVE-2021-29441 (2021-04-27)

<code>Nacos is a platform designed for dynamic service discovery and configuration and service management. In Nacos before version 1.4.1, when configured to use authentication (-Dnacos.core.auth.enabled=true) Nacos uses the AuthFilter servlet filter to enforce authentication. This filter has a backdoor that enables Nacos servers to bypass this filter and therefore skip authentication checks. This mechanism relies on the user-agent HTTP header so it can be easily spoofed. This issue may allow any user to carry out any administrative tasks on the Nacos server.
</code>

- [azhao1981/CVE-2021-29441](https://github.com/azhao1981/CVE-2021-29441)

### CVE-2021-29442 (2021-04-27)

<code>Nacos is a platform designed for dynamic service discovery and configuration and service management. In Nacos before version 1.4.1, the ConfigOpsController lets the user perform management operations like querying the database or even wiping it out. While the /data/remove endpoint is properly protected with the @Secured annotation, the /derby endpoint is not protected and can be openly accessed by unauthenticated users. These endpoints are only valid when using embedded storage (derby DB) so this issue should not affect those installations using external storage (e.g. mysql)
</code>

- [XiaomingX/cve-2021-29442-Nacos-Derby-rce-exp](https://github.com/XiaomingX/cve-2021-29442-Nacos-Derby-rce-exp)

### CVE-2021-29447 (2021-04-15)

<code>Wordpress is an open source CMS. A user with the ability to upload files (like an Author) can exploit an XML parsing issue in the Media Library leading to XXE attacks. This requires WordPress installation to be using PHP 8. Access to internal files is possible in a successful XXE attack. This has been patched in WordPress version 5.7.1, along with the older affected versions via a minor release. We strongly recommend you keep auto-updates enabled.
</code>

- [specializzazione-cyber-security/demo-CVE-2021-29447-lezione](https://github.com/specializzazione-cyber-security/demo-CVE-2021-29447-lezione)

### CVE-2021-30461 (2021-05-29)

<code>A remote code execution issue was discovered in the web UI of VoIPmonitor before 24.61. When the recheck option is used, the user-supplied SPOOLDIR value (which might contain PHP code) is injected into config/configuration.php.
</code>

- [daedalus/CVE-2021-30461](https://github.com/daedalus/CVE-2021-30461)
- [Vulnmachines/CVE-2021-30461](https://github.com/Vulnmachines/CVE-2021-30461)

### CVE-2021-30860 (2021-08-24)

<code>An integer overflow was addressed with improved input validation. This issue is fixed in Security Update 2021-005 Catalina, iOS 14.8 and iPadOS 14.8, macOS Big Sur 11.6, watchOS 7.6.2. Processing a maliciously crafted PDF may lead to arbitrary code execution. Apple is aware of a report that this issue may have been actively exploited.
</code>

- [jeffssh/CVE-2021-30860](https://github.com/jeffssh/CVE-2021-30860)

### CVE-2021-30862 (2021-08-24)

<code>A validation issue was addressed with improved input sanitization. This issue is fixed in iTunes U 3.8.3. Processing a maliciously crafted URL may lead to arbitrary javascript code execution.
</code>

- [Umarovm/CVE-2021-30862](https://github.com/Umarovm/CVE-2021-30862)

### CVE-2021-31166 (2021-05-11)

<code>HTTP Protocol Stack Remote Code Execution Vulnerability
</code>

- [corelight/CVE-2021-31166](https://github.com/corelight/CVE-2021-31166)

### CVE-2021-32471 (2021-05-10)

<code>Insufficient input validation in the Marvin Minsky 1967 implementation of the Universal Turing Machine allows program users to execute arbitrary code via crafted data. For example, a tape head may have an unexpected location after the processing of input composed of As and Bs (instead of 0s and 1s). NOTE: the discoverer states &quot;this vulnerability has no real-world implications.&quot;
</code>

- [intrinsic-propensity/turing-machine](https://github.com/intrinsic-propensity/turing-machine)

### CVE-2021-32708 (2021-06-24)

<code>Flysystem is an open source file storage library for PHP. The whitespace normalisation using in 1.x and 2.x removes any unicode whitespace. Under certain specific conditions this could potentially allow a malicious user to execute code remotely. The conditions are: A user is allowed to supply the path or filename of an uploaded file, the supplied path or filename is not checked against unicode chars, the supplied pathname checked against an extension deny-list, not an allow-list, the supplied path or filename contains a unicode whitespace char in the extension, the uploaded file is stored in a directory that allows PHP code to be executed. Given these conditions are met a user can upload and execute arbitrary code on the system under attack. The unicode whitespace removal has been replaced with a rejection (exception). For 1.x users, upgrade to 1.1.4. For 2.x users, upgrade to 2.1.1.
</code>

- [fazilbaig1/CVE-2021-32708](https://github.com/fazilbaig1/CVE-2021-32708)

### CVE-2021-33026 (2021-05-13)

<code>The Flask-Caching extension through 1.10.1 for Flask relies on Pickle for serialization, which may lead to remote code execution or local privilege escalation. If an attacker gains access to cache storage (e.g., filesystem, Memcached, Redis, etc.), they can construct a crafted payload, poison the cache, and execute Python code. NOTE: a third party indicates that exploitation is extremely unlikely unless the machine is already compromised; in other cases, the attacker would be unable to write their payload to the cache and generate the required collision
</code>

- [Agilevatester/FlaskCache_CVE-2021-33026_POC](https://github.com/Agilevatester/FlaskCache_CVE-2021-33026_POC)

### CVE-2021-35475 (2021-06-25)

<code>SAS Environment Manager 2.5 allows XSS through the Name field when creating/editing a server. The XSS will prompt when editing the Configuration Properties.
</code>

- [saitamang/CVE-2021-35475](https://github.com/saitamang/CVE-2021-35475)

### CVE-2021-36260 (2021-09-22)

<code>A command injection vulnerability in the web server of some Hikvision product. Due to the insufficient input validation, attacker can exploit the vulnerability to launch a command injection attack by sending some messages with malicious commands.
</code>

- [rabbitsafe/CVE-2021-36260](https://github.com/rabbitsafe/CVE-2021-36260)
- [aengussong/hikvision_probe](https://github.com/aengussong/hikvision_probe)

### CVE-2021-39863 (2021-09-29)

<code>Acrobat Reader DC versions 2021.005.20060 (and earlier), 2020.004.30006 (and earlier) and 2017.011.30199 (and earlier) are affected by a Buffer Overflow vulnerability when parsing a specially crafted PDF file. An unauthenticated attacker could leverage this vulnerability to achieve arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.
</code>

- [WHS-SEGFAULT/CVE-2021-39863](https://github.com/WHS-SEGFAULT/CVE-2021-39863)

### CVE-2021-40345 (2021-10-26)

<code>An issue was discovered in Nagios XI 5.8.5. In the Manage Dashlets section of the Admin panel, an administrator can upload ZIP files. A command injection (within the name of the first file in the archive) allows an attacker to execute system commands.
</code>

- [ArianeBlow/NagiosXI-RCE-all-version-CVE-2021-40345](https://github.com/ArianeBlow/NagiosXI-RCE-all-version-CVE-2021-40345)

### CVE-2021-40438 (2021-09-16)

<code>A crafted request uri-path can cause mod_proxy to forward the request to an origin server choosen by the remote user. This issue affects Apache HTTP Server 2.4.48 and earlier.
</code>

- [yakir2b/check-point-gateways-rce](https://github.com/yakir2b/check-point-gateways-rce)

### CVE-2021-40539 (2021-09-07)

<code>Zoho ManageEngine ADSelfService Plus version 6113 and prior is vulnerable to REST API authentication bypass with resultant remote code execution.
</code>

- [lpyzds/CVE-2021-40539](https://github.com/lpyzds/CVE-2021-40539)
- [lpyydxs/CVE-2021-40539](https://github.com/lpyydxs/CVE-2021-40539)
- [Bu0uCat/ADSelfService-Plus-RCE-CVE-2021-40539](https://github.com/Bu0uCat/ADSelfService-Plus-RCE-CVE-2021-40539)

### CVE-2021-41773 (2021-10-05)

<code>A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.
</code>

- [justakazh/mass_cve-2021-41773](https://github.com/justakazh/mass_cve-2021-41773)
- [MrCl0wnLab/SimplesApachePathTraversal](https://github.com/MrCl0wnLab/SimplesApachePathTraversal)
- [skentagon/CVE-2021-41773](https://github.com/skentagon/CVE-2021-41773)
- [Zyx2440/Apache-HTTP-Server-2.4.50-RCE](https://github.com/Zyx2440/Apache-HTTP-Server-2.4.50-RCE)
- [0xc4t/CVE-2021-41773](https://github.com/0xc4t/CVE-2021-41773)
- [jkska23/Additive-Vulnerability-Analysis-CVE-2021-41773](https://github.com/jkska23/Additive-Vulnerability-Analysis-CVE-2021-41773)
- [redspy-sec/CVE-2021-41773](https://github.com/redspy-sec/CVE-2021-41773)
- [FakesiteSecurity/CVE-2021-41773](https://github.com/FakesiteSecurity/CVE-2021-41773)
- [Taldrid1/cve-2021-41773](https://github.com/Taldrid1/cve-2021-41773)
- [tiemio/SSH-key-and-RCE-PoC-for-CVE-2021-41773](https://github.com/tiemio/SSH-key-and-RCE-PoC-for-CVE-2021-41773)

### CVE-2021-41805 (2021-12-12)

<code>HashiCorp Consul Enterprise before 1.8.17, 1.9.x before 1.9.11, and 1.10.x before 1.10.4 has Incorrect Access Control. An ACL token (with the default operator:write permissions) in one namespace can be used for unintended privilege escalation in a different namespace.
</code>

- [acfirthh/CVE-2021-41805](https://github.com/acfirthh/CVE-2021-41805)

### CVE-2021-42013 (2021-10-07)

<code>It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.
</code>

- [dream434/cve-2021-42013-apache](https://github.com/dream434/cve-2021-42013-apache)
- [asepsaepdin/CVE-2021-42013](https://github.com/asepsaepdin/CVE-2021-42013)

### CVE-2021-42056 (2022-06-24)

<code>Thales Safenet Authentication Client (SAC) for Linux and Windows through 10.7.7 creates insecure temporary hid and lock files allowing a local attacker, through a symlink attack, to overwrite arbitrary files, and potentially achieve arbitrary command execution with high privileges.
</code>

- [z00z00z00/Safenet_SAC_CVE-2021-42056](https://github.com/z00z00z00/Safenet_SAC_CVE-2021-42056)

### CVE-2021-42260 (2021-10-11)

<code>TinyXML through 2.6.2 has an infinite loop in TiXmlParsingData::Stamp in tinyxmlparser.cpp via the TIXML_UTF_LEAD_0 case. It can be triggered by a crafted XML message and leads to a denial of service.
</code>

- [vm2mv/tinyxml](https://github.com/vm2mv/tinyxml)

### CVE-2021-43008 (2022-04-05)

<code>Improper Access Control in Adminer versions 1.12.0 to 4.6.2 (fixed in version 4.6.3) allows an attacker to achieve Arbitrary File Read on the remote server by requesting the Adminer to connect to a remote MySQL database.
</code>

- [p0dalirius/CVE-2021-43008-AdminerRead](https://github.com/p0dalirius/CVE-2021-43008-AdminerRead)

### CVE-2021-43503
- [guoyanan1g/Laravel-vul](https://github.com/guoyanan1g/Laravel-vul)

### CVE-2021-43650 (2022-03-22)

<code>WebRun 3.6.0.42 is vulnerable to SQL Injection via the P_0 parameter used to set the username during the login process.
</code>

- [OpenXP-Research/CVE-2021-43650](https://github.com/OpenXP-Research/CVE-2021-43650)

### CVE-2021-43798 (2021-12-07)

<code>Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `&lt;grafana_host_url&gt;/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.
</code>

- [A-D-Team/grafanaExp](https://github.com/A-D-Team/grafanaExp)
- [0xSAZZAD/Grafana-CVE-2021-43798](https://github.com/0xSAZZAD/Grafana-CVE-2021-43798)
- [wezoomagency/GrafXploit](https://github.com/wezoomagency/GrafXploit)
- [davidr-io/Grafana-8.3-Directory-Traversal](https://github.com/davidr-io/Grafana-8.3-Directory-Traversal)
- [ravi5hanka/CVE-2021-43798-Exploit-for-Windows-and-Linux](https://github.com/ravi5hanka/CVE-2021-43798-Exploit-for-Windows-and-Linux)
- [monke443/CVE-2021-43798-Grafana-Arbitrary-File-Read](https://github.com/monke443/CVE-2021-43798-Grafana-Arbitrary-File-Read)

### CVE-2021-44228 (2021-12-10)

<code>Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.
</code>

- [christophetd/log4shell-vulnerable-app](https://github.com/christophetd/log4shell-vulnerable-app)
- [winnpixie/log4noshell](https://github.com/winnpixie/log4noshell)
- [kozmer/log4j-shell-poc](https://github.com/kozmer/log4j-shell-poc)
- [racoon-rac/CVE-2021-44228](https://github.com/racoon-rac/CVE-2021-44228)
- [b-abderrahmane/CVE-2021-44228-playground](https://github.com/b-abderrahmane/CVE-2021-44228-playground)
- [0xsyr0/Log4Shell](https://github.com/0xsyr0/Log4Shell)
- [corelight/cve-2021-44228](https://github.com/corelight/cve-2021-44228)
- [alexbakker/log4shell-tools](https://github.com/alexbakker/log4shell-tools)
- [0xInfection/LogMePwn](https://github.com/0xInfection/LogMePwn)
- [redhuntlabs/Log4JHunt](https://github.com/redhuntlabs/Log4JHunt)
- [inettgmbh/checkmk-log4j-scanner](https://github.com/inettgmbh/checkmk-log4j-scanner)
- [michaelsanford/Log4Shell-Honeypot](https://github.com/michaelsanford/Log4Shell-Honeypot)
- [thomaspatzke/Log4Pot](https://github.com/thomaspatzke/Log4Pot)
- [julian911015/Log4j-Scanner-Exploit](https://github.com/julian911015/Log4j-Scanner-Exploit)
- [puzzlepeaches/Log4jUnifi](https://github.com/puzzlepeaches/Log4jUnifi)
- [s-retlaw/l4s_poc](https://github.com/s-retlaw/l4s_poc)
- [sec13b/CVE-2021-44228-POC](https://github.com/sec13b/CVE-2021-44228-POC)
- [OtisSymbos/CVE-2021-44228-Log4Shell-](https://github.com/OtisSymbos/CVE-2021-44228-Log4Shell-)
- [safeer-accuknox/log4j-shell-poc](https://github.com/safeer-accuknox/log4j-shell-poc)
- [Carlos-Mesquita/TPASLog4ShellPoC](https://github.com/Carlos-Mesquita/TPASLog4ShellPoC)
- [AhmedMansour93/-Unveiling-the-Lessons-from-Log4Shell-A-Wake-Up-Call-for-Cybersecurity-](https://github.com/AhmedMansour93/-Unveiling-the-Lessons-from-Log4Shell-A-Wake-Up-Call-for-Cybersecurity-)
- [Super-Binary/cve-2021-44228](https://github.com/Super-Binary/cve-2021-44228)
- [ZacharyZcR/CVE-2021-44228](https://github.com/ZacharyZcR/CVE-2021-44228)
- [qw3rtyou/CVE-2021-44228_dockernize](https://github.com/qw3rtyou/CVE-2021-44228_dockernize)
- [yadavmukesh/Log4Shell-vulnerability-CVE-2021-44228-](https://github.com/yadavmukesh/Log4Shell-vulnerability-CVE-2021-44228-)
- [lustrouscave/log4shell-tools](https://github.com/lustrouscave/log4shell-tools)

### CVE-2021-44270
- [pinpinsec/CVE-2021-44270](https://github.com/pinpinsec/CVE-2021-44270)

### CVE-2021-44832 (2021-12-28)

<code>Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding security fix releases 2.3.2 and 2.12.4) are vulnerable to a remote code execution (RCE) attack when a configuration uses a JDBC Appender with a JNDI LDAP data source URI when an attacker has control of the target LDAP server. This issue is fixed by limiting JNDI data source names to the java protocol in Log4j2 versions 2.17.1, 2.12.4, and 2.3.2.
</code>

- [name/log4j-scanner](https://github.com/name/log4j-scanner)

### CVE-2021-44967 (2022-02-22)

<code>A Remote Code Execution (RCE) vulnerabilty exists in LimeSurvey 5.2.4 via the upload and install plugins function, which could let a remote malicious user upload an arbitrary PHP code file. NOTE: the Supplier's position is that plugins intentionally can contain arbitrary PHP code, and can only be installed by a superadmin, and therefore the security model is not violated by this finding.
</code>

- [D3Ext/CVE-2021-44967](https://github.com/D3Ext/CVE-2021-44967)
- [godylockz/CVE-2021-44967](https://github.com/godylockz/CVE-2021-44967)


## 2020
### CVE-2020-0022 (2020-02-13)

<code>In reassemble_and_dispatch of packet_fragmenter.cc, there is possible out of bounds write due to an incorrect bounds calculation. This could lead to remote code execution over Bluetooth with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-8.0 Android-8.1 Android-9 Android-10Android ID: A-143894715
</code>

- [k3vinlusec/Bluefrag_CVE-2020-0022](https://github.com/k3vinlusec/Bluefrag_CVE-2020-0022)
- [5k1l/cve-2020-0022](https://github.com/5k1l/cve-2020-0022)

### CVE-2020-0041 (2020-03-10)

<code>In binder_transaction of binder.c, there is a possible out of bounds write due to an incorrect bounds check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-145988638References: Upstream kernel
</code>

- [j4nn/CVE-2020-0041](https://github.com/j4nn/CVE-2020-0041)

### CVE-2020-0069 (2020-03-10)

<code>In the ioctl handlers of the Mediatek Command Queue driver, there is a possible out of bounds write due to insufficient input sanitization and missing SELinux restrictions. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-147882143References: M-ALPS04356754
</code>

- [R0rt1z2/AutomatedRoot](https://github.com/R0rt1z2/AutomatedRoot)

### CVE-2020-0113 (2020-06-10)

<code>In sendCaptureResult of Camera3OutputUtils.cpp, there is a possible out of bounds read due to a use after free. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-9Android ID: A-150944913
</code>

- [XDo0/ServiceCheater](https://github.com/XDo0/ServiceCheater)

### CVE-2020-0601 (2020-01-14)

<code>A spoofing vulnerability exists in the way Windows CryptoAPI (Crypt32.dll) validates Elliptic Curve Cryptography (ECC) certificates.An attacker could exploit the vulnerability by using a spoofed code-signing certificate to sign a malicious executable, making it appear the file was from a trusted, legitimate source, aka 'Windows CryptoAPI Spoofing Vulnerability'.
</code>

- [0xxon/cve-2020-0601](https://github.com/0xxon/cve-2020-0601)
- [kudelskisecurity/chainoffools](https://github.com/kudelskisecurity/chainoffools)
- [saleemrashid/badecparams](https://github.com/saleemrashid/badecparams)
- [Hans-MartinHannibalLauridsen/CurveBall](https://github.com/Hans-MartinHannibalLauridsen/CurveBall)
- [ioncodes/Curveball](https://github.com/ioncodes/Curveball)

### CVE-2020-0683 (2020-02-11)

<code>An elevation of privilege vulnerability exists in the Windows Installer when MSI packages process symbolic links, aka 'Windows Installer Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-0686.
</code>

- [padovah4ck/CVE-2020-0683](https://github.com/padovah4ck/CVE-2020-0683)

### CVE-2020-0688 (2020-02-11)

<code>A remote code execution vulnerability exists in Microsoft Exchange software when the software fails to properly handle objects in memory, aka 'Microsoft Exchange Memory Corruption Vulnerability'.
</code>

- [Ridter/cve-2020-0688](https://github.com/Ridter/cve-2020-0688)
- [truongtn/cve-2020-0688](https://github.com/truongtn/cve-2020-0688)
- [w4fz5uck5/cve-2020-0688-webshell-upload-technique](https://github.com/w4fz5uck5/cve-2020-0688-webshell-upload-technique)
- [zyn3rgy/ecp_slap](https://github.com/zyn3rgy/ecp_slap)

### CVE-2020-0787 (2020-03-12)

<code>An elevation of privilege vulnerability exists when the Windows Background Intelligent Transfer Service (BITS) improperly handles symbolic links, aka 'Windows Background Intelligent Transfer Service Elevation of Privilege Vulnerability'.
</code>

- [MasterSploit/CVE-2020-0787](https://github.com/MasterSploit/CVE-2020-0787)
- [MasterSploit/CVE-2020-0787-BitsArbitraryFileMove-master](https://github.com/MasterSploit/CVE-2020-0787-BitsArbitraryFileMove-master)

### CVE-2020-0796 (2020-03-12)

<code>A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.
</code>

- [T13nn3s/CVE-2020-0796](https://github.com/T13nn3s/CVE-2020-0796)
- [awareseven/eternalghosttest](https://github.com/awareseven/eternalghosttest)
- [eerykitty/CVE-2020-0796-PoC](https://github.com/eerykitty/CVE-2020-0796-PoC)
- [w1ld3r/SMBGhost_Scanner](https://github.com/w1ld3r/SMBGhost_Scanner)
- [ran-sama/CVE-2020-0796](https://github.com/ran-sama/CVE-2020-0796)
- [julixsalas/CVE-2020-0796](https://github.com/julixsalas/CVE-2020-0796)
- [Barriuso/SMBGhost_AutomateExploitation](https://github.com/Barriuso/SMBGhost_AutomateExploitation)
- [datntsec/CVE-2020-0796](https://github.com/datntsec/CVE-2020-0796)

### CVE-2020-1034 (2020-09-11)

<code>&lt;p&gt;An elevation of privilege vulnerability exists in the way that the Windows Kernel handles objects in memory. An attacker who successfully exploited the vulnerability could execute code with elevated permissions.&lt;/p&gt;\n&lt;p&gt;To exploit the vulnerability, a locally authenticated attacker could run a specially crafted application.&lt;/p&gt;\n&lt;p&gt;The security update addresses the vulnerability by ensuring the Windows Kernel properly handles objects in memory.&lt;/p&gt;\n
</code>

- [yardenshafir/CVE-2020-1034](https://github.com/yardenshafir/CVE-2020-1034)

### CVE-2020-1102 (2020-05-21)

<code>A remote code execution vulnerability exists in Microsoft SharePoint when the software fails to check the source markup of an application package, aka 'Microsoft SharePoint Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2020-1023, CVE-2020-1024.
</code>

- [DanielRuf/snyk-js-jquery-565129](https://github.com/DanielRuf/snyk-js-jquery-565129)

### CVE-2020-1337 (2020-08-17)

<code>An elevation of privilege vulnerability exists when the Windows Print Spooler service improperly allows arbitrary writing to the file system. An attacker who successfully exploited this vulnerability could run arbitrary code with elevated system privileges. An attacker could then install programs; view, change, or delete data; or create new accounts with full user rights.\nTo exploit this vulnerability, an attacker would have to log on to an affected system and run a specially crafted script or application.\nThe update addresses the vulnerability by correcting how the Windows Print Spooler Component writes to the file system.\n
</code>

- [math1as/CVE-2020-1337-exploit](https://github.com/math1as/CVE-2020-1337-exploit)

### CVE-2020-1350 (2020-07-14)

<code>A remote code execution vulnerability exists in Windows Domain Name System servers when they fail to properly handle requests, aka 'Windows DNS Server Remote Code Execution Vulnerability'.
</code>

- [T13nn3s/CVE-2020-1350](https://github.com/T13nn3s/CVE-2020-1350)

### CVE-2020-1472 (2020-08-17)

<code>An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC). An attacker who successfully exploited the vulnerability could run a specially crafted application on a device on the network.\nTo exploit the vulnerability, an unauthenticated attacker would be required to use MS-NRPC to connect to a domain controller to obtain domain administrator access.\nMicrosoft is addressing the vulnerability in a phased two-part rollout. These updates address the vulnerability by modifying how Netlogon handles the usage of Netlogon secure channels.\nFor guidelines on how to manage the changes required for this vulnerability and more information on the phased rollout, see  How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472 (updated September 28, 2020).\nWhen the second phase of Windows updates become available in Q1 2021, customers will be notified via a revision to this security vulnerability. If you wish to be notified when these updates are released, we recommend that you register for the security notifications mailer to be alerted of content changes to this advisory. See Microsoft Technical Security Notifications.\n
</code>

- [SecuraBV/CVE-2020-1472](https://github.com/SecuraBV/CVE-2020-1472)
- [bb00/zer0dump](https://github.com/bb00/zer0dump)
- [zeronetworks/zerologon](https://github.com/zeronetworks/zerologon)
- [sv3nbeast/CVE-2020-1472](https://github.com/sv3nbeast/CVE-2020-1472)
- [CPO-EH/CVE-2020-1472_ZeroLogonChecker](https://github.com/CPO-EH/CVE-2020-1472_ZeroLogonChecker)
- [puckiestyle/CVE-2020-1472](https://github.com/puckiestyle/CVE-2020-1472)
- [JayP232/The_big_Zero](https://github.com/JayP232/The_big_Zero)
- [SaharAttackit/CVE-2020-1472](https://github.com/SaharAttackit/CVE-2020-1472)

### CVE-2020-1938 (2020-02-24)

<code>When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.
</code>

- [w4fz5uck5/CVE-2020-1938-Clean-Version](https://github.com/w4fz5uck5/CVE-2020-1938-Clean-Version)

### CVE-2020-1948 (2020-07-14)

<code>This vulnerability can affect all Dubbo users stay on version 2.7.6 or lower. An attacker can send RPC requests with unrecognized service name or method name along with some malicious parameter payloads. When the malicious parameter is deserialized, it will execute some malicious code. More details can be found below.
</code>

- [L0kiii/Dubbo-deserialization](https://github.com/L0kiii/Dubbo-deserialization)

### CVE-2020-1967 (2020-04-21)

<code>Server or client applications that call the SSL_check_chain() function during or after a TLS 1.3 handshake may crash due to a NULL pointer dereference as a result of incorrect handling of the &quot;signature_algorithms_cert&quot; TLS extension. The crash occurs if an invalid or unrecognised signature algorithm is received from the peer. This could be exploited by a malicious peer in a Denial of Service attack. OpenSSL version 1.1.1d, 1.1.1e, and 1.1.1f are affected by this issue. This issue did not affect OpenSSL versions prior to 1.1.1d. Fixed in OpenSSL 1.1.1g (Affected 1.1.1d-1.1.1f).
</code>

- [irsl/CVE-2020-1967](https://github.com/irsl/CVE-2020-1967)

### CVE-2020-1971 (2020-12-08)

<code>The X.509 GeneralName type is a generic type for representing different types of names. One of those name types is known as EDIPartyName. OpenSSL provides a function GENERAL_NAME_cmp which compares different instances of a GENERAL_NAME to see if they are equal or not. This function behaves incorrectly when both GENERAL_NAMEs contain an EDIPARTYNAME. A NULL pointer dereference and a crash may occur leading to a possible denial of service attack. OpenSSL itself uses the GENERAL_NAME_cmp function for two purposes: 1) Comparing CRL distribution point names between an available CRL and a CRL distribution point embedded in an X509 certificate 2) When verifying that a timestamp response token signer matches the timestamp authority name (exposed via the API functions TS_RESP_verify_response and TS_RESP_verify_token) If an attacker can control both items being compared then that attacker could trigger a crash. For example if the attacker can trick a client or server into checking a malicious certificate against a malicious CRL then this may occur. Note that some applications automatically download CRLs based on a URL embedded in a certificate. This checking happens prior to the signatures on the certificate and CRL being verified. OpenSSL's s_server, s_client and verify tools have support for the &quot;-crl_download&quot; option which implements automatic CRL downloading and this attack has been demonstrated to work against those tools. Note that an unrelated bug means that affected versions of OpenSSL cannot parse or construct correct encodings of EDIPARTYNAME. However it is possible to construct a malformed EDIPARTYNAME that OpenSSL's parser will accept and hence trigger this attack. All OpenSSL 1.1.1 and 1.0.2 versions are affected by this issue. Other OpenSSL releases are out of support and have not been checked. Fixed in OpenSSL 1.1.1i (Affected 1.1.1-1.1.1h). Fixed in OpenSSL 1.0.2x (Affected 1.0.2-1.0.2w).
</code>

- [MBHudson/CVE-2020-1971](https://github.com/MBHudson/CVE-2020-1971)

### CVE-2020-2546 (2020-01-15)

<code>Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Application Container - JavaEE). Supported versions that are affected are 10.3.6.0.0 and 12.1.3.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
</code>

- [hktalent/CVE_2020_2546](https://github.com/hktalent/CVE_2020_2546)

### CVE-2020-2551 (2020-01-15)

<code>Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: WLS Core Components). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
</code>

- [0xn0ne/weblogicScanner](https://github.com/0xn0ne/weblogicScanner)
- [hktalent/CVE-2020-2551](https://github.com/hktalent/CVE-2020-2551)
- [zzwlpx/weblogicPoc](https://github.com/zzwlpx/weblogicPoc)

### CVE-2020-2555 (2020-01-15)

<code>Vulnerability in the Oracle Coherence product of Oracle Fusion Middleware (component: Caching,CacheStore,Invocation). Supported versions that are affected are 3.7.1.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle Coherence. Successful attacks of this vulnerability can result in takeover of Oracle Coherence. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
</code>

- [Y4er/CVE-2020-2555](https://github.com/Y4er/CVE-2020-2555)

### CVE-2020-2978 (2020-07-15)

<code>Vulnerability in the Oracle Database - Enterprise Edition component of Oracle Database Server. Supported versions that are affected are 12.1.0.2, 12.2.0.1, 18c and 19c. Easily exploitable vulnerability allows high privileged attacker having DBA role account privilege with network access via Oracle Net to compromise Oracle Database - Enterprise Edition. While the vulnerability is in Oracle Database - Enterprise Edition, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle Database - Enterprise Edition accessible data. CVSS 3.1 Base Score 4.1 (Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:L/A:N).
</code>

- [emad-almousa/CVE-2020-2978](https://github.com/emad-almousa/CVE-2020-2978)

### CVE-2020-3161 (2020-04-15)

<code>A vulnerability in the web server for Cisco IP Phones could allow an unauthenticated, remote attacker to execute code with root privileges or cause a reload of an affected IP phone, resulting in a denial of service (DoS) condition. The vulnerability is due to a lack of proper input validation of HTTP requests. An attacker could exploit this vulnerability by sending a crafted HTTP request to the web server of a targeted device. A successful exploit could allow the attacker to remotely execute code with root privileges or cause a reload of an affected IP phone, resulting in a DoS condition.
</code>

- [abood05972/CVE-2020-3161](https://github.com/abood05972/CVE-2020-3161)

### CVE-2020-3452 (2020-07-22)

<code>A vulnerability in the web services interface of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to conduct directory traversal attacks and read sensitive files on a targeted system. The vulnerability is due to a lack of proper input validation of URLs in HTTP requests processed by an affected device. An attacker could exploit this vulnerability by sending a crafted HTTP request containing directory traversal character sequences to an affected device. A successful exploit could allow the attacker to view arbitrary files within the web services file system on the targeted device. The web services file system is enabled when the affected device is configured with either WebVPN or AnyConnect features. This vulnerability cannot be used to obtain access to ASA or FTD system files or underlying operating system (OS) files.
</code>

- [cygenta/CVE-2020-3452](https://github.com/cygenta/CVE-2020-3452)

### CVE-2020-3992 (2020-10-20)

<code>OpenSLP as used in VMware ESXi (7.0 before ESXi_7.0.1-0.0.16850804, 6.7 before ESXi670-202010401-SG, 6.5 before ESXi650-202010401-SG) has a use-after-free issue. A malicious actor residing in the management network who has access to port 427 on an ESXi machine may be able to trigger a use-after-free in the OpenSLP service resulting in remote code execution.
</code>

- [HynekPetrak/CVE-2019-5544_CVE-2020-3992](https://github.com/HynekPetrak/CVE-2019-5544_CVE-2020-3992)

### CVE-2020-4463 (2020-07-29)

<code>IBM Maximo Asset Management 7.6.0.1 and 7.6.0.2 is vulnerable to an XML External Entity Injection (XXE) attack when processing XML data. A remote attacker could exploit this vulnerability to expose sensitive information or consume memory resources. IBM X-Force ID: 181484.
</code>

- [Ibonok/CVE-2020-4463](https://github.com/Ibonok/CVE-2020-4463)

### CVE-2020-5014 (2021-03-08)

<code>IBM DataPower Gateway V10 and V2018 could allow a local attacker with administrative privileges to execute arbitrary code on the system using a server-side requesr forgery attack. IBM X-Force ID: 193247.
</code>

- [copethomas/datapower-redis-rce-exploit](https://github.com/copethomas/datapower-redis-rce-exploit)

### CVE-2020-5248 (2020-05-12)

<code>GLPI before before version 9.4.6 has a vulnerability involving a default encryption key. GLPIKEY is public and is used on every instance. This means anyone can decrypt sensitive data stored using this key. It is possible to change the key before installing GLPI. But on existing instances, data must be reencrypted with the new key. Problem is we can not know which columns or rows in the database are using that; espcially from plugins. Changing the key without updating data would lend in bad password sent from glpi; but storing them again from the UI will work.
</code>

- [indevi0us/CVE-2020-5248](https://github.com/indevi0us/CVE-2020-5248)

### CVE-2020-5267 (2020-03-19)

<code>In ActionView before versions 6.0.2.2 and 5.2.4.2, there is a possible XSS vulnerability in ActionView's JavaScript literal escape helpers. Views that use the `j` or `escape_javascript` methods may be susceptible to XSS attacks. The issue is fixed in versions 6.0.2.2 and 5.2.4.2.
</code>

- [GUI/legacy-rails-CVE-2020-5267-patch](https://github.com/GUI/legacy-rails-CVE-2020-5267-patch)

### CVE-2020-5398 (2020-01-16)

<code>In Spring Framework, versions 5.2.x prior to 5.2.3, versions 5.1.x prior to 5.1.13, and versions 5.0.x prior to 5.0.16, an application is vulnerable to a reflected file download (RFD) attack when it sets a &quot;Content-Disposition&quot; header in the response where the filename attribute is derived from user supplied input.
</code>

- [motikan2010/CVE-2020-5398](https://github.com/motikan2010/CVE-2020-5398)

### CVE-2020-5902 (2020-07-01)

<code>In BIG-IP versions 15.0.0-15.1.0.3, 14.1.0-14.1.2.5, 13.1.0-13.1.3.3, 12.1.0-12.1.5.1, and 11.6.1-11.6.5.1, the Traffic Management User Interface (TMUI), also referred to as the Configuration utility, has a Remote Code Execution (RCE) vulnerability in undisclosed pages.
</code>

- [aqhmal/CVE-2020-5902-Scanner](https://github.com/aqhmal/CVE-2020-5902-Scanner)
- [jas502n/CVE-2020-5902](https://github.com/jas502n/CVE-2020-5902)
- [yasserjanah/CVE-2020-5902](https://github.com/yasserjanah/CVE-2020-5902)
- [dunderhay/CVE-2020-5902](https://github.com/dunderhay/CVE-2020-5902)
- [cristiano-corrado/f5_scanner](https://github.com/cristiano-corrado/f5_scanner)
- [PushpenderIndia/CVE-2020-5902-Scanner](https://github.com/PushpenderIndia/CVE-2020-5902-Scanner)

### CVE-2020-6287 (2020-07-14)

<code>SAP NetWeaver AS JAVA (LM Configuration Wizard), versions - 7.30, 7.31, 7.40, 7.50, does not perform an authentication check which allows an attacker without prior authentication to execute configuration tasks to perform critical actions against the SAP Java system, including the ability to create an administrative user, and therefore compromising Confidentiality, Integrity and Availability of the system, leading to Missing Authentication Check.
</code>

- [Onapsis/CVE-2020-6287_RECON-scanner](https://github.com/Onapsis/CVE-2020-6287_RECON-scanner)

### CVE-2020-6308 (2020-10-20)

<code>SAP BusinessObjects Business Intelligence Platform (Web Services) versions - 410, 420, 430, allows an unauthenticated attacker to inject arbitrary values as CMS parameters to perform lookups on the internal network which is otherwise not accessible externally. On successful exploitation, attacker can scan internal network to determine internal infrastructure and gather information for further attacks like remote file inclusion, retrieve server files, bypass firewall and force the vulnerable server to perform malicious requests, resulting in a Server-Side Request Forgery vulnerability.
</code>

- [InitRoot/CVE-2020-6308-PoC](https://github.com/InitRoot/CVE-2020-6308-PoC)

### CVE-2020-7247 (2020-01-29)

<code>smtp_mailaddr in smtp_session.c in OpenSMTPD 6.6, as used in OpenBSD 6.6 and other products, allows remote attackers to execute arbitrary commands as root via a crafted SMTP session, as demonstrated by shell metacharacters in a MAIL FROM field. This affects the &quot;uncommented&quot; default configuration. The issue exists because of an incorrect return value upon failure of input validation.
</code>

- [superzerosec/cve-2020-7247](https://github.com/superzerosec/cve-2020-7247)

### CVE-2020-7473 (2020-05-07)

<code>In certain situations, all versions of Citrix ShareFile StorageZones (aka storage zones) Controller, including the most recent 5.10.x releases as of May 2020, allow unauthenticated attackers to access the documents and folders of ShareFile users. NOTE: unlike most CVEs, exploitability depends on the product version that was in use when a particular setup step was performed, NOT the product version that is in use during a current assessment of a CVE consumer's product inventory. Specifically, the vulnerability can be exploited if a storage zone was created by one of these product versions: 5.9.0, 5.8.0, 5.7.0, 5.6.0, 5.5.0, or earlier. This CVE differs from CVE-2020-8982 and CVE-2020-8983 but has essentially the same risk.
</code>

- [DimitriNL/CTX-CVE-2020-7473](https://github.com/DimitriNL/CTX-CVE-2020-7473)

### CVE-2020-7661 (2020-06-04)

<code>all versions of url-regex are vulnerable to Regular Expression Denial of Service. An attacker providing a very long string in String.test can cause a Denial of Service.
</code>

- [spamscanner/url-regex-safe](https://github.com/spamscanner/url-regex-safe)

### CVE-2020-7961 (2020-03-20)

<code>Deserialization of Untrusted Data in Liferay Portal prior to 7.2.1 CE GA2 allows remote attackers to execute arbitrary code via JSON web services (JSONWS).
</code>

- [shacojx/POC-CVE-2020-7961-Token-iterate](https://github.com/shacojx/POC-CVE-2020-7961-Token-iterate)

### CVE-2020-7980 (2020-01-25)

<code>Intellian Aptus Web 1.24 allows remote attackers to execute arbitrary OS commands via the Q field within JSON data to the cgi-bin/libagent.cgi URI. NOTE: a valid sid cookie for a login to the intellian default account might be needed.
</code>

- [Xh4H/Satellian-CVE-2020-7980](https://github.com/Xh4H/Satellian-CVE-2020-7980)

### CVE-2020-8012 (2020-02-18)

<code>CA Unified Infrastructure Management (Nimsoft/UIM) 20.1, 20.3.x, and 9.20 and below contains a buffer overflow vulnerability in the robot (controller) component. A remote attacker can execute arbitrary code.
</code>

- [wetw0rk/Exploit-Development](https://github.com/wetw0rk/Exploit-Development)

### CVE-2020-8163 (2020-07-02)

<code>The is a code injection vulnerability in versions of Rails prior to 5.0.1 that wouldallow an attacker who controlled the `locals` argument of a `render` call to perform a RCE.
</code>

- [lucasallan/CVE-2020-8163](https://github.com/lucasallan/CVE-2020-8163)
- [h4ms1k/CVE-2020-8163](https://github.com/h4ms1k/CVE-2020-8163)

### CVE-2020-8165 (2020-06-19)

<code>A deserialization of untrusted data vulnernerability exists in rails &lt; 5.2.4.3, rails &lt; 6.0.3.1 that can allow an attacker to unmarshal user-provided objects in MemCacheStore and RedisCacheStore potentially resulting in an RCE.
</code>

- [masahiro331/CVE-2020-8165](https://github.com/masahiro331/CVE-2020-8165)
- [taipansec/CVE-2020-8165](https://github.com/taipansec/CVE-2020-8165)

### CVE-2020-8193 (2020-07-10)

<code>Improper access control in Citrix ADC and Citrix Gateway versions before 13.0-58.30, 12.1-57.18, 12.0-63.21, 11.1-64.14 and 10.5-70.18 and Citrix SDWAN WAN-OP versions before 11.1.1a, 11.0.3d and 10.2.7 allows unauthenticated access to certain URL endpoints.
</code>

- [PR3R00T/CVE-2020-8193-Citrix-Scanner](https://github.com/PR3R00T/CVE-2020-8193-Citrix-Scanner)

### CVE-2020-8209 (2020-08-17)

<code>Improper access control in Citrix XenMobile Server 10.12 before RP2, Citrix XenMobile Server 10.11 before RP4, Citrix XenMobile Server 10.10 before RP6 and Citrix XenMobile Server before 10.9 RP5 and leads to the ability to read arbitrary files.
</code>

- [B1anda0/CVE-2020-8209](https://github.com/B1anda0/CVE-2020-8209)

### CVE-2020-8417 (2020-01-28)

<code>The Code Snippets plugin before 2.14.0 for WordPress allows CSRF because of the lack of a Referer check on the import menu.
</code>

- [Rapidsafeguard/codesnippets_CVE-2020-8417](https://github.com/Rapidsafeguard/codesnippets_CVE-2020-8417)

### CVE-2020-8554 (2021-01-21)

<code>Kubernetes API server in all versions allow an attacker who is able to create a ClusterIP service and set the spec.externalIPs field, to intercept traffic to that IP address. Additionally, an attacker who is able to patch the status (which is considered a privileged operation and should not typically be granted to users) of a LoadBalancer service can set the status.loadBalancer.ingress.ip to similar effect.
</code>

- [rancher/externalip-webhook](https://github.com/rancher/externalip-webhook)
- [jrmurray000/CVE-2020-8554](https://github.com/jrmurray000/CVE-2020-8554)
- [twistlock/k8s-cve-2020-8554-mitigations](https://github.com/twistlock/k8s-cve-2020-8554-mitigations)

### CVE-2020-8635 (2020-03-06)

<code>Wing FTP Server v6.2.3 for Linux, macOS, and Solaris sets insecure permissions on installation directories and configuration files. This allows local users to arbitrarily create FTP users with full privileges, and escalate privileges within the operating system by modifying system files.
</code>

- [Al1ex/CVE-2020-8635](https://github.com/Al1ex/CVE-2020-8635)

### CVE-2020-8816 (2020-05-29)

<code>Pi-hole Web v4.3.2 (aka AdminLTE) allows Remote Code Execution by privileged dashboard users via a crafted DHCP static lease.
</code>

- [martinsohn/CVE-2020-8816](https://github.com/martinsohn/CVE-2020-8816)

### CVE-2020-8825 (2020-02-10)

<code>index.php?p=/dashboard/settings/branding in Vanilla 2.6.3 allows stored XSS.
</code>

- [hacky1997/CVE-2020-8825](https://github.com/hacky1997/CVE-2020-8825)

### CVE-2020-8840 (2020-02-10)

<code>FasterXML jackson-databind 2.0.0 through 2.9.10.2 lacks certain xbean-reflect/JNDI blocking, as demonstrated by org.apache.xbean.propertyeditor.JndiConverter.
</code>

- [Wfzsec/FastJson1.2.62-RCE](https://github.com/Wfzsec/FastJson1.2.62-RCE)
- [Veraxy00/CVE-2020-8840](https://github.com/Veraxy00/CVE-2020-8840)

### CVE-2020-9006 (2020-02-17)

<code>The Popup Builder plugin 2.2.8 through 2.6.7.6 for WordPress is vulnerable to SQL injection (in the sgImportPopups function in sg_popup_ajax.php) via PHP Deserialization on attacker-controlled data with the attachmentUrl POST variable. This allows creation of an arbitrary WordPress Administrator account, leading to possible Remote Code Execution because Administrators can run PHP code on Wordpress instances. (This issue has been fixed in the 3.x branch of popup-builder.)
</code>

- [s3rgeym/cve-2020-9006](https://github.com/s3rgeym/cve-2020-9006)

### CVE-2020-9273 (2020-02-20)

<code>In ProFTPD 1.3.7, it is possible to corrupt the memory pool by interrupting the data transfer channel. This triggers a use-after-free in alloc_pool in pool.c, and possible remote code execution.
</code>

- [ptef/CVE-2020-9273](https://github.com/ptef/CVE-2020-9273)

### CVE-2020-9380 (2020-03-05)

<code>IPTV Smarters WEB TV PLAYER through 2020-02-22 allows attackers to execute OS commands by uploading a script.
</code>

- [migueltarga/CVE-2020-9380](https://github.com/migueltarga/CVE-2020-9380)

### CVE-2020-9470 (2020-03-07)

<code>An issue was discovered in Wing FTP Server 6.2.5 before February 2020. Due to insecure permissions when handling session cookies, a local user may view the contents of the session and session_admin directories, which expose active session cookies within the Wing FTP HTTP interface and administration panel. These cookies may be used to hijack user and administrative sessions, including the ability to execute Lua commands as root within the administration panel.
</code>

- [Al1ex/CVE-2020-9470](https://github.com/Al1ex/CVE-2020-9470)

### CVE-2020-9484 (2020-05-20)

<code>When using Apache Tomcat versions 10.0.0-M1 to 10.0.0-M4, 9.0.0.M1 to 9.0.34, 8.5.0 to 8.5.54 and 7.0.0 to 7.0.103 if a) an attacker is able to control the contents and name of a file on the server; and b) the server is configured to use the PersistenceManager with a FileStore; and c) the PersistenceManager is configured with sessionAttributeValueClassNameFilter=&quot;null&quot; (the default unless a SecurityManager is used) or a sufficiently lax filter to allow the attacker provided object to be deserialized; and d) the attacker knows the relative file path from the storage location used by FileStore to the file the attacker has control over; then, using a specifically crafted request, the attacker will be able to trigger remote code execution via deserialization of the file under their control. Note that all of conditions a) to d) must be true for the attack to succeed.
</code>

- [PenTestical/CVE-2020-9484](https://github.com/PenTestical/CVE-2020-9484)

### CVE-2020-10148 (2020-12-29)

<code>The SolarWinds Orion API is vulnerable to an authentication bypass that could allow a remote attacker to execute API commands. This vulnerability could allow a remote attacker to bypass authentication and execute API commands which may result in a compromise of the SolarWinds instance. SolarWinds Orion Platform versions 2019.4 HF 5, 2020.2 with no hotfix installed, and 2020.2 HF 1 are affected.
</code>

- [rdoix/CVE-2020-10148-Solarwinds-Orion](https://github.com/rdoix/CVE-2020-10148-Solarwinds-Orion)

### CVE-2020-10558 (2020-03-20)

<code>The driving interface of Tesla Model 3 vehicles in any release before 2020.4.10 allows Denial of Service to occur due to improper process separation, which allows attackers to disable the speedometer, web browser, climate controls, turn signal visual and sounds, navigation, autopilot notifications, along with other miscellaneous functions from the main screen.
</code>

- [nullze/CVE-2020-10558](https://github.com/nullze/CVE-2020-10558)

### CVE-2020-10560 (2020-03-30)

<code>An issue was discovered in Open Source Social Network (OSSN) through 5.3. A user-controlled file path with a weak cryptographic rand() can be used to read any file with the permissions of the webserver. This can lead to further compromise. The attacker must conduct a brute-force attack against the SiteKey to insert into a crafted URL for components/OssnComments/ossn_com.php and/or libraries/ossn.lib.upgrade.php.
</code>

- [kevthehermit/CVE-2020-10560](https://github.com/kevthehermit/CVE-2020-10560)

### CVE-2020-10663 (2020-04-28)

<code>The JSON gem through 2.2.0 for Ruby, as used in Ruby 2.4 through 2.4.9, 2.5 through 2.5.7, and 2.6 through 2.6.5, has an Unsafe Object Creation Vulnerability. This is quite similar to CVE-2013-0269, but does not rely on poor garbage-collection behavior within Ruby. Specifically, use of JSON parsing methods can lead to creation of a malicious object within the interpreter, with adverse effects that are application-dependent.
</code>

- [rails-lts/json_cve_2020_10663](https://github.com/rails-lts/json_cve_2020_10663)

### CVE-2020-10673 (2020-03-18)

<code>FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to com.caucho.config.types.ResourceRef (aka caucho-quercus).
</code>

- [Al1ex/CVE-2020-10673](https://github.com/Al1ex/CVE-2020-10673)

### CVE-2020-10977 (2020-04-08)

<code>GitLab EE/CE 8.5 to 12.9 is vulnerable to a an path traversal when moving an issue between projects.
</code>

- [thewhiteh4t/cve-2020-10977](https://github.com/thewhiteh4t/cve-2020-10977)

### CVE-2020-11113 (2020-03-31)

<code>FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to org.apache.openjpa.ee.WASRegistryManagedRuntime (aka openjpa).
</code>

- [Al1ex/CVE-2020-11113](https://github.com/Al1ex/CVE-2020-11113)

### CVE-2020-11519 (2020-06-22)

<code>The SDDisk2k.sys driver of WinMagic SecureDoc v8.5 and earlier allows local users to read or write to physical disc sectors via a \\.\SecureDocDevice handle. Exploiting this vulnerability results in privileged code execution.
</code>

- [patois/winmagic_sd](https://github.com/patois/winmagic_sd)

### CVE-2020-11579 (2020-09-03)

<code>An issue was discovered in Chadha PHPKB 9.0 Enterprise Edition. installer/test-connection.php (part of the installation process) allows a remote unauthenticated attacker to disclose local files on hosts running PHP before 7.2.16, or on hosts where the MySQL ALLOW LOCAL DATA INFILE option is enabled.
</code>

- [ShielderSec/CVE-2020-11579](https://github.com/ShielderSec/CVE-2020-11579)

### CVE-2020-11651 (2020-04-30)

<code>An issue was discovered in SaltStack Salt before 2019.2.4 and 3000 before 3000.2. The salt-master process ClearFuncs class does not properly validate method calls. This allows a remote user to access some methods without authentication. These methods can be used to retrieve user tokens from the salt master and/or run arbitrary commands on salt minions.
</code>

- [ssrsec/CVE-2020-11651-CVE-2020-11652-EXP](https://github.com/ssrsec/CVE-2020-11651-CVE-2020-11652-EXP)

### CVE-2020-11652 (2020-04-30)

<code>An issue was discovered in SaltStack Salt before 2019.2.4 and 3000 before 3000.2. The salt-master process ClearFuncs class allows access to some methods that improperly sanitize paths. These methods allow arbitrary directory access to authenticated users.
</code>

- [Al1ex/CVE-2020-11652](https://github.com/Al1ex/CVE-2020-11652)

### CVE-2020-11890 (2020-04-21)

<code>An issue was discovered in Joomla! before 3.9.17. Improper input validations in the usergroup table class could lead to a broken ACL configuration.
</code>

- [HoangKien1020/CVE-2020-11890](https://github.com/HoangKien1020/CVE-2020-11890)

### CVE-2020-11996 (2020-06-26)

<code>A specially crafted sequence of HTTP/2 requests sent to Apache Tomcat 10.0.0-M1 to 10.0.0-M5, 9.0.0.M1 to 9.0.35 and 8.5.0 to 8.5.55 could trigger high CPU usage for several seconds. If a sufficient number of such requests were made on concurrent HTTP/2 connections, the server could become unresponsive.
</code>

- [rusakovichma/tomcat-embed-core-9.0.31-CVE-2020-11996](https://github.com/rusakovichma/tomcat-embed-core-9.0.31-CVE-2020-11996)

### CVE-2020-12695 (2020-06-08)

<code>The Open Connectivity Foundation UPnP specification before 2020-04-17 does not forbid the acceptance of a subscription request with a delivery URL on a different network segment than the fully qualified event-subscription URL, aka the CallStranger issue.
</code>

- [corelight/callstranger-detector](https://github.com/corelight/callstranger-detector)

### CVE-2020-12696 (2020-05-07)

<code>The iframe plugin before 4.5 for WordPress does not sanitize a URL.
</code>

- [g-rubert/CVE-2020-12696](https://github.com/g-rubert/CVE-2020-12696)

### CVE-2020-12717 (2020-05-14)

<code>The COVIDSafe (Australia) app 1.0 and 1.1 for iOS allows a remote attacker to crash the app, and consequently interfere with COVID-19 contact tracing, via a Bluetooth advertisement containing manufacturer data that is too short. This occurs because of an erroneous OpenTrace manuData.subdata call. The ABTraceTogether (Alberta), ProteGO (Poland), and TraceTogether (Singapore) apps were also affected.
</code>

- [wabzqem/covidsafe-CVE-2020-12717-exploit](https://github.com/wabzqem/covidsafe-CVE-2020-12717-exploit)

### CVE-2020-12800 (2020-06-08)

<code>The drag-and-drop-multiple-file-upload-contact-form-7 plugin before 1.3.3.3 for WordPress allows Unrestricted File Upload and remote code execution by setting supported_type to php% and uploading a .php% file.
</code>

- [amartinsec/CVE-2020-12800](https://github.com/amartinsec/CVE-2020-12800)

### CVE-2020-12928 (2020-10-13)

<code>A vulnerability in a dynamically loaded AMD driver in AMD Ryzen Master V15 may allow any authenticated user to escalate privileges to NT authority system.
</code>

- [ekknod/AmdRyzenMasterCheat](https://github.com/ekknod/AmdRyzenMasterCheat)

### CVE-2020-13259 (2020-09-16)

<code>A vulnerability in the web-based management interface of RAD SecFlow-1v os-image SF_0290_2.3.01.26 could allow an unauthenticated, remote attacker to conduct a cross-site request forgery (CSRF) attack on an affected system. The vulnerability is due to insufficient CSRF protections for the web UI on an affected device. An attacker could exploit this vulnerability by persuading a user of the interface to follow a malicious link. A successful exploit could allow the attacker to perform arbitrary actions with the privilege level of the affected user. This could be exploited in conjunction with CVE-2020-13260.
</code>

- [UrielYochpaz/CVE-2020-13259](https://github.com/UrielYochpaz/CVE-2020-13259)

### CVE-2020-13277 (2020-06-19)

<code>An authorization issue in the mirroring logic allowed read access to private repositories in GitLab CE/EE 10.6 and later through 13.0.5
</code>

- [EXP-Docs/CVE-2020-13277](https://github.com/EXP-Docs/CVE-2020-13277)

### CVE-2020-13777 (2020-06-04)

<code>GnuTLS 3.6.x before 3.6.14 uses incorrect cryptography for encrypting a session ticket (a loss of confidentiality in TLS 1.2, and an authentication bypass in TLS 1.3). The earliest affected version is 3.6.4 (2018-09-24) because of an error in a 2018-09-18 commit. Until the first key rotation, the TLS server always uses wrong data in place of an encryption key derived from an application.
</code>

- [0xxon/cve-2020-13777](https://github.com/0xxon/cve-2020-13777)

### CVE-2020-13933 (2020-08-17)

<code>Apache Shiro before 1.6.0, when using Apache Shiro, a specially crafted HTTP request may cause an authentication bypass.
</code>

- [EXP-Docs/CVE-2020-13933](https://github.com/EXP-Docs/CVE-2020-13933)

### CVE-2020-13942 (2020-11-24)

<code>It is possible to inject malicious OGNL or MVEL scripts into the /context.json public endpoint. This was partially fixed in 1.5.1 but a new attack vector was found. In Apache Unomi version 1.5.2 scripts are now completely filtered from the input. It is highly recommended to upgrade to the latest available version of the 1.5.x release to fix this problem.
</code>

- [eugenebmx/CVE-2020-13942](https://github.com/eugenebmx/CVE-2020-13942)
- [blackmarketer/CVE-2020-13942](https://github.com/blackmarketer/CVE-2020-13942)
- [yaunsky/Unomi-CVE-2020-13942](https://github.com/yaunsky/Unomi-CVE-2020-13942)

### CVE-2020-14064 (2020-07-15)

<code>IceWarp Email Server 12.3.0.1 has Incorrect Access Control for user accounts.
</code>

- [networksecure/CVE-2020-14064](https://github.com/networksecure/CVE-2020-14064)

### CVE-2020-14065 (2020-07-15)

<code>IceWarp Email Server 12.3.0.1 allows remote attackers to upload files and consume disk space.
</code>

- [networksecure/CVE-2020-14065](https://github.com/networksecure/CVE-2020-14065)

### CVE-2020-14066 (2020-07-15)

<code>IceWarp Email Server 12.3.0.1 allows remote attackers to upload JavaScript files that are dangerous for clients to access.
</code>

- [networksecure/CVE-2020-14066](https://github.com/networksecure/CVE-2020-14066)

### CVE-2020-14181 (2020-09-17)

<code>Affected versions of Atlassian Jira Server and Data Center allow an unauthenticated user to enumerate users via an Information Disclosure vulnerability in the /ViewUserHover.jspa endpoint. The affected versions are before version 7.13.6, from version 8.0.0 before 8.5.7, and from version 8.6.0 before 8.12.0.
</code>

- [Rival420/CVE-2020-14181](https://github.com/Rival420/CVE-2020-14181)

### CVE-2020-14195 (2020-06-16)

<code>FasterXML jackson-databind 2.x before 2.9.10.5 mishandles the interaction between serialization gadgets and typing, related to org.jsecurity.realm.jndi.JndiRealmFactory (aka org.jsecurity).
</code>

- [Al1ex/CVE-2020-14195](https://github.com/Al1ex/CVE-2020-14195)

### CVE-2020-14645 (2020-07-15)

<code>Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
</code>

- [Schira4396/CVE-2020-14645](https://github.com/Schira4396/CVE-2020-14645)

### CVE-2020-14882 (2020-10-21)

<code>Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
</code>

- [GGyao/CVE-2020-14882_ALL](https://github.com/GGyao/CVE-2020-14882_ALL)
- [corelight/CVE-2020-14882-weblogicRCE](https://github.com/corelight/CVE-2020-14882-weblogicRCE)
- [adm1in/CodeTest](https://github.com/adm1in/CodeTest)

### CVE-2020-15002 (2020-10-23)

<code>OX App Suite through 7.10.3 allows SSRF via the the /ajax/messaging/message message API.
</code>

- [skr0x1c0/Blind-SSRF-CVE-2020-15002](https://github.com/skr0x1c0/Blind-SSRF-CVE-2020-15002)
- [skr0x1c0/SSRF-CVE-2020-15002](https://github.com/skr0x1c0/SSRF-CVE-2020-15002)

### CVE-2020-15257 (2020-12-01)

<code>containerd is an industry-standard container runtime and is available as a daemon for Linux and Windows. In containerd before versions 1.3.9 and 1.4.3, the containerd-shim API is improperly exposed to host network containers. Access controls for the shim’s API socket verified that the connecting process had an effective UID of 0, but did not otherwise restrict access to the abstract Unix domain socket. This would allow malicious containers running in the same network namespace as the shim, with an effective UID of 0 but otherwise reduced privileges, to cause new processes to be run with elevated privileges. This vulnerability has been fixed in containerd 1.3.9 and 1.4.3. Users should update to these versions as soon as they are released. It should be noted that containers started with an old version of containerd-shim should be stopped and restarted, as running containers will continue to be vulnerable even after an upgrade. If you are not providing the ability for untrusted users to start containers in the same network namespace as the shim (typically the &quot;host&quot; network namespace, for example with docker run --net=host or hostNetwork: true in a Kubernetes pod) and run with an effective UID of 0, you are not vulnerable to this issue. If you are running containers with a vulnerable configuration, you can deny access to all abstract sockets with AppArmor by adding a line similar to deny unix addr=@**, to your policy. It is best practice to run containers with a reduced set of privileges, with a non-zero UID, and with isolated namespaces. The containerd maintainers strongly advise against sharing namespaces with the host. Reducing the set of isolation mechanisms used for a container necessarily increases that container's privilege, regardless of what container runtime is used for running that container.
</code>

- [nccgroup/abstractshimmer](https://github.com/nccgroup/abstractshimmer)

### CVE-2020-15416 (2020-07-28)

<code>This vulnerability allows network-adjacent attackers to bypass authentication on affected installations of NETGEAR R6700 V1.0.4.84_10.0.58 routers. Authentication is not required to exploit this vulnerability. The specific flaw exists within the httpd service, which listens on TCP port 80 by default. The issue results from the lack of proper validation of the length of user-supplied data prior to copying it to a fixed-length, stack-based buffer. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-9703.
</code>

- [k3vinlusec/R7000_httpd_BOF_CVE-2020-15416](https://github.com/k3vinlusec/R7000_httpd_BOF_CVE-2020-15416)

### CVE-2020-15778 (2020-07-24)

<code>scp in OpenSSH through 8.3p1 allows command injection in the scp.c toremote function, as demonstrated by backtick characters in the destination argument. NOTE: the vendor reportedly has stated that they intentionally omit validation of &quot;anomalous argument transfers&quot; because that could &quot;stand a great chance of breaking existing workflows.&quot;
</code>

- [cpandya2909/CVE-2020-15778](https://github.com/cpandya2909/CVE-2020-15778)

### CVE-2020-15999 (2020-11-03)

<code>Heap buffer overflow in Freetype in Google Chrome prior to 86.0.4240.111 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.
</code>

- [maarlo/CVE-2020-15999](https://github.com/maarlo/CVE-2020-15999)
- [Marmeus/CVE-2020-15999](https://github.com/Marmeus/CVE-2020-15999)

### CVE-2020-16012 (2021-01-08)

<code>Side-channel information leakage in graphics in Google Chrome prior to 87.0.4280.66 allowed a remote attacker to leak cross-origin data via a crafted HTML page.
</code>

- [aleksejspopovs/cve-2020-16012](https://github.com/aleksejspopovs/cve-2020-16012)

### CVE-2020-16898 (2020-10-16)

<code>&lt;p&gt;A remote code execution vulnerability exists when the Windows TCP/IP stack improperly handles ICMPv6 Router Advertisement packets. An attacker who successfully exploited this vulnerability could gain the ability to execute code on the target server or client.&lt;/p&gt;\n&lt;p&gt;To exploit this vulnerability, an attacker would have to send specially crafted ICMPv6 Router Advertisement packets to a remote Windows computer.&lt;/p&gt;\n&lt;p&gt;The update addresses the vulnerability by correcting how the Windows TCP/IP stack handles ICMPv6 Router Advertisement packets.&lt;/p&gt;\n
</code>

- [corelight/CVE-2020-16898](https://github.com/corelight/CVE-2020-16898)

### CVE-2020-17008
- [jas502n/CVE-2020-17008](https://github.com/jas502n/CVE-2020-17008)

### CVE-2020-17035 (2020-11-11)

<code>Windows Kernel Elevation of Privilege Vulnerability
</code>

- [flamelu/CVE-2020-17035-patch-analysis](https://github.com/flamelu/CVE-2020-17035-patch-analysis)

### CVE-2020-17057 (2020-11-11)

<code>Windows Win32k Elevation of Privilege Vulnerability
</code>

- [fengjixuchui/cve-2020-17057](https://github.com/fengjixuchui/cve-2020-17057)

### CVE-2020-17144 (2020-12-09)

<code>Microsoft Exchange Remote Code Execution Vulnerability
</code>

- [Airboi/CVE-2020-17144-EXP](https://github.com/Airboi/CVE-2020-17144-EXP)
- [zcgonvh/CVE-2020-17144](https://github.com/zcgonvh/CVE-2020-17144)

### CVE-2020-17530 (2020-12-11)

<code>Forced OGNL evaluation, when evaluated on raw user input in tag attributes, may lead to remote code execution. Affected software : Apache Struts 2.0.0 - Struts 2.5.25.
</code>

- [secpool2000/CVE-2020-17530](https://github.com/secpool2000/CVE-2020-17530)
- [ka1n4t/CVE-2020-17530](https://github.com/ka1n4t/CVE-2020-17530)
- [wuzuowei/CVE-2020-17530](https://github.com/wuzuowei/CVE-2020-17530)
- [Al1ex/CVE-2020-17530](https://github.com/Al1ex/CVE-2020-17530)
- [fengziHK/CVE-2020-17530-strust2-061](https://github.com/fengziHK/CVE-2020-17530-strust2-061)
- [ludy-dev/freemarker_RCE_struts2_s2-061](https://github.com/ludy-dev/freemarker_RCE_struts2_s2-061)
- [CyborgSecurity/CVE-2020-17530](https://github.com/CyborgSecurity/CVE-2020-17530)

### CVE-2020-17531 (2020-12-08)

<code>A Java Serialization vulnerability was found in Apache Tapestry 4. Apache Tapestry 4 will attempt to deserialize the &quot;sp&quot; parameter even before invoking the page's validate method, leading to deserialization without authentication. Apache Tapestry 4 reached end of life in 2008 and no update to address this issue will be released. Apache Tapestry 5 versions are not vulnerable to this issue. Users of Apache Tapestry 4 should upgrade to the latest Apache Tapestry 5 version.
</code>

- [154802388/CVE-2020-17531](https://github.com/154802388/CVE-2020-17531)

### CVE-2020-17533 (2020-12-29)

<code>Apache Accumulo versions 1.5.0 through 1.10.0 and version 2.0.0 do not properly check the return value of some policy enforcement functions before permitting an authenticated user to perform certain administrative operations. Specifically, the return values of the 'canFlush' and 'canPerformSystemActions' security functions are not checked in some instances, therefore allowing an authenticated user with insufficient permissions to perform the following actions: flushing a table, shutting down Accumulo or an individual tablet server, and setting or removing system-wide Accumulo configuration properties.
</code>

- [pazeray/CVE-2020-17533](https://github.com/pazeray/CVE-2020-17533)

### CVE-2020-20093 (2022-03-23)

<code>The Facebook Messenger app for iOS 227.0 and prior and Android 228.1.0.10.116 and prior user interface does not properly represent URI messages to the user, which results in URI spoofing via specially crafted messages.
</code>

- [zadewg/RIUS](https://github.com/zadewg/RIUS)

### CVE-2020-23934 (2020-08-18)

<code>An issue was discovered in RiteCMS 2.2.1. An authenticated user can directly execute system commands by uploading a php web shell in the &quot;Filemanager&quot; section.
</code>

- [H0j3n/CVE-2020-23934](https://github.com/H0j3n/CVE-2020-23934)

### CVE-2020-23968 (2020-11-10)

<code>Ilex International Sign&amp;go Workstation Security Suite 7.1 allows elevation of privileges via a symlink attack on ProgramData\Ilex\S&amp;G\Logs\000-sngWSService1.log.
</code>

- [ricardojba/CVE-2020-23968-ILEX-SignGo-EoP](https://github.com/ricardojba/CVE-2020-23968-ILEX-SignGo-EoP)

### CVE-2020-24750 (2020-09-17)

<code>FasterXML jackson-databind 2.x before 2.9.10.6 mishandles the interaction between serialization gadgets and typing, related to com.pastdev.httpcomponents.configuration.JndiConfiguration.
</code>

- [Al1ex/CVE-2020-24750](https://github.com/Al1ex/CVE-2020-24750)

### CVE-2020-25515 (2020-09-22)

<code>Sourcecodester Simple Library Management System 1.0 is affected by Insecure Permissions via Books &gt; New Book , http://&lt;site&gt;/lms/index.php?page=books.
</code>

- [Ko-kn3t/CVE-2020-25515](https://github.com/Ko-kn3t/CVE-2020-25515)

### CVE-2020-25540 (2020-09-14)

<code>ThinkAdmin v6 is affected by a directory traversal vulnerability. An unauthorized attacker can read arbitrarily file on a remote server via GET request encode parameter.
</code>

- [Schira4396/CVE-2020-25540](https://github.com/Schira4396/CVE-2020-25540)

### CVE-2020-25578 (2021-03-26)

<code>In FreeBSD 12.2-STABLE before r368969, 11.4-STABLE before r369047, 12.2-RELEASE before p3, 12.1-RELEASE before p13 and 11.4-RELEASE before p7 several file systems were not properly initializing the d_off field of the dirent structures returned by VOP_READDIR. In particular, tmpfs(5), smbfs(5), autofs(5) and mqueuefs(5) were failing to do so. As a result, eight uninitialized kernel stack bytes may be leaked to userspace by these file systems.
</code>

- [farazsth98/freebsd-dirent-info-leak-bugs](https://github.com/farazsth98/freebsd-dirent-info-leak-bugs)

### CVE-2020-25637 (2020-10-06)

<code>A double free memory issue was found to occur in the libvirt API, in versions before 6.8.0, responsible for requesting information about network interfaces of a running QEMU domain. This flaw affects the polkit access control driver. Specifically, clients connecting to the read-write socket with limited ACL permissions could use this flaw to crash the libvirt daemon, resulting in a denial of service, or potentially escalate their privileges on the system. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.
</code>

- [brahmiboudjema/CVE-2020-25637-libvirt-double-free](https://github.com/brahmiboudjema/CVE-2020-25637-libvirt-double-free)

### CVE-2020-25790 (2020-09-19)

<code>Typesetter CMS 5.x through 5.1 allows admins to upload and execute arbitrary PHP code via a .php file inside a ZIP archive. NOTE: the vendor disputes the significance of this report because &quot;admins are considered trustworthy&quot;; however, the behavior &quot;contradicts our security policy&quot; and is being fixed for 5.2
</code>

- [7Mitu/CVE-2020-25790](https://github.com/7Mitu/CVE-2020-25790)

### CVE-2020-25860 (2020-12-21)

<code>The install.c module in the Pengutronix RAUC update client prior to version 1.5 has a Time-of-Check Time-of-Use vulnerability, where signature verification on an update file takes place before the file is reopened for installation. An attacker who can modify the update file just before it is reopened can install arbitrary code on the device.
</code>

- [rauc/rauc-1.5-integration](https://github.com/rauc/rauc-1.5-integration)

### CVE-2020-25867 (2020-10-07)

<code>SoPlanning before 1.47 doesn't correctly check the security key used to publicly share plannings. It allows a bypass to get access without authentication.
</code>

- [thomasfady/CVE-2020-25867](https://github.com/thomasfady/CVE-2020-25867)

### CVE-2020-26217 (2020-11-16)

<code>XStream before version 1.4.14 is vulnerable to Remote Code Execution.The vulnerability may allow a remote attacker to run arbitrary shell commands only by manipulating the processed input stream. Only users who rely on blocklists are affected. Anyone using XStream's Security Framework allowlist is not affected. The linked advisory provides code workarounds for users who cannot upgrade. The issue is fixed in version 1.4.14.
</code>

- [novysodope/CVE-2020-26217-XStream-RCE-POC](https://github.com/novysodope/CVE-2020-26217-XStream-RCE-POC)

### CVE-2020-26259 (2020-12-16)

<code>XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.15, is vulnerable to an Arbitrary File Deletion on the local host when unmarshalling. The vulnerability may allow a remote attacker to delete arbitrary know files on the host as log as the executing process has sufficient rights only by manipulating the processed input stream. If you rely on XStream's default blacklist of the Security Framework, you will have to use at least version 1.4.15. The reported vulnerability does not exist running Java 15 or higher. No user is affected, who followed the recommendation to setup XStream's Security Framework with a whitelist! Anyone relying on XStream's default blacklist can immediately switch to a whilelist for the allowed types to avoid the vulnerability. Users of XStream 1.4.14 or below who still want to use XStream default blacklist can use a workaround described in more detailed in the referenced advisories.
</code>

- [jas502n/CVE-2020-26259](https://github.com/jas502n/CVE-2020-26259)

### CVE-2020-27190
- [qlh831/x-CVE-2020-27190](https://github.com/qlh831/x-CVE-2020-27190)

### CVE-2020-27194 (2020-10-16)

<code>An issue was discovered in the Linux kernel before 5.8.15. scalar32_min_max_or in kernel/bpf/verifier.c mishandles bounds tracking during use of 64-bit values, aka CID-5b9fbeb75b6a.
</code>

- [xmzyshypnc/CVE-2020-27194](https://github.com/xmzyshypnc/CVE-2020-27194)

### CVE-2020-27199 (2020-12-17)

<code>The Magic Home Pro application 1.5.1 for Android allows Authentication Bypass. The security control that the application currently has in place is a simple Username and Password authentication function. Using enumeration, an attacker is able to forge a User specific token without the need for correct password to gain access to the mobile application as that victim user.
</code>

- [9lyph/CVE-2020-27199](https://github.com/9lyph/CVE-2020-27199)

### CVE-2020-27688 (2020-11-05)

<code>RVToolsPasswordEncryption.exe in RVTools 4.0.6 allows users to encrypt passwords to be used in the configuration files. This encryption used a static IV and key, and thus using the Decrypt() method from VISKD.cs from the RVTools.exe executable allows for decrypting the encrypted passwords. The accounts used in the configuration files have access to vSphere instances.
</code>

- [matthiasmaes/CVE-2020-27688](https://github.com/matthiasmaes/CVE-2020-27688)

### CVE-2020-27935 (2021-04-02)

<code>Multiple issues were addressed with improved logic. This issue is fixed in iOS 14.2 and iPadOS 14.2, macOS Big Sur 11.0.1, watchOS 7.1, tvOS 14.2. A sandboxed process may be able to circumvent sandbox restrictions.
</code>

- [LIJI32/SnatchBox](https://github.com/LIJI32/SnatchBox)

### CVE-2020-27949 (2021-04-02)

<code>This issue was addressed with improved checks to prevent unauthorized actions. This issue is fixed in macOS Big Sur 11.1, Security Update 2020-001 Catalina, Security Update 2020-007 Mojave. A malicious application may cause unexpected changes in memory belonging to processes traced by DTrace.
</code>

- [seemoo-lab/dtrace-memaccess_cve-2020-27949](https://github.com/seemoo-lab/dtrace-memaccess_cve-2020-27949)

### CVE-2020-27950 (2020-12-08)

<code>A memory initialization issue was addressed. This issue is fixed in macOS Big Sur 11.0.1, watchOS 7.1, iOS 12.4.9, watchOS 6.2.9, Security Update 2020-006 High Sierra, Security Update 2020-006 Mojave, iOS 14.2 and iPadOS 14.2, watchOS 5.3.9, macOS Catalina 10.15.7 Supplemental Update, macOS Catalina 10.15.7 Update. A malicious application may be able to disclose kernel memory.
</code>

- [synacktiv/CVE-2020-27950](https://github.com/synacktiv/CVE-2020-27950)

### CVE-2020-27955 (2020-11-05)

<code>Git LFS 2.12.0 allows Remote Code Execution.
</code>

- [ExploitBox/git-lfs-RCE-exploit-CVE-2020-27955](https://github.com/ExploitBox/git-lfs-RCE-exploit-CVE-2020-27955)
- [shubham0d/CVE-2020-27955](https://github.com/shubham0d/CVE-2020-27955)
- [TheTh1nk3r/cve-2020-27955](https://github.com/TheTh1nk3r/cve-2020-27955)

### CVE-2020-28052 (2020-12-18)

<code>An issue was discovered in Legion of the Bouncy Castle BC Java 1.65 and 1.66. The OpenBSDBCrypt.checkPassword utility method compared incorrect data when checking the password, allowing incorrect passwords to indicate they were matching with previously hashed ones that were different.
</code>

- [madstap/bouncy-castle-generative-test-poc](https://github.com/madstap/bouncy-castle-generative-test-poc)

### CVE-2020-28169 (2020-12-24)

<code>The td-agent-builder plugin before 2020-12-18 for Fluentd allows attackers to gain privileges because the bin directory is writable by a user account, but a file in bin is executed as NT AUTHORITY\SYSTEM.
</code>

- [zubrahzz/FluentD-TD-agent-Exploit-CVE-2020-28169](https://github.com/zubrahzz/FluentD-TD-agent-Exploit-CVE-2020-28169)

### CVE-2020-28243 (2021-02-27)

<code>An issue was discovered in SaltStack Salt before 3002.5. The minion's restartcheck is vulnerable to command injection via a crafted process name. This allows for a local privilege escalation by any user able to create a files on the minion in a non-blacklisted directory.
</code>

- [stealthcopter/CVE-2020-28243](https://github.com/stealthcopter/CVE-2020-28243)

### CVE-2020-28647 (2020-11-17)

<code>In Progress MOVEit Transfer before 2020.1, a malicious user could craft and store a payload within the application. If a victim within the MOVEit Transfer instance interacts with the stored payload, it could invoke and execute arbitrary code within the context of the victim's browser (XSS).
</code>

- [SECFORCE/Progress-MOVEit-Transfer-2020.1-Stored-XSS-CVE-2020-28647](https://github.com/SECFORCE/Progress-MOVEit-Transfer-2020.1-Stored-XSS-CVE-2020-28647)

### CVE-2020-29007 (2023-04-15)

<code>The Score extension through 0.3.0 for MediaWiki has a remote code execution vulnerability due to improper sandboxing of the GNU LilyPond executable. This allows any user with an ability to edit articles (potentially including unauthenticated anonymous users) to execute arbitrary Scheme or shell code by using crafted {{Image data to generate musical scores containing malicious code.
</code>

- [seqred-s-a/cve-2020-29007](https://github.com/seqred-s-a/cve-2020-29007)

### CVE-2020-29156 (2020-12-27)

<code>The WooCommerce plugin before 4.7.0 for WordPress allows remote attackers to view the status of arbitrary orders via the order_id parameter in a fetch_order_status action.
</code>

- [Ko-kn3t/CVE-2020-29156](https://github.com/Ko-kn3t/CVE-2020-29156)

### CVE-2020-29254 (2020-12-11)

<code>TikiWiki 21.2 allows templates to be edited without CSRF protection. This could allow an unauthenticated, remote attacker to conduct a cross-site request forgery (CSRF) attack and perform arbitrary actions on an affected system. The vulnerability is due to insufficient CSRF protections for the web-based management interface of the affected system. An attacker could exploit this vulnerability by persuading a user of the interface to follow a maliciously crafted link. A successful exploit could allow the attacker to perform arbitrary actions on an affected system with the privileges of the user. These action include allowing attackers to submit their own code through an authenticated user resulting in local file Inclusion. If an authenticated user who is able to edit TikiWiki templates visits an malicious website, template code can be edited.
</code>

- [S1lkys/CVE-2020-29254](https://github.com/S1lkys/CVE-2020-29254)

### CVE-2020-29666 (2020-12-10)

<code>In Lan ATMService M3 ATM Monitoring System 6.1.0, due to a directory-listing vulnerability, a remote attacker can view log files, located in /websocket/logs/, that contain a user's cookie values and the predefined developer's cookie value.
</code>

- [jet-pentest/CVE-2020-29666](https://github.com/jet-pentest/CVE-2020-29666)

### CVE-2020-29667 (2020-12-10)

<code>In Lan ATMService M3 ATM Monitoring System 6.1.0, a remote attacker able to use a default cookie value, such as PHPSESSID=LANIT-IMANAGER, can achieve control over the system because of Insufficient Session Expiration.
</code>

- [jet-pentest/CVE-2020-29667](https://github.com/jet-pentest/CVE-2020-29667)

### CVE-2020-29669 (2020-12-14)

<code>In the Macally WIFISD2-2A82 Media and Travel Router 2.000.010, the Guest user is able to reset its own password. This process has a vulnerability which can be used to take over the administrator account and results in shell access. As the admin user may read the /etc/shadow file, the password hashes of each user (including root) can be dumped. The root hash can be cracked easily which results in a complete system compromise.
</code>

- [code-byter/CVE-2020-29669](https://github.com/code-byter/CVE-2020-29669)

### CVE-2020-35488 (2021-01-05)

<code>The fileop module of the NXLog service in NXLog Community Edition 2.10.2150 allows remote attackers to cause a denial of service (daemon crash) via a crafted Syslog payload to the Syslog service. This attack requires a specific configuration. Also, the name of the directory created must use a Syslog field. (For example, on Linux it is not possible to create a .. directory. On Windows, it is not possible to create a CON directory.)
</code>

- [GuillaumePetit84/CVE-2020-35488](https://github.com/GuillaumePetit84/CVE-2020-35488)

### CVE-2020-35489 (2020-12-17)

<code>The contact-form-7 (aka Contact Form 7) plugin before 5.3.2 for WordPress allows Unrestricted File Upload and remote code execution because a filename may contain special characters.
</code>

- [dn9uy3n/Check-WP-CVE-2020-35489](https://github.com/dn9uy3n/Check-WP-CVE-2020-35489)

### CVE-2020-35590 (2020-12-21)

<code>LimitLoginAttempts.php in the limit-login-attempts-reloaded plugin before 2.17.4 for WordPress allows a bypass of (per IP address) rate limits because the X-Forwarded-For header can be forged. When the plugin is configured to accept an arbitrary header for the client source IP address, a malicious user is not limited to perform a brute force attack, because the client IP header accepts any arbitrary string. When randomizing the header input, the login count does not ever reach the maximum allowed retries.
</code>

- [N4nj0/CVE-2020-35590](https://github.com/N4nj0/CVE-2020-35590)

### CVE-2020-35606 (2020-12-21)

<code>Arbitrary command execution can occur in Webmin through 1.962. Any user authorized for the Package Updates module can execute arbitrary commands with root privileges via vectors involving %0A and %0C. NOTE: this issue exists because of an incomplete fix for CVE-2019-12840.
</code>

- [anasbousselham/webminscan](https://github.com/anasbousselham/webminscan)

### CVE-2020-35669 (2020-12-24)

<code>An issue was discovered in the http package through 0.12.2 for Dart. If the attacker controls the HTTP method and the app is using Request directly, it's possible to achieve CRLF injection in an HTTP request.
</code>

- [n0npax/CVE-2020-35669](https://github.com/n0npax/CVE-2020-35669)

### CVE-2020-35728 (2020-12-27)

<code>FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to com.oracle.wls.shaded.org.apache.xalan.lib.sql.JNDIConnectionPool (aka embedded Xalan in org.glassfish.web/javax.servlet.jsp.jstl).
</code>

- [Al1ex/CVE-2020-35728](https://github.com/Al1ex/CVE-2020-35728)


## 2019
### CVE-2019-0232 (2019-04-15)

<code>When running on Windows with enableCmdLineArguments enabled, the CGI Servlet in Apache Tomcat 9.0.0.M1 to 9.0.17, 8.5.0 to 8.5.39 and 7.0.0 to 7.0.93 is vulnerable to Remote Code Execution due to a bug in the way the JRE passes command line arguments to Windows. The CGI Servlet is disabled by default. The CGI option enableCmdLineArguments is disable by default in Tomcat 9.0.x (and will be disabled by default in all versions in response to this vulnerability). For a detailed explanation of the JRE behaviour, see Markus Wulftange's blog (https://codewhitesec.blogspot.com/2016/02/java-and-command-line-injections-in-windows.html) and this archived MSDN blog (https://web.archive.org/web/20161228144344/https://blogs.msdn.microsoft.com/twistylittlepassagesallalike/2011/04/23/everyone-quotes-command-line-arguments-the-wrong-way/).
</code>

- [Dharan10/CVE-2019-0232](https://github.com/Dharan10/CVE-2019-0232)
- [iumiro/CVE-2019-0232](https://github.com/iumiro/CVE-2019-0232)
- [k3Pn1c/CVE-2019-0232_tomcat_cgi_exploit](https://github.com/k3Pn1c/CVE-2019-0232_tomcat_cgi_exploit)

### CVE-2019-0567 (2019-01-08)

<code>A remote code execution vulnerability exists in the way that the Chakra scripting engine handles objects in memory in Microsoft Edge, aka &quot;Chakra Scripting Engine Memory Corruption Vulnerability.&quot; This affects Microsoft Edge, ChakraCore. This CVE ID is unique from CVE-2019-0539, CVE-2019-0568.
</code>

- [ntdelta/chakra-exploit-framework](https://github.com/ntdelta/chakra-exploit-framework)

### CVE-2019-0604 (2019-03-06)

<code>A remote code execution vulnerability exists in Microsoft SharePoint when the software fails to check the source markup of an application package, aka 'Microsoft SharePoint Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2019-0594.
</code>

- [boxhg/CVE-2019-0604](https://github.com/boxhg/CVE-2019-0604)

### CVE-2019-0708 (2019-05-16)

<code>A remote code execution vulnerability exists in Remote Desktop Services formerly known as Terminal Services when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests, aka 'Remote Desktop Services Remote Code Execution Vulnerability'.
</code>

- [Ekultek/BlueKeep](https://github.com/Ekultek/BlueKeep)
- [algo7/bluekeep_CVE-2019-0708_poc_to_exploit](https://github.com/algo7/bluekeep_CVE-2019-0708_poc_to_exploit)
- [Pa55w0rd/CVE-2019-0708](https://github.com/Pa55w0rd/CVE-2019-0708)
- [at0mik/CVE-2019-0708-PoC](https://github.com/at0mik/CVE-2019-0708-PoC)
- [worawit/CVE-2019-0708](https://github.com/worawit/CVE-2019-0708)

### CVE-2019-0986 (2019-06-12)

<code>An elevation of privilege vulnerability exists when the Windows User Profile Service (ProfSvc) improperly handles symlinks, aka 'Windows User Profile Service Elevation of Privilege Vulnerability'.
</code>

- [padovah4ck/CVE-2019-0986](https://github.com/padovah4ck/CVE-2019-0986)

### CVE-2019-1040 (2019-06-12)

<code>A tampering vulnerability exists in Microsoft Windows when a man-in-the-middle attacker is able to successfully bypass the NTLM MIC (Message Integrity Check) protection, aka 'Windows NTLM Tampering Vulnerability'.
</code>

- [Ridter/CVE-2019-1040](https://github.com/Ridter/CVE-2019-1040)
- [Ridter/CVE-2019-1040-dcpwn](https://github.com/Ridter/CVE-2019-1040-dcpwn)

### CVE-2019-1218 (2019-08-14)

<code>A spoofing vulnerability exists in the way Microsoft Outlook iOS software parses specifically crafted email messages. An authenticated attacker could exploit the vulnerability by sending a specially crafted email message to a victim.\nThe attacker who successfully exploited this vulnerability could then perform cross-site scripting attacks on the affected systems and run scripts in the security context of the current user.\nThe security update addresses the vulnerability by correcting how Outlook iOS parses specially crafted email messages.\n
</code>

- [d0gukank/CVE-2019-1218](https://github.com/d0gukank/CVE-2019-1218)

### CVE-2019-1388 (2019-11-12)

<code>An elevation of privilege vulnerability exists in the Windows Certificate Dialog when it does not properly enforce user privileges, aka 'Windows Certificate Dialog Elevation of Privilege Vulnerability'.
</code>

- [sv3nbeast/CVE-2019-1388](https://github.com/sv3nbeast/CVE-2019-1388)

### CVE-2019-1619 (2019-06-27)

<code>A vulnerability in the web-based management interface of Cisco Data Center Network Manager (DCNM) could allow an unauthenticated, remote attacker to bypass authentication and execute arbitrary actions with administrative privileges on an affected device. The vulnerability is due to improper session management on affected DCNM software. An attacker could exploit this vulnerability by sending a crafted HTTP request to the affected device. A successful exploit could allow the attacker to gain administrative access on the affected device.
</code>

- [Cipolone95/CVE-2019-1619](https://github.com/Cipolone95/CVE-2019-1619)

### CVE-2019-1663 (2019-02-28)

<code>A vulnerability in the web-based management interface of the Cisco RV110W Wireless-N VPN Firewall, Cisco RV130W Wireless-N Multifunction VPN Router, and Cisco RV215W Wireless-N VPN Router could allow an unauthenticated, remote attacker to execute arbitrary code on an affected device. The vulnerability is due to improper validation of user-supplied data in the web-based management interface. An attacker could exploit this vulnerability by sending malicious HTTP requests to a targeted device. A successful exploit could allow the attacker to execute arbitrary code on the underlying operating system of the affected device as a high-privilege user. RV110W Wireless-N VPN Firewall versions prior to 1.2.2.1 are affected. RV130W Wireless-N Multifunction VPN Router versions prior to 1.0.3.45 are affected. RV215W Wireless-N VPN Router versions prior to 1.3.1.1 are affected.
</code>

- [WolffCorentin/CVE-2019-1663-Binary-Analysis](https://github.com/WolffCorentin/CVE-2019-1663-Binary-Analysis)

### CVE-2019-2215 (2019-10-11)

<code>A use-after-free in binder.c allows an elevation of privilege from an application to the Linux Kernel. No user interaction is required to exploit this vulnerability, however exploitation does require either the installation of a malicious local application or a separate vulnerability in a network facing application.Product: AndroidAndroid ID: A-141720095
</code>

- [llccd/TempRoot-Huawei](https://github.com/llccd/TempRoot-Huawei)

### CVE-2019-2618 (2019-04-23)

<code>Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0 and 12.2.1.3.0. Easily exploitable vulnerability allows high privileged attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data as well as unauthorized update, insert or delete access to some of Oracle WebLogic Server accessible data. CVSS 3.0 Base Score 5.5 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:L/A:N).
</code>

- [dr0op/WeblogicScan](https://github.com/dr0op/WeblogicScan)

### CVE-2019-2706 (2019-04-23)

<code>Vulnerability in the Oracle Business Process Management Suite component of Oracle Fusion Middleware (subcomponent: BPM Foundation Services). The supported version that is affected is 11.1.1.9.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Business Process Management Suite. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle Business Process Management Suite, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle Business Process Management Suite accessible data as well as unauthorized update, insert or delete access to some of Oracle Business Process Management Suite accessible data. CVSS 3.0 Base Score 8.2 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N).
</code>

- [athuljayaram/Oracle-CVE-2019-2706](https://github.com/athuljayaram/Oracle-CVE-2019-2706)

### CVE-2019-2725 (2019-04-26)

<code>Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Web Services). Supported versions that are affected are 10.3.6.0.0 and 12.1.3.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
</code>

- [lufeirider/CVE-2019-2725](https://github.com/lufeirider/CVE-2019-2725)

### CVE-2019-3396 (2019-03-25)

<code>The Widget Connector macro in Atlassian Confluence Server before version 6.6.12 (the fixed version for 6.6.x), from version 6.7.0 before 6.12.3 (the fixed version for 6.12.x), from version 6.13.0 before 6.13.3 (the fixed version for 6.13.x), and from version 6.14.0 before 6.14.2 (the fixed version for 6.14.x), allows remote attackers to achieve path traversal and remote code execution on a Confluence Server or Data Center instance via server-side template injection.
</code>

- [JonathanZhou348/CVE-2019-3396TEST](https://github.com/JonathanZhou348/CVE-2019-3396TEST)

### CVE-2019-5010 (2019-10-31)

<code>An exploitable denial-of-service vulnerability exists in the X509 certificate parser of Python.org Python 2.7.11 / 3.6.6. A specially crafted X509 certificate can cause a NULL pointer dereference, resulting in a denial of service. An attacker can initiate or accept TLS connections using crafted certificates to trigger this vulnerability.
</code>

- [JonathanWilbur/CVE-2019-5010](https://github.com/JonathanWilbur/CVE-2019-5010)

### CVE-2019-5029 (2019-11-13)

<code>An exploitable command injection vulnerability exists in the Config editor of the Exhibitor Web UI versions 1.0.9 to 1.7.1. Arbitrary shell commands surrounded by backticks or $() can be inserted into the editor and will be executed by the Exhibitor process when it launches ZooKeeper. An attacker can execute any command as the user running the Exhibitor process.
</code>

- [yZ1337/CVE-2019-5029](https://github.com/yZ1337/CVE-2019-5029)

### CVE-2019-5418 (2019-03-27)

<code>There is a File Content Disclosure vulnerability in Action View &lt;5.2.2.1, &lt;5.1.6.2, &lt;5.0.7.2, &lt;4.2.11.1 and v3 where specially crafted accept headers can cause contents of arbitrary files on the target system's filesystem to be exposed.
</code>

- [mpgn/CVE-2019-5418](https://github.com/mpgn/CVE-2019-5418)
- [mpgn/Rails-doubletap-RCE](https://github.com/mpgn/Rails-doubletap-RCE)
- [ztgrace/CVE-2019-5418-Rails3](https://github.com/ztgrace/CVE-2019-5418-Rails3)

### CVE-2019-5420 (2019-03-27)

<code>A remote code execution vulnerability in development mode Rails &lt;5.2.2.1, &lt;6.0.0.beta3 can allow an attacker to guess the automatically generated development mode secret token. This secret token can be used in combination with other Rails internals to escalate to a remote code execution exploit.
</code>

- [cved-sources/cve-2019-5420](https://github.com/cved-sources/cve-2019-5420)
- [WildWestCyberSecurity/cve-2019-5420-POC](https://github.com/WildWestCyberSecurity/cve-2019-5420-POC)

### CVE-2019-5489 (2019-01-07)

<code>The mincore() implementation in mm/mincore.c in the Linux kernel through 4.19.13 allowed local attackers to observe page cache access patterns of other processes on the same system, potentially allowing sniffing of secret information. (Fixing this affects the output of the fincore program.) Limited remote exploitation may be possible, as demonstrated by latency differences in accessing public files from an Apache HTTP Server.
</code>

- [mmxsrup/CVE-2019-5489](https://github.com/mmxsrup/CVE-2019-5489)

### CVE-2019-5602 (2019-07-03)

<code>In FreeBSD 12.0-STABLE before r349628, 12.0-RELEASE before 12.0-RELEASE-p7, 11.3-PRERELEASE before r349629, 11.3-RC3 before 11.3-RC3-p1, and 11.2-RELEASE before 11.2-RELEASE-p11, a bug in the cdrom driver allows users with read access to the cdrom device to arbitrarily overwrite kernel memory when media is present thereby allowing a malicious user in the operator group to gain root privileges.
</code>

- [test-one9/CVE-2019-5602-poc](https://github.com/test-one9/CVE-2019-5602-poc)

### CVE-2019-5736 (2019-02-11)

<code>runc through 1.0-rc6, as used in Docker before 18.09.2 and other products, allows attackers to overwrite the host runc binary (and consequently obtain host root access) by leveraging the ability to execute a command as root within one of these types of containers: (1) a new container with an attacker-controlled image, or (2) an existing container, to which the attacker previously had write access, that can be attached with docker exec. This occurs because of file-descriptor mishandling, related to /proc/self/exe.
</code>

- [Frichetten/CVE-2019-5736-PoC](https://github.com/Frichetten/CVE-2019-5736-PoC)
- [panzouh/Docker-Runc-Exploit](https://github.com/panzouh/Docker-Runc-Exploit)
- [sonyavalo/CVE-2019-5736-Dockerattack-and-security-mechanism](https://github.com/sonyavalo/CVE-2019-5736-Dockerattack-and-security-mechanism)

### CVE-2019-6249 (2019-01-13)

<code>An issue was discovered in HuCart v5.7.4. There is a CSRF vulnerability that can add an admin account via /adminsys/index.php?load=admins&amp;act=edit_info&amp;act_type=add.
</code>

- [AlphabugX/CVE-2019-6249_Hucart-cms](https://github.com/AlphabugX/CVE-2019-6249_Hucart-cms)

### CVE-2019-6329 (2019-06-25)

<code>HP Support Assistant 8.7.50 and earlier allows a user to gain system privilege and allows unauthorized modification of directories or files. Note: A different vulnerability than CVE-2019-6328.
</code>

- [ManhNDd/CVE-2019-6329](https://github.com/ManhNDd/CVE-2019-6329)

### CVE-2019-6340 (2019-02-21)

<code>Some field types do not properly sanitize data from non-form sources in Drupal 8.5.x before 8.5.11 and Drupal 8.6.x before 8.6.10. This can lead to arbitrary PHP code execution in some cases. A site is only affected by this if one of the following conditions is met: The site has the Drupal 8 core RESTful Web Services (rest) module enabled and allows PATCH or POST requests, or the site has another web services module enabled, like JSON:API in Drupal 8, or Services or RESTful Web Services in Drupal 7. (Note: The Drupal 7 Services module itself does not require an update at this time, but you should apply other contributed updates associated with this advisory if Services is in use.)
</code>

- [knqyf263/CVE-2019-6340](https://github.com/knqyf263/CVE-2019-6340)
- [cved-sources/cve-2019-6340](https://github.com/cved-sources/cve-2019-6340)

### CVE-2019-6447 (2019-01-16)

<code>The ES File Explorer File Manager application through 4.1.9.7.4 for Android allows remote attackers to read arbitrary files or execute applications via TCP port 59777 requests on the local Wi-Fi network. This TCP port remains open after the ES application has been launched once, and responds to unauthenticated application/json data over HTTP.
</code>

- [fs0c131y/ESFileExplorerOpenPortVuln](https://github.com/fs0c131y/ESFileExplorerOpenPortVuln)

### CVE-2019-6453 (2019-02-18)

<code>mIRC before 7.55 allows remote command execution by using argument injection through custom URI protocol handlers. The attacker can specify an irc:// URI that loads an arbitrary .ini file from a UNC share pathname. Exploitation depends on browser-specific URI handling (Chrome is not exploitable).
</code>

- [proofofcalc/cve-2019-6453-poc](https://github.com/proofofcalc/cve-2019-6453-poc)

### CVE-2019-7609 (2019-03-25)

<code>Kibana versions before 5.6.15 and 6.6.1 contain an arbitrary code execution flaw in the Timelion visualizer. An attacker with access to the Timelion application could send a request that will attempt to execute javascript code. This could possibly lead to an attacker executing arbitrary commands with permissions of the Kibana process on the host system.
</code>

- [mpgn/CVE-2019-7609](https://github.com/mpgn/CVE-2019-7609)
- [LandGrey/CVE-2019-7609](https://github.com/LandGrey/CVE-2019-7609)

### CVE-2019-8561 (2019-12-18)

<code>A logic issue was addressed with improved validation. This issue is fixed in macOS Mojave 10.14.4. A malicious application may be able to elevate privileges.
</code>

- [0xmachos/CVE-2019-8561](https://github.com/0xmachos/CVE-2019-8561)

### CVE-2019-9053 (2019-03-26)

<code>An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.
</code>

- [Mahamedm/CVE-2019-9053-Exploit-Python-3](https://github.com/Mahamedm/CVE-2019-9053-Exploit-Python-3)
- [louisthedonothing/CVE-2019-9053](https://github.com/louisthedonothing/CVE-2019-9053)
- [Yzhacker/CVE-2019-9053-CMS46635-python3](https://github.com/Yzhacker/CVE-2019-9053-CMS46635-python3)
- [hf3cyber/CMS-Made-Simple-2.2.9-Unauthenticated-SQL-Injection-Exploit-CVE-2019-9053-](https://github.com/hf3cyber/CMS-Made-Simple-2.2.9-Unauthenticated-SQL-Injection-Exploit-CVE-2019-9053-)

### CVE-2019-9184 (2019-02-26)

<code>SQL injection vulnerability in the J2Store plugin 3.x before 3.3.7 for Joomla! allows remote attackers to execute arbitrary SQL commands via the product_option[] parameter.
</code>

- [cved-sources/cve-2019-9184](https://github.com/cved-sources/cve-2019-9184)

### CVE-2019-9194 (2019-02-26)

<code>elFinder before 2.1.48 has a command injection vulnerability in the PHP connector.
</code>

- [cved-sources/cve-2019-9194](https://github.com/cved-sources/cve-2019-9194)

### CVE-2019-9621 (2019-04-30)

<code>Zimbra Collaboration Suite before 8.6 patch 13, 8.7.x before 8.7.11 patch 10, and 8.8.x before 8.8.10 patch 7 or 8.8.x before 8.8.11 patch 3 allows SSRF via the ProxyServlet component.
</code>

- [k8gege/ZimbraExploit](https://github.com/k8gege/ZimbraExploit)

### CVE-2019-9978 (2019-03-24)

<code>The social-warfare plugin before 3.5.3 for WordPress has stored XSS via the wp-admin/admin-post.php?swp_debug=load_options swp_url parameter, as exploited in the wild in March 2019. This affects Social Warfare and Social Warfare Pro.
</code>

- [hash3liZer/CVE-2019-9978](https://github.com/hash3liZer/CVE-2019-9978)
- [cved-sources/cve-2019-9978](https://github.com/cved-sources/cve-2019-9978)

### CVE-2019-10092 (2019-09-26)

<code>In Apache HTTP Server 2.4.0-2.4.39, a limited cross-site scripting issue was reported affecting the mod_proxy error page. An attacker could cause the link on the error page to be malformed and instead point to a page of their choice. This would only be exploitable where a server was set up with proxying enabled but was misconfigured in such a way that the Proxy Error page was displayed.
</code>

- [motikan2010/CVE-2019-10092_Docker](https://github.com/motikan2010/CVE-2019-10092_Docker)

### CVE-2019-10149 (2019-06-05)

<code>A flaw was found in Exim versions 4.87 to 4.91 (inclusive). Improper validation of recipient address in deliver_message() function in /src/deliver.c may lead to remote command execution.
</code>

- [darsigovrustam/CVE-2019-10149](https://github.com/darsigovrustam/CVE-2019-10149)
- [Diefunction/CVE-2019-10149](https://github.com/Diefunction/CVE-2019-10149)

### CVE-2019-10475 (2019-10-23)

<code>A reflected cross-site scripting vulnerability in Jenkins build-metrics Plugin allows attackers to inject arbitrary HTML and JavaScript into web pages provided by this plugin.
</code>

- [vesche/CVE-2019-10475](https://github.com/vesche/CVE-2019-10475)

### CVE-2019-10678 (2019-03-31)

<code>Domoticz before 4.10579 neglects to categorize \n and \r as insecure argument options.
</code>

- [cved-sources/cve-2019-10678](https://github.com/cved-sources/cve-2019-10678)

### CVE-2019-10758 (2019-12-24)

<code>mongo-express before 0.54.0 is vulnerable to Remote Code Execution via endpoints that uses the `toBSON` method. A misuse of the `vm` dependency to perform `exec` commands in a non-safe environment.
</code>

- [masahiro331/CVE-2019-10758](https://github.com/masahiro331/CVE-2019-10758)

### CVE-2019-10999 (2019-05-06)

<code>The D-Link DCS series of Wi-Fi cameras contains a stack-based buffer overflow in alphapd, the camera's web server. The overflow allows a remotely authenticated attacker to execute arbitrary code by providing a long string in the WEPEncryption parameter when requesting wireless.htm. Vulnerable devices include DCS-5009L (1.08.11 and below), DCS-5010L (1.14.09 and below), DCS-5020L (1.15.12 and below), DCS-5025L (1.03.07 and below), DCS-5030L (1.04.10 and below), DCS-930L (2.16.01 and below), DCS-931L (1.14.11 and below), DCS-932L (2.17.01 and below), DCS-933L (1.14.11 and below), and DCS-934L (1.05.04 and below).
</code>

- [tacnetsol/CVE-2019-10999](https://github.com/tacnetsol/CVE-2019-10999)

### CVE-2019-11043 (2019-10-28)

<code>In PHP versions 7.1.x below 7.1.33, 7.2.x below 7.2.24 and 7.3.x below 7.3.11 in certain configurations of FPM setup it is possible to cause FPM module to write past allocated buffers into the space reserved for FCGI protocol data, thus opening the possibility of remote code execution.
</code>

- [jas502n/CVE-2019-11043](https://github.com/jas502n/CVE-2019-11043)
- [AleWong/PHP-FPM-Remote-Code-Execution-Vulnerability-CVE-2019-11043-](https://github.com/AleWong/PHP-FPM-Remote-Code-Execution-Vulnerability-CVE-2019-11043-)

### CVE-2019-11157 (2019-12-16)

<code>Improper conditions check in voltage settings for some Intel(R) Processors may allow a privileged user to potentially enable escalation of privilege and/or information disclosure via local access.
</code>

- [zkenjar/v0ltpwn](https://github.com/zkenjar/v0ltpwn)

### CVE-2019-11358 (2019-04-19)

<code>jQuery before 3.4.0, as used in Drupal, Backdrop CMS, and other products, mishandles jQuery.extend(true, {}, ...) because of Object.prototype pollution. If an unsanitized source object contained an enumerable __proto__ property, it could extend the native Object.prototype.
</code>

- [DanielRuf/snyk-js-jquery-174006](https://github.com/DanielRuf/snyk-js-jquery-174006)

### CVE-2019-11510 (2019-05-08)

<code>In Pulse Secure Pulse Connect Secure (PCS) 8.2 before 8.2R12.1, 8.3 before 8.3R7.1, and 9.0 before 9.0R3.4, an unauthenticated remote attacker can send a specially crafted URI to perform an arbitrary file reading vulnerability .
</code>

- [aqhmal/pulsexploit](https://github.com/aqhmal/pulsexploit)

### CVE-2019-11687 (2019-05-02)

<code>An issue was discovered in the DICOM Part 10 File Format in the NEMA DICOM Standard 1995 through 2019b. The preamble of a DICOM file that complies with this specification can contain the header for an executable file, such as Portable Executable (PE) malware. This space is left unspecified so that dual-purpose files can be created. (For example, dual-purpose TIFF/DICOM files are used in digital whole slide imaging for applications in medicine.) To exploit this vulnerability, someone must execute a maliciously crafted file that is encoded in the DICOM Part 10 File Format. PE/DICOM files are executable even with the .dcm file extension. Anti-malware configurations at healthcare facilities often ignore medical imagery. Also, anti-malware tools and business processes could violate regulatory frameworks (such as HIPAA) when processing suspicious DICOM files.
</code>

- [kosmokato/bad-dicom](https://github.com/kosmokato/bad-dicom)

### CVE-2019-11932 (2019-10-03)

<code>A double free vulnerability in the DDGifSlurp function in decoding.c in the android-gif-drawable library before version 1.2.18, as used in WhatsApp for Android before version 2.19.244 and many other Android applications, allows remote attackers to execute arbitrary code or cause a denial of service when the library is used to parse a specially crafted GIF image.
</code>

- [dorkerdevil/CVE-2019-11932](https://github.com/dorkerdevil/CVE-2019-11932)
- [fastmo/CVE-2019-11932](https://github.com/fastmo/CVE-2019-11932)

### CVE-2019-11933 (2019-10-23)

<code>A heap buffer overflow bug in libpl_droidsonroids_gif before 1.2.19, as used in WhatsApp for Android before version 2.19.291 could allow remote attackers to execute arbitrary code or cause a denial of service.
</code>

- [NatleoJ/CVE-2019-11933](https://github.com/NatleoJ/CVE-2019-11933)

### CVE-2019-12725 (2019-07-19)

<code>Zeroshell 3.9.0 is prone to a remote command execution vulnerability. Specifically, this issue occurs because the web application mishandles a few HTTP parameters. An unauthenticated attacker can exploit this issue by injecting OS commands inside the vulnerable parameters.
</code>

- [YZS17/CVE-2019-12725](https://github.com/YZS17/CVE-2019-12725)
- [nowindows9/CVE-2019-12725-modified-exp](https://github.com/nowindows9/CVE-2019-12725-modified-exp)

### CVE-2019-12750 (2019-07-31)

<code>Symantec Endpoint Protection, prior to 14.2 RU1 &amp; 12.1 RU6 MP10 and Symantec Endpoint Protection Small Business Edition, prior to 12.1 RU6 MP10c (12.1.7491.7002), may be susceptible to a privilege escalation vulnerability, which is a type of issue whereby an attacker may attempt to compromise the software application to gain elevated access to resources that are normally protected from an application or user.
</code>

- [v-p-b/cve-2019-12750](https://github.com/v-p-b/cve-2019-12750)

### CVE-2019-12836 (2019-06-21)

<code>The Bobronix JEditor editor before 3.0.6 for Jira allows an attacker to add a URL/Link (to an existing issue) that can cause forgery of a request to an out-of-origin domain. This in turn may allow for a forged request that can be invoked in the context of an authenticated user, leading to stealing of session tokens and account takeover.
</code>

- [9lyph/CVE-2019-12836](https://github.com/9lyph/CVE-2019-12836)

### CVE-2019-13025 (2019-10-02)

<code>Compal CH7465LG CH7465LG-NCIP-6.12.18.24-5p8-NOSH devices have Incorrect Access Control because of Improper Input Validation. The attacker can send a maliciously modified POST (HTTP) request containing shell commands, which will be executed on the device, to an backend API endpoint of the cable modem.
</code>

- [x1tan/CVE-2019-13025](https://github.com/x1tan/CVE-2019-13025)

### CVE-2019-13115 (2019-07-16)

<code>In libssh2 before 1.9.0, kex_method_diffie_hellman_group_exchange_sha256_key_exchange in kex.c has an integer overflow that could lead to an out-of-bounds read in the way packets are read from the server. A remote attacker who compromises a SSH server may be able to disclose sensitive information or cause a denial of service condition on the client system when a user connects to the server. This is related to an _libssh2_check_length mistake, and is different from the various issues fixed in 1.8.1, such as CVE-2019-3855.
</code>

- [viz27/Libssh2-Exploit](https://github.com/viz27/Libssh2-Exploit)

### CVE-2019-14287 (2019-10-17)

<code>In Sudo before 1.8.28, an attacker with access to a Runas ALL sudoer account can bypass certain policy blacklists and session PAM modules, and can cause incorrect logging, by invoking sudo with a crafted user ID. For example, this allows bypass of !root configuration, and USER= logging, for a &quot;sudo -u \#$((0xffffffff))&quot; command.
</code>

- [CashWilliams/CVE-2019-14287-demo](https://github.com/CashWilliams/CVE-2019-14287-demo)
- [shallvhack/Sudo-Security-Bypass-CVE-2019-14287](https://github.com/shallvhack/Sudo-Security-Bypass-CVE-2019-14287)
- [Sindayifu/CVE-2019-14287-CVE-2014-6271](https://github.com/Sindayifu/CVE-2019-14287-CVE-2014-6271)

### CVE-2019-15107 (2019-08-16)

<code>An issue was discovered in Webmin &lt;=1.920. The parameter old in password_change.cgi contains a command injection vulnerability.
</code>

- [hannob/webminex](https://github.com/hannob/webminex)
- [ChakoMoonFish/webmin_CVE-2019-15107](https://github.com/ChakoMoonFish/webmin_CVE-2019-15107)
- [MasterCode112/CVE-2019-15107](https://github.com/MasterCode112/CVE-2019-15107)

### CVE-2019-15707 (2020-01-23)

<code>An improper access control vulnerability in FortiMail admin webUI 6.2.0, 6.0.0 to 6.0.6, 5.4.10 and below may allow administrators to perform system backup config download they should not be authorized for.
</code>

- [cristianovisk/CVE-2019-15707](https://github.com/cristianovisk/CVE-2019-15707)

### CVE-2019-16097 (2019-09-08)

<code>core/api/user.go in Harbor 1.7.0 through 1.8.2 allows non-admin users to create admin accounts via the POST /api/users API, when Harbor is setup with DB as authentication backend and allow user to do self-registration. Fixed version: v1.7.6 v1.8.3. v.1.9.0. Workaround without applying the fix: configure Harbor to use non-DB authentication backend such as LDAP.
</code>

- [luckybool1020/CVE-2019-16097](https://github.com/luckybool1020/CVE-2019-16097)

### CVE-2019-16278 (2019-10-14)

<code>Directory Traversal in the function http_verify in nostromo nhttpd through 1.9.6 allows an attacker to achieve remote code execution via a crafted HTTP request.
</code>

- [ianxtianxt/CVE-2019-16278](https://github.com/ianxtianxt/CVE-2019-16278)
- [Kr0ff/cve-2019-16278](https://github.com/Kr0ff/cve-2019-16278)
- [CybermonkX/CVE-2019-16278_Nostromo-1.9.6---Remote-Code-Execution](https://github.com/CybermonkX/CVE-2019-16278_Nostromo-1.9.6---Remote-Code-Execution)

### CVE-2019-16405 (2019-11-21)

<code>Centreon Web before 2.8.30, 18.10.x before 18.10.8, 19.04.x before 19.04.5 and 19.10.x before 19.10.2 allows Remote Code Execution by an administrator who can modify Macro Expression location settings. CVE-2019-16405 and CVE-2019-17501 are similar to one another and may be the same.
</code>

- [TheCyberGeek/CVE-2019-16405.rb](https://github.com/TheCyberGeek/CVE-2019-16405.rb)

### CVE-2019-16759 (2019-09-24)

<code>vBulletin 5.x through 5.5.4 allows remote command execution via the widgetConfig[code] parameter in an ajax/render/widget_php routestring request.
</code>

- [theLSA/vbulletin5-rce](https://github.com/theLSA/vbulletin5-rce)
- [andripwn/pwn-vbulletin](https://github.com/andripwn/pwn-vbulletin)

### CVE-2019-16889 (2019-09-25)

<code>Ubiquiti EdgeMAX devices before 2.0.3 allow remote attackers to cause a denial of service (disk consumption) because *.cache files in /var/run/beaker/container_file/ are created when providing a valid length payload of 249 characters or fewer to the beaker.session.id cookie in a GET header. The attacker can use a long series of unique session IDs.
</code>

- [grampae/CVE-2019-16889-poc](https://github.com/grampae/CVE-2019-16889-poc)

### CVE-2019-17234 (2019-11-12)

<code>includes/class-coming-soon-creator.php in the igniteup plugin through 3.4 for WordPress allows unauthenticated arbitrary file deletion.
</code>

- [administra1tor/CVE-2019-17234b-Exploit](https://github.com/administra1tor/CVE-2019-17234b-Exploit)

### CVE-2019-17240 (2019-10-06)

<code>bl-kernel/security.class.php in Bludit 3.9.2 allows attackers to bypass a brute-force protection mechanism by using many different forged X-Forwarded-For or Client-IP HTTP headers.
</code>

- [0xDTC/Bludit-3.9.2-Auth-Bruteforce-Bypass-CVE-2019-17240](https://github.com/0xDTC/Bludit-3.9.2-Auth-Bruteforce-Bypass-CVE-2019-17240)

### CVE-2019-17495 (2019-10-10)

<code>A Cascading Style Sheets (CSS) injection vulnerability in Swagger UI before 3.23.11 allows attackers to use the Relative Path Overwrite (RPO) technique to perform CSS-based input field value exfiltration, such as exfiltration of a CSRF token value. In other words, this product intentionally allows the embedding of untrusted JSON data from remote servers, but it was not previously known that &lt;style&gt;@import within the JSON data was a functional attack method.
</code>

- [SecT0uch/CVE-2019-17495-test](https://github.com/SecT0uch/CVE-2019-17495-test)

### CVE-2019-17571 (2019-12-20)

<code>Included in Log4j 1.2 is a SocketServer class that is vulnerable to deserialization of untrusted data which can be exploited to remotely execute arbitrary code when combined with a deserialization gadget when listening to untrusted network traffic for log data. This affects Log4j versions up to 1.2 up to 1.2.17.
</code>

- [shadow-horse/CVE-2019-17571](https://github.com/shadow-horse/CVE-2019-17571)

### CVE-2019-17625 (2019-10-16)

<code>There is a stored XSS in Rambox 0.6.9 that can lead to code execution. The XSS is in the name field while adding/editing a service. The problem occurs due to incorrect sanitization of the name field when being processed and stored. This allows a user to craft a payload for Node.js and Electron, such as an exec of OS commands within the onerror attribute of an IMG element.
</code>

- [Ekultek/CVE-2019-17625](https://github.com/Ekultek/CVE-2019-17625)

### CVE-2019-17633 (2019-12-19)

<code>For Eclipse Che versions 6.16 to 7.3.0, with both authentication and TLS disabled, visiting a malicious web site could trigger the start of an arbitrary Che workspace. Che with no authentication and no TLS is not usually deployed on a public network but is often used for local installations (e.g. on personal laptops). In that case, even if the Che API is not exposed externally, some javascript running in the local browser is able to send requests to it.
</code>

- [mgrube/CVE-2019-17633](https://github.com/mgrube/CVE-2019-17633)

### CVE-2019-18634 (2020-01-29)

<code>In Sudo before 1.8.26, if pwfeedback is enabled in /etc/sudoers, users can trigger a stack-based buffer overflow in the privileged sudo process. (pwfeedback is a default setting in Linux Mint and elementary OS; however, it is NOT the default for upstream and many other packages, and would exist only if enabled by an administrator.) The attacker needs to deliver a long string to the stdin of getln() in tgetpass.c.
</code>

- [l0w3/CVE-2019-18634](https://github.com/l0w3/CVE-2019-18634)

### CVE-2019-18818 (2019-11-07)

<code>strapi before 3.0.0-beta.17.5 mishandles password resets within packages/strapi-admin/controllers/Auth.js and packages/strapi-plugin-users-permissions/controllers/Auth.js.
</code>

- [abelsrzz/CVE-2019-18818_CVE-2019-19609](https://github.com/abelsrzz/CVE-2019-18818_CVE-2019-19609)

### CVE-2019-18885 (2019-11-14)

<code>fs/btrfs/volumes.c in the Linux kernel before 5.1 allows a btrfs_verify_dev_extents NULL pointer dereference via a crafted btrfs image because fs_devices-&gt;devices is mishandled within find_device, aka CID-09ba3bc9dd15.
</code>

- [bobfuzzer/CVE-2019-18885](https://github.com/bobfuzzer/CVE-2019-18885)

### CVE-2019-18935 (2019-12-11)

<code>Progress Telerik UI for ASP.NET AJAX through 2019.3.1023 contains a .NET deserialization vulnerability in the RadAsyncUpload function. This is exploitable when the encryption keys are known due to the presence of CVE-2017-11317 or CVE-2017-11357, or other means. Exploitation can result in remote code execution. (As of 2020.1.114, a default setting prevents the exploit. In 2019.3.1023, but not earlier versions, a non-default setting can prevent exploitation.)
</code>

- [noperator/CVE-2019-18935](https://github.com/noperator/CVE-2019-18935)
- [clarkvoss/telerik](https://github.com/clarkvoss/telerik)

### CVE-2019-19203 (2019-11-21)

<code>An issue was discovered in Oniguruma 6.x before 6.9.4_rc2. In the function gb18030_mbc_enc_len in file gb18030.c, a UChar pointer is dereferenced without checking if it passed the end of the matched string. This leads to a heap-based buffer over-read.
</code>

- [tarantula-team/CVE-2019-19203](https://github.com/tarantula-team/CVE-2019-19203)

### CVE-2019-19204 (2019-11-21)

<code>An issue was discovered in Oniguruma 6.x before 6.9.4_rc2. In the function fetch_interval_quantifier (formerly known as fetch_range_quantifier) in regparse.c, PFETCH is called without checking PEND. This leads to a heap-based buffer over-read.
</code>

- [tarantula-team/CVE-2019-19204](https://github.com/tarantula-team/CVE-2019-19204)

### CVE-2019-19231 (2019-12-20)

<code>An insecure file access vulnerability exists in CA Client Automation 14.0, 14.1, 14.2, and 14.3 Agent for Windows that can allow a local attacker to gain escalated privileges.
</code>

- [hessandrew/CVE-2019-19231](https://github.com/hessandrew/CVE-2019-19231)

### CVE-2019-19315 (2019-12-17)

<code>NLSSRV32.EXE in Nalpeiron Licensing Service 7.3.4.0, as used with Nitro PDF and other products, allows Elevation of Privilege via the \\.\mailslot\nlsX86ccMailslot mailslot.
</code>

- [monoxgas/mailorder](https://github.com/monoxgas/mailorder)

### CVE-2019-19356 (2020-02-07)

<code>Netis WF2419 is vulnerable to authenticated Remote Code Execution (RCE) as root through the router Web management page. The vulnerability has been found in firmware version V1.2.31805 and V2.2.36123. After one is connected to this page, it is possible to execute system commands as root through the tracert diagnostic tool because of lack of user input sanitizing.
</code>

- [shadowgatt/CVE-2019-19356](https://github.com/shadowgatt/CVE-2019-19356)

### CVE-2019-19383 (2019-12-03)

<code>freeFTPd 1.0.8 has a Post-Authentication Buffer Overflow via a crafted SIZE command (this is exploitable even if logging is disabled).
</code>

- [killvxk/CVE-2019-19383](https://github.com/killvxk/CVE-2019-19383)

### CVE-2019-19511
- [jra89/CVE-2019-19511](https://github.com/jra89/CVE-2019-19511)

### CVE-2019-19576 (2019-12-04)

<code>class.upload.php in verot.net class.upload before 1.0.3 and 2.x before 2.0.4, as used in the K2 extension for Joomla! and other products, omits .phar from the set of dangerous file extensions.
</code>

- [jra89/CVE-2019-19576](https://github.com/jra89/CVE-2019-19576)

### CVE-2019-19633
- [jra89/CVE-2019-19633](https://github.com/jra89/CVE-2019-19633)

### CVE-2019-19653
- [jra89/CVE-2019-19653](https://github.com/jra89/CVE-2019-19653)

### CVE-2019-19654
- [jra89/CVE-2019-19654](https://github.com/jra89/CVE-2019-19654)

### CVE-2019-19844 (2019-12-18)

<code>Django before 1.11.27, 2.x before 2.2.9, and 3.x before 3.0.1 allows account takeover. A suitably crafted email address (that is equal to an existing user's email address after case transformation of Unicode characters) would allow an attacker to be sent a password reset token for the matched user account. (One mitigation in the new releases is to send password reset tokens only to the registered user email address.)
</code>

- [ryu22e/django_cve_2019_19844_poc](https://github.com/ryu22e/django_cve_2019_19844_poc)
- [andripwn/django_cve201919844](https://github.com/andripwn/django_cve201919844)

### CVE-2019-20085 (2019-12-30)

<code>TVT NVMS-1000 devices allow GET /.. Directory Traversal
</code>

- [0hmsec/NVMS-1000-Directory-Traversal-Bash](https://github.com/0hmsec/NVMS-1000-Directory-Traversal-Bash)

### CVE-2019-20372 (2020-01-09)

<code>NGINX before 1.17.7, with certain error_page configurations, allows HTTP request smuggling, as demonstrated by the ability of an attacker to read unauthorized web pages in environments where NGINX is being fronted by a load balancer.
</code>

- [moften/CVE-2019-20372](https://github.com/moften/CVE-2019-20372)

### CVE-2019-25162 (2024-02-26)

<code>In the Linux kernel, the following vulnerability has been resolved:\n\ni2c: Fix a potential use after free\n\nFree the adap structure only after we are done using it.\nThis patch just moves the put_device() down a bit to avoid the\nuse after free.\n\n[wsa: added comment to the code, added Fixes tag]
</code>

- [uthrasri/CVE-2019-25162](https://github.com/uthrasri/CVE-2019-25162)

### CVE-2019-1003000 (2019-01-22)

<code>A sandbox bypass vulnerability exists in Script Security Plugin 1.49 and earlier in src/main/java/org/jenkinsci/plugins/scriptsecurity/sandbox/groovy/GroovySandbox.java that allows attackers with the ability to provide sandboxed scripts to execute arbitrary code on the Jenkins master JVM.
</code>

- [wetw0rk/Exploit-Development](https://github.com/wetw0rk/Exploit-Development)

### CVE-2019-1003030 (2019-03-08)

<code>A sandbox bypass vulnerability exists in Jenkins Pipeline: Groovy Plugin 2.63 and earlier in pom.xml, src/main/java/org/jenkinsci/plugins/workflow/cps/CpsGroovyShell.java that allows attackers able to control pipeline scripts to execute arbitrary code on the Jenkins master JVM.
</code>

- [overgrowncarrot1/CVE-2019-1003030](https://github.com/overgrowncarrot1/CVE-2019-1003030)

### CVE-2019-1010174 (2019-07-25)

<code>CImg The CImg Library v.2.3.3 and earlier is affected by: command injection. The impact is: RCE. The component is: load_network() function. The attack vector is: Loading an image from a user-controllable url can lead to command injection, because no string sanitization is done on the url. The fixed version is: v.2.3.4.
</code>

- [NketiahGodfred/CVE-2019-1010174](https://github.com/NketiahGodfred/CVE-2019-1010174)


## 2018
### CVE-2018-0101 (2018-01-29)

<code>A vulnerability in the Secure Sockets Layer (SSL) VPN functionality of the Cisco Adaptive Security Appliance (ASA) Software could allow an unauthenticated, remote attacker to cause a reload of the affected system or to remotely execute code. The vulnerability is due to an attempt to double free a region of memory when the webvpn feature is enabled on the Cisco ASA device. An attacker could exploit this vulnerability by sending multiple, crafted XML packets to a webvpn-configured interface on the affected system. An exploit could allow the attacker to execute arbitrary code and obtain full control of the system, or cause a reload of the affected device. This vulnerability affects Cisco ASA Software that is running on the following Cisco products: 3000 Series Industrial Security Appliance (ISA), ASA 5500 Series Adaptive Security Appliances, ASA 5500-X Series Next-Generation Firewalls, ASA Services Module for Cisco Catalyst 6500 Series Switches and Cisco 7600 Series Routers, ASA 1000V Cloud Firewall, Adaptive Security Virtual Appliance (ASAv), Firepower 2100 Series Security Appliance, Firepower 4110 Security Appliance, Firepower 9300 ASA Security Module, Firepower Threat Defense Software (FTD). Cisco Bug IDs: CSCvg35618.
</code>

- [Cymmetria/ciscoasa_honeypot](https://github.com/Cymmetria/ciscoasa_honeypot)

### CVE-2018-0114 (2018-01-04)

<code>A vulnerability in the Cisco node-jose open source library before 0.11.0 could allow an unauthenticated, remote attacker to re-sign tokens using a key that is embedded within the token. The vulnerability is due to node-jose following the JSON Web Signature (JWS) standard for JSON Web Tokens (JWTs). This standard specifies that a JSON Web Key (JWK) representing a public key can be embedded within the header of a JWS. This public key is then trusted for verification. An attacker could exploit this by forging valid JWS objects by removing the original signature, adding a new public key to the header, and then signing the object using the (attacker-owned) private key associated with the public key embedded in that JWS header.
</code>

- [zi0Black/POC-CVE-2018-0114](https://github.com/zi0Black/POC-CVE-2018-0114)
- [z-bool/Venom-JWT](https://github.com/z-bool/Venom-JWT)

### CVE-2018-0202 (2018-03-27)

<code>clamscan in ClamAV before 0.99.4 contains a vulnerability that could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected device. The vulnerability is due to improper input validation checking mechanisms when handling Portable Document Format (.pdf) files sent to an affected device. An unauthenticated, remote attacker could exploit this vulnerability by sending a crafted .pdf file to an affected device. This action could cause an out-of-bounds read when ClamAV scans the malicious file, allowing the attacker to cause a DoS condition. This concerns pdf_parse_array and pdf_parse_string in libclamav/pdfng.c. Cisco Bug IDs: CSCvh91380, CSCvh91400.
</code>

- [jcjjaidigital/CVE-2018-0202](https://github.com/jcjjaidigital/CVE-2018-0202)

### CVE-2018-0296 (2018-06-07)

<code>A vulnerability in the web interface of the Cisco Adaptive Security Appliance (ASA) could allow an unauthenticated, remote attacker to cause an affected device to reload unexpectedly, resulting in a denial of service (DoS) condition. It is also possible on certain software releases that the ASA will not reload, but an attacker could view sensitive system information without authentication by using directory traversal techniques. The vulnerability is due to lack of proper input validation of the HTTP URL. An attacker could exploit this vulnerability by sending a crafted HTTP request to an affected device. An exploit could allow the attacker to cause a DoS condition or unauthenticated disclosure of information. This vulnerability applies to IPv4 and IPv6 HTTP traffic. This vulnerability affects Cisco ASA Software and Cisco Firepower Threat Defense (FTD) Software that is running on the following Cisco products: 3000 Series Industrial Security Appliance (ISA), ASA 1000V Cloud Firewall, ASA 5500 Series Adaptive Security Appliances, ASA 5500-X Series Next-Generation Firewalls, ASA Services Module for Cisco Catalyst 6500 Series Switches and Cisco 7600 Series Routers, Adaptive Security Virtual Appliance (ASAv), Firepower 2100 Series Security Appliance, Firepower 4100 Series Security Appliance, Firepower 9300 ASA Security Module, FTD Virtual (FTDv). Cisco Bug IDs: CSCvi16029.
</code>

- [milo2012/CVE-2018-0296](https://github.com/milo2012/CVE-2018-0296)
- [yassineaboukir/CVE-2018-0296](https://github.com/yassineaboukir/CVE-2018-0296)
- [qiantu88/CVE-2018-0296](https://github.com/qiantu88/CVE-2018-0296)

### CVE-2018-0824 (2018-05-09)

<code>A remote code execution vulnerability exists in &quot;Microsoft COM for Windows&quot; when it fails to properly handle serialized objects, aka &quot;Microsoft COM for Windows Remote Code Execution Vulnerability.&quot; This affects Windows 7, Windows Server 2012 R2, Windows RT 8.1, Windows Server 2008, Windows Server 2012, Windows 8.1, Windows Server 2016, Windows Server 2008 R2, Windows 10, Windows 10 Servers.
</code>

- [codewhitesec/UnmarshalPwn](https://github.com/codewhitesec/UnmarshalPwn)

### CVE-2018-0834 (2018-02-15)

<code>Microsoft Edge and ChakraCore in Microsoft Windows 10 Gold, 1511, 1607, 1703, 1709, and Windows Server 2016 allows remote code execution, due to how the scripting engine handles objects in memory, aka &quot;Scripting Engine Memory Corruption Vulnerability&quot;. This CVE ID is unique from CVE-2018-0835, CVE-2018-0836, CVE-2018-0837, CVE-2018-0838, CVE-2018-0840, CVE-2018-0856, CVE-2018-0857, CVE-2018-0858, CVE-2018-0859, CVE-2018-0860, CVE-2018-0861, and CVE-2018-0866.
</code>

- [SpiralBL0CK/-CVE-2018-0834-aab-aar](https://github.com/SpiralBL0CK/-CVE-2018-0834-aab-aar)

### CVE-2018-0886 (2018-03-14)

<code>The Credential Security Support Provider protocol (CredSSP) in Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1 and RT 8.1, Windows Server 2012 and R2, Windows 10 Gold, 1511, 1607, 1703, and 1709 Windows Server 2016 and Windows Server, version 1709 allows a remote code execution vulnerability due to how CredSSP validates request during the authentication process, aka &quot;CredSSP Remote Code Execution Vulnerability&quot;.
</code>

- [preempt/credssp](https://github.com/preempt/credssp)

### CVE-2018-1088 (2018-04-18)

<code>A privilege escalation flaw was found in gluster 3.x snapshot scheduler. Any gluster client allowed to mount gluster volumes could also mount shared gluster storage volume and escalate privileges by scheduling malicious cronjob via symlink.
</code>

- [MauroEldritch/GEVAUDAN](https://github.com/MauroEldritch/GEVAUDAN)

### CVE-2018-1270 (2018-04-06)

<code>Spring Framework, versions 5.0 prior to 5.0.5 and versions 4.3 prior to 4.3.15 and older unsupported versions, allow applications to expose STOMP over WebSocket endpoints with a simple, in-memory STOMP broker through the spring-messaging module. A malicious user (or attacker) can craft a message to the broker that can lead to a remote code execution attack.
</code>

- [Venscor/CVE-2018-1270](https://github.com/Venscor/CVE-2018-1270)

### CVE-2018-1324 (2018-03-16)

<code>A specially crafted ZIP archive can be used to cause an infinite loop inside of Apache Commons Compress' extra field parser used by the ZipFile and ZipArchiveInputStream classes in versions 1.11 to 1.15. This can be used to mount a denial of service attack against services that use Compress' zip package.
</code>

- [tafamace/CVE-2018-1324](https://github.com/tafamace/CVE-2018-1324)

### CVE-2018-2628 (2018-04-19)

<code>Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.2 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
</code>

- [jas502n/CVE-2018-2628](https://github.com/jas502n/CVE-2018-2628)

### CVE-2018-2636 (2018-01-18)

<code>Vulnerability in the Oracle Hospitality Simphony component of Oracle Hospitality Applications (subcomponent: Security). Supported versions that are affected are 2.7, 2.8 and 2.9. Difficult to exploit vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Hospitality Simphony. Successful attacks of this vulnerability can result in takeover of Oracle Hospitality Simphony. CVSS 3.0 Base Score 8.1 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H).
</code>

- [Cymmetria/micros_honeypot](https://github.com/Cymmetria/micros_honeypot)

### CVE-2018-2879 (2018-04-19)

<code>Vulnerability in the Oracle Access Manager component of Oracle Fusion Middleware (subcomponent: Authentication Engine). Supported versions that are affected are 11.1.2.3.0 and 12.2.1.3.0. Difficult to exploit vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Access Manager. While the vulnerability is in Oracle Access Manager, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in takeover of Oracle Access Manager. Note: Please refer to Doc ID &lt;a href=&quot;http://support.oracle.com/CSP/main/article?cmd=show&amp;type=NOT&amp;id=2386496.1&quot;&gt;My Oracle Support Note 2386496.1 for instructions on how to address this issue. CVSS 3.0 Base Score 9.0 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H).
</code>

- [MostafaSoliman/Oracle-OAM-Padding-Oracle-CVE-2018-2879-Exploit](https://github.com/MostafaSoliman/Oracle-OAM-Padding-Oracle-CVE-2018-2879-Exploit)
- [AymanElSherif/oracle-oam-authentication-bypas-exploit](https://github.com/AymanElSherif/oracle-oam-authentication-bypas-exploit)

### CVE-2018-2893 (2018-07-18)

<code>Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.2 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
</code>

- [pyn3rd/CVE-2018-2893](https://github.com/pyn3rd/CVE-2018-2893)
- [qianl0ng/CVE-2018-2893](https://github.com/qianl0ng/CVE-2018-2893)

### CVE-2018-2894 (2018-07-18)

<code>Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS - Web Services). Supported versions that are affected are 12.1.3.0, 12.2.1.2 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
</code>

- [jas502n/CVE-2018-2894](https://github.com/jas502n/CVE-2018-2894)

### CVE-2018-3245 (2018-10-17)

<code>Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
</code>

- [pyn3rd/CVE-2018-3245](https://github.com/pyn3rd/CVE-2018-3245)

### CVE-2018-3252 (2018-10-17)

<code>Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
</code>

- [go-spider/CVE-2018-3252](https://github.com/go-spider/CVE-2018-3252)
- [pyn3rd/CVE-2018-3252](https://github.com/pyn3rd/CVE-2018-3252)

### CVE-2018-3260
- [ionescu007/SpecuCheck](https://github.com/ionescu007/SpecuCheck)

### CVE-2018-3760 (2018-06-26)

<code>There is an information leak vulnerability in Sprockets. Versions Affected: 4.0.0.beta7 and lower, 3.7.1 and lower, 2.12.4 and lower. Specially crafted requests can be used to access files that exists on the filesystem that is outside an application's root directory, when the Sprockets server is used in production. All users running an affected release should either upgrade or use one of the work arounds immediately.
</code>

- [wudidwo/CVE-2018-3760-poc](https://github.com/wudidwo/CVE-2018-3760-poc)

### CVE-2018-4013 (2018-10-19)

<code>An exploitable code execution vulnerability exists in the HTTP packet-parsing functionality of the LIVE555 RTSP server library version 0.92. A specially crafted packet can cause a stack-based buffer overflow, resulting in code execution. An attacker can send a packet to trigger this vulnerability.
</code>

- [DoubleMice/cve-2018-4013](https://github.com/DoubleMice/cve-2018-4013)
- [r3dxpl0it/RTSPServer-Code-Execution-Vulnerability](https://github.com/r3dxpl0it/RTSPServer-Code-Execution-Vulnerability)

### CVE-2018-4087 (2018-04-03)

<code>An issue was discovered in certain Apple products. iOS before 11.2.5 is affected. tvOS before 11.2.5 is affected. watchOS before 4.2.2 is affected. The issue involves the &quot;Core Bluetooth&quot; component. It allows attackers to execute arbitrary code in a privileged context or cause a denial of service (memory corruption) via a crafted app.
</code>

- [rani-i/bluetoothdPoC](https://github.com/rani-i/bluetoothdPoC)

### CVE-2018-4233 (2018-06-08)

<code>An issue was discovered in certain Apple products. iOS before 11.4 is affected. Safari before 11.1.1 is affected. iCloud before 7.5 on Windows is affected. iTunes before 12.7.5 on Windows is affected. tvOS before 11.4 is affected. watchOS before 4.3.1 is affected. The issue involves the &quot;WebKit&quot; component. It allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption and application crash) via a crafted web site.
</code>

- [saelo/cve-2018-4233](https://github.com/saelo/cve-2018-4233)

### CVE-2018-4242 (2018-06-08)

<code>An issue was discovered in certain Apple products. macOS before 10.13.5 is affected. The issue involves the &quot;Hypervisor&quot; component. It allows attackers to execute arbitrary code in a privileged context or cause a denial of service (memory corruption) via a crafted app.
</code>

- [yeonnic/Look-at-The-XNU-Through-A-Tube-CVE-2018-4242-Write-up-Translation-](https://github.com/yeonnic/Look-at-The-XNU-Through-A-Tube-CVE-2018-4242-Write-up-Translation-)

### CVE-2018-4280 (2019-04-03)

<code>A memory corruption issue was addressed with improved memory handling. This issue affected versions prior to iOS 11.4.1, macOS High Sierra 10.13.6, tvOS 11.4.1, watchOS 4.3.2.
</code>

- [bazad/launchd-portrep](https://github.com/bazad/launchd-portrep)
- [bazad/blanket](https://github.com/bazad/blanket)

### CVE-2018-4407 (2019-04-03)

<code>A memory corruption issue was addressed with improved validation. This issue affected versions prior to iOS 12, macOS Mojave 10.14, tvOS 12, watchOS 5.
</code>

- [farisv/AppleDOS](https://github.com/farisv/AppleDOS)
- [WyAtu/CVE-2018-4407](https://github.com/WyAtu/CVE-2018-4407)
- [zteeed/CVE-2018-4407-IOS](https://github.com/zteeed/CVE-2018-4407-IOS)
- [anonymouz4/Apple-Remote-Crash-Tool-CVE-2018-4407](https://github.com/anonymouz4/Apple-Remote-Crash-Tool-CVE-2018-4407)
- [soccercab/wifi](https://github.com/soccercab/wifi)
- [zeng9t/CVE-2018-4407-iOS-exploit](https://github.com/zeng9t/CVE-2018-4407-iOS-exploit)

### CVE-2018-4415 (2019-04-03)

<code>A memory corruption issue was addressed with improved memory handling. This issue affected versions prior to macOS Mojave 10.14.1.
</code>

- [T1V0h/CVE-2018-4415](https://github.com/T1V0h/CVE-2018-4415)

### CVE-2018-4431 (2019-04-03)

<code>A memory initialization issue was addressed with improved memory handling. This issue affected versions prior to iOS 12.1.1, macOS Mojave 10.14.2, tvOS 12.1.1, watchOS 5.1.2.
</code>

- [ktiOSz/PoC_iOS12](https://github.com/ktiOSz/PoC_iOS12)

### CVE-2018-4878 (2018-02-06)

<code>A use-after-free vulnerability was discovered in Adobe Flash Player before 28.0.0.161. This vulnerability occurs due to a dangling pointer in the Primetime SDK related to media player handling of listener objects. A successful attack can lead to arbitrary code execution. This was exploited in the wild in January and February 2018.
</code>

- [Yable/CVE-2018-4878](https://github.com/Yable/CVE-2018-4878)

### CVE-2018-5955 (2018-01-21)

<code>An issue was discovered in GitStack through 2.3.10. User controlled input is not sufficiently filtered, allowing an unauthenticated attacker to add a user to the server via the username and password fields to the rest/user/ URI.
</code>

- [MikeTheHash/CVE-2018-5955](https://github.com/MikeTheHash/CVE-2018-5955)

### CVE-2018-6242 (2018-05-01)

<code>Some NVIDIA Tegra mobile processors released prior to 2016 contain a buffer overflow vulnerability in BootROM Recovery Mode (RCM). An attacker with physical access to the device's USB and the ability to force the device to reboot into RCM could exploit the vulnerability to execute unverified code.
</code>

- [DavidBuchanan314/NXLoader](https://github.com/DavidBuchanan314/NXLoader)

### CVE-2018-6389 (2018-02-06)

<code>In WordPress through 4.9.2, unauthenticated attackers can cause a denial of service (resource consumption) by using the large list of registered .js files (from wp-includes/script-loader.php) to construct a series of requests to load every file many times.
</code>

- [alessiogilardi/PoC---CVE-2018-6389](https://github.com/alessiogilardi/PoC---CVE-2018-6389)
- [s0md3v/Shiva](https://github.com/s0md3v/Shiva)

### CVE-2018-6574 (2018-02-07)

<code>Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow &quot;go get&quot; remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.
</code>

- [neargle/Go-Get-RCE-CVE-2018-6574-POC](https://github.com/neargle/Go-Get-RCE-CVE-2018-6574-POC)
- [20matan/CVE-2018-6574-POC](https://github.com/20matan/CVE-2018-6574-POC)
- [zur250/Zur-Go-GET-RCE-Solution](https://github.com/zur250/Zur-Go-GET-RCE-Solution)
- [mekhalleh/cve-2018-6574](https://github.com/mekhalleh/cve-2018-6574)
- [faqihudin13/CVE-2018-6574](https://github.com/faqihudin13/CVE-2018-6574)
- [lisu60/cve-2018-6574](https://github.com/lisu60/cve-2018-6574)
- [Saboor-Hakimi/CVE-2018-6574](https://github.com/Saboor-Hakimi/CVE-2018-6574)

### CVE-2018-6789 (2018-02-08)

<code>An issue was discovered in the base64d function in the SMTP listener in Exim before 4.90.1. By sending a handcrafted message, a buffer overflow may happen. This can be used to execute code remotely.
</code>

- [beraphin/CVE-2018-6789](https://github.com/beraphin/CVE-2018-6789)

### CVE-2018-6961 (2018-06-11)

<code>VMware NSX SD-WAN Edge by VeloCloud prior to version 3.1.0 contains a command injection vulnerability in the local web UI component. This component is disabled by default and should not be enabled on untrusted networks. VeloCloud by VMware will be removing this service from the product in future releases. Successful exploitation of this issue could result in remote code execution.
</code>

- [bokanrb/CVE-2018-6961](https://github.com/bokanrb/CVE-2018-6961)

### CVE-2018-7489 (2018-02-26)

<code>FasterXML jackson-databind before 2.7.9.3, 2.8.x before 2.8.11.1 and 2.9.x before 2.9.5 allows unauthenticated remote code execution because of an incomplete fix for the CVE-2017-7525 deserialization flaw. This is exploitable by sending maliciously crafted JSON input to the readValue method of the ObjectMapper, bypassing a blacklist that is ineffective if the c3p0 libraries are available in the classpath.
</code>

- [tafamace/CVE-2018-7489](https://github.com/tafamace/CVE-2018-7489)

### CVE-2018-7600 (2018-03-29)

<code>Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations.
</code>

- [a2u/CVE-2018-7600](https://github.com/a2u/CVE-2018-7600)
- [dreadlocked/Drupalgeddon2](https://github.com/dreadlocked/Drupalgeddon2)
- [knqyf263/CVE-2018-7600](https://github.com/knqyf263/CVE-2018-7600)
- [thehappydinoa/CVE-2018-7600](https://github.com/thehappydinoa/CVE-2018-7600)
- [shellord/CVE-2018-7600-Drupal-RCE](https://github.com/shellord/CVE-2018-7600-Drupal-RCE)
- [r3dxpl0it/CVE-2018-7600](https://github.com/r3dxpl0it/CVE-2018-7600)

### CVE-2018-7602 (2018-07-19)

<code>A remote code execution vulnerability exists within multiple subsystems of Drupal 7.x and 8.x. This potentially allows attackers to exploit multiple attack vectors on a Drupal site, which could result in the site being compromised. This vulnerability is related to Drupal core - Highly critical - Remote Code Execution - SA-CORE-2018-002. Both SA-CORE-2018-002 and this vulnerability are being exploited in the wild.
</code>

- [kastellanos/CVE-2018-7602](https://github.com/kastellanos/CVE-2018-7602)

### CVE-2018-7690 (2018-12-13)

<code>A potential Remote Unauthorized Access in Micro Focus Fortify Software Security Center (SSC), versions 17.10, 17.20, 18.10 this exploitation could allow Remote Unauthorized Access
</code>

- [alt3kx/CVE-2018-7690](https://github.com/alt3kx/CVE-2018-7690)

### CVE-2018-7691 (2018-12-13)

<code>A potential Remote Unauthorized Access in Micro Focus Fortify Software Security Center (SSC), versions 17.10, 17.20, 18.10 this exploitation could allow Remote Unauthorized Access
</code>

- [alt3kx/CVE-2018-7691](https://github.com/alt3kx/CVE-2018-7691)

### CVE-2018-7750 (2018-03-13)

<code>transport.py in the SSH server implementation of Paramiko before 1.17.6, 1.18.x before 1.18.5, 2.0.x before 2.0.8, 2.1.x before 2.1.5, 2.2.x before 2.2.3, 2.3.x before 2.3.2, and 2.4.x before 2.4.1 does not properly check whether authentication is completed before processing other requests, as demonstrated by channel-open. A customized SSH client can simply skip the authentication step.
</code>

- [tlavi00/CVE-2018-7750](https://github.com/tlavi00/CVE-2018-7750)

### CVE-2018-7935 (2023-02-10)

<code>\nThere is a vulnerability in 21.328.01.00.00 version of the E5573Cs-322. Remote attackers could exploit this vulnerability to make the network where the E5573Cs-322 is running temporarily unavailable.\n\n
</code>

- [zux0x3a/CVE-2018-7935](https://github.com/zux0x3a/CVE-2018-7935)

### CVE-2018-8021 (2018-11-07)

<code>Versions of Superset prior to 0.23 used an unsafe load method from the pickle library to deserialize data leading to possible remote code execution. Note Superset 0.23 was released prior to any Superset release under the Apache Software Foundation.
</code>

- [r3dxpl0it/Apache-Superset-Remote-Code-Execution-PoC-CVE-2018-8021](https://github.com/r3dxpl0it/Apache-Superset-Remote-Code-Execution-PoC-CVE-2018-8021)

### CVE-2018-8065 (2018-03-12)

<code>An issue was discovered in the web server in Flexense SyncBreeze Enterprise 10.6.24. There is a user mode write access violation on the syncbrs.exe memory region that can be triggered by rapidly sending a variety of HTTP requests with long HTTP header values or long URIs.
</code>

- [EgeBalci/CVE-2018-8065](https://github.com/EgeBalci/CVE-2018-8065)

### CVE-2018-8115 (2018-05-02)

<code>A remote code execution vulnerability exists when the Windows Host Compute Service Shim (hcsshim) library fails to properly validate input while importing a container image, aka &quot;Windows Host Compute Service Shim Remote Code Execution Vulnerability.&quot; This affects Windows Host Compute.
</code>

- [aquasecurity/scan-cve-2018-8115](https://github.com/aquasecurity/scan-cve-2018-8115)

### CVE-2018-8120 (2018-05-09)

<code>An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka &quot;Win32k Elevation of Privilege Vulnerability.&quot; This affects Windows Server 2008, Windows 7, Windows Server 2008 R2. This CVE ID is unique from CVE-2018-8124, CVE-2018-8164, CVE-2018-8166.
</code>

- [qiantu88/CVE-2018-8120](https://github.com/qiantu88/CVE-2018-8120)

### CVE-2018-8174 (2018-05-09)

<code>A remote code execution vulnerability exists in the way that the VBScript engine handles objects in memory, aka &quot;Windows VBScript Engine Remote Code Execution Vulnerability.&quot; This affects Windows 7, Windows Server 2012 R2, Windows RT 8.1, Windows Server 2008, Windows Server 2012, Windows 8.1, Windows Server 2016, Windows Server 2008 R2, Windows 10, Windows 10 Servers.
</code>

- [Yt1g3r/CVE-2018-8174_EXP](https://github.com/Yt1g3r/CVE-2018-8174_EXP)

### CVE-2018-8414 (2018-08-15)

<code>A remote code execution vulnerability exists when the Windows Shell does not properly validate file paths, aka &quot;Windows Shell Remote Code Execution Vulnerability.&quot; This affects Windows 10 Servers, Windows 10.
</code>

- [whereisr0da/CVE-2018-8414-POC](https://github.com/whereisr0da/CVE-2018-8414-POC)

### CVE-2018-8581 (2018-11-14)

<code>An elevation of privilege vulnerability exists in Microsoft Exchange Server, aka &quot;Microsoft Exchange Server Elevation of Privilege Vulnerability.&quot; This affects Microsoft Exchange Server.
</code>

- [WyAtu/CVE-2018-8581](https://github.com/WyAtu/CVE-2018-8581)
- [qiantu88/CVE-2018-8581](https://github.com/qiantu88/CVE-2018-8581)

### CVE-2018-9075 (2018-09-28)

<code>For some Iomega, Lenovo, LenovoEMC NAS devices versions 4.1.402.34662 and earlier, when joining a PersonalCloud setup, an attacker can craft a command injection payload using backtick &quot;``&quot; characters in the client:password parameter. As a result, arbitrary commands may be executed as the root user. The attack requires a value __c and iomega parameter.
</code>

- [beverlymiller818/cve-2018-9075](https://github.com/beverlymiller818/cve-2018-9075)

### CVE-2018-9206 (2018-10-11)

<code>Unauthenticated arbitrary file upload vulnerability in Blueimp jQuery-File-Upload &lt;= v9.22.0
</code>

- [MikeyPPPPPPPP/CVE-2018-9206](https://github.com/MikeyPPPPPPPP/CVE-2018-9206)

### CVE-2018-9338 (2024-11-19)

<code>In ResStringPool::setTo of ResourceTypes.cpp, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.
</code>

- [Pazhanivelmani/frameworks_base_Android_6.0.1_r22_CVE-2018-9338](https://github.com/Pazhanivelmani/frameworks_base_Android_6.0.1_r22_CVE-2018-9338)

### CVE-2018-9375 (2025-01-17)

<code>In multiple functions of UserDictionaryProvider.java, there is a possible way to add and delete words in the user dictionary due to a confused deputy. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.
</code>

- [IOActive/AOSP-ExploitUserDictionary](https://github.com/IOActive/AOSP-ExploitUserDictionary)

### CVE-2018-9995 (2018-04-10)

<code>TBK DVR4104 and DVR4216 devices, as well as Novo, CeNova, QSee, Pulnix, XVR 5 in 1, Securus, Night OWL, DVR Login, HVR Login, and MDVR Login, which run re-branded versions of the original TBK DVR4104 and DVR4216 series, allow remote attackers to bypass authentication via a &quot;Cookie: uid=admin&quot; header, as demonstrated by a device.rsp?opt=user&amp;cmd=list request that provides credentials within JSON data in a response.
</code>

- [ezelf/CVE-2018-9995_dvr_credentials](https://github.com/ezelf/CVE-2018-9995_dvr_credentials)
- [Cyb0r9/DVR-Exploiter](https://github.com/Cyb0r9/DVR-Exploiter)
- [batmoshka55/CVE-2018-9995_dvr_credentials](https://github.com/batmoshka55/CVE-2018-9995_dvr_credentials)

### CVE-2018-10732 (2018-05-28)

<code>The REST API in Dataiku DSS before 4.2.3 allows remote attackers to obtain sensitive information (i.e., determine if a username is valid) because of profile pictures visibility.
</code>

- [alt3kx/CVE-2018-10732](https://github.com/alt3kx/CVE-2018-10732)

### CVE-2018-10933 (2018-10-17)

<code>A vulnerability was found in libssh's server-side state machine before versions 0.7.6 and 0.8.4. A malicious client could create channels without first performing authentication, resulting in unauthorized access.
</code>

- [blacknbunny/CVE-2018-10933](https://github.com/blacknbunny/CVE-2018-10933)
- [xFreed0m/CVE-2018-10933](https://github.com/xFreed0m/CVE-2018-10933)
- [ensimag-security/CVE-2018-10933](https://github.com/ensimag-security/CVE-2018-10933)
- [sambiyal/CVE-2018-10933-POC](https://github.com/sambiyal/CVE-2018-10933-POC)
- [nikhil1232/LibSSH-Authentication-Bypass](https://github.com/nikhil1232/LibSSH-Authentication-Bypass)

### CVE-2018-10936 (2018-08-30)

<code>A weakness was found in postgresql-jdbc before version 42.2.5. It was possible to provide an SSL Factory and not check the host name if a host name verifier was not provided to the driver. This could lead to a condition where a man-in-the-middle attacker could masquerade as a trusted server by providing a certificate for the wrong host, as long as it was signed by a trusted CA.
</code>

- [tafamace/CVE-2018-10936](https://github.com/tafamace/CVE-2018-10936)

### CVE-2018-11235 (2018-05-30)

<code>In Git before 2.13.7, 2.14.x before 2.14.4, 2.15.x before 2.15.2, 2.16.x before 2.16.4, and 2.17.x before 2.17.1, remote code execution can occur. With a crafted .gitmodules file, a malicious project can execute an arbitrary script on a machine that runs &quot;git clone --recurse-submodules&quot; because submodule &quot;names&quot; are obtained from this file, and then appended to $GIT_DIR/modules, leading to directory traversal with &quot;../&quot; in a name. Finally, post-checkout hooks from a submodule are executed, bypassing the intended design in which hooks are not obtained from a remote server.
</code>

- [Rogdham/CVE-2018-11235](https://github.com/Rogdham/CVE-2018-11235)
- [knqyf263/CVE-2018-11235](https://github.com/knqyf263/CVE-2018-11235)
- [ygouzerh/CVE-2018-11235](https://github.com/ygouzerh/CVE-2018-11235)

### CVE-2018-11759 (2018-10-31)

<code>The Apache Web Server (httpd) specific code that normalised the requested path before matching it to the URI-worker map in Apache Tomcat JK (mod_jk) Connector 1.2.0 to 1.2.44 did not handle some edge cases correctly. If only a sub-set of the URLs supported by Tomcat were exposed via httpd, then it was possible for a specially constructed request to expose application functionality through the reverse proxy that was not intended for clients accessing the application via the reverse proxy. It was also possible in some configurations for a specially constructed request to bypass the access controls configured in httpd. While there is some overlap between this issue and CVE-2018-1323, they are not identical.
</code>

- [immunIT/CVE-2018-11759](https://github.com/immunIT/CVE-2018-11759)
- [Jul10l1r4/Identificador-CVE-2018-11759](https://github.com/Jul10l1r4/Identificador-CVE-2018-11759)

### CVE-2018-11776 (2018-08-22)

<code>Apache Struts versions 2.3 to 2.3.34 and 2.5 to 2.5.16 suffer from possible Remote Code Execution when alwaysSelectFullNamespace is true (either by user or a plugin like Convention Plugin) and then: results are used with no namespace and in same time, its upper package have no or wildcard namespace and similar to results, same possibility when using url tag which doesn't have value and action set and in same time, its upper package have no or wildcard namespace.
</code>

- [xfox64x/CVE-2018-11776](https://github.com/xfox64x/CVE-2018-11776)
- [jiguangsdf/CVE-2018-11776](https://github.com/jiguangsdf/CVE-2018-11776)

### CVE-2018-12038 (2018-11-20)

<code>An issue was discovered on Samsung 840 EVO devices. Vendor-specific commands may allow access to the disk-encryption key.
</code>

- [gdraperi/remote-bitlocker-encryption-report](https://github.com/gdraperi/remote-bitlocker-encryption-report)

### CVE-2018-12463 (2018-07-12)

<code>An XML external entity (XXE) vulnerability in Fortify Software Security Center (SSC), version 17.1, 17.2, 18.1 allows remote unauthenticated users to read arbitrary files or conduct server-side request forgery (SSRF) attacks via a crafted DTD in an XML request.
</code>

- [alt3kx/CVE-2018-12463](https://github.com/alt3kx/CVE-2018-12463)

### CVE-2018-12533 (2018-06-18)

<code>JBoss RichFaces 3.1.0 through 3.3.4 allows unauthenticated remote attackers to inject expression language (EL) expressions and execute arbitrary Java code via a /DATA/ substring in a path with an org.richfaces.renderkit.html.Paint2DResource$ImageData object, aka RF-14310.
</code>

- [llamaonsecurity/CVE-2018-12533](https://github.com/llamaonsecurity/CVE-2018-12533)

### CVE-2018-12596 (2018-10-10)

<code>Episerver Ektron CMS before 9.0 SP3 Site CU 31, 9.1 before SP3 Site CU 45, or 9.2 before SP2 Site CU 22 allows remote attackers to call aspx pages via the &quot;activateuser.aspx&quot; page, even if a page is located under the /WorkArea/ path, which is forbidden (normally available exclusively for local admins).
</code>

- [alt3kx/CVE-2018-12596](https://github.com/alt3kx/CVE-2018-12596)

### CVE-2018-12895 (2018-06-26)

<code>WordPress through 4.9.6 allows Author users to execute arbitrary code by leveraging directory traversal in the wp-admin/post.php thumb parameter, which is passed to the PHP unlink function and can delete the wp-config.php file. This is related to missing filename validation in the wp-includes/post.php wp_delete_attachment function. The attacker must have capabilities for files and posts that are normally available only to the Author, Editor, and Administrator roles. The attack methodology is to delete wp-config.php and then launch a new installation process to increase the attacker's privileges.
</code>

- [bloom-ux/cve-2018-12895-hotfix](https://github.com/bloom-ux/cve-2018-12895-hotfix)

### CVE-2018-13382 (2019-06-04)

<code>An Improper Authorization vulnerability in Fortinet FortiOS 6.0.0 to 6.0.4, 5.6.0 to 5.6.8 and 5.4.1 to 5.4.10 and FortiProxy 2.0.0, 1.2.0 to 1.2.8, 1.1.0 to 1.1.6, 1.0.0 to 1.0.7 under SSL VPN web portal allows an unauthenticated attacker to modify the password of an SSL VPN web portal user via specially crafted HTTP requests
</code>

- [cojoben/CVE-2018-13382](https://github.com/cojoben/CVE-2018-13382)

### CVE-2018-14442 (2018-07-20)

<code>Foxit Reader before 9.2 and PhantomPDF before 9.2 have a Use-After-Free that leads to Remote Code Execution, aka V-88f4smlocs.
</code>

- [payatu/CVE-2018-14442](https://github.com/payatu/CVE-2018-14442)

### CVE-2018-14665 (2018-10-25)

<code>A flaw was found in xorg-x11-server before 1.20.3. An incorrect permission check for -modulepath and -logfile options when starting Xorg. X server allows unprivileged users with the ability to log in to the system via physical console to escalate their privileges and run arbitrary code under root privileges.
</code>

- [bolonobolo/CVE-2018-14665](https://github.com/bolonobolo/CVE-2018-14665)

### CVE-2018-14667 (2018-11-06)

<code>The RichFaces Framework 3.X through 3.3.4 is vulnerable to Expression Language (EL) injection via the UserResource resource. A remote, unauthenticated attacker could exploit this to execute arbitrary code using a chain of java serialized objects via org.ajax4jsf.resource.UserResource$UriData.
</code>

- [zeroto01/CVE-2018-14667](https://github.com/zeroto01/CVE-2018-14667)
- [r00t4dm/CVE-2018-14667](https://github.com/r00t4dm/CVE-2018-14667)
- [syriusbughunt/CVE-2018-14667](https://github.com/syriusbughunt/CVE-2018-14667)

### CVE-2018-14714 (2019-05-13)

<code>System command injection in appGet.cgi on ASUS RT-AC3200 version 3.0.0.4.382.50010 allows attackers to execute system commands via the &quot;load_script&quot; URL parameter.
</code>

- [BTtea/CVE-2018-14714-RCE-exploit](https://github.com/BTtea/CVE-2018-14714-RCE-exploit)

### CVE-2018-14847 (2018-08-02)

<code>MikroTik RouterOS through 6.42 allows unauthenticated remote attackers to read arbitrary files and remote authenticated attackers to write arbitrary files due to a directory traversal vulnerability in the WinBox interface.
</code>

- [BasuCert/WinboxPoC](https://github.com/BasuCert/WinboxPoC)
- [jas502n/CVE-2018-14847](https://github.com/jas502n/CVE-2018-14847)

### CVE-2018-14881 (2019-10-03)

<code>The BGP parser in tcpdump before 4.9.3 has a buffer over-read in print-bgp.c:bgp_capabilities_print() (BGP_CAPCODE_RESTART).
</code>

- [uthrasri/CVE-2018-14881_no_patch](https://github.com/uthrasri/CVE-2018-14881_no_patch)

### CVE-2018-15133 (2018-08-09)

<code>In Laravel Framework through 5.5.40 and 5.6.x through 5.6.29, remote code execution might occur as a result of an unserialize call on a potentially untrusted X-XSRF-TOKEN value. This involves the decrypt method in Illuminate/Encryption/Encrypter.php and PendingBroadcast in gadgetchains/Laravel/RCE/3/chain.php in phpggc. The attacker must know the application key, which normally would never occur, but could happen if the attacker previously had privileged access or successfully accomplished a previous attack.
</code>

- [kozmic/laravel-poc-CVE-2018-15133](https://github.com/kozmic/laravel-poc-CVE-2018-15133)

### CVE-2018-15365 (2018-09-28)

<code>A Reflected Cross-Site Scripting (XSS) vulnerability in Trend Micro Deep Discovery Inspector 3.85 and below could allow an attacker to bypass CSRF protection and conduct an attack on vulnerable installations. An attacker must be an authenticated user in order to exploit the vulnerability.
</code>

- [nixwizard/CVE-2018-15365](https://github.com/nixwizard/CVE-2018-15365)

### CVE-2018-15473 (2018-08-17)

<code>OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid authenticating user until after the packet containing the request has been fully parsed, related to auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c.
</code>

- [trimstray/massh-enum](https://github.com/trimstray/massh-enum)
- [gbonacini/opensshenum](https://github.com/gbonacini/opensshenum)
- [Rhynorater/CVE-2018-15473-Exploit](https://github.com/Rhynorater/CVE-2018-15473-Exploit)
- [epi052/cve-2018-15473](https://github.com/epi052/cve-2018-15473)
- [pyperanger/CVE-2018-15473_exploit](https://github.com/pyperanger/CVE-2018-15473_exploit)
- [r3dxpl0it/CVE-2018-15473](https://github.com/r3dxpl0it/CVE-2018-15473)
- [JoeBlackSecurity/SSHUsernameBruter-SSHUB](https://github.com/JoeBlackSecurity/SSHUsernameBruter-SSHUB)
- [NestyF/SSH_Enum_CVE-2018-15473](https://github.com/NestyF/SSH_Enum_CVE-2018-15473)
- [SUDORM0X/PoC-CVE-2018-15473](https://github.com/SUDORM0X/PoC-CVE-2018-15473)
- [OmarV4066/SSHEnumKL](https://github.com/OmarV4066/SSHEnumKL)

### CVE-2018-15832 (2018-09-20)

<code>upc.exe in Ubisoft Uplay Desktop Client versions 63.0.5699.0 allows remote attackers to execute arbitrary code. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the processing of URI handlers. The issue results from the lack of proper validation of a user-supplied string before using it to execute a system call. An attacker can leverage this vulnerability to execute code under the context of the current process.
</code>

- [JacksonKuo/ubisoft-uplay-desktop-client-63.0.5699.0](https://github.com/JacksonKuo/ubisoft-uplay-desktop-client-63.0.5699.0)

### CVE-2018-15961 (2018-09-25)

<code>Adobe ColdFusion versions July 12 release (2018.0.0.310739), Update 6 and earlier, and Update 14 and earlier have an unrestricted file upload vulnerability. Successful exploitation could lead to arbitrary code execution.
</code>

- [vah13/CVE-2018-15961](https://github.com/vah13/CVE-2018-15961)

### CVE-2018-15982 (2019-01-18)

<code>Flash Player versions 31.0.0.153 and earlier, and 31.0.0.108 and earlier have a use after free vulnerability. Successful exploitation could lead to arbitrary code execution.
</code>

- [FlatL1neAPT/CVE-2018-15982](https://github.com/FlatL1neAPT/CVE-2018-15982)
- [Ormicron/CVE-2018-15982_PoC](https://github.com/Ormicron/CVE-2018-15982_PoC)
- [Ridter/CVE-2018-15982_EXP](https://github.com/Ridter/CVE-2018-15982_EXP)
- [kphongagsorn/adobe-flash-cve2018-15982](https://github.com/kphongagsorn/adobe-flash-cve2018-15982)
- [jas502n/CVE-2018-15982_EXP_IE](https://github.com/jas502n/CVE-2018-15982_EXP_IE)
- [scanfsec/CVE-2018-15982](https://github.com/scanfsec/CVE-2018-15982)
- [SyFi/CVE-2018-15982](https://github.com/SyFi/CVE-2018-15982)

### CVE-2018-16119 (2019-06-20)

<code>Stack-based buffer overflow in the httpd server of TP-Link WR1043nd (Firmware Version 3) allows remote attackers to execute arbitrary code via a malicious MediaServer request to /userRpm/MediaServerFoldersCfgRpm.htm.
</code>

- [hdbreaker/CVE-2018-16119](https://github.com/hdbreaker/CVE-2018-16119)

### CVE-2018-16156 (2019-05-17)

<code>In PaperStream IP (TWAIN) 1.42.0.5685 (Service Update 7), the FJTWSVIC service running with SYSTEM privilege processes unauthenticated messages received over the FjtwMkic_Fjicube_32 named pipe. One of these message processing functions attempts to dynamically load the UninOldIS.dll library and executes an exported function named ChangeUninstallString. The default install does not contain this library and therefore if any DLL with that name exists in any directory listed in the PATH variable, it can be used to escalate to SYSTEM level privilege.
</code>

- [securifera/CVE-2018-16156-Exploit](https://github.com/securifera/CVE-2018-16156-Exploit)

### CVE-2018-16323 (2018-09-01)

<code>ReadXBMImage in coders/xbm.c in ImageMagick before 7.0.8-9 leaves data uninitialized when processing an XBM file that has a negative pixel value. If the affected code is used as a library loaded into a process that includes sensitive information, that information sometimes can be leaked via the image data.
</code>

- [ttffdd/XBadManners](https://github.com/ttffdd/XBadManners)

### CVE-2018-16431 (2018-09-04)

<code>admin/admin/adminsave.html in YFCMF v3.0 allows CSRF to add an administrator account.
</code>

- [RHYru9/CVE-2018-16431](https://github.com/RHYru9/CVE-2018-16431)

### CVE-2018-16509 (2018-09-05)

<code>An issue was discovered in Artifex Ghostscript before 9.24. Incorrect &quot;restoration of privilege&quot; checking during handling of /invalidaccess exceptions could be used by attackers able to supply crafted PostScript to execute code using the &quot;pipe&quot; instruction.
</code>

- [farisv/PIL-RCE-Ghostscript-CVE-2018-16509](https://github.com/farisv/PIL-RCE-Ghostscript-CVE-2018-16509)
- [knqyf263/CVE-2018-16509](https://github.com/knqyf263/CVE-2018-16509)

### CVE-2018-16711 (2018-09-26)

<code>IObit Advanced SystemCare, which includes Monitor_win10_x64.sys or Monitor_win7_x64.sys, 1.2.0.5 (and possibly earlier versions) allows a user to send an IOCTL (0x9C402088) with a buffer containing user defined content. The driver's subroutine will execute a wrmsr instruction with the user's buffer for input.
</code>

- [DownWithUp/CVE-2018-16711](https://github.com/DownWithUp/CVE-2018-16711)

### CVE-2018-16712 (2018-09-26)

<code>IObit Advanced SystemCare, which includes Monitor_win10_x64.sys or Monitor_win7_x64.sys, 1.2.0.5 (and possibly earlier versions) allows a user to send a specially crafted IOCTL 0x9C406104 to read physical memory.
</code>

- [DownWithUp/CVE-2018-16712](https://github.com/DownWithUp/CVE-2018-16712)

### CVE-2018-16713 (2018-09-26)

<code>IObit Advanced SystemCare, which includes Monitor_win10_x64.sys or Monitor_win7_x64.sys, 1.2.0.5 (and possibly earlier versions) allows a user to send an IOCTL (0x9C402084) with a buffer containing user defined content. The driver's subroutine will execute a rdmsr instruction with the user's buffer for input, and provide output from the instruction.
</code>

- [DownWithUp/CVE-2018-16713](https://github.com/DownWithUp/CVE-2018-16713)

### CVE-2018-16763 (2018-09-09)

<code>FUEL CMS 1.4.1 allows PHP Code Evaluation via the pages/select/ filter parameter or the preview/ data parameter. This can lead to Pre-Auth Remote Code Execution.
</code>

- [n3rdh4x0r/CVE-2018-16763](https://github.com/n3rdh4x0r/CVE-2018-16763)
- [p0dalirius/CVE-2018-16763-FuelCMS-1.4.1-RCE](https://github.com/p0dalirius/CVE-2018-16763-FuelCMS-1.4.1-RCE)
- [saccles/CVE-2018-16763-Proof-of-Concept](https://github.com/saccles/CVE-2018-16763-Proof-of-Concept)
- [altsun/CVE-2018-16763-FuelCMS-1.4.1-RCE](https://github.com/altsun/CVE-2018-16763-FuelCMS-1.4.1-RCE)

### CVE-2018-16875 (2018-12-14)

<code>The crypto/x509 package of Go before 1.10.6 and 1.11.x before 1.11.3 does not limit the amount of work performed for each chain verification, which might allow attackers to craft pathological inputs leading to a CPU denial of service. Go TLS servers accepting client certificates and TLS clients are affected.
</code>

- [alexzorin/poc-cve-2018-16875](https://github.com/alexzorin/poc-cve-2018-16875)

### CVE-2018-17081 (2018-09-26)

<code>e107 2.1.9 allows CSRF via e107_admin/wmessage.php?mode=&amp;action=inline&amp;ajax_used=1&amp;id= for changing the title of an arbitrary page.
</code>

- [himanshurahi/e107_2.1.9_CSRF_POC](https://github.com/himanshurahi/e107_2.1.9_CSRF_POC)

### CVE-2018-17182 (2018-09-19)

<code>An issue was discovered in the Linux kernel through 4.18.8. The vmacache_flush_all function in mm/vmacache.c mishandles sequence number overflows. An attacker can trigger a use-after-free (and possibly gain privileges) via certain thread creation, map, unmap, invalidation, and dereference operations.
</code>

- [jas502n/CVE-2018-17182](https://github.com/jas502n/CVE-2018-17182)

### CVE-2018-17240 (2022-06-10)

<code>There is a memory dump vulnerability on Netwave IP camera devices at //proc/kcore that allows an unauthenticated attacker to exfiltrate sensitive information from the network configuration (e.g., username and password).
</code>

- [Xewdy444/Netgrave](https://github.com/Xewdy444/Netgrave)
- [FenrirSec/CVE-2018-17240_exploit](https://github.com/FenrirSec/CVE-2018-17240_exploit)

### CVE-2018-17418 (2019-03-07)

<code>Monstra CMS 3.0.4 allows remote attackers to execute arbitrary PHP code via a mixed-case file extension, as demonstrated by the 123.PhP filename, because plugins\box\filesmanager\filesmanager.admin.php mishandles the forbidden_types variable.
</code>

- [Jx0n0/monstra_cms-3.0.4--getshell](https://github.com/Jx0n0/monstra_cms-3.0.4--getshell)

### CVE-2018-17431 (2019-01-29)

<code>Web Console in Comodo UTM Firewall before 2.7.0 allows remote attackers to execute arbitrary code without authentication via a crafted URL.
</code>

- [Fadavvi/CVE-2018-17431-PoC](https://github.com/Fadavvi/CVE-2018-17431-PoC)

### CVE-2018-18820 (2018-11-05)

<code>A buffer overflow was discovered in the URL-authentication backend of the Icecast before 2.4.4. If the backend is enabled, then any malicious HTTP client can send a request for that specific resource including a crafted header, leading to denial of service and potentially remote code execution.
</code>

- [impulsiveness/CVE-2018-18820](https://github.com/impulsiveness/CVE-2018-18820)

### CVE-2018-19126 (2018-11-09)

<code>PrestaShop 1.6.x before 1.6.1.23 and 1.7.x before 1.7.4.4 allows remote attackers to execute arbitrary code via a file upload.
</code>

- [farisv/PrestaShop-CVE-2018-19126](https://github.com/farisv/PrestaShop-CVE-2018-19126)

### CVE-2018-19207 (2018-11-12)

<code>The Van Ons WP GDPR Compliance (aka wp-gdpr-compliance) plugin before 1.4.3 for WordPress allows remote attackers to execute arbitrary code because $wpdb-&gt;prepare() input is mishandled, as exploited in the wild in November 2018.
</code>

- [aeroot/WP-GDPR-Compliance-Plugin-Exploit](https://github.com/aeroot/WP-GDPR-Compliance-Plugin-Exploit)

### CVE-2018-19466 (2019-03-27)

<code>A vulnerability was found in Portainer before 1.20.0. Portainer stores LDAP credentials, corresponding to a master password, in cleartext and allows their retrieval via API calls.
</code>

- [MauroEldritch/lempo](https://github.com/MauroEldritch/lempo)

### CVE-2018-19487 (2019-03-17)

<code>The WP-jobhunt plugin before version 2.4 for WordPress does not control AJAX requests sent to the cs_employer_ajax_profile() function through the admin-ajax.php file, which allows remote unauthenticated attackers to enumerate information about users.
</code>

- [YOLOP0wn/wp-jobhunt-exploit](https://github.com/YOLOP0wn/wp-jobhunt-exploit)

### CVE-2018-19518 (2018-11-25)

<code>University of Washington IMAP Toolkit 2007f on UNIX, as used in imap_open() in PHP and other products, launches an rsh command (by means of the imap_rimap function in c-client/imap4r1.c and the tcp_aopen function in osdep/unix/tcp_unix.c) without preventing argument injection, which might allow remote attackers to execute arbitrary OS commands if the IMAP server name is untrusted input (e.g., entered by a user of a web application) and if rsh has been replaced by a program with different argument semantics. For example, if rsh is a link to ssh (as seen on Debian and Ubuntu systems), then the attack can use an IMAP server name containing a &quot;-oProxyCommand&quot; argument.
</code>

- [ensimag-security/CVE-2018-19518](https://github.com/ensimag-security/CVE-2018-19518)

### CVE-2018-19537 (2018-11-26)

<code>TP-Link Archer C5 devices through V2_160201_US allow remote command execution via shell metacharacters on the wan_dyn_hostname line of a configuration file that is encrypted with the 478DA50BF9E3D2CF key and uploaded through the web GUI by using the web admin account. The default password of admin may be used in some cases.
</code>

- [JackDoan/TP-Link-ArcherC5-RCE](https://github.com/JackDoan/TP-Link-ArcherC5-RCE)

### CVE-2018-19592 (2019-09-27)

<code>The &quot;CLink4Service&quot; service is installed with Corsair Link 4.9.7.35 with insecure permissions by default. This allows unprivileged users to take control of the service and execute commands in the context of NT AUTHORITY\SYSTEM, leading to total system takeover, a similar issue to CVE-2018-12441.
</code>

- [BradyDonovan/CVE-2018-19592](https://github.com/BradyDonovan/CVE-2018-19592)

### CVE-2018-19788 (2018-12-03)

<code>A flaw was found in PolicyKit (aka polkit) 0.115 that allows a user with a uid greater than INT_MAX to successfully execute any systemctl command.
</code>

- [AbsoZed/CVE-2018-19788](https://github.com/AbsoZed/CVE-2018-19788)
- [d4gh0s7/CVE-2018-19788](https://github.com/d4gh0s7/CVE-2018-19788)
- [Ekultek/PoC](https://github.com/Ekultek/PoC)
- [jhlongjr/CVE-2018-19788](https://github.com/jhlongjr/CVE-2018-19788)

### CVE-2018-19911 (2018-12-06)

<code>FreeSWITCH through 1.8.2, when mod_xml_rpc is enabled, allows remote attackers to execute arbitrary commands via the api/system or txtapi/system (or api/bg_system or txtapi/bg_system) query string on TCP port 8080, as demonstrated by an api/system?calc URI. This can also be exploited via CSRF. Alternatively, the default password of works for the freeswitch account can sometimes be used.
</code>

- [iSafeBlue/freeswitch_rce](https://github.com/iSafeBlue/freeswitch_rce)

### CVE-2018-20343 (2020-03-02)

<code>Multiple buffer overflow vulnerabilities have been found in Ken Silverman Build Engine 1. An attacker could craft a special map file to execute arbitrary code when the map file is loaded.
</code>

- [Alexandre-Bartel/CVE-2018-20343](https://github.com/Alexandre-Bartel/CVE-2018-20343)

### CVE-2018-20377 (2018-12-23)

<code>Orange Livebox 00.96.320S devices allow remote attackers to discover Wi-Fi credentials via /get_getnetworkconf.cgi on port 8080, leading to full control if the admin password equals the Wi-Fi password or has the default admin value. This is related to Firmware 01.11.2017-11:43:44, Boot v0.70.03, Modem 5.4.1.10.1.1A, Hardware 02, and Arcadyan ARV7519RW22-A-L T VR9 1.2.
</code>

- [zadewg/LIVEBOX-0DAY](https://github.com/zadewg/LIVEBOX-0DAY)

### CVE-2018-25031 (2022-03-11)

<code>Swagger UI 4.1.2 and earlier could allow a remote attacker to conduct spoofing attacks. By persuading a victim to open a crafted URL, an attacker could exploit this vulnerability to display remote OpenAPI definitions. Note: This was originally claimed to be resolved in 4.1.3. However, third parties have indicated this is not resolved in 4.1.3 and even occurs in that version and possibly others.
</code>

- [mathis2001/CVE-2018-25031](https://github.com/mathis2001/CVE-2018-25031)
- [KonEch0/CVE-2018-25031-SG](https://github.com/KonEch0/CVE-2018-25031-SG)
- [Proklinius897/CVE-2018-25031-tests](https://github.com/Proklinius897/CVE-2018-25031-tests)

### CVE-2018-1000531 (2018-06-26)

<code>inversoft prime-jwt version prior to commit abb0d479389a2509f939452a6767dc424bb5e6ba contains a CWE-20 vulnerability in JWTDecoder.decode that can result in an incorrect signature validation of a JWT token. This attack can be exploitable when an attacker crafts a JWT token with a valid header using 'none' as algorithm and a body to requests it be validated. This vulnerability was fixed after commit abb0d479389a2509f939452a6767dc424bb5e6ba.
</code>

- [realbatuhan/JWT-Bruteforcer](https://github.com/realbatuhan/JWT-Bruteforcer)

### CVE-2018-1000802 (2018-09-18)

<code>Python Software Foundation Python (CPython) version 2.7 contains a CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection') vulnerability in shutil module (make_archive function) that can result in Denial of service, Information gain via injection of arbitrary files on the system or entire drive. This attack appear to be exploitable via Passage of unfiltered user input to the function. This vulnerability appears to have been fixed in after commit add531a1e55b0a739b0f42582f1c9747e5649ace.
</code>

- [tna0y/CVE-2018-1000802-PoC](https://github.com/tna0y/CVE-2018-1000802-PoC)

### CVE-2018-1002105 (2018-12-05)

<code>In all Kubernetes versions prior to v1.10.11, v1.11.5, and v1.12.3, incorrect handling of error responses to proxied upgrade requests in the kube-apiserver allowed specially crafted requests to establish a connection through the Kubernetes API server to backend servers, then send arbitrary requests over the same connection directly to the backend, authenticated with the Kubernetes API server's TLS credentials used to establish the backend connection.
</code>

- [gravitational/cve-2018-1002105](https://github.com/gravitational/cve-2018-1002105)
- [evict/poc_CVE-2018-1002105](https://github.com/evict/poc_CVE-2018-1002105)
- [imlzw/Kubernetes-1.12.3-all-auto-install](https://github.com/imlzw/Kubernetes-1.12.3-all-auto-install)

### CVE-2018-1999002 (2018-07-23)

<code>A arbitrary file read vulnerability exists in Jenkins 2.132 and earlier, 2.121.1 and earlier in the Stapler web framework's org/kohsuke/stapler/Stapler.java that allows attackers to send crafted HTTP requests returning the contents of any file on the Jenkins master file system that the Jenkins master has access to.
</code>

- [wetw0rk/Exploit-Development](https://github.com/wetw0rk/Exploit-Development)


## 2017
### CVE-2017-0065 (2017-03-17)

<code>Microsoft Edge allows remote attackers to obtain sensitive information from process memory via a crafted web site, aka &quot;Microsoft Browser Information Disclosure Vulnerability.&quot; This vulnerability is different from those described in CVE-2017-0009, CVE-2017-0011, CVE-2017-0017, and CVE-2017-0068.
</code>

- [Dankirk/cve-2017-0065](https://github.com/Dankirk/cve-2017-0065)

### CVE-2017-0089 (2017-03-17)

<code>Uniscribe in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, and Windows 7 SP1 allows remote attackers to execute arbitrary code via a crafted web site, aka &quot;Uniscribe Remote Code Execution Vulnerability.&quot; This vulnerability is different from those described in CVE-2017-0072, CVE-2017-0083, CVE-2017-0084, CVE-2017-0086, CVE-2017-0087, CVE-2017-0088, and CVE-2017-0090.
</code>

- [rainhawk13/Added-Pentest-Ground-to-vulnerable-websites-for-training](https://github.com/rainhawk13/Added-Pentest-Ground-to-vulnerable-websites-for-training)

### CVE-2017-0143 (2017-03-17)

<code>The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka &quot;Windows SMB Remote Code Execution Vulnerability.&quot; This vulnerability is different from those described in CVE-2017-0144, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.
</code>

- [NatteeSetobol/Etern-blue-Windows-7-Checker](https://github.com/NatteeSetobol/Etern-blue-Windows-7-Checker)
- [n3rdh4x0r/MS17-010_CVE-2017-0143](https://github.com/n3rdh4x0r/MS17-010_CVE-2017-0143)

### CVE-2017-0144 (2017-03-17)

<code>The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka &quot;Windows SMB Remote Code Execution Vulnerability.&quot; This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.
</code>

- [peterpt/eternal_scanner](https://github.com/peterpt/eternal_scanner)
- [kimocoder/eternalblue](https://github.com/kimocoder/eternalblue)
- [ducanh2oo3/Vulnerability-Research-CVE-2017-0144](https://github.com/ducanh2oo3/Vulnerability-Research-CVE-2017-0144)
- [AnugiArrawwala/CVE-Research](https://github.com/AnugiArrawwala/CVE-Research)
- [DenuwanJayasekara/CVE-Exploitation-Reports](https://github.com/DenuwanJayasekara/CVE-Exploitation-Reports)
- [sethwhy/BlueDoor](https://github.com/sethwhy/BlueDoor)
- [AtithKhawas/autoblue](https://github.com/AtithKhawas/autoblue)
- [MedX267/EternalBlue-Vulnerability-Scanner](https://github.com/MedX267/EternalBlue-Vulnerability-Scanner)

### CVE-2017-0148 (2017-03-17)

<code>The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka &quot;Windows SMB Remote Code Execution Vulnerability.&quot; This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0144, CVE-2017-0145, and CVE-2017-0146.
</code>

- [HakaKali/CVE-2017-0148](https://github.com/HakaKali/CVE-2017-0148)

### CVE-2017-0199 (2017-04-12)

<code>Microsoft Office 2007 SP3, Microsoft Office 2010 SP2, Microsoft Office 2013 SP1, Microsoft Office 2016, Microsoft Windows Vista SP2, Windows Server 2008 SP2, Windows 7 SP1, Windows 8.1 allow remote attackers to execute arbitrary code via a crafted document, aka &quot;Microsoft Office/WordPad Remote Code Execution Vulnerability w/Windows API.&quot;
</code>

- [bhdresh/CVE-2017-0199](https://github.com/bhdresh/CVE-2017-0199)
- [sUbc0ol/Microsoft-Word-CVE-2017-0199-](https://github.com/sUbc0ol/Microsoft-Word-CVE-2017-0199-)
- [viethdgit/CVE-2017-0199](https://github.com/viethdgit/CVE-2017-0199)
- [nicpenning/RTF-Cleaner](https://github.com/nicpenning/RTF-Cleaner)
- [herbiezimmerman/2017-11-17-Maldoc-Using-CVE-2017-0199](https://github.com/herbiezimmerman/2017-11-17-Maldoc-Using-CVE-2017-0199)
- [jacobsoo/RTF-Cleaner](https://github.com/jacobsoo/RTF-Cleaner)
- [TheCyberWatchers/CVE-2017-0199-v5.0](https://github.com/TheCyberWatchers/CVE-2017-0199-v5.0)
- [kash-123/CVE-2017-0199](https://github.com/kash-123/CVE-2017-0199)

### CVE-2017-0213 (2017-05-12)

<code>Windows COM Aggregate Marshaler in Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, and 1703, and Windows Server 2016 allows an elevation privilege vulnerability when an attacker runs a specially crafted application, aka &quot;Windows COM Elevation of Privilege Vulnerability&quot;. This CVE ID is unique from CVE-2017-0214.
</code>

- [zcgonvh/CVE-2017-0213](https://github.com/zcgonvh/CVE-2017-0213)
- [billa3283/CVE-2017-0213](https://github.com/billa3283/CVE-2017-0213)

### CVE-2017-0554 (2017-04-07)

<code>An elevation of privilege vulnerability in the Telephony component could enable a local malicious application to access capabilities outside of its permission levels. This issue is rated as Moderate because it could be used to gain access to elevated capabilities, which are not normally accessible to a third-party application. Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1. Android ID: A-33815946.
</code>

- [lanrat/tethr](https://github.com/lanrat/tethr)

### CVE-2017-0781 (2017-09-14)

<code>A remote code execution vulnerability in the Android system (bluetooth). Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-63146105.
</code>

- [ojasookert/CVE-2017-0781](https://github.com/ojasookert/CVE-2017-0781)
- [DamianSuess/Learn.BlueJam](https://github.com/DamianSuess/Learn.BlueJam)

### CVE-2017-0785 (2017-09-14)

<code>A information disclosure vulnerability in the Android system (bluetooth). Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-63146698.
</code>

- [ojasookert/CVE-2017-0785](https://github.com/ojasookert/CVE-2017-0785)
- [aymankhalfatni/CVE-2017-0785](https://github.com/aymankhalfatni/CVE-2017-0785)
- [Alfa100001/-CVE-2017-0785-BlueBorne-PoC](https://github.com/Alfa100001/-CVE-2017-0785-BlueBorne-PoC)
- [Hackerscript/BlueBorne-CVE-2017-0785](https://github.com/Hackerscript/BlueBorne-CVE-2017-0785)
- [pieterbork/blueborne](https://github.com/pieterbork/blueborne)
- [MasterCode112/Upgraded_BlueBourne-CVE-2017-0785-](https://github.com/MasterCode112/Upgraded_BlueBourne-CVE-2017-0785-)

### CVE-2017-75
- [CalebFIN/EXP-CVE-2017-75](https://github.com/CalebFIN/EXP-CVE-2017-75)

### CVE-2017-1235 (2017-09-25)

<code>IBM WebSphere MQ 8.0 could allow an authenticated user to cause a premature termination of a client application thread which could potentially cause denial of service. IBM X-Force ID: 123914.
</code>

- [11k4r/CVE-2017-1235_exploit](https://github.com/11k4r/CVE-2017-1235_exploit)

### CVE-2017-2024
- [FarizDevloper/CVE-2017-2024](https://github.com/FarizDevloper/CVE-2017-2024)

### CVE-2017-2368 (2017-02-20)

<code>An issue was discovered in certain Apple products. iOS before 10.2.1 is affected. The issue involves the &quot;Contacts&quot; component. It allows remote attackers to cause a denial of service (application crash) via a crafted contact card.
</code>

- [vincedes3/CVE-2017-2368](https://github.com/vincedes3/CVE-2017-2368)

### CVE-2017-2388 (2017-04-02)

<code>An issue was discovered in certain Apple products. macOS before 10.12.4 is affected. The issue involves the &quot;IOFireWireFamily&quot; component. It allows attackers to cause a denial of service (NULL pointer dereference) via a crafted app.
</code>

- [bazad/IOFireWireFamily-null-deref](https://github.com/bazad/IOFireWireFamily-null-deref)

### CVE-2017-2751 (2018-10-03)

<code>A BIOS password extraction vulnerability has been reported on certain consumer notebooks with firmware F.22 and others. The BIOS password was stored in CMOS in a way that allowed it to be extracted. This applies to consumer notebooks launched in early 2014.
</code>

- [BaderSZ/CVE-2017-2751](https://github.com/BaderSZ/CVE-2017-2751)

### CVE-2017-2793 (2017-05-23)

<code>An exploitable heap corruption vulnerability exists in the UnCompressUnicode functionality of Antenna House DMC HTMLFilter used by MarkLogic 8.0-6. A specially crafted xls file can cause a heap corruption resulting in arbitrary code execution. An attacker can send/provide malicious XLS file to trigger this vulnerability.
</code>

- [sUbc0ol/Detection-for-CVE-2017-2793](https://github.com/sUbc0ol/Detection-for-CVE-2017-2793)

### CVE-2017-2903 (2018-04-24)

<code>An exploitable integer overflow exists in the DPX loading functionality of the Blender open-source 3d creation suite version 2.78c. A specially crafted '.cin' file can cause an integer overflow resulting in a buffer overflow which can allow for code execution under the context of the application. An attacker can convince a user to use the file as an asset via the sequencer in order to trigger this vulnerability.
</code>

- [SpiralBL0CK/dpx_work_CVE-2017-2903](https://github.com/SpiralBL0CK/dpx_work_CVE-2017-2903)

### CVE-2017-3078 (2017-06-20)

<code>Adobe Flash Player versions 25.0.0.171 and earlier have an exploitable memory corruption vulnerability in the Adobe Texture Format (ATF) module. Successful exploitation could lead to arbitrary code execution.
</code>

- [homjxi0e/CVE-2017-3078](https://github.com/homjxi0e/CVE-2017-3078)

### CVE-2017-3164 (2019-03-08)

<code>Server Side Request Forgery in Apache Solr, versions 1.3 until 7.6 (inclusive). Since the &quot;shards&quot; parameter does not have a corresponding whitelist mechanism, a remote attacker with access to the server could make Solr perform an HTTP GET request to any reachable URL.
</code>

- [tdwyer/PoC_CVE-2017-3164_CVE-2017-1262](https://github.com/tdwyer/PoC_CVE-2017-3164_CVE-2017-1262)

### CVE-2017-3241 (2017-01-27)

<code>Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent: RMI). Supported versions that are affected are Java SE: 6u131, 7u121 and 8u112; Java SE Embedded: 8u111; JRockit: R28.3.12. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Java SE, Java SE Embedded, JRockit. While the vulnerability is in Java SE, Java SE Embedded, JRockit, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in takeover of Java SE, Java SE Embedded, JRockit. Note: This vulnerability can only be exploited by supplying data to APIs in the specified Component without using Untrusted Java Web Start applications or Untrusted Java applets, such as through a web service. CVSS v3.0 Base Score 9.0 (Confidentiality, Integrity and Availability impacts).
</code>

- [xfei3/CVE-2017-3241-POC](https://github.com/xfei3/CVE-2017-3241-POC)

### CVE-2017-3248 (2017-01-27)

<code>Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.0 and 12.2.1.1. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS v3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).
</code>

- [0xn0ne/weblogicScanner](https://github.com/0xn0ne/weblogicScanner)

### CVE-2017-4490
- [homjxi0e/CVE-2017-4490-](https://github.com/homjxi0e/CVE-2017-4490-)
- [homjxi0e/CVE-2017-4490-install-Script-Python-in-Terminal-](https://github.com/homjxi0e/CVE-2017-4490-install-Script-Python-in-Terminal-)

### CVE-2017-5123 (2021-11-02)

<code>Insufficient data validation in waitid allowed an user to escape sandboxes on Linux.
</code>

- [FloatingGuy/CVE-2017-5123](https://github.com/FloatingGuy/CVE-2017-5123)
- [0x5068656e6f6c/CVE-2017-5123](https://github.com/0x5068656e6f6c/CVE-2017-5123)

### CVE-2017-5124 (2018-02-07)

<code>Incorrect application of sandboxing in Blink in Google Chrome prior to 62.0.3202.62 allowed a remote attacker to inject arbitrary scripts or HTML (UXSS) via a crafted MHTML page.
</code>

- [Bo0oM/CVE-2017-5124](https://github.com/Bo0oM/CVE-2017-5124)

### CVE-2017-5487 (2017-01-15)

<code>wp-includes/rest-api/endpoints/class-wp-rest-users-controller.php in the REST API implementation in WordPress 4.7 before 4.7.1 does not properly restrict listings of post authors, which allows remote attackers to obtain sensitive information via a wp-json/wp/v2/users request.
</code>

- [teambugsbunny/wpUsersScan](https://github.com/teambugsbunny/wpUsersScan)
- [Ravindu-Priyankara/CVE-2017-5487-vulnerability-on-NSBM](https://github.com/Ravindu-Priyankara/CVE-2017-5487-vulnerability-on-NSBM)
- [K3ysTr0K3R/CVE-2017-5487-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2017-5487-EXPLOIT)
- [dream434/CVE-2017-5487](https://github.com/dream434/CVE-2017-5487)

### CVE-2017-5638 (2017-03-11)

<code>The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.
</code>

- [jas502n/S2-045-EXP-POC-TOOLS](https://github.com/jas502n/S2-045-EXP-POC-TOOLS)
- [mthbernardes/strutszeiro](https://github.com/mthbernardes/strutszeiro)
- [jrrombaldo/CVE-2017-5638](https://github.com/jrrombaldo/CVE-2017-5638)
- [initconf/CVE-2017-5638_struts](https://github.com/initconf/CVE-2017-5638_struts)
- [mazen160/struts-pwn](https://github.com/mazen160/struts-pwn)
- [jas502n/st2-046-poc](https://github.com/jas502n/st2-046-poc)
- [tahmed11/strutsy](https://github.com/tahmed11/strutsy)
- [SpiderMate/Stutsfi](https://github.com/SpiderMate/Stutsfi)
- [sUbc0ol/Apache-Struts-CVE-2017-5638-RCE-Mass-Scanner](https://github.com/sUbc0ol/Apache-Struts-CVE-2017-5638-RCE-Mass-Scanner)
- [sUbc0ol/Apache-Struts2-RCE-Exploit-v2-CVE-2017-5638](https://github.com/sUbc0ol/Apache-Struts2-RCE-Exploit-v2-CVE-2017-5638)
- [R4v3nBl4ck/Apache-Struts-2-CVE-2017-5638-Exploit-](https://github.com/R4v3nBl4ck/Apache-Struts-2-CVE-2017-5638-Exploit-)
- [Xhendos/CVE-2017-5638](https://github.com/Xhendos/CVE-2017-5638)
- [TamiiLambrado/Apache-Struts-CVE-2017-5638-RCE-Mass-Scanner](https://github.com/TamiiLambrado/Apache-Struts-CVE-2017-5638-RCE-Mass-Scanner)
- [invisiblethreat/strutser](https://github.com/invisiblethreat/strutser)
- [lizhi16/CVE-2017-5638](https://github.com/lizhi16/CVE-2017-5638)
- [c002/Apache-Struts](https://github.com/c002/Apache-Struts)
- [donaldashdown/Common-Vulnerability-and-Exploit](https://github.com/donaldashdown/Common-Vulnerability-and-Exploit)
- [FredBrave/CVE-2017-5638-ApacheStruts2.3.5](https://github.com/FredBrave/CVE-2017-5638-ApacheStruts2.3.5)
- [Nithylesh/web-application-firewall-](https://github.com/Nithylesh/web-application-firewall-)
- [kloutkake/CVE-2017-5638-PoC](https://github.com/kloutkake/CVE-2017-5638-PoC)
- [Xernary/CVE-2017-5638-POC](https://github.com/Xernary/CVE-2017-5638-POC)

### CVE-2017-5645 (2017-04-17)

<code>In Apache Log4j 2.x before 2.8.2, when using the TCP socket server or UDP socket server to receive serialized log events from another application, a specially crafted binary payload can be sent that, when deserialized, can execute arbitrary code.
</code>

- [pimps/CVE-2017-5645](https://github.com/pimps/CVE-2017-5645)
- [HynekPetrak/log4shell-finder](https://github.com/HynekPetrak/log4shell-finder)

### CVE-2017-5689 (2017-05-02)

<code>An unprivileged network attacker could gain system privileges to provisioned Intel manageability SKUs: Intel Active Management Technology (AMT) and Intel Standard Manageability (ISM). An unprivileged local attacker could provision manageability features gaining unprivileged network or local system privileges on Intel manageability SKUs: Intel Active Management Technology (AMT), Intel Standard Manageability (ISM), and Intel Small Business Technology (SBT).
</code>

- [haxrob/amthoneypot](https://github.com/haxrob/amthoneypot)
- [embedi/amt_auth_bypass_poc](https://github.com/embedi/amt_auth_bypass_poc)

### CVE-2017-5693 (2018-07-31)

<code>Firmware in the Intel Puma 5, 6, and 7 Series might experience resource depletion or timeout, which allows a network attacker to create a denial of service via crafted network traffic.
</code>

- [LunNova/Puma6Fail](https://github.com/LunNova/Puma6Fail)

### CVE-2017-5715 (2018-01-04)

<code>Systems with microprocessors utilizing speculative execution and indirect branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis.
</code>

- [GalloLuigi/Analisi-CVE-2017-5715](https://github.com/GalloLuigi/Analisi-CVE-2017-5715)

### CVE-2017-5721 (2017-10-11)

<code>Insufficient input validation in system firmware for Intel NUC7i3BNK, NUC7i3BNH, NUC7i5BNK, NUC7i5BNH, NUC7i7BNH versions BN0049 and below allows local attackers to execute arbitrary code via manipulation of memory.
</code>

- [embedi/smm_usbrt_poc](https://github.com/embedi/smm_usbrt_poc)

### CVE-2017-5941 (2017-02-09)

<code>An issue was discovered in the node-serialize package 0.0.4 for Node.js. Untrusted data passed into the unserialize() function can be exploited to achieve arbitrary code execution by passing a JavaScript Object with an Immediately Invoked Function Expression (IIFE).
</code>

- [turnernator1/Node.js-CVE-2017-5941](https://github.com/turnernator1/Node.js-CVE-2017-5941)
- [Cr4zyD14m0nd137/Lab-for-cve-2018-15133](https://github.com/Cr4zyD14m0nd137/Lab-for-cve-2018-15133)
- [uartu0/nodejshell](https://github.com/uartu0/nodejshell)

### CVE-2017-6008 (2017-09-13)

<code>A kernel pool overflow in the driver hitmanpro37.sys in Sophos SurfRight HitmanPro before 3.7.20 Build 286 (included in the HitmanPro.Alert solution and Sophos Clean) allows local users to escalate privileges via a malformed IOCTL call.
</code>

- [cbayet/Exploit-CVE-2017-6008](https://github.com/cbayet/Exploit-CVE-2017-6008)

### CVE-2017-6074 (2017-02-18)

<code>The dccp_rcv_state_process function in net/dccp/input.c in the Linux kernel through 4.9.11 mishandles DCCP_PKT_REQUEST packet data structures in the LISTEN state, which allows local users to obtain root privileges or cause a denial of service (double free) via an application that makes an IPV6_RECVPKTINFO setsockopt system call.
</code>

- [toanthang1842002/CVE-2017-6074](https://github.com/toanthang1842002/CVE-2017-6074)

### CVE-2017-6206 (2017-02-23)

<code>D-Link DGS-1510-28XMP, DGS-1510-28X, DGS-1510-52X, DGS-1510-52, DGS-1510-28P, DGS-1510-28, and DGS-1510-20 Websmart devices with firmware before 1.31.B003 allow attackers to conduct Unauthenticated Information Disclosure attacks via unspecified vectors.
</code>

- [varangamin/CVE-2017-6206](https://github.com/varangamin/CVE-2017-6206)

### CVE-2017-6558 (2017-03-09)

<code>iball Baton 150M iB-WRA150N v1 00000001 1.2.6 build 110401 Rel.47776n devices are prone to an authentication bypass vulnerability that allows remote attackers to view and modify administrative router settings by reading the HTML source code of the password.cgi file.
</code>

- [GemGeorge/iBall-UTStar-CVEChecker](https://github.com/GemGeorge/iBall-UTStar-CVEChecker)

### CVE-2017-7038 (2017-07-20)

<code>A DOMParser XSS issue was discovered in certain Apple products. iOS before 10.3.3 is affected. Safari before 10.1.2 is affected. tvOS before 10.2.2 is affected. The issue involves the &quot;WebKit&quot; component.
</code>

- [ansjdnakjdnajkd/CVE-2017-7038](https://github.com/ansjdnakjdnajkd/CVE-2017-7038)

### CVE-2017-7047 (2017-07-20)

<code>An issue was discovered in certain Apple products. iOS before 10.3.3 is affected. macOS before 10.12.6 is affected. tvOS before 10.2.2 is affected. watchOS before 3.2.3 is affected. The issue involves the &quot;libxpc&quot; component. It allows attackers to execute arbitrary code in a privileged context or cause a denial of service (memory corruption) via a crafted app.
</code>

- [JosephShenton/Triple_Fetch-Kernel-Creds](https://github.com/JosephShenton/Triple_Fetch-Kernel-Creds)
- [q1f3/Triple_fetch](https://github.com/q1f3/Triple_fetch)

### CVE-2017-7089 (2017-10-23)

<code>An issue was discovered in certain Apple products. iOS before 11 is affected. Safari before 11 is affected. iCloud before 7.0 on Windows is affected. The issue involves the &quot;WebKit&quot; component. It allows remote attackers to conduct Universal XSS (UXSS) attacks via a crafted web site that is mishandled during parent-tab processing.
</code>

- [Bo0oM/CVE-2017-7089](https://github.com/Bo0oM/CVE-2017-7089)
- [aymankhalfatni/Safari_Mac](https://github.com/aymankhalfatni/Safari_Mac)

### CVE-2017-7092 (2017-10-23)

<code>An issue was discovered in certain Apple products. iOS before 11 is affected. Safari before 11 is affected. iCloud before 7.0 on Windows is affected. iTunes before 12.7 on Windows is affected. tvOS before 11 is affected. The issue involves the &quot;WebKit&quot; component. It allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption and application crash) via a crafted web site.
</code>

- [xuechiyaobai/CVE-2017-7092-PoC](https://github.com/xuechiyaobai/CVE-2017-7092-PoC)

### CVE-2017-7173 (2018-04-03)

<code>An issue was discovered in certain Apple products. macOS before 10.13.2 is affected. The issue involves the &quot;Kernel&quot; component. It allows attackers to bypass intended memory-read restrictions via a crafted app.
</code>

- [bazad/sysctl_coalition_get_pid_list-dos](https://github.com/bazad/sysctl_coalition_get_pid_list-dos)

### CVE-2017-7269 (2017-03-27)

<code>Buffer overflow in the ScStoragePathFromUrl function in the WebDAV service in Internet Information Services (IIS) 6.0 in Microsoft Windows Server 2003 R2 allows remote attackers to execute arbitrary code via a long header beginning with &quot;If: &lt;http://&quot; in a PROPFIND request, as exploited in the wild in July or August 2016.
</code>

- [lcatro/CVE-2017-7269-Echo-PoC](https://github.com/lcatro/CVE-2017-7269-Echo-PoC)
- [g0rx/iis6-exploit-2017-CVE-2017-7269](https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269)
- [Cappricio-Securities/CVE-2017-7269](https://github.com/Cappricio-Securities/CVE-2017-7269)
- [VanishedPeople/CVE-2017-7269](https://github.com/VanishedPeople/CVE-2017-7269)
- [geniuszly/CVE-2017-7269](https://github.com/geniuszly/CVE-2017-7269)
- [AxthonyV/CVE-2017-7269](https://github.com/AxthonyV/CVE-2017-7269)

### CVE-2017-7410 (2017-04-03)

<code>Multiple SQL injection vulnerabilities in account/signup.php and account/signup2.php in WebsiteBaker 2.10.0 and earlier allow remote attackers to execute arbitrary SQL commands via the (1) username, (2) display_name parameter.
</code>

- [ashangp923/CVE-2017-7410](https://github.com/ashangp923/CVE-2017-7410)

### CVE-2017-7494 (2017-05-30)

<code>Samba since version 3.5.0 and before 4.6.4, 4.5.10 and 4.4.14 is vulnerable to remote code execution vulnerability, allowing a malicious client to upload a shared library to a writable share, and then cause the server to load and execute it.
</code>

- [betab0t/cve-2017-7494](https://github.com/betab0t/cve-2017-7494)
- [opsxcq/exploit-CVE-2017-7494](https://github.com/opsxcq/exploit-CVE-2017-7494)
- [brianwrf/SambaHunter](https://github.com/brianwrf/SambaHunter)
- [joxeankoret/CVE-2017-7494](https://github.com/joxeankoret/CVE-2017-7494)
- [Zer0d0y/Samba-CVE-2017-7494](https://github.com/Zer0d0y/Samba-CVE-2017-7494)

### CVE-2017-7504 (2017-05-19)

<code>HTTPServerILServlet.java in JMS over HTTP Invocation Layer of the JbossMQ implementation, which is enabled by default in Red Hat Jboss Application Server &lt;= Jboss 4.X does not restrict the classes for which it performs deserialization, which allows remote attackers to execute arbitrary code via crafted serialized data.
</code>

- [wudidwo/CVE-2017-7504-poc](https://github.com/wudidwo/CVE-2017-7504-poc)

### CVE-2017-7525 (2018-02-06)

<code>A deserialization flaw was discovered in the jackson-databind, versions before 2.6.7.1, 2.7.9.1 and 2.8.9, which could allow an unauthenticated user to perform code execution by sending the maliciously crafted input to the readValue method of the ObjectMapper.
</code>

- [SecureSkyTechnology/study-struts2-s2-054_055-jackson-cve-2017-7525_cve-2017-15095](https://github.com/SecureSkyTechnology/study-struts2-s2-054_055-jackson-cve-2017-7525_cve-2017-15095)
- [Nazicc/S2-055](https://github.com/Nazicc/S2-055)
- [Dannners/jackson-deserialization-2017-7525](https://github.com/Dannners/jackson-deserialization-2017-7525)
- [Ingenuity-Fainting-Goats/CVE-2017-7525-Jackson-Deserialization-Lab](https://github.com/Ingenuity-Fainting-Goats/CVE-2017-7525-Jackson-Deserialization-Lab)

### CVE-2017-7529 (2017-07-13)

<code>Nginx versions since 0.5.6 up to and including 1.13.2 are vulnerable to integer overflow vulnerability in nginx range filter module resulting into leak of potentially sensitive information triggered by specially crafted request.
</code>

- [liusec/CVE-2017-7529](https://github.com/liusec/CVE-2017-7529)
- [coolman6942o/-Exploit-CVE-2017-7529](https://github.com/coolman6942o/-Exploit-CVE-2017-7529)
- [SirEagIe/CVE-2017-7529](https://github.com/SirEagIe/CVE-2017-7529)
- [Fenil2511/CVE-2017-7529-POC](https://github.com/Fenil2511/CVE-2017-7529-POC)

### CVE-2017-7912 (2019-04-08)

<code>Hanwha Techwin SRN-4000, SRN-4000 firmware versions prior to SRN4000_v2.16_170401, A specially crafted http request and response could allow an attacker to gain access to the device management page with admin privileges without proper authentication.
</code>

- [homjxi0e/CVE-2017-7912_Sneak](https://github.com/homjxi0e/CVE-2017-7912_Sneak)

### CVE-2017-7921 (2017-05-06)

<code>An Improper Authentication issue was discovered in Hikvision DS-2CD2xx2F-I Series V5.2.0 build 140721 to V5.4.0 build 160530, DS-2CD2xx0F-I Series V5.2.0 build 140721 to V5.4.0 Build 160401, DS-2CD2xx2FWD Series V5.3.1 build 150410 to V5.4.4 Build 161125, DS-2CD4x2xFWD Series V5.2.0 build 140721 to V5.4.0 Build 160414, DS-2CD4xx5 Series V5.2.0 build 140721 to V5.4.0 Build 160421, DS-2DFx Series V5.2.0 build 140805 to V5.4.5 Build 160928, and DS-2CD63xx Series V5.0.9 build 140305 to V5.3.5 Build 160106 devices. The improper authentication vulnerability occurs when an application does not adequately or correctly authenticate users. This may allow a malicious user to escalate his or her privileges on the system and gain access to sensitive information.
</code>

- [JrDw0/CVE-2017-7921-EXP](https://github.com/JrDw0/CVE-2017-7921-EXP)
- [krypton612/hikivision](https://github.com/krypton612/hikivision)
- [K3ysTr0K3R/CVE-2017-7921-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2017-7921-EXPLOIT)
- [fracergu/CVE-2017-7921](https://github.com/fracergu/CVE-2017-7921)
- [AnonkiGroup/AnonHik](https://github.com/AnonkiGroup/AnonHik)
- [b3pwn3d/CVE-2017-7921](https://github.com/b3pwn3d/CVE-2017-7921)
- [yousouf-Tasfin/cve-2017-7921-Mass-Exploit](https://github.com/yousouf-Tasfin/cve-2017-7921-Mass-Exploit)
- [kooroshsanaei/HikVision-CVE-2017-7921](https://github.com/kooroshsanaei/HikVision-CVE-2017-7921)
- [aengussong/hikvision_probe](https://github.com/aengussong/hikvision_probe)

### CVE-2017-7998 (2018-01-08)

<code>Multiple cross-site scripting (XSS) vulnerabilities in Gespage before 7.4.9 allow remote attackers to inject arbitrary web script or HTML via the (1) printer name when adding a printer in the admin panel or (2) username parameter to webapp/users/user_reg.jsp.
</code>

- [homjxi0e/CVE-2017-7998](https://github.com/homjxi0e/CVE-2017-7998)

### CVE-2017-8046 (2018-01-04)

<code>Malicious PATCH requests submitted to servers using Spring Data REST versions prior to 2.6.9 (Ingalls SR9), versions prior to 3.0.1 (Kay SR1) and Spring Boot versions prior to 1.5.9, 2.0 M6 can use specially crafted JSON data to run arbitrary Java code.
</code>

- [Soontao/CVE-2017-8046-DEMO](https://github.com/Soontao/CVE-2017-8046-DEMO)
- [sj/spring-data-rest-CVE-2017-8046](https://github.com/sj/spring-data-rest-CVE-2017-8046)

### CVE-2017-8056 (2017-04-22)

<code>WatchGuard Fireware v11.12.1 and earlier mishandles requests referring to an XML External Entity (XXE), in the XML-RPC agent. This causes the Firebox wgagent process to crash. This process crash ends all authenticated sessions to the Firebox, including management connections, and prevents new authenticated sessions until the process has recovered. The Firebox may also experience an overall degradation in performance while the wgagent process recovers. An attacker could continuously send XML-RPC requests that contain references to external entities to perform a limited Denial of Service (DoS) attack against an affected Firebox.
</code>

- [itzexploit/CVE-2017-8056](https://github.com/itzexploit/CVE-2017-8056)

### CVE-2017-8225 (2017-04-25)

<code>On Wireless IP Camera (P2P) WIFICAM devices, access to .ini files (containing credentials) is not correctly checked. An attacker can bypass authentication by providing an empty loginuse parameter and an empty loginpas parameter in the URI.
</code>

- [K3ysTr0K3R/CVE-2017-8225-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2017-8225-EXPLOIT)

### CVE-2017-8295 (2017-05-04)

<code>WordPress through 4.7.4 relies on the Host HTTP header for a password-reset e-mail message, which makes it easier for remote attackers to reset arbitrary passwords by making a crafted wp-login.php?action=lostpassword request and then arranging for this message to bounce or be resent, leading to transmission of the reset key to a mailbox on an attacker-controlled SMTP server. This is related to problematic use of the SERVER_NAME variable in wp-includes/pluggable.php in conjunction with the PHP mail function. Exploitation is not achievable in all cases because it requires at least one of the following: (1) the attacker can prevent the victim from receiving any e-mail messages for an extended period of time (such as 5 days), (2) the victim's e-mail system sends an autoresponse containing the original message, or (3) the victim manually composes a reply containing the original message.
</code>

- [cyberheartmi9/CVE-2017-8295](https://github.com/cyberheartmi9/CVE-2017-8295)

### CVE-2017-8464 (2017-06-15)

<code>Windows Shell in Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, 1703, and Windows Server 2016 allows local users or remote attackers to execute arbitrary code via a crafted .LNK file, which is not properly handled during icon display in Windows Explorer or any other application that parses the icon of the shortcut. aka &quot;LNK Remote Code Execution Vulnerability.&quot;
</code>

- [Elm0D/CVE-2017-8464](https://github.com/Elm0D/CVE-2017-8464)
- [3gstudent/CVE-2017-8464-EXP](https://github.com/3gstudent/CVE-2017-8464-EXP)
- [doudouhala/CVE-2017-8464-exp-generator](https://github.com/doudouhala/CVE-2017-8464-exp-generator)
- [X-Vector/usbhijacking](https://github.com/X-Vector/usbhijacking)
- [tuankiethkt020/Phat-hien-CVE-2017-8464](https://github.com/tuankiethkt020/Phat-hien-CVE-2017-8464)
- [TieuLong21Prosper/Detect-CVE-2017-8464](https://github.com/TieuLong21Prosper/Detect-CVE-2017-8464)

### CVE-2017-8570 (2017-07-11)

<code>Microsoft Office allows a remote code execution vulnerability due to the way that it handles objects in memory, aka &quot;Microsoft Office Remote Code Execution Vulnerability&quot;. This CVE ID is unique from CVE-2017-0243.
</code>

- [temesgeny/ppsx-file-generator](https://github.com/temesgeny/ppsx-file-generator)

### CVE-2017-8625 (2017-08-08)

<code>Internet Explorer in Windows 10 Gold, 1511, 1607, 1703, and Windows Server 2016 allows an attacker to bypass Device Guard User Mode Code Integrity (UMCI) policies due to Internet Explorer failing to validate UMCI policies, aka &quot;Internet Explorer Security Feature Bypass Vulnerability&quot;.
</code>

- [homjxi0e/CVE-2017-8625_Bypass_UMCI](https://github.com/homjxi0e/CVE-2017-8625_Bypass_UMCI)

### CVE-2017-8641 (2017-08-08)

<code>Microsoft browsers in Microsoft Windows 7 SP1, Windows Server 2008 R2 SP1, Windows 8.1 and Windows RT 8.1, Windows Server 2012 and R2, Windows 10 Gold, 1511, 1607, 1703, and Windows Server 2016 allow an attacker to execute arbitrary code in the context of the current user due to the way that Microsoft browser JavaScript engines render when handling objects in memory, aka &quot;Scripting Engine Memory Corruption Vulnerability&quot;. This CVE ID is unique from CVE-2017-8634, CVE-2017-8635, CVE-2017-8636, CVE-2017-8638, CVE-2017-8639, CVE-2017-8640, CVE-2017-8645, CVE-2017-8646, CVE-2017-8647, CVE-2017-8655, CVE-2017-8656, CVE-2017-8657, CVE-2017-8670, CVE-2017-8671, CVE-2017-8672, and CVE-2017-8674.
</code>

- [homjxi0e/CVE-2017-8641_chakra_Js_GlobalObject](https://github.com/homjxi0e/CVE-2017-8641_chakra_Js_GlobalObject)

### CVE-2017-8759 (2017-09-13)

<code>Microsoft .NET Framework 2.0, 3.5, 3.5.1, 4.5.2, 4.6, 4.6.1, 4.6.2 and 4.7 allow an attacker to execute code remotely via a malicious document or application, aka &quot;.NET Framework Remote Code Execution Vulnerability.&quot;
</code>

- [Voulnet/CVE-2017-8759-Exploit-sample](https://github.com/Voulnet/CVE-2017-8759-Exploit-sample)
- [nccgroup/CVE-2017-8759](https://github.com/nccgroup/CVE-2017-8759)
- [vysecurity/CVE-2017-8759](https://github.com/vysecurity/CVE-2017-8759)
- [BasuCert/CVE-2017-8759](https://github.com/BasuCert/CVE-2017-8759)
- [tahisaad6/CVE-2017-8759-Exploit-sample2](https://github.com/tahisaad6/CVE-2017-8759-Exploit-sample2)
- [homjxi0e/CVE-2017-8759_-SOAP_WSDL](https://github.com/homjxi0e/CVE-2017-8759_-SOAP_WSDL)
- [bhdresh/CVE-2017-8759](https://github.com/bhdresh/CVE-2017-8759)
- [JonasUliana/CVE-2017-8759](https://github.com/JonasUliana/CVE-2017-8759)
- [sythass/CVE-2017-8759](https://github.com/sythass/CVE-2017-8759)
- [ashr/CVE-2017-8759-exploits](https://github.com/ashr/CVE-2017-8759-exploits)
- [l0n3rs/CVE-2017-8759](https://github.com/l0n3rs/CVE-2017-8759)

### CVE-2017-8869 (2017-07-27)

<code>Buffer overflow in MediaCoder 0.8.48.5888 allows remote attackers to execute arbitrary code via a crafted .m3u file.
</code>

- [tankist0x01/CVE-2017-8869](https://github.com/tankist0x01/CVE-2017-8869)

### CVE-2017-8890 (2017-05-10)

<code>The inet_csk_clone_lock function in net/ipv4/inet_connection_sock.c in the Linux kernel through 4.10.15 allows attackers to cause a denial of service (double free) or possibly have unspecified other impact by leveraging use of the accept system call.
</code>

- [beraphin/CVE-2017-8890](https://github.com/beraphin/CVE-2017-8890)

### CVE-2017-8917 (2017-05-17)

<code>SQL injection vulnerability in Joomla! 3.7.x before 3.7.1 allows attackers to execute arbitrary SQL commands via unspecified vectors.
</code>

- [stefanlucas/Exploit-Joomla](https://github.com/stefanlucas/Exploit-Joomla)
- [BaptisteContreras/CVE-2017-8917-Joomla](https://github.com/BaptisteContreras/CVE-2017-8917-Joomla)
- [gloliveira1701/Joomblah](https://github.com/gloliveira1701/Joomblah)

### CVE-2017-9248 (2017-07-03)

<code>Telerik.Web.UI.dll in Progress Telerik UI for ASP.NET AJAX before R2 2017 SP1 and Sitefinity before 10.0.6412.0 does not properly protect Telerik.Web.UI.DialogParametersEncryptionKey or the MachineKey, which makes it easier for remote attackers to defeat cryptographic protection mechanisms, leading to a MachineKey leak, arbitrary file uploads or downloads, XSS, or ASP.NET ViewState compromise.
</code>

- [blacklanternsecurity/dp_cryptomg](https://github.com/blacklanternsecurity/dp_cryptomg)
- [cehamod/UI_CVE-2017-9248](https://github.com/cehamod/UI_CVE-2017-9248)
- [hlong12042/CVE-2017-9248](https://github.com/hlong12042/CVE-2017-9248)

### CVE-2017-9417 (2017-06-03)

<code>Broadcom BCM43xx Wi-Fi chips allow remote attackers to execute arbitrary code via unspecified vectors, aka the &quot;Broadpwn&quot; issue.
</code>

- [mailinneberg/Broadpwn](https://github.com/mailinneberg/Broadpwn)

### CVE-2017-9430 (2017-06-05)

<code>Stack-based buffer overflow in dnstracer through 1.9 allows attackers to cause a denial of service (application crash) or possibly have unspecified other impact via a command line with a long name argument that is mishandled in a strcpy call for argv[0]. An example threat model is a web application that launches dnstracer with an untrusted name string.
</code>

- [j0lama/Dnstracer-1.9-Fix](https://github.com/j0lama/Dnstracer-1.9-Fix)

### CVE-2017-9476 (2017-07-31)

<code>The Comcast firmware on Cisco DPC3939 (firmware version dpc3939-P20-18-v303r20421733-160420a-CMCST); Cisco DPC3939 (firmware version dpc3939-P20-18-v303r20421746-170221a-CMCST); and Arris TG1682G (eMTA&amp;DOCSIS version 10.0.132.SIP.PC20.CT, software version TG1682_2.2p7s2_PROD_sey) devices makes it easy for remote attackers to determine the hidden SSID and passphrase for a Home Security Wi-Fi network.
</code>

- [wiire-a/CVE-2017-9476](https://github.com/wiire-a/CVE-2017-9476)

### CVE-2017-9757 (2017-06-19)

<code>IPFire 2.19 has a Remote Command Injection vulnerability in ids.cgi via the OINKCODE parameter, which is mishandled by a shell. This can be exploited directly by authenticated users, or through CSRF.
</code>

- [peterleiva/CVE-2017-9757](https://github.com/peterleiva/CVE-2017-9757)

### CVE-2017-9779 (2017-09-07)

<code>OCaml compiler allows attackers to have unspecified impact via unknown vectors, a similar issue to CVE-2017-9772 &quot;but with much less impact.&quot;
</code>

- [homjxi0e/CVE-2017-9779](https://github.com/homjxi0e/CVE-2017-9779)

### CVE-2017-9791 (2017-07-10)

<code>The Struts 1 plugin in Apache Struts 2.1.x and 2.3.x might allow remote code execution via a malicious field value passed in a raw message to the ActionMessage.
</code>

- [IanSmith123/s2-048](https://github.com/IanSmith123/s2-048)
- [dragoneeg/Struts2-048](https://github.com/dragoneeg/Struts2-048)
- [xfer0/CVE-2017-9791](https://github.com/xfer0/CVE-2017-9791)

### CVE-2017-9798 (2017-09-18)

<code>Apache httpd allows remote attackers to read secret data from process memory if the Limit directive can be set in a user's .htaccess file, or if httpd.conf has certain misconfigurations, aka Optionsbleed. This affects the Apache HTTP Server through 2.2.34 and 2.4.x through 2.4.27. The attacker sends an unauthenticated OPTIONS HTTP request when attempting to read secret data. This is a use-after-free issue and thus secret data is not always sent, and the specific data depends on many factors including configuration. Exploitation with .htaccess can be blocked with a patch to the ap_limit_section function in server/core.c.
</code>

- [nitrado/CVE-2017-9798](https://github.com/nitrado/CVE-2017-9798)
- [pabloec20/optionsbleed](https://github.com/pabloec20/optionsbleed)
- [l0n3rs/CVE-2017-9798](https://github.com/l0n3rs/CVE-2017-9798)
- [brokensound77/OptionsBleed-POC-Scanner](https://github.com/brokensound77/OptionsBleed-POC-Scanner)

### CVE-2017-9805 (2017-09-15)

<code>The REST Plugin in Apache Struts 2.1.1 through 2.3.x before 2.3.34 and 2.5.x before 2.5.13 uses an XStreamHandler with an instance of XStream for deserialization without any type filtering, which can lead to Remote Code Execution when deserializing XML payloads.
</code>

- [luc10/struts-rce-cve-2017-9805](https://github.com/luc10/struts-rce-cve-2017-9805)
- [hahwul/struts2-rce-cve-2017-9805-ruby](https://github.com/hahwul/struts2-rce-cve-2017-9805-ruby)
- [mazen160/struts-pwn_CVE-2017-9805](https://github.com/mazen160/struts-pwn_CVE-2017-9805)
- [Lone-Ranger/apache-struts-pwn_CVE-2017-9805](https://github.com/Lone-Ranger/apache-struts-pwn_CVE-2017-9805)
- [0x00-0x00/-CVE-2017-9805](https://github.com/0x00-0x00/-CVE-2017-9805)
- [BeyondCy/S2-052](https://github.com/BeyondCy/S2-052)
- [chrisjd20/cve-2017-9805.py](https://github.com/chrisjd20/cve-2017-9805.py)

### CVE-2017-9841 (2017-06-27)

<code>Util/PHP/eval-stdin.php in PHPUnit before 4.8.28 and 5.x before 5.6.3 allows remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a &quot;&lt;?php &quot; substring, as demonstrated by an attack on a site with an exposed /vendor folder, i.e., external access to the /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php URI.
</code>

- [dream434/CVE-2017-9841-](https://github.com/dream434/CVE-2017-9841-)
- [MrG3P5/CVE-2017-9841](https://github.com/MrG3P5/CVE-2017-9841)
- [Chocapikk/CVE-2017-9841](https://github.com/Chocapikk/CVE-2017-9841)

### CVE-2017-9934 (2017-07-17)

<code>Missing CSRF token checks and improper input validation in Joomla! CMS 1.7.3 through 3.7.2 lead to an XSS vulnerability.
</code>

- [xyringe/CVE-2017-9934](https://github.com/xyringe/CVE-2017-9934)

### CVE-2017-9947 (2017-10-23)

<code>A vulnerability has been identified in Siemens APOGEE PXC and TALON TC BACnet Automation Controllers in all versions &lt;V3.5. A directory traversal vulnerability could allow a remote attacker with network access to the integrated web server (80/tcp and 443/tcp) to obtain information on the structure of the file system of the affected devices.
</code>

- [RoseSecurity/APOLOGEE](https://github.com/RoseSecurity/APOLOGEE)

### CVE-2017-9999
- [homjxi0e/CVE-2017-9999_bypassing_General_Firefox](https://github.com/homjxi0e/CVE-2017-9999_bypassing_General_Firefox)

### CVE-2017-10235 (2017-08-08)

<code>Vulnerability in the Oracle VM VirtualBox component of Oracle Virtualization (subcomponent: Core). The supported version that is affected is Prior to 5.1.24. Easily exploitable vulnerability allows high privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle VM VirtualBox as well as unauthorized update, insert or delete access to some of Oracle VM VirtualBox accessible data. CVSS 3.0 Base Score 6.7 (Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:L/A:H).
</code>

- [fundacion-sadosky/vbox_cve_2017_10235](https://github.com/fundacion-sadosky/vbox_cve_2017_10235)

### CVE-2017-10271 (2017-10-19)

<code>Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Security). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.1.0 and 12.2.1.2.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 7.5 (Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H).
</code>

- [1337g/CVE-2017-10271](https://github.com/1337g/CVE-2017-10271)
- [s3xy/CVE-2017-10271](https://github.com/s3xy/CVE-2017-10271)
- [ZH3FENG/PoCs-Weblogic_2017_10271](https://github.com/ZH3FENG/PoCs-Weblogic_2017_10271)
- [c0mmand3rOpSec/CVE-2017-10271](https://github.com/c0mmand3rOpSec/CVE-2017-10271)
- [Luffin/CVE-2017-10271](https://github.com/Luffin/CVE-2017-10271)
- [XHSecurity/Oracle-WebLogic-CVE-2017-10271](https://github.com/XHSecurity/Oracle-WebLogic-CVE-2017-10271)

### CVE-2017-10617 (2017-10-13)

<code>The ifmap service that comes bundled with Contrail has an XML External Entity (XXE) vulnerability that may allow an attacker to retrieve sensitive system files. Affected releases are Juniper Networks Contrail 2.2 prior to 2.21.4; 3.0 prior to 3.0.3.4; 3.1 prior to 3.1.4.0; 3.2 prior to 3.2.5.0. CVE-2017-10616 and CVE-2017-10617 can be chained together and have a combined CVSSv3 score of 5.8 (AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N).
</code>

- [gteissier/CVE-2017-10617](https://github.com/gteissier/CVE-2017-10617)

### CVE-2017-10661 (2017-08-19)

<code>Race condition in fs/timerfd.c in the Linux kernel before 4.10.15 allows local users to gain privileges or cause a denial of service (list corruption or use-after-free) via simultaneous file-descriptor operations that leverage improper might_cancel queueing.
</code>

- [GeneBlue/CVE-2017-10661_POC](https://github.com/GeneBlue/CVE-2017-10661_POC)

### CVE-2017-11165 (2017-07-12)

<code>dataTaker DT80 dEX 1.50.012 allows remote attackers to obtain sensitive credential and configuration information via a direct request for the /services/getFile.cmd?userfile=config.xml URI.
</code>

- [xymbiot-solution/CVE-2017-11165](https://github.com/xymbiot-solution/CVE-2017-11165)

### CVE-2017-11176 (2017-07-11)

<code>The mq_notify function in the Linux kernel through 4.11.9 does not set the sock pointer to NULL upon entry into the retry logic. During a user-space close of a Netlink socket, it allows attackers to cause a denial of service (use-after-free) or possibly have unspecified other impact.
</code>

- [Yanoro/CVE-2017-11176](https://github.com/Yanoro/CVE-2017-11176)

### CVE-2017-11317 (2017-08-23)

<code>Telerik.Web.UI in Progress Telerik UI for ASP.NET AJAX before R1 2017 and R2 before R2 2017 SP2 uses weak RadAsyncUpload encryption, which allows remote attackers to perform arbitrary file uploads or execute arbitrary code.
</code>

- [hlong12042/CVE-2017-11317-and-CVE-2017-11357-in-Telerik](https://github.com/hlong12042/CVE-2017-11317-and-CVE-2017-11357-in-Telerik)

### CVE-2017-11611 (2017-09-08)

<code>Wolf CMS 0.8.3.1 allows Cross-Site Scripting (XSS) attacks. The vulnerability exists due to insufficient sanitization of the file name in a &quot;create-file-popup&quot; action, and the directory name in a &quot;create-directory-popup&quot; action, in the HTTP POST method to the &quot;/plugin/file_manager/&quot; script (aka an /admin/plugin/file_manager/browse// URI).
</code>

- [faizzaidi/Wolfcms-v0.8.3.1-xss-POC-by-Provensec-llc](https://github.com/faizzaidi/Wolfcms-v0.8.3.1-xss-POC-by-Provensec-llc)

### CVE-2017-11882 (2017-11-15)

<code>Microsoft Office 2007 Service Pack 3, Microsoft Office 2010 Service Pack 2, Microsoft Office 2013 Service Pack 1, and Microsoft Office 2016 allow an attacker to run arbitrary code in the context of the current user by failing to properly handle objects in memory, aka &quot;Microsoft Office Memory Corruption Vulnerability&quot;. This CVE ID is unique from CVE-2017-11884.
</code>

- [zhouat/cve-2017-11882](https://github.com/zhouat/cve-2017-11882)
- [embedi/CVE-2017-11882](https://github.com/embedi/CVE-2017-11882)
- [Ridter/CVE-2017-11882](https://github.com/Ridter/CVE-2017-11882)
- [BlackMathIT/2017-11882_Generator](https://github.com/BlackMathIT/2017-11882_Generator)
- [rip1s/CVE-2017-11882](https://github.com/rip1s/CVE-2017-11882)
- [0x09AL/CVE-2017-11882-metasploit](https://github.com/0x09AL/CVE-2017-11882-metasploit)
- [HZachev/ABC](https://github.com/HZachev/ABC)
- [starnightcyber/CVE-2017-11882](https://github.com/starnightcyber/CVE-2017-11882)
- [Grey-Li/CVE-2017-11882](https://github.com/Grey-Li/CVE-2017-11882)
- [legendsec/CVE-2017-11882-for-Kali](https://github.com/legendsec/CVE-2017-11882-for-Kali)
- [CSC-pentest/cve-2017-11882](https://github.com/CSC-pentest/cve-2017-11882)
- [Shadowshusky/CVE-2017-11882-](https://github.com/Shadowshusky/CVE-2017-11882-)
- [n18dcat053-luuvannga/DetectPacket-CVE-2017-11882](https://github.com/n18dcat053-luuvannga/DetectPacket-CVE-2017-11882)
- [nhuynhuy/cve-2017-11882](https://github.com/nhuynhuy/cve-2017-11882)
- [jadeapar/Dragonfish-s-Malware-Cyber-Analysis](https://github.com/jadeapar/Dragonfish-s-Malware-Cyber-Analysis)
- [yaseenibnakhtar/001-Malware-Analysis-CVE-2017-11882](https://github.com/yaseenibnakhtar/001-Malware-Analysis-CVE-2017-11882)

### CVE-2017-12149 (2017-10-04)

<code>In Jboss Application Server as shipped with Red Hat Enterprise Application Platform 5.2, it was found that the doFilter method in the ReadOnlyAccessFilter of the HTTP Invoker does not restrict classes for which it performs deserialization and thus allowing an attacker to execute arbitrary code via crafted serialized data.
</code>

- [sevck/CVE-2017-12149](https://github.com/sevck/CVE-2017-12149)
- [yunxu1/jboss-_CVE-2017-12149](https://github.com/yunxu1/jboss-_CVE-2017-12149)
- [1337g/CVE-2017-12149](https://github.com/1337g/CVE-2017-12149)
- [MrE-Fog/jboss-_CVE-2017-12149](https://github.com/MrE-Fog/jboss-_CVE-2017-12149)
- [JesseClarkND/CVE-2017-12149](https://github.com/JesseClarkND/CVE-2017-12149)
- [zesnd/cve-2017-12149](https://github.com/zesnd/cve-2017-12149)

### CVE-2017-12426 (2017-08-14)

<code>GitLab Community Edition (CE) and Enterprise Edition (EE) before 8.17.8, 9.0.x before 9.0.13, 9.1.x before 9.1.10, 9.2.x before 9.2.10, 9.3.x before 9.3.10, and 9.4.x before 9.4.4 might allow remote attackers to execute arbitrary code via a crafted SSH URL in a project import.
</code>

- [sm-paul-schuette/CVE-2017-12426](https://github.com/sm-paul-schuette/CVE-2017-12426)

### CVE-2017-12611 (2017-09-20)

<code>In Apache Struts 2.0.0 through 2.3.33 and 2.5 through 2.5.10.1, using an unintentional expression in a Freemarker tag instead of string literals can lead to a RCE attack.
</code>

- [brianwrf/S2-053-CVE-2017-12611](https://github.com/brianwrf/S2-053-CVE-2017-12611)

### CVE-2017-12615 (2017-09-19)

<code>When running Apache Tomcat 7.0.0 to 7.0.79 on Windows with HTTP PUTs enabled (e.g. via setting the readonly initialisation parameter of the Default to false) it was possible to upload a JSP file to the server via a specially crafted request. This JSP could then be requested and any code it contained would be executed by the server.
</code>

- [breaktoprotect/CVE-2017-12615](https://github.com/breaktoprotect/CVE-2017-12615)
- [mefulton/cve-2017-12615](https://github.com/mefulton/cve-2017-12615)
- [zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717](https://github.com/zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717)
- [wsg00d/cve-2017-12615](https://github.com/wsg00d/cve-2017-12615)
- [BeyondCy/CVE-2017-12615](https://github.com/BeyondCy/CVE-2017-12615)
- [1337g/CVE-2017-12615](https://github.com/1337g/CVE-2017-12615)
- [xiaokp7/Tomcat_PUT_GUI_EXP](https://github.com/xiaokp7/Tomcat_PUT_GUI_EXP)
- [lizhianyuguangming/TomcatScanPro](https://github.com/lizhianyuguangming/TomcatScanPro)
- [wudidwo/CVE-2017-12615-poc](https://github.com/wudidwo/CVE-2017-12615-poc)

### CVE-2017-12617 (2017-10-03)

<code>When running Apache Tomcat versions 9.0.0.M1 to 9.0.0, 8.5.0 to 8.5.22, 8.0.0.RC1 to 8.0.46 and 7.0.0 to 7.0.81 with HTTP PUTs enabled (e.g. via setting the readonly initialisation parameter of the Default servlet to false) it was possible to upload a JSP file to the server via a specially crafted request. This JSP could then be requested and any code it contained would be executed by the server.
</code>

- [cyberheartmi9/CVE-2017-12617](https://github.com/cyberheartmi9/CVE-2017-12617)
- [K3ysTr0K3R/CVE-2017-12617-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2017-12617-EXPLOIT)
- [scirusvulgaris/CVE-2017-12617](https://github.com/scirusvulgaris/CVE-2017-12617)
- [yZ1337/CVE-2017-12617](https://github.com/yZ1337/CVE-2017-12617)
- [DevaDJ/CVE-2017-12617](https://github.com/DevaDJ/CVE-2017-12617)

### CVE-2017-12635 (2017-11-14)

<code>Due to differences in the Erlang-based JSON parser and JavaScript-based JSON parser, it is possible in Apache CouchDB before 1.7.0 and 2.x before 2.1.1 to submit _users documents with duplicate keys for 'roles' used for access control within the database, including the special case '_admin' role, that denotes administrative users. In combination with CVE-2017-12636 (Remote Code Execution), this can be used to give non-admin users access to arbitrary shell commands on the server as the database system user. The JSON parser differences result in behaviour that if two 'roles' keys are available in the JSON, the second one will be used for authorising the document write, but the first 'roles' key is used for subsequent authorization for the newly created user. By design, users can not assign themselves roles. The vulnerability allows non-admin users to give themselves admin privileges.
</code>

- [Weisant/CVE-2017-12635-POC](https://github.com/Weisant/CVE-2017-12635-POC)

### CVE-2017-12792 (2017-10-02)

<code>Multiple cross-site request forgery (CSRF) vulnerabilities in NexusPHP 1.5 allow remote attackers to hijack the authentication of administrators for requests that conduct cross-site scripting (XSS) attacks via the (1) linkname, (2) url, or (3) title parameter in an add action to linksmanage.php.
</code>

- [ZZS2017/cve-2017-12792](https://github.com/ZZS2017/cve-2017-12792)

### CVE-2017-12852 (2017-08-15)

<code>The numpy.pad function in Numpy 1.13.1 and older versions is missing input validation. An empty list or ndarray will stick into an infinite loop, which can allow attackers to cause a DoS attack.
</code>

- [BT123/numpy-1.13.1](https://github.com/BT123/numpy-1.13.1)

### CVE-2017-12943 (2017-08-18)

<code>D-Link DIR-600 Rev Bx devices with v2.x firmware allow remote attackers to read passwords via a model/__show_info.php?REQUIRE_FILE= absolute path traversal attack, as demonstrated by discovering the admin password.
</code>

- [aymankhalfatni/D-Link](https://github.com/aymankhalfatni/D-Link)

### CVE-2017-13089 (2017-10-27)

<code>The http.c:skip_short_body() function is called in some circumstances, such as when processing redirects. When the response is sent chunked in wget before 1.19.2, the chunk parser uses strtol() to read each chunk's length, but doesn't check that the chunk length is a non-negative number. The code then tries to skip the chunk in pieces of 512 bytes by using the MIN() macro, but ends up passing the negative chunk length to connect.c:fd_read(). As fd_read() takes an int argument, the high 32 bits of the chunk length are discarded, leaving fd_read() with a completely attacker controlled length argument.
</code>

- [r1b/CVE-2017-13089](https://github.com/r1b/CVE-2017-13089)
- [mzeyong/CVE-2017-13089](https://github.com/mzeyong/CVE-2017-13089)

### CVE-2017-13156 (2017-12-06)

<code>An elevation of privilege vulnerability in the Android system (art). Product: Android. Versions: 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID A-64211847.
</code>

- [xyzAsian/Janus-CVE-2017-13156](https://github.com/xyzAsian/Janus-CVE-2017-13156)
- [nahid0x1/Janus-Vulnerability-CVE-2017-13156-Exploit](https://github.com/nahid0x1/Janus-Vulnerability-CVE-2017-13156-Exploit)

### CVE-2017-13286 (2018-04-04)

<code>In writeToParcel and readFromParcel of OutputConfiguration.java, there is a permission bypass due to mismatched serialization. This could lead to a local escalation of privilege where the user can start an activity with system privileges, with no additional execution privileges needed. User interaction is not needed for exploitation. Product: Android. Versions: 8.0, 8.1. Android ID: A-69683251.
</code>

- [UmVfX1BvaW50/CVE-2017-13286](https://github.com/UmVfX1BvaW50/CVE-2017-13286)

### CVE-2017-13672 (2017-09-01)

<code>QEMU (aka Quick Emulator), when built with the VGA display emulator support, allows local guest OS privileged users to cause a denial of service (out-of-bounds read and QEMU process crash) via vectors involving display update.
</code>

- [DavidBuchanan314/CVE-2017-13672](https://github.com/DavidBuchanan314/CVE-2017-13672)

### CVE-2017-13868 (2017-12-25)

<code>An issue was discovered in certain Apple products. iOS before 11.2 is affected. macOS before 10.13.2 is affected. tvOS before 11.2 is affected. watchOS before 4.2 is affected. The issue involves the &quot;Kernel&quot; component. It allows attackers to bypass intended memory-read restrictions via a crafted app.
</code>

- [bazad/ctl_ctloutput-leak](https://github.com/bazad/ctl_ctloutput-leak)

### CVE-2017-13872 (2017-11-29)

<code>An issue was discovered in certain Apple products. macOS High Sierra before Security Update 2017-001 is affected. The issue involves the &quot;Directory Utility&quot; component. It allows attackers to obtain administrator access without a password via certain interactions involving entry of the root user name.
</code>

- [giovannidispoto/CVE-2017-13872-Patch](https://github.com/giovannidispoto/CVE-2017-13872-Patch)

### CVE-2017-14105 (2017-09-01)

<code>HiveManager Classic through 8.1r1 allows arbitrary JSP code execution by modifying a backup archive before a restore, because the restore feature does not validate pathnames within the archive. An authenticated, local attacker - even restricted as a tenant - can add a jsp at HiveManager/tomcat/webapps/hm/domains/$yourtenant/maps (it will be exposed at the web interface).
</code>

- [theguly/CVE-2017-14105](https://github.com/theguly/CVE-2017-14105)

### CVE-2017-14262 (2017-09-11)

<code>On Samsung NVR devices, remote attackers can read the MD5 password hash of the 'admin' account via certain szUserName JSON data to cgi-bin/main-cgi, and login to the device with that hash in the szUserPasswd parameter.
</code>

- [zzz66686/CVE-2017-14262](https://github.com/zzz66686/CVE-2017-14262)

### CVE-2017-14263 (2017-09-11)

<code>Honeywell NVR devices allow remote attackers to create a user account in the admin group by leveraging access to a guest account to obtain a session ID, and then sending that session ID in a userManager.addUser request to the /RPC2 URI. The attacker can login to the device with that new user account to fully control the device.
</code>

- [zzz66686/CVE-2017-14263](https://github.com/zzz66686/CVE-2017-14263)

### CVE-2017-14491 (2017-10-02)

<code>Heap-based buffer overflow in dnsmasq before 2.78 allows remote attackers to cause a denial of service (crash) or execute arbitrary code via a crafted DNS response.
</code>

- [skyformat99/dnsmasq-2.4.1-fix-CVE-2017-14491](https://github.com/skyformat99/dnsmasq-2.4.1-fix-CVE-2017-14491)

### CVE-2017-14980 (2017-10-09)

<code>Buffer overflow in Sync Breeze Enterprise 10.0.28 allows remote attackers to have unspecified impact via a long username parameter to /login.
</code>

- [xn0kkx/Exploit_Sync_Breeze_v10.0.28_CVE-2017-14980](https://github.com/xn0kkx/Exploit_Sync_Breeze_v10.0.28_CVE-2017-14980)

### CVE-2017-15099 (2017-11-22)

<code>INSERT ... ON CONFLICT DO UPDATE commands in PostgreSQL 10.x before 10.1, 9.6.x before 9.6.6, and 9.5.x before 9.5.10 disclose table contents that the invoker lacks privilege to read. These exploits affect only tables where the attacker lacks full read access but has both INSERT and UPDATE privileges. Exploits bypass row level security policies and lack of SELECT privilege.
</code>

- [ToontjeM/CVE-2017-15099](https://github.com/ToontjeM/CVE-2017-15099)

### CVE-2017-15361 (2017-10-16)

<code>The Infineon RSA library 1.02.013 in Infineon Trusted Platform Module (TPM) firmware, such as versions before 0000000000000422 - 4.34, before 000000000000062b - 6.43, and before 0000000000008521 - 133.33, mishandles RSA key generation, which makes it easier for attackers to defeat various cryptographic protection mechanisms via targeted attacks, aka ROCA. Examples of affected technologies include BitLocker with TPM 1.2, YubiKey 4 (before 4.3.5) PGP key generation, and the Cached User Data encryption feature in Chrome OS.
</code>

- [lva/Infineon-CVE-2017-15361](https://github.com/lva/Infineon-CVE-2017-15361)
- [titanous/rocacheck](https://github.com/titanous/rocacheck)
- [nsacyber/Detect-CVE-2017-15361-TPM](https://github.com/nsacyber/Detect-CVE-2017-15361-TPM)
- [0xxon/zeek-plugin-roca](https://github.com/0xxon/zeek-plugin-roca)
- [0xxon/roca](https://github.com/0xxon/roca)
- [Elbarbons/ROCA-attack-on-vulnerability-CVE-2017-15361](https://github.com/Elbarbons/ROCA-attack-on-vulnerability-CVE-2017-15361)

### CVE-2017-15394 (2018-02-07)

<code>Insufficient Policy Enforcement in Extensions in Google Chrome prior to 62.0.3202.62 allowed a remote attacker to perform domain spoofing in permission dialogs via IDN homographs in a crafted Chrome Extension.
</code>

- [sudosammy/CVE-2017-15394](https://github.com/sudosammy/CVE-2017-15394)

### CVE-2017-15428 (2019-01-09)

<code>Insufficient data validation in V8 builtins string generator could lead to out of bounds read and write access in V8 in Google Chrome prior to 62.0.3202.94 and allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page.
</code>

- [w1ldb1t/CVE-2017-15428](https://github.com/w1ldb1t/CVE-2017-15428)

### CVE-2017-15708 (2017-12-11)

<code>In Apache Synapse, by default no authentication is required for Java Remote Method Invocation (RMI). So Apache Synapse 3.0.1 or all previous releases (3.0.0, 2.1.0, 2.0.0, 1.2, 1.1.2, 1.1.1) allows remote code execution attacks that can be performed by injecting specially crafted serialized objects. And the presence of Apache Commons Collections 3.2.1 (commons-collections-3.2.1.jar) or previous versions in Synapse distribution makes this exploitable. To mitigate the issue, we need to limit RMI access to trusted users only. Further upgrading to 3.0.1 version will eliminate the risk of having said Commons Collection version. In Synapse 3.0.1, Commons Collection has been updated to 3.2.2 version.
</code>

- [HuSoul/CVE-2017-15708](https://github.com/HuSoul/CVE-2017-15708)

### CVE-2017-15944 (2017-12-11)

<code>Palo Alto Networks PAN-OS before 6.1.19, 7.0.x before 7.0.19, 7.1.x before 7.1.14, and 8.0.x before 8.0.6 allows remote attackers to execute arbitrary code via vectors involving the management interface.
</code>

- [xxnbyy/CVE-2017-15944-POC](https://github.com/xxnbyy/CVE-2017-15944-POC)

### CVE-2017-16524 (2017-11-06)

<code>Web Viewer 1.0.0.193 on Samsung SRN-1670D devices suffers from an Unrestricted file upload vulnerability: 'network_ssl_upload.php' allows remote authenticated attackers to upload and execute arbitrary PHP code via a filename with a .php extension, which is then accessed via a direct request to the file in the upload/ directory. To authenticate for this attack, one can obtain web-interface credentials in cleartext by leveraging the existing Local File Read Vulnerability referenced as CVE-2015-8279, which allows remote attackers to read the web-interface credentials via a request for the cslog_export.php?path=/root/php_modules/lighttpd/sbin/userpw URI.
</code>

- [realistic-security/CVE-2017-16524](https://github.com/realistic-security/CVE-2017-16524)

### CVE-2017-16567 (2017-11-09)

<code>Persistent Cross-Site Scripting (XSS) vulnerability in Logitech Media Server 7.9.0, affecting the &quot;Favorites&quot; feature. This vulnerability allows remote attackers to inject and permanently store malicious JavaScript payloads, which are executed when users access the affected functionality. Exploitation of this vulnerability can lead to Session Hijacking and Credential Theft, Execution of unauthorized actions on behalf of users, and Exfiltration of sensitive data. This vulnerability presents a potential risk for widespread exploitation in connected IoT environments.
</code>

- [dewankpant/CVE-2017-16567](https://github.com/dewankpant/CVE-2017-16567)

### CVE-2017-16651 (2017-11-09)

<code>Roundcube Webmail before 1.1.10, 1.2.x before 1.2.7, and 1.3.x before 1.3.3 allows unauthorized access to arbitrary files on the host's filesystem, including configuration files, as exploited in the wild in November 2017. The attacker must be able to authenticate at the target system with a valid username/password as the attack requires an active session. The issue is related to file-based attachment plugins and _task=settings&amp;_action=upload-display&amp;_from=timezone requests.
</code>

- [sephiroth950911/CVE-2017-16651-Exploit](https://github.com/sephiroth950911/CVE-2017-16651-Exploit)

### CVE-2017-16720 (2018-01-05)

<code>A Path Traversal issue was discovered in WebAccess versions 8.3.2 and earlier. An attacker has access to files within the directory structure of the target device.
</code>

- [CN016/WebAccess-CVE-2017-16720-](https://github.com/CN016/WebAccess-CVE-2017-16720-)

### CVE-2017-16806 (2017-11-13)

<code>The Process function in RemoteTaskServer/WebServer/HttpServer.cs in Ulterius before 1.9.5.0 allows HTTP server directory traversal.
</code>

- [rickoooooo/ulteriusExploit](https://github.com/rickoooooo/ulteriusExploit)

### CVE-2017-16894 (2017-11-20)

<code>In Laravel framework through 5.5.21, remote attackers can obtain sensitive information (such as externally usable passwords) via a direct request for the /.env URI. NOTE: this CVE is only about Laravel framework's writeNewEnvironmentFileWith function in src/Illuminate/Foundation/Console/KeyGenerateCommand.php, which uses file_put_contents without restricting the .env permissions. The .env filename is not used exclusively by Laravel framework.
</code>

- [ibnurusdianto/CVE-2017-16894](https://github.com/ibnurusdianto/CVE-2017-16894)

### CVE-2017-16994 (2017-11-27)

<code>The walk_hugetlb_range function in mm/pagewalk.c in the Linux kernel before 4.14.2 mishandles holes in hugetlb ranges, which allows local users to obtain sensitive information from uninitialized kernel memory via crafted use of the mincore() system call.
</code>

- [jedai47/CVE-2017-16994](https://github.com/jedai47/CVE-2017-16994)

### CVE-2017-16995 (2017-12-22)

<code>The check_alu_op function in kernel/bpf/verifier.c in the Linux kernel through 4.4 allows local users to cause a denial of service (memory corruption) or possibly have unspecified other impact by leveraging incorrect sign extension.
</code>

- [mareks1007/cve-2017-16995](https://github.com/mareks1007/cve-2017-16995)
- [ZhiQiAnSecFork/cve-2017-16995](https://github.com/ZhiQiAnSecFork/cve-2017-16995)

### CVE-2017-17099 (2017-12-03)

<code>There exists an unauthenticated SEH based Buffer Overflow vulnerability in the HTTP server of Flexense SyncBreeze Enterprise v10.1.16. When sending a GET request with an excessive length, it is possible for a malicious user to overwrite the SEH record and execute a payload that would run under the Windows SYSTEM account.
</code>

- [wetw0rk/Exploit-Development](https://github.com/wetw0rk/Exploit-Development)

### CVE-2017-17215 (2018-03-20)

<code>Huawei HG532 with some customized versions has a remote code execution vulnerability. An authenticated attacker could send malicious packets to port 37215 to launch attacks. Successful exploit could lead to the remote execution of arbitrary code.
</code>

- [1337g/CVE-2017-17215](https://github.com/1337g/CVE-2017-17215)

### CVE-2017-17309 (2018-06-14)

<code>Huawei HG255s-10 V100R001C163B025SP02 has a path traversal vulnerability due to insufficient validation of the received HTTP requests, a remote attacker may access the local files on the device without authentication.
</code>

- [exploit-labs/huawei_hg255s_exploit](https://github.com/exploit-labs/huawei_hg255s_exploit)

### CVE-2017-17562 (2017-12-12)

<code>Embedthis GoAhead before 3.6.5 allows remote code execution if CGI is enabled and a CGI program is dynamically linked. This is a result of initializing the environment of forked CGI scripts using untrusted HTTP request parameters in the cgiHandler function in cgi.c. When combined with the glibc dynamic linker, this behaviour can be abused for remote code execution using special parameter names such as LD_PRELOAD. An attacker can POST their shared object payload in the body of the request, and reference it using /proc/self/fd/0.
</code>

- [1337g/CVE-2017-17562](https://github.com/1337g/CVE-2017-17562)
- [nu11pointer/goahead-rce-exploit](https://github.com/nu11pointer/goahead-rce-exploit)

### CVE-2017-17917 (2017-12-29)

<code>SQL injection vulnerability in the 'where' method in Ruby on Rails 5.1.4 and earlier allows remote attackers to execute arbitrary SQL commands via the 'id' parameter. NOTE: The vendor disputes this issue because the documentation states that this method is not intended for use with untrusted input
</code>

- [matiasarenhard/rails-cve-2017-17917](https://github.com/matiasarenhard/rails-cve-2017-17917)

### CVE-2017-18019 (2018-01-04)

<code>In K7 Total Security before 15.1.0.305, user-controlled input to the K7Sentry device is not sufficiently sanitized: the user-controlled input can be used to compare an arbitrary memory address with a fixed value, which in turn can be used to read the contents of arbitrary memory. Similarly, the product crashes upon a \\.\K7Sentry DeviceIoControl call with an invalid kernel pointer.
</code>

- [SpiralBL0CK/CVE-2017-18019](https://github.com/SpiralBL0CK/CVE-2017-18019)

### CVE-2017-18345 (2018-08-26)

<code>The Joomanager component through 2.0.0 for Joomla! has an arbitrary file download issue, resulting in exposing the credentials of the database via an index.php?option=com_joomanager&amp;controller=details&amp;task=download&amp;path=configuration.php request.
</code>

- [Luth1er/CVE-2017-18345-COM_JOOMANAGER-ARBITRARY-FILE-DOWNLOAD](https://github.com/Luth1er/CVE-2017-18345-COM_JOOMANAGER-ARBITRARY-FILE-DOWNLOAD)

### CVE-2017-18486 (2019-08-09)

<code>Jitbit Helpdesk before 9.0.3 allows remote attackers to escalate privileges because of mishandling of the User/AutoLogin userHash parameter. By inspecting the token value provided in a password reset link, a user can leverage a weak PRNG to recover the shared secret used by the server for remote authentication. The shared secret can be used to escalate privileges by forging new tokens for any user. These tokens can be used to automatically log in as the affected user.
</code>

- [Kc57/JitBit_Helpdesk_Auth_Bypass](https://github.com/Kc57/JitBit_Helpdesk_Auth_Bypass)

### CVE-2017-20165 (2023-01-09)

<code>Es wurde eine Schwachstelle in debug-js debug bis 3.0.x entdeckt. Sie wurde als problematisch eingestuft. Es betrifft die Funktion useColors der Datei src/node.js. Durch Manipulieren des Arguments str mit unbekannten Daten kann eine inefficient regular expression complexity-Schwachstelle ausgenutzt werden. Ein Aktualisieren auf die Version 3.1.0 vermag dieses Problem zu lösen. Der Patch wird als c38a0166c266a679c8de012d4eaccec3f944e685 bezeichnet. Als bestmögliche Massnahme wird das Einspielen eines Upgrades empfohlen.
</code>

- [fastify/send](https://github.com/fastify/send)

### CVE-2017-98505
- [mike-williams/Struts2Vuln](https://github.com/mike-williams/Struts2Vuln)

### CVE-2017-1000028 (2017-07-13)

<code>Oracle, GlassFish Server Open Source Edition 4.1 is vulnerable to both authenticated and unauthenticated Directory Traversal vulnerability, that can be exploited by issuing a specially crafted HTTP GET request.
</code>

- [NeonNOXX/CVE-2017-1000028](https://github.com/NeonNOXX/CVE-2017-1000028)

### CVE-2017-1000117 (2017-10-04)

<code>A malicious third-party can give a crafted &quot;ssh://...&quot; URL to an unsuspecting victim, and an attempt to visit the URL can result in any program that exists on the victim's machine being executed. Such a URL could be placed in the .gitmodules file of a malicious project, and an unsuspecting victim could be tricked into running &quot;git clone --recurse-submodules&quot; to trigger the vulnerability.
</code>

- [timwr/CVE-2017-1000117](https://github.com/timwr/CVE-2017-1000117)
- [Manouchehri/CVE-2017-1000117](https://github.com/Manouchehri/CVE-2017-1000117)
- [thelastbyte/CVE-2017-1000117](https://github.com/thelastbyte/CVE-2017-1000117)
- [alilangtest/CVE-2017-1000117](https://github.com/alilangtest/CVE-2017-1000117)
- [VulApps/CVE-2017-1000117](https://github.com/VulApps/CVE-2017-1000117)
- [greymd/CVE-2017-1000117](https://github.com/greymd/CVE-2017-1000117)
- [shogo82148/Fix-CVE-2017-1000117](https://github.com/shogo82148/Fix-CVE-2017-1000117)
- [sasairc/CVE-2017-1000117_wasawasa](https://github.com/sasairc/CVE-2017-1000117_wasawasa)
- [Shadow5523/CVE-2017-1000117-test](https://github.com/Shadow5523/CVE-2017-1000117-test)
- [ieee0824/CVE-2017-1000117](https://github.com/ieee0824/CVE-2017-1000117)
- [rootclay/CVE-2017-1000117](https://github.com/rootclay/CVE-2017-1000117)
- [ieee0824/CVE-2017-1000117-sl](https://github.com/ieee0824/CVE-2017-1000117-sl)
- [takehaya/CVE-2017-1000117](https://github.com/takehaya/CVE-2017-1000117)
- [ikmski/CVE-2017-1000117](https://github.com/ikmski/CVE-2017-1000117)
- [nkoneko/CVE-2017-1000117](https://github.com/nkoneko/CVE-2017-1000117)
- [chenzhuo0618/test](https://github.com/chenzhuo0618/test)
- [siling2017/CVE-2017-1000117](https://github.com/siling2017/CVE-2017-1000117)
- [Q2h1Cg/CVE-2017-1000117](https://github.com/Q2h1Cg/CVE-2017-1000117)

### CVE-2017-1000250 (2017-09-12)

<code>All versions of the SDP server in BlueZ 5.46 and earlier are vulnerable to an information disclosure vulnerability which allows remote attackers to obtain sensitive information from the bluetoothd process memory. This vulnerability lies in the processing of SDP search attribute requests.
</code>

- [olav-st/CVE-2017-1000250-PoC](https://github.com/olav-st/CVE-2017-1000250-PoC)

### CVE-2017-1000251 (2017-09-12)

<code>The native Bluetooth stack in the Linux Kernel (BlueZ), starting at the Linux kernel version 2.6.32 and up to and including 4.13.1, are vulnerable to a stack overflow vulnerability in the processing of L2CAP configuration responses resulting in Remote code execution in kernel space.
</code>

- [hayzamjs/Blueborne-CVE-2017-1000251](https://github.com/hayzamjs/Blueborne-CVE-2017-1000251)
- [tlatkdgus1/blueborne-CVE-2017-1000251](https://github.com/tlatkdgus1/blueborne-CVE-2017-1000251)
- [own2pwn/blueborne-CVE-2017-1000251-POC](https://github.com/own2pwn/blueborne-CVE-2017-1000251-POC)
- [sgxgsx/blueborne-CVE-2017-1000251](https://github.com/sgxgsx/blueborne-CVE-2017-1000251)

### CVE-2017-1000405 (2017-11-30)

<code>The Linux Kernel versions 2.6.38 through 4.14 have a problematic use of pmd_mkdirty() in the touch_pmd() function inside the THP implementation. touch_pmd() can be reached by get_user_pages(). In such case, the pmd will become dirty. This scenario breaks the new can_follow_write_pmd()'s logic - pmd can become dirty without going through a COW cycle. This bug is not as severe as the original &quot;Dirty cow&quot; because an ext4 file (or any other regular file) cannot be mapped using THP. Nevertheless, it does allow us to overwrite read-only huge pages. For example, the zero huge page and sealed shmem files can be overwritten (since their mapping can be populated using THP). Note that after the first write page-fault to the zero page, it will be replaced with a new fresh (and zeroed) thp.
</code>

- [bindecy/HugeDirtyCowPOC](https://github.com/bindecy/HugeDirtyCowPOC)

### CVE-2017-1000486 (2018-01-03)

<code>Primetek Primefaces 5.x is vulnerable to a weak encryption flaw resulting in remote code execution
</code>

- [pimps/CVE-2017-1000486](https://github.com/pimps/CVE-2017-1000486)
- [oppsec/pwnfaces](https://github.com/oppsec/pwnfaces)
- [LongWayHomie/CVE-2017-1000486](https://github.com/LongWayHomie/CVE-2017-1000486)
- [jam620/primefaces](https://github.com/jam620/primefaces)


## 2016
### CVE-2016-0040 (2016-02-10)

<code>The kernel in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, and Windows 7 SP1 allows local users to gain privileges via a crafted application, aka &quot;Windows Elevation of Privilege Vulnerability.&quot;
</code>

- [Rootkitsmm-zz/cve-2016-0040](https://github.com/Rootkitsmm-zz/cve-2016-0040)

### CVE-2016-0049 (2016-02-10)

<code>Kerberos in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, and Windows 10 Gold and 1511 does not properly validate password changes, which allows remote attackers to bypass authentication by deploying a crafted Key Distribution Center (KDC) and then performing a sign-in action, aka &quot;Windows Kerberos Security Feature Bypass.&quot;
</code>

- [JackOfMostTrades/bluebox](https://github.com/JackOfMostTrades/bluebox)

### CVE-2016-0051 (2016-02-10)

<code>The WebDAV client in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, and Windows 10 Gold and 1511 allows local users to gain privileges via a crafted application, aka &quot;WebDAV Elevation of Privilege Vulnerability.&quot;
</code>

- [koczkatamas/CVE-2016-0051](https://github.com/koczkatamas/CVE-2016-0051)
- [hexx0r/CVE-2016-0051](https://github.com/hexx0r/CVE-2016-0051)
- [ganrann/CVE-2016-0051](https://github.com/ganrann/CVE-2016-0051)

### CVE-2016-0189 (2016-05-11)

<code>The Microsoft (1) JScript 5.8 and (2) VBScript 5.7 and 5.8 engines, as used in Internet Explorer 9 through 11 and other products, allow remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted web site, aka &quot;Scripting Engine Memory Corruption Vulnerability,&quot; a different vulnerability than CVE-2016-0187.
</code>

- [theori-io/cve-2016-0189](https://github.com/theori-io/cve-2016-0189)
- [deamwork/MS16-051-poc](https://github.com/deamwork/MS16-051-poc)

### CVE-2016-0701 (2016-02-15)

<code>The DH_check_pub_key function in crypto/dh/dh_check.c in OpenSSL 1.0.2 before 1.0.2f does not ensure that prime numbers are appropriate for Diffie-Hellman (DH) key exchange, which makes it easier for remote attackers to discover a private DH exponent by making multiple handshakes with a peer that chose an inappropriate number, as demonstrated by a number in an X9.42 file.
</code>

- [luanjampa/cve-2016-0701](https://github.com/luanjampa/cve-2016-0701)

### CVE-2016-0728 (2016-02-08)

<code>The join_session_keyring function in security/keys/process_keys.c in the Linux kernel before 4.4.1 mishandles object references in a certain error case, which allows local users to gain privileges or cause a denial of service (integer overflow and use-after-free) via crafted keyctl commands.
</code>

- [idl3r/cve-2016-0728](https://github.com/idl3r/cve-2016-0728)
- [kennetham/cve_2016_0728](https://github.com/kennetham/cve_2016_0728)
- [nardholio/cve-2016-0728](https://github.com/nardholio/cve-2016-0728)
- [googleweb/CVE-2016-0728](https://github.com/googleweb/CVE-2016-0728)
- [neuschaefer/cve-2016-0728-testbed](https://github.com/neuschaefer/cve-2016-0728-testbed)
- [bittorrent3389/cve-2016-0728](https://github.com/bittorrent3389/cve-2016-0728)

### CVE-2016-0752 (2016-02-16)

<code>Directory traversal vulnerability in Action View in Ruby on Rails before 3.2.22.1, 4.0.x and 4.1.x before 4.1.14.1, 4.2.x before 4.2.5.1, and 5.x before 5.0.0.beta1.1 allows remote attackers to read arbitrary files by leveraging an application's unrestricted use of the render method and providing a .. (dot dot) in a pathname.
</code>

- [forced-request/rails-rce-cve-2016-0752](https://github.com/forced-request/rails-rce-cve-2016-0752)
- [dachidahu/CVE-2016-0752](https://github.com/dachidahu/CVE-2016-0752)

### CVE-2016-0801 (2016-02-07)

<code>The Broadcom Wi-Fi driver in the kernel in Android 4.x before 4.4.4, 5.x before 5.1.1 LMY49G, and 6.x before 2016-02-01 allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via crafted wireless control message packets, aka internal bug 25662029.
</code>

- [abdsec/CVE-2016-0801](https://github.com/abdsec/CVE-2016-0801)
- [zsaurus/CVE-2016-0801-test](https://github.com/zsaurus/CVE-2016-0801-test)

### CVE-2016-0805 (2016-02-07)

<code>The performance event manager for Qualcomm ARM processors in Android 4.x before 4.4.4, 5.x before 5.1.1 LMY49G, and 6.x before 2016-02-01 allows attackers to gain privileges via a crafted application, aka internal bug 25773204.
</code>

- [hulovebin/cve-2016-0805](https://github.com/hulovebin/cve-2016-0805)

### CVE-2016-0846 (2016-04-18)

<code>libs/binder/IMemory.cpp in the IMemory Native Interface in Android 4.x before 4.4.4, 5.0.x before 5.0.2, 5.1.x before 5.1.1, and 6.x before 2016-04-01 does not properly consider the heap size, which allows attackers to gain privileges via a crafted application, as demonstrated by obtaining Signature or SignatureOrSystem access, aka internal bug 26877992.
</code>

- [secmob/CVE-2016-0846](https://github.com/secmob/CVE-2016-0846)
- [b0b0505/CVE-2016-0846-PoC](https://github.com/b0b0505/CVE-2016-0846-PoC)

### CVE-2016-1240 (2016-10-03)

<code>The Tomcat init script in the tomcat7 package before 7.0.56-3+deb8u4 and tomcat8 package before 8.0.14-1+deb8u3 on Debian jessie and the tomcat6 and libtomcat6-java packages before 6.0.35-1ubuntu3.8 on Ubuntu 12.04 LTS, the tomcat7 and libtomcat7-java packages before 7.0.52-1ubuntu0.7 on Ubuntu 14.04 LTS, and tomcat8 and libtomcat8-java packages before 8.0.32-1ubuntu1.2 on Ubuntu 16.04 LTS allows local users with access to the tomcat account to gain root privileges via a symlink attack on the Catalina log file, as demonstrated by /var/log/tomcat7/catalina.out.
</code>

- [Naramsim/Offensive](https://github.com/Naramsim/Offensive)

### CVE-2016-1287 (2016-02-11)

<code>Buffer overflow in the IKEv1 and IKEv2 implementations in Cisco ASA Software before 8.4(7.30), 8.7 before 8.7(1.18), 9.0 before 9.0(4.38), 9.1 before 9.1(7), 9.2 before 9.2(4.5), 9.3 before 9.3(3.7), 9.4 before 9.4(2.4), and 9.5 before 9.5(2.2) on ASA 5500 devices, ASA 5500-X devices, ASA Services Module for Cisco Catalyst 6500 and Cisco 7600 devices, ASA 1000V devices, Adaptive Security Virtual Appliance (aka ASAv), Firepower 9300 ASA Security Module, and ISA 3000 devices allows remote attackers to execute arbitrary code or cause a denial of service (device reload) via crafted UDP packets, aka Bug IDs CSCux29978 and CSCux42019.
</code>

- [jgajek/killasa](https://github.com/jgajek/killasa)
- [NetSPI/asa_tools](https://github.com/NetSPI/asa_tools)

### CVE-2016-1494 (2016-01-13)

<code>The verify function in the RSA package for Python (Python-RSA) before 3.3 allows attackers to spoof signatures with a small public exponent via crafted signature padding, aka a BERserk attack.
</code>

- [matthiasbe/secuimag3a](https://github.com/matthiasbe/secuimag3a)

### CVE-2016-1734 (2016-03-24)

<code>AppleUSBNetworking in Apple iOS before 9.3 and OS X before 10.11.4 allows physically proximate attackers to execute arbitrary code in a privileged context or cause a denial of service (memory corruption) via a crafted USB device.
</code>

- [Manouchehri/CVE-2016-1734](https://github.com/Manouchehri/CVE-2016-1734)

### CVE-2016-1757 (2016-03-24)

<code>Race condition in the kernel in Apple iOS before 9.3 and OS X before 10.11.4 allows attackers to execute arbitrary code in a privileged context via a crafted app.
</code>

- [gdbinit/mach_race](https://github.com/gdbinit/mach_race)

### CVE-2016-1764 (2016-03-24)

<code>The Content Security Policy (CSP) implementation in Messages in Apple OS X before 10.11.4 allows remote attackers to obtain sensitive information via a javascript: URL.
</code>

- [moloch--/cve-2016-1764](https://github.com/moloch--/cve-2016-1764)

### CVE-2016-1825 (2016-05-20)

<code>IOHIDFamily in Apple OS X before 10.11.5 allows attackers to execute arbitrary code in a privileged context or cause a denial of service (memory corruption) via a crafted app.
</code>

- [bazad/physmem](https://github.com/bazad/physmem)

### CVE-2016-1828 (2016-05-20)

<code>The kernel in Apple iOS before 9.3.2, OS X before 10.11.5, tvOS before 9.2.1, and watchOS before 2.2.1 allows attackers to execute arbitrary code in a privileged context or cause a denial of service (memory corruption) via a crafted app, a different vulnerability than CVE-2016-1827, CVE-2016-1829, and CVE-2016-1830.
</code>

- [bazad/rootsh](https://github.com/bazad/rootsh)

### CVE-2016-2098 (2016-04-07)

<code>Action Pack in Ruby on Rails before 3.2.22.2, 4.x before 4.1.14.2, and 4.2.x before 4.2.5.2 allows remote attackers to execute arbitrary Ruby code by leveraging an application's unrestricted use of the render method.
</code>

- [hderms/dh-CVE_2016_2098](https://github.com/hderms/dh-CVE_2016_2098)
- [CyberDefenseInstitute/PoC_CVE-2016-2098_Rails42](https://github.com/CyberDefenseInstitute/PoC_CVE-2016-2098_Rails42)

### CVE-2016-2107 (2016-05-05)

<code>The AES-NI implementation in OpenSSL before 1.0.1t and 1.0.2 before 1.0.2h does not consider memory allocation during a certain padding check, which allows remote attackers to obtain sensitive cleartext information via a padding-oracle attack against an AES CBC session. NOTE: this vulnerability exists because of an incorrect fix for CVE-2013-0169.
</code>

- [FiloSottile/CVE-2016-2107](https://github.com/FiloSottile/CVE-2016-2107)
- [tmiklas/docker-cve-2016-2107](https://github.com/tmiklas/docker-cve-2016-2107)

### CVE-2016-2118 (2016-04-12)

<code>The MS-SAMR and MS-LSAD protocol implementations in Samba 3.x and 4.x before 4.2.11, 4.3.x before 4.3.8, and 4.4.x before 4.4.2 mishandle DCERPC connections, which allows man-in-the-middle attackers to perform protocol-downgrade attacks and impersonate users by modifying the client-server data stream, aka &quot;BADLOCK.&quot;
</code>

- [nickanderson/cfengine-CVE-2016-2118](https://github.com/nickanderson/cfengine-CVE-2016-2118)

### CVE-2016-2402 (2017-01-30)

<code>OkHttp before 2.7.4 and 3.x before 3.1.2 allows man-in-the-middle attackers to bypass certificate pinning by sending a certificate chain with a certificate from a non-pinned trusted CA and the pinned certificate.
</code>

- [ikoz/cert-pinning-flaw-poc](https://github.com/ikoz/cert-pinning-flaw-poc)
- [ikoz/certPinningVulnerableOkHttp](https://github.com/ikoz/certPinningVulnerableOkHttp)

### CVE-2016-2431 (2016-05-09)

<code>The Qualcomm TrustZone component in Android before 2016-05-01 on Nexus 5, Nexus 6, Nexus 7 (2013), and Android One devices allows attackers to gain privileges via a crafted application, aka internal bug 24968809.
</code>

- [laginimaineb/cve-2016-2431](https://github.com/laginimaineb/cve-2016-2431)
- [laginimaineb/ExtractKeyMaster](https://github.com/laginimaineb/ExtractKeyMaster)

### CVE-2016-2434 (2016-05-09)

<code>The NVIDIA video driver in Android before 2016-05-01 on Nexus 9 devices allows attackers to gain privileges via a crafted application, aka internal bug 27251090.
</code>

- [jianqiangzhao/CVE-2016-2434](https://github.com/jianqiangzhao/CVE-2016-2434)

### CVE-2016-2468 (2016-06-13)

<code>The Qualcomm GPU driver in Android before 2016-06-01 on Nexus 5, 5X, 6, 6P, and 7 devices allows attackers to gain privileges via a crafted application, aka internal bug 27475454.
</code>

- [gitcollect/CVE-2016-2468](https://github.com/gitcollect/CVE-2016-2468)

### CVE-2016-2776 (2016-09-28)

<code>buffer.c in named in ISC BIND 9 before 9.9.9-P3, 9.10.x before 9.10.4-P3, and 9.11.x before 9.11.0rc3 does not properly construct responses, which allows remote attackers to cause a denial of service (assertion failure and daemon exit) via a crafted query.
</code>

- [KosukeShimofuji/CVE-2016-2776](https://github.com/KosukeShimofuji/CVE-2016-2776)
- [infobyte/CVE-2016-2776](https://github.com/infobyte/CVE-2016-2776)

### CVE-2016-3141 (2016-03-31)

<code>Use-after-free vulnerability in wddx.c in the WDDX extension in PHP before 5.5.33 and 5.6.x before 5.6.19 allows remote attackers to cause a denial of service (memory corruption and application crash) or possibly have unspecified other impact by triggering a wddx_deserialize call on XML data containing a crafted var element.
</code>

- [peternguyen93/CVE-2016-3141](https://github.com/peternguyen93/CVE-2016-3141)

### CVE-2016-3308 (2016-08-09)

<code>The kernel-mode drivers in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607 allow local users to gain privileges via a crafted application, aka &quot;Win32k Elevation of Privilege Vulnerability,&quot; a different vulnerability than CVE-2016-3309, CVE-2016-3310, and CVE-2016-3311.
</code>

- [jackhuyh/CVE-2016-3308](https://github.com/jackhuyh/CVE-2016-3308)

### CVE-2016-3714 (2016-05-05)

<code>The (1) EPHEMERAL, (2) HTTPS, (3) MVG, (4) MSL, (5) TEXT, (6) SHOW, (7) WIN, and (8) PLT coders in ImageMagick before 6.9.3-10 and 7.x before 7.0.1-1 allow remote attackers to execute arbitrary code via shell metacharacters in a crafted image, aka &quot;ImageTragick.&quot;
</code>

- [jackdpeterson/imagick_secure_puppet](https://github.com/jackdpeterson/imagick_secure_puppet)
- [tommiionfire/CVE-2016-3714](https://github.com/tommiionfire/CVE-2016-3714)
- [chusiang/CVE-2016-3714.ansible.role](https://github.com/chusiang/CVE-2016-3714.ansible.role)
- [jpeanut/ImageTragick-CVE-2016-3714-RShell](https://github.com/jpeanut/ImageTragick-CVE-2016-3714-RShell)
- [Hood3dRob1n/CVE-2016-3714](https://github.com/Hood3dRob1n/CVE-2016-3714)

### CVE-2016-3959 (2016-05-23)

<code>The Verify function in crypto/dsa/dsa.go in Go before 1.5.4 and 1.6.x before 1.6.1 does not properly check parameters passed to the big integer library, which might allow remote attackers to cause a denial of service (infinite loop) via a crafted public key to a program that uses HTTPS client certificates or SSH server libraries.
</code>

- [alexmullins/dsa](https://github.com/alexmullins/dsa)

### CVE-2016-3962 (2016-07-03)

<code>Stack-based buffer overflow in the NTP time-server interface on Meinberg IMS-LANTIME M3000, IMS-LANTIME M1000, IMS-LANTIME M500, LANTIME M900, LANTIME M600, LANTIME M400, LANTIME M300, LANTIME M200, LANTIME M100, SyncFire 1100, and LCES devices with firmware before 6.20.004 allows remote attackers to obtain sensitive information, modify data, or cause a denial of service via a crafted parameter in a POST request.
</code>

- [securifera/CVE-2016-3962-Exploit](https://github.com/securifera/CVE-2016-3962-Exploit)

### CVE-2016-4010 (2017-01-23)

<code>Magento CE and EE before 2.0.6 allows remote attackers to conduct PHP objection injection attacks and execute arbitrary PHP code via crafted serialized shopping cart data.
</code>

- [brianwrf/Magento-CVE-2016-4010](https://github.com/brianwrf/Magento-CVE-2016-4010)

### CVE-2016-4438 (2016-07-04)

<code>The REST plugin in Apache Struts 2 2.3.19 through 2.3.28.1 allows remote attackers to execute arbitrary code via a crafted expression.
</code>

- [jason3e7/CVE-2016-4438](https://github.com/jason3e7/CVE-2016-4438)

### CVE-2016-4622 (2016-07-22)

<code>WebKit in Apple iOS before 9.3.3, Safari before 9.1.2, and tvOS before 9.2.2 allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted web site, a different vulnerability than CVE-2016-4589, CVE-2016-4623, and CVE-2016-4624.
</code>

- [saelo/jscpwn](https://github.com/saelo/jscpwn)

### CVE-2016-4631 (2016-07-22)

<code>ImageIO in Apple iOS before 9.3.3, OS X before 10.11.6, tvOS before 9.2.2, and watchOS before 2.2.2 allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted TIFF file.
</code>

- [hansnielsen/tiffdisabler](https://github.com/hansnielsen/tiffdisabler)

### CVE-2016-4845 (2016-09-24)

<code>Cross-site request forgery (CSRF) vulnerability on I-O DATA DEVICE HVL-A2.0, HVL-A3.0, HVL-A4.0, HVL-AT1.0S, HVL-AT2.0, HVL-AT3.0, HVL-AT4.0, HVL-AT2.0A, HVL-AT3.0A, and HVL-AT4.0A devices with firmware before 2.04 allows remote attackers to hijack the authentication of arbitrary users for requests that delete content.
</code>

- [kaito834/cve-2016-4845_csrf](https://github.com/kaito834/cve-2016-4845_csrf)

### CVE-2016-4861 (2017-02-16)

<code>The (1) order and (2) group methods in Zend_Db_Select in the Zend Framework before 1.12.20 might allow remote attackers to conduct SQL injection attacks by leveraging failure to remove comments from an SQL statement before validation.
</code>

- [KosukeShimofuji/CVE-2016-4861](https://github.com/KosukeShimofuji/CVE-2016-4861)

### CVE-2016-4971 (2016-06-30)

<code>GNU wget before 1.18 allows remote servers to write to arbitrary files by redirecting a request from HTTP to a crafted FTP resource.
</code>

- [gitcollect/CVE-2016-4971](https://github.com/gitcollect/CVE-2016-4971)

### CVE-2016-5195 (2016-11-10)

<code>Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka &quot;Dirty COW.&quot;
</code>

- [timwr/CVE-2016-5195](https://github.com/timwr/CVE-2016-5195)
- [sideeffect42/DirtyCOWTester](https://github.com/sideeffect42/DirtyCOWTester)
- [scumjr/dirtycow-vdso](https://github.com/scumjr/dirtycow-vdso)
- [gbonacini/CVE-2016-5195](https://github.com/gbonacini/CVE-2016-5195)
- [oleg-fiksel/ansible_CVE-2016-5195_check](https://github.com/oleg-fiksel/ansible_CVE-2016-5195_check)
- [firefart/dirtycow](https://github.com/firefart/dirtycow)
- [ndobson/inspec_CVE-2016-5195](https://github.com/ndobson/inspec_CVE-2016-5195)

### CVE-2016-5636 (2016-09-02)

<code>Integer overflow in the get_data function in zipimport.c in CPython (aka Python) before 2.7.12, 3.x before 3.4.5, and 3.5.x before 3.5.2 allows remote attackers to have unspecified impact via a negative data size value, which triggers a heap-based buffer overflow.
</code>

- [insuyun/CVE-2016-5636](https://github.com/insuyun/CVE-2016-5636)

### CVE-2016-5696 (2016-08-06)

<code>net/ipv4/tcp_input.c in the Linux kernel before 4.7 does not properly determine the rate of challenge ACK segments, which makes it easier for remote attackers to hijack TCP sessions via a blind in-window attack.
</code>

- [Gnoxter/mountain_goat](https://github.com/Gnoxter/mountain_goat)
- [violentshell/rover](https://github.com/violentshell/rover)
- [jduck/challack](https://github.com/jduck/challack)
- [bplinux/chackd](https://github.com/bplinux/chackd)
- [unkaktus/grill](https://github.com/unkaktus/grill)

### CVE-2016-5699 (2016-09-02)

<code>CRLF injection vulnerability in the HTTPConnection.putheader function in urllib2 and urllib in CPython (aka Python) before 2.7.10 and 3.x before 3.4.4 allows remote attackers to inject arbitrary HTTP headers via CRLF sequences in a URL.
</code>

- [bunseokbot/CVE-2016-5699-poc](https://github.com/bunseokbot/CVE-2016-5699-poc)
- [shajinzheng/cve-2016-5699-jinzheng-sha](https://github.com/shajinzheng/cve-2016-5699-jinzheng-sha)

### CVE-2016-5734 (2016-07-03)

<code>phpMyAdmin 4.0.x before 4.0.10.16, 4.4.x before 4.4.15.7, and 4.6.x before 4.6.3 does not properly choose delimiters to prevent use of the preg_replace e (aka eval) modifier, which might allow remote attackers to execute arbitrary PHP code via a crafted string, as demonstrated by the table search-and-replace implementation.
</code>

- [KosukeShimofuji/CVE-2016-5734](https://github.com/KosukeShimofuji/CVE-2016-5734)

### CVE-2016-6366 (2016-08-18)

<code>Buffer overflow in Cisco Adaptive Security Appliance (ASA) Software through 9.4.2.3 on ASA 5500, ASA 5500-X, ASA Services Module, ASA 1000V, ASAv, Firepower 9300 ASA Security Module, PIX, and FWSM devices allows remote authenticated users to execute arbitrary code via crafted IPv4 SNMP packets, aka Bug ID CSCva92151 or EXTRABACON.
</code>

- [RiskSense-Ops/CVE-2016-6366](https://github.com/RiskSense-Ops/CVE-2016-6366)

### CVE-2016-6515 (2016-08-07)

<code>The auth_password function in auth-passwd.c in sshd in OpenSSH before 7.3 does not limit password lengths for password authentication, which allows remote attackers to cause a denial of service (crypt CPU consumption) via a long string.
</code>

- [opsxcq/exploit-CVE-2016-6515](https://github.com/opsxcq/exploit-CVE-2016-6515)

### CVE-2016-6584
- [ViralSecurityGroup/KNOXout](https://github.com/ViralSecurityGroup/KNOXout)

### CVE-2016-6662 (2016-09-20)

<code>Oracle MySQL through 5.5.52, 5.6.x through 5.6.33, and 5.7.x through 5.7.15; MariaDB before 5.5.51, 10.0.x before 10.0.27, and 10.1.x before 10.1.17; and Percona Server before 5.5.51-38.1, 5.6.x before 5.6.32-78.0, and 5.7.x before 5.7.14-7 allow local users to create arbitrary configurations and bypass certain protection mechanisms by setting general_log_file to a my.cnf configuration. NOTE: this can be leveraged to execute arbitrary code with root privileges by setting malloc_lib. NOTE: the affected MySQL version information is from Oracle's October 2016 CPU. Oracle has not commented on third-party claims that the issue was silently patched in MySQL 5.5.52, 5.6.33, and 5.7.15.
</code>

- [konstantin-kelemen/mysqld_safe-CVE-2016-6662-patch](https://github.com/konstantin-kelemen/mysqld_safe-CVE-2016-6662-patch)
- [meersjo/ansible-mysql-cve-2016-6662](https://github.com/meersjo/ansible-mysql-cve-2016-6662)
- [KosukeShimofuji/CVE-2016-6662](https://github.com/KosukeShimofuji/CVE-2016-6662)
- [Ashrafdev/MySQL-Remote-Root-Code-Execution](https://github.com/Ashrafdev/MySQL-Remote-Root-Code-Execution)

### CVE-2016-6754 (2016-11-25)

<code>A remote code execution vulnerability in Webview in Android 5.0.x before 5.0.2, 5.1.x before 5.1.1, and 6.x before 2016-11-05 could enable a remote attacker to execute arbitrary code when the user is navigating to a website. This issue is rated as High due to the possibility of remote code execution in an unprivileged process. Android ID: A-31217937.
</code>

- [secmob/BadKernel](https://github.com/secmob/BadKernel)

### CVE-2016-7434 (2017-01-13)

<code>The read_mru_list function in NTP before 4.2.8p9 allows remote attackers to cause a denial of service (crash) via a crafted mrulist query.
</code>

- [opsxcq/exploit-CVE-2016-7434](https://github.com/opsxcq/exploit-CVE-2016-7434)
- [shekkbuilder/CVE-2016-7434](https://github.com/shekkbuilder/CVE-2016-7434)

### CVE-2016-8016 (2017-03-14)

<code>Information exposure in Intel Security VirusScan Enterprise Linux (VSEL) 2.0.3 (and earlier) allows authenticated remote attackers to obtain the existence of unauthorized files on the system via a URL parameter.
</code>

- [opsxcq/exploit-CVE-2016-8016-25](https://github.com/opsxcq/exploit-CVE-2016-8016-25)

### CVE-2016-8462 (2017-01-12)

<code>An information disclosure vulnerability in the bootloader could enable a local attacker to access data outside of its permission level. This issue is rated as High because it could be used to access sensitive data. Product: Android. Versions: N/A. Android ID: A-32510383.
</code>

- [CunningLogic/PixelDump_CVE-2016-8462](https://github.com/CunningLogic/PixelDump_CVE-2016-8462)

### CVE-2016-8610 (2017-11-13)

<code>A denial of service flaw was found in OpenSSL 0.9.8, 1.0.1, 1.0.2 through 1.0.2h, and 1.1.0 in the way the TLS/SSL protocol defined processing of ALERT packets during a connection handshake. A remote attacker could use this flaw to make a TLS/SSL server consume an excessive amount of CPU and fail to accept connections from other clients.
</code>

- [cujanovic/CVE-2016-8610-PoC](https://github.com/cujanovic/CVE-2016-8610-PoC)

### CVE-2016-8655 (2016-12-08)

<code>Race condition in net/packet/af_packet.c in the Linux kernel through 4.8.12 allows local users to gain privileges or cause a denial of service (use-after-free) by leveraging the CAP_NET_RAW capability to change a socket version, related to the packet_set_ring and packet_setsockopt functions.
</code>

- [scarvell/cve-2016-8655](https://github.com/scarvell/cve-2016-8655)
- [LakshmiDesai/CVE-2016-8655](https://github.com/LakshmiDesai/CVE-2016-8655)
- [KosukeShimofuji/CVE-2016-8655](https://github.com/KosukeShimofuji/CVE-2016-8655)
- [agkunkle/chocobo](https://github.com/agkunkle/chocobo)
- [martinmullins/CVE-2016-8655_Android](https://github.com/martinmullins/CVE-2016-8655_Android)

### CVE-2016-8858 (2016-12-09)

<code>The kex_input_kexinit function in kex.c in OpenSSH 6.x and 7.x through 7.3 allows remote attackers to cause a denial of service (memory consumption) by sending many duplicate KEXINIT requests.  NOTE: a third party reports that &quot;OpenSSH upstream does not consider this as a security issue.&quot;
</code>

- [dag-erling/kexkill](https://github.com/dag-erling/kexkill)

### CVE-2016-9192 (2016-12-14)

<code>A vulnerability in Cisco AnyConnect Secure Mobility Client for Windows could allow an authenticated, local attacker to install and execute an arbitrary executable file with privileges equivalent to the Microsoft Windows operating system SYSTEM account. More Information: CSCvb68043. Known Affected Releases: 4.3(2039) 4.3(748). Known Fixed Releases: 4.3(4019) 4.4(225).
</code>

- [serializingme/cve-2016-9192](https://github.com/serializingme/cve-2016-9192)

### CVE-2016-10033 (2016-12-30)

<code>The mailSend function in the isMail transport in PHPMailer before 5.2.18 might allow remote attackers to pass extra parameters to the mail command and consequently execute arbitrary code via a \&quot; (backslash double quote) in a crafted Sender property.
</code>

- [opsxcq/exploit-CVE-2016-10033](https://github.com/opsxcq/exploit-CVE-2016-10033)
- [Zenexer/safeshell](https://github.com/Zenexer/safeshell)


## 2015
### CVE-2015-0072 (2015-02-07)

<code>Cross-site scripting (XSS) vulnerability in Microsoft Internet Explorer 9 through 11 allows remote attackers to bypass the Same Origin Policy and inject arbitrary web script or HTML via vectors involving an IFRAME element that triggers a redirect, a second IFRAME element that does not trigger a redirect, and an eval of a WindowProxy object, aka &quot;Universal XSS (UXSS).&quot;
</code>

- [dbellavista/uxss-poc](https://github.com/dbellavista/uxss-poc)

### CVE-2015-0204 (2015-01-09)

<code>The ssl3_get_key_exchange function in s3_clnt.c in OpenSSL before 0.9.8zd, 1.0.0 before 1.0.0p, and 1.0.1 before 1.0.1k allows remote SSL servers to conduct RSA-to-EXPORT_RSA downgrade attacks and facilitate brute-force decryption by offering a weak ephemeral RSA key in a noncompliant role, related to the &quot;FREAK&quot; issue.  NOTE: the scope of this CVE is only client code based on OpenSSL, not EXPORT_RSA issues associated with servers or other TLS implementations.
</code>

- [felmoltor/FreakVulnChecker](https://github.com/felmoltor/FreakVulnChecker)
- [scottjpack/Freak-Scanner](https://github.com/scottjpack/Freak-Scanner)
- [AbhishekGhosh/FREAK-Attack-CVE-2015-0204-Testing-Script](https://github.com/AbhishekGhosh/FREAK-Attack-CVE-2015-0204-Testing-Script)
- [niccoX/patch-openssl-CVE-2014-0291_CVE-2015-0204](https://github.com/niccoX/patch-openssl-CVE-2014-0291_CVE-2015-0204)
- [anthophilee/A2SV--SSL-VUL-Scan](https://github.com/anthophilee/A2SV--SSL-VUL-Scan)

### CVE-2015-0205 (2015-01-09)

<code>The ssl3_get_cert_verify function in s3_srvr.c in OpenSSL 1.0.0 before 1.0.0p and 1.0.1 before 1.0.1k accepts client authentication with a Diffie-Hellman (DH) certificate without requiring a CertificateVerify message, which allows remote attackers to obtain access without knowledge of a private key via crafted TLS Handshake Protocol traffic to a server that recognizes a Certification Authority with DH support.
</code>

- [saurabh2088/OpenSSL_1_0_1g_CVE-2015-0205](https://github.com/saurabh2088/OpenSSL_1_0_1g_CVE-2015-0205)

### CVE-2015-0235 (2015-01-28)

<code>Heap-based buffer overflow in the __nss_hostname_digits_dots function in glibc 2.2, and other 2.x versions before 2.18, allows context-dependent attackers to execute arbitrary code via vectors related to the (1) gethostbyname or (2) gethostbyname2 function, aka &quot;GHOST.&quot;
</code>

- [F88/ghostbusters15](https://github.com/F88/ghostbusters15)
- [makelinux/CVE-2015-0235-workaround](https://github.com/makelinux/CVE-2015-0235-workaround)
- [arm13/ghost_exploit](https://github.com/arm13/ghost_exploit)

### CVE-2015-0311 (2015-01-23)

<code>Unspecified vulnerability in Adobe Flash Player through 13.0.0.262 and 14.x, 15.x, and 16.x through 16.0.0.287 on Windows and OS X and through 11.2.202.438 on Linux allows remote attackers to execute arbitrary code via unknown vectors, as exploited in the wild in January 2015.
</code>

- [jr64/CVE-2015-0311](https://github.com/jr64/CVE-2015-0311)

### CVE-2015-0313 (2015-02-02)

<code>Use-after-free vulnerability in Adobe Flash Player before 13.0.0.269 and 14.x through 16.x before 16.0.0.305 on Windows and OS X and before 11.2.202.442 on Linux allows remote attackers to execute arbitrary code via unspecified vectors, as exploited in the wild in February 2015, a different vulnerability than CVE-2015-0315, CVE-2015-0320, and CVE-2015-0322.
</code>

- [SecurityObscurity/cve-2015-0313](https://github.com/SecurityObscurity/cve-2015-0313)

### CVE-2015-0345 (2015-04-15)

<code>Cross-site scripting (XSS) vulnerability in Adobe ColdFusion 10 before Update 16 and 11 before Update 5 allows remote attackers to inject arbitrary web script or HTML via unspecified vectors.
</code>

- [BishopFox/coldfusion-10-11-xss](https://github.com/BishopFox/coldfusion-10-11-xss)

### CVE-2015-1130 (2015-04-10)

<code>The XPC implementation in Admin Framework in Apple OS X before 10.10.3 allows local users to bypass authentication and obtain admin privileges via unspecified vectors.
</code>

- [Shmoopi/RootPipe-Demo](https://github.com/Shmoopi/RootPipe-Demo)
- [sideeffect42/RootPipeTester](https://github.com/sideeffect42/RootPipeTester)

### CVE-2015-1140 (2015-04-10)

<code>Buffer overflow in IOHIDFamily in Apple OS X before 10.10.3 allows local users to gain privileges via unspecified vectors.
</code>

- [kpwn/vpwn](https://github.com/kpwn/vpwn)

### CVE-2015-1157 (2015-05-28)

<code>CoreText in Apple iOS 8.x through 8.3 allows remote attackers to cause a denial of service (reboot and messaging disruption) via crafted Unicode text that is not properly handled during display truncation in the Notifications feature, as demonstrated by Arabic characters in (1) an SMS message or (2) a WhatsApp message.
</code>

- [perillamint/CVE-2015-1157](https://github.com/perillamint/CVE-2015-1157)

### CVE-2015-1318 (2015-04-17)

<code>The crash reporting feature in Apport 2.13 through 2.17.x before 2.17.1 allows local users to gain privileges via a crafted usr/share/apport/apport file in a namespace (container).
</code>

- [ScottyBauer/CVE-2015-1318](https://github.com/ScottyBauer/CVE-2015-1318)

### CVE-2015-1328 (2016-11-28)

<code>The overlayfs implementation in the linux (aka Linux kernel) package before 3.19.0-21.21 in Ubuntu through 15.04 does not properly check permissions for file creation in the upper filesystem directory, which allows local users to obtain root access by leveraging a configuration in which overlayfs is permitted in an arbitrary mount namespace.
</code>

- [notlikethis/CVE-2015-1328](https://github.com/notlikethis/CVE-2015-1328)
- [elit3pwner/CVE-2015-1328-GoldenEye](https://github.com/elit3pwner/CVE-2015-1328-GoldenEye)
- [BlackFrog-hub/cve-2015-1328](https://github.com/BlackFrog-hub/cve-2015-1328)
- [YastrebX/CVE-2015-1328](https://github.com/YastrebX/CVE-2015-1328)
- [devtz007/overlayfs_CVE-2015-1328](https://github.com/devtz007/overlayfs_CVE-2015-1328)

### CVE-2015-1397 (2015-04-29)

<code>SQL injection vulnerability in the getCsvFile function in the Mage_Adminhtml_Block_Widget_Grid class in Magento Community Edition (CE) 1.9.1.0 and Enterprise Edition (EE) 1.14.1.0 allows remote administrators to execute arbitrary SQL commands via the popularity[field_expr] parameter when the popularity[from] or popularity[to] parameter is set.
</code>

- [tmatejicek/CVE-2015-1397](https://github.com/tmatejicek/CVE-2015-1397)
- [WHOISshuvam/CVE-2015-1397](https://github.com/WHOISshuvam/CVE-2015-1397)
- [Wytchwulf/CVE-2015-1397-Magento-Shoplift](https://github.com/Wytchwulf/CVE-2015-1397-Magento-Shoplift)
- [0xDTC/Magento-eCommerce-RCE-CVE-2015-1397](https://github.com/0xDTC/Magento-eCommerce-RCE-CVE-2015-1397)

### CVE-2015-1427 (2015-02-17)

<code>The Groovy scripting engine in Elasticsearch before 1.3.8 and 1.4.x before 1.4.3 allows remote attackers to bypass the sandbox protection mechanism and execute arbitrary shell commands via a crafted script.
</code>

- [cved-sources/cve-2015-1427](https://github.com/cved-sources/cve-2015-1427)
- [xpgdgit/CVE-2015-1427](https://github.com/xpgdgit/CVE-2015-1427)
- [Sebikea/CVE-2015-1427-for-trixie](https://github.com/Sebikea/CVE-2015-1427-for-trixie)

### CVE-2015-1474 (2015-02-16)

<code>Multiple integer overflows in the GraphicBuffer::unflatten function in platform/frameworks/native/libs/ui/GraphicBuffer.cpp in Android through 5.0 allow attackers to gain privileges or cause a denial of service (memory corruption) via vectors that trigger a large number of (1) file descriptors or (2) integer values.
</code>

- [p1gl3t/CVE-2015-1474_poc](https://github.com/p1gl3t/CVE-2015-1474_poc)

### CVE-2015-1528 (2015-10-01)

<code>Integer overflow in the native_handle_create function in libcutils/native_handle.c in Android before 5.1.1 LMY48M allows attackers to obtain a different application's privileges or cause a denial of service (Binder heap memory corruption) via a crafted application, aka internal bug 19334482.
</code>

- [secmob/PoCForCVE-2015-1528](https://github.com/secmob/PoCForCVE-2015-1528)
- [kanpol/PoCForCVE-2015-1528](https://github.com/kanpol/PoCForCVE-2015-1528)

### CVE-2015-1538 (2015-10-01)

<code>Integer overflow in the SampleTable::setSampleToChunkParams function in SampleTable.cpp in libstagefright in Android before 5.1.1 LMY48I allows remote attackers to execute arbitrary code via crafted atoms in MP4 data that trigger an unchecked multiplication, aka internal bug 20139950, a related issue to CVE-2015-4496.
</code>

- [oguzhantopgul/cve-2015-1538-1](https://github.com/oguzhantopgul/cve-2015-1538-1)
- [renjithsasidharan/cve-2015-1538-1](https://github.com/renjithsasidharan/cve-2015-1538-1)
- [jduck/cve-2015-1538-1](https://github.com/jduck/cve-2015-1538-1)

### CVE-2015-1560 (2015-07-14)

<code>SQL injection vulnerability in the isUserAdmin function in include/common/common-Func.php in Centreon (formerly Merethis Centreon) 2.5.4 and earlier (fixed in Centreon web 2.7.0) allows remote attackers to execute arbitrary SQL commands via the sid parameter to include/common/XmlTree/GetXmlTree.php.
</code>

- [Iansus/Centreon-CVE-2015-1560_1561](https://github.com/Iansus/Centreon-CVE-2015-1560_1561)

### CVE-2015-1578 (2015-02-11)

<code>Multiple open redirect vulnerabilities in u5CMS before 3.9.4 allow remote attackers to redirect users to arbitrary web sites and conduct phishing attacks via a URL in the (1) pidvesa cookie to u5admin/pidvesa.php or (2) uri parameter to u5admin/meta2.php.
</code>

- [Zeppperoni/CVE-2015-1578](https://github.com/Zeppperoni/CVE-2015-1578)

### CVE-2015-1592 (2015-02-19)

<code>Movable Type Pro, Open Source, and Advanced before 5.2.12 and Pro and Advanced 6.0.x before 6.0.7 does not properly use the Perl Storable::thaw function, which allows remote attackers to include and execute arbitrary local Perl files and possibly execute arbitrary code via unspecified vectors.
</code>

- [lightsey/cve-2015-1592](https://github.com/lightsey/cve-2015-1592)

### CVE-2015-1635 (2015-04-14)

<code>HTTP.sys in Microsoft Windows 7 SP1, Windows Server 2008 R2 SP1, Windows 8, Windows 8.1, and Windows Server 2012 Gold and R2 allows remote attackers to execute arbitrary code via crafted HTTP requests, aka &quot;HTTP.sys Remote Code Execution Vulnerability.&quot;
</code>

- [xPaw/HTTPsys](https://github.com/xPaw/HTTPsys)
- [Zx7ffa4512-Python/Project-CVE-2015-1635](https://github.com/Zx7ffa4512-Python/Project-CVE-2015-1635)
- [technion/erlvulnscan](https://github.com/technion/erlvulnscan)
- [wiredaem0n/chk-ms15-034](https://github.com/wiredaem0n/chk-ms15-034)
- [n3rdh4x0r/CVE-2015-1635-POC](https://github.com/n3rdh4x0r/CVE-2015-1635-POC)
- [n3rdh4x0r/CVE-2015-1635](https://github.com/n3rdh4x0r/CVE-2015-1635)
- [w01ke/CVE-2015-1635-POC](https://github.com/w01ke/CVE-2015-1635-POC)
- [SkinAir/ms15-034-Scan](https://github.com/SkinAir/ms15-034-Scan)
- [Cappricio-Securities/CVE-2015-1635](https://github.com/Cappricio-Securities/CVE-2015-1635)

### CVE-2015-1641 (2015-04-14)

<code>Microsoft Word 2007 SP3, Office 2010 SP2, Word 2010 SP2, Word 2013 SP1, Word 2013 RT SP1, Word for Mac 2011, Office Compatibility Pack SP3, Word Automation Services on SharePoint Server 2010 SP2 and 2013 SP1, and Office Web Apps Server 2010 SP2 and 2013 SP1 allow remote attackers to execute arbitrary code via a crafted RTF document, aka &quot;Microsoft Office Memory Corruption Vulnerability.&quot;
</code>

- [Cyberclues/rtf_exploit_extractor](https://github.com/Cyberclues/rtf_exploit_extractor)

### CVE-2015-1701 (2015-04-21)

<code>Win32k.sys in the kernel-mode drivers in Microsoft Windows Server 2003 SP2, Vista SP2, and Server 2008 SP2 allows local users to gain privileges via a crafted application, as exploited in the wild in April 2015, aka &quot;Win32k Elevation of Privilege Vulnerability.&quot;
</code>

- [hfiref0x/CVE-2015-1701](https://github.com/hfiref0x/CVE-2015-1701)
- [Anonymous-Family/CVE-2015-1701](https://github.com/Anonymous-Family/CVE-2015-1701)
- [Anonymous-Family/CVE-2015-1701-download](https://github.com/Anonymous-Family/CVE-2015-1701-download)

### CVE-2015-1769 (2015-08-15)

<code>Mount Manager in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT Gold and 8.1, and Windows 10 mishandles symlinks, which allows physically proximate attackers to execute arbitrary code by connecting a crafted USB device, aka &quot;Mount Manager Elevation of Privilege Vulnerability.&quot;
</code>

- [int0/CVE-2015-1769](https://github.com/int0/CVE-2015-1769)

### CVE-2015-1788 (2015-06-12)

<code>The BN_GF2m_mod_inv function in crypto/bn/bn_gf2m.c in OpenSSL before 0.9.8s, 1.0.0 before 1.0.0e, 1.0.1 before 1.0.1n, and 1.0.2 before 1.0.2b does not properly handle ECParameters structures in which the curve is over a malformed binary polynomial field, which allows remote attackers to cause a denial of service (infinite loop) via a session that uses an Elliptic Curve algorithm, as demonstrated by an attack against a server that supports client authentication.
</code>

- [pazhanivel07/OpenSSL_1_0_1g_CVE-2015-1788](https://github.com/pazhanivel07/OpenSSL_1_0_1g_CVE-2015-1788)

### CVE-2015-1790 (2015-06-12)

<code>The PKCS7_dataDecodefunction in crypto/pkcs7/pk7_doit.c in OpenSSL before 0.9.8zg, 1.0.0 before 1.0.0s, 1.0.1 before 1.0.1n, and 1.0.2 before 1.0.2b allows remote attackers to cause a denial of service (NULL pointer dereference and application crash) via a PKCS#7 blob that uses ASN.1 encoding and lacks inner EncryptedContent data.
</code>

- [Trinadh465/OpenSSL-1_0_1g_CVE-2015-1790](https://github.com/Trinadh465/OpenSSL-1_0_1g_CVE-2015-1790)

### CVE-2015-1791 (2015-06-12)

<code>Race condition in the ssl3_get_new_session_ticket function in ssl/s3_clnt.c in OpenSSL before 0.9.8zg, 1.0.0 before 1.0.0s, 1.0.1 before 1.0.1n, and 1.0.2 before 1.0.2b, when used for a multi-threaded client, allows remote attackers to cause a denial of service (double free and application crash) or possibly have unspecified other impact by providing a NewSessionTicket during an attempt to reuse a ticket that had been obtained earlier.
</code>

- [Trinadh465/OpenSSL-1_0_1g_CVE-2015-1791](https://github.com/Trinadh465/OpenSSL-1_0_1g_CVE-2015-1791)

### CVE-2015-1792 (2015-06-12)

<code>The do_free_upto function in crypto/cms/cms_smime.c in OpenSSL before 0.9.8zg, 1.0.0 before 1.0.0s, 1.0.1 before 1.0.1n, and 1.0.2 before 1.0.2b allows remote attackers to cause a denial of service (infinite loop) via vectors that trigger a NULL value of a BIO data structure, as demonstrated by an unrecognized X.660 OID for a hash function.
</code>

- [Trinadh465/OpenSSL-1_0_1g_CVE-2015-1792](https://github.com/Trinadh465/OpenSSL-1_0_1g_CVE-2015-1792)

### CVE-2015-1805 (2015-08-08)

<code>The (1) pipe_read and (2) pipe_write implementations in fs/pipe.c in the Linux kernel before 3.16 do not properly consider the side effects of failed __copy_to_user_inatomic and __copy_from_user_inatomic calls, which allows local users to cause a denial of service (system crash) or possibly gain privileges via a crafted application, aka an &quot;I/O vector array overrun.&quot;
</code>

- [ireshchaminda1/Android-Privilege-Escalation-Remote-Access-Vulnerability-CVE-2015-1805](https://github.com/ireshchaminda1/Android-Privilege-Escalation-Remote-Access-Vulnerability-CVE-2015-1805)

### CVE-2015-1986 (2015-06-30)

<code>The server in IBM Tivoli Storage Manager FastBack 6.1 before 6.1.12 allows remote attackers to execute arbitrary commands via unspecified vectors, a different vulnerability than CVE-2015-1938.
</code>

- [3t3rn4lv01d/CVE-2015-1986](https://github.com/3t3rn4lv01d/CVE-2015-1986)

### CVE-2015-2153 (2015-03-24)

<code>The rpki_rtr_pdu_print function in print-rpki-rtr.c in the TCP printer in tcpdump before 4.7.2 allows remote attackers to cause a denial of service (out-of-bounds read or write and crash) via a crafted header length in an RPKI-RTR Protocol Data Unit (PDU).
</code>

- [arntsonl/CVE-2015-2153](https://github.com/arntsonl/CVE-2015-2153)

### CVE-2015-2166 (2015-04-06)

<code>Directory traversal vulnerability in the Instance Monitor in Ericsson Drutt Mobile Service Delivery Platform (MSDP) 4, 5, and 6 allows remote attackers to read arbitrary files via a ..%2f (dot dot encoded slash) in the default URI.
</code>

- [K3ysTr0K3R/CVE-2015-2166-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2015-2166-EXPLOIT)

### CVE-2015-2208 (2015-03-12)

<code>The saveObject function in moadmin.php in phpMoAdmin 1.1.2 allows remote attackers to execute arbitrary commands via shell metacharacters in the object parameter.
</code>

- [ptantiku/cve-2015-2208](https://github.com/ptantiku/cve-2015-2208)

### CVE-2015-2231
- [rednaga/adups-get-super-serial](https://github.com/rednaga/adups-get-super-serial)

### CVE-2015-2291 (2017-08-09)

<code>(1) IQVW32.sys before 1.3.1.0 and (2) IQVW64.sys before 1.3.1.0 in the Intel Ethernet diagnostics driver for Windows allows local users to cause a denial of service or possibly execute arbitrary code with kernel privileges via a crafted (a) 0x80862013, (b) 0x8086200B, (c) 0x8086200F, or (d) 0x80862007 IOCTL call.
</code>

- [gmh5225/CVE-2015-2291](https://github.com/gmh5225/CVE-2015-2291)

### CVE-2015-2315 (2015-03-17)

<code>Cross-site scripting (XSS) vulnerability in the WPML plugin before 3.1.9 for WordPress allows remote attackers to inject arbitrary web script or HTML via the target parameter in a reminder_popup action to the default URI.
</code>

- [weidongl74/cve-2015-2315-report](https://github.com/weidongl74/cve-2015-2315-report)

### CVE-2015-2925 (2015-11-16)

<code>The prepend_path function in fs/dcache.c in the Linux kernel before 4.2.4 does not properly handle rename actions inside a bind mount, which allows local users to bypass an intended container protection mechanism by renaming a directory, related to a &quot;double-chroot attack.&quot;
</code>

- [Kagami/docker_cve-2015-2925](https://github.com/Kagami/docker_cve-2015-2925)

### CVE-2015-3043 (2015-04-14)

<code>Adobe Flash Player before 13.0.0.281 and 14.x through 17.x before 17.0.0.169 on Windows and OS X and before 11.2.202.457 on Linux allows attackers to execute arbitrary code or cause a denial of service (memory corruption) via unspecified vectors, as exploited in the wild in April 2015, a different vulnerability than CVE-2015-0347, CVE-2015-0350, CVE-2015-0352, CVE-2015-0353, CVE-2015-0354, CVE-2015-0355, CVE-2015-0360, CVE-2015-3038, CVE-2015-3041, and CVE-2015-3042.
</code>

- [whitehairman/Exploit](https://github.com/whitehairman/Exploit)

### CVE-2015-3073 (2015-05-13)

<code>Adobe Reader and Acrobat 10.x before 10.1.14 and 11.x before 11.0.11 on Windows and OS X allow attackers to bypass intended restrictions on JavaScript API execution via unspecified vectors, a different vulnerability than CVE-2015-3060, CVE-2015-3061, CVE-2015-3062, CVE-2015-3063, CVE-2015-3064, CVE-2015-3065, CVE-2015-3066, CVE-2015-3067, CVE-2015-3068, CVE-2015-3069, CVE-2015-3071, CVE-2015-3072, and CVE-2015-3074.
</code>

- [reigningshells/CVE-2015-3073](https://github.com/reigningshells/CVE-2015-3073)

### CVE-2015-3090 (2015-05-13)

<code>Adobe Flash Player before 13.0.0.289 and 14.x through 17.x before 17.0.0.188 on Windows and OS X and before 11.2.202.460 on Linux, Adobe AIR before 17.0.0.172, Adobe AIR SDK before 17.0.0.172, and Adobe AIR SDK &amp; Compiler before 17.0.0.172 allow attackers to execute arbitrary code or cause a denial of service (memory corruption) via unspecified vectors, a different vulnerability than CVE-2015-3078, CVE-2015-3089, and CVE-2015-3093.
</code>

- [Xattam1/Adobe-Flash-Exploits_17-18](https://github.com/Xattam1/Adobe-Flash-Exploits_17-18)

### CVE-2015-3145 (2015-04-24)

<code>The sanitize_cookie_path function in cURL and libcurl 7.31.0 through 7.41.0 does not properly calculate an index, which allows remote attackers to cause a denial of service (out-of-bounds write and crash) or possibly have other unspecified impact via a cookie path containing only a double-quote character.
</code>

- [serz999/CVE-2015-3145](https://github.com/serz999/CVE-2015-3145)

### CVE-2015-3152 (2016-05-16)

<code>Oracle MySQL before 5.7.3, Oracle MySQL Connector/C (aka libmysqlclient) before 6.1.3, and MariaDB before 5.5.44 use the --ssl option to mean that SSL is optional, which allows man-in-the-middle attackers to spoof servers via a cleartext-downgrade attack, aka a &quot;BACKRONYM&quot; attack.
</code>

- [duo-labs/mysslstrip](https://github.com/duo-labs/mysslstrip)

### CVE-2015-3194 (2015-12-06)

<code>crypto/rsa/rsa_ameth.c in OpenSSL 1.0.1 before 1.0.1q and 1.0.2 before 1.0.2e allows remote attackers to cause a denial of service (NULL pointer dereference and application crash) via an RSA PSS ASN.1 signature that lacks a mask generation function parameter.
</code>

- [Trinadh465/OpenSSL-1_0_1g_CVE-2015-3194](https://github.com/Trinadh465/OpenSSL-1_0_1g_CVE-2015-3194)

### CVE-2015-3195 (2015-12-06)

<code>The ASN1_TFLG_COMBINE implementation in crypto/asn1/tasn_dec.c in OpenSSL before 0.9.8zh, 1.0.0 before 1.0.0t, 1.0.1 before 1.0.1q, and 1.0.2 before 1.0.2e mishandles errors caused by malformed X509_ATTRIBUTE data, which allows remote attackers to obtain sensitive information from process memory by triggering a decoding failure in a PKCS#7 or CMS application.
</code>

- [Trinadh465/OpenSSL-1_0_1g_CVE-2015-3195](https://github.com/Trinadh465/OpenSSL-1_0_1g_CVE-2015-3195)

### CVE-2015-3197 (2016-02-15)

<code>ssl/s2_srvr.c in OpenSSL 1.0.1 before 1.0.1r and 1.0.2 before 1.0.2f does not prevent use of disabled ciphers, which makes it easier for man-in-the-middle attackers to defeat cryptographic protection mechanisms by performing computations on SSLv2 traffic, related to the get_client_master_key and get_client_hello functions.
</code>

- [Trinadh465/OpenSSL-1_0_1g_CVE-2015-3197](https://github.com/Trinadh465/OpenSSL-1_0_1g_CVE-2015-3197)

### CVE-2015-3224 (2015-07-26)

<code>request.rb in Web Console before 2.1.3, as used with Ruby on Rails 3.x and 4.x, does not properly restrict the use of X-Forwarded-For headers in determining a client's IP address, which allows remote attackers to bypass the whitelisted_ips protection mechanism via a crafted request.
</code>

- [n000xy/CVE-2015-3224-](https://github.com/n000xy/CVE-2015-3224-)

### CVE-2015-3239 (2015-08-26)

<code>Off-by-one error in the dwarf_to_unw_regnum function in include/dwarf_i.h in libunwind 1.1 allows local users to have unspecified impact via invalid dwarf opcodes.
</code>

- [RenukaSelvar/libunwind_CVE-2015-3239](https://github.com/RenukaSelvar/libunwind_CVE-2015-3239)
- [RenukaSelvar/libunwind_CVE-2015-3239_AfterPatch](https://github.com/RenukaSelvar/libunwind_CVE-2015-3239_AfterPatch)
- [RenukaSelvar/libunwind_CVE-2015-3239_After](https://github.com/RenukaSelvar/libunwind_CVE-2015-3239_After)

### CVE-2015-3306 (2015-05-18)

<code>The mod_copy module in ProFTPD 1.3.5 allows remote attackers to read and write to arbitrary files via the site cpfr and site cpto commands.
</code>

- [shk0x/cpx_proftpd](https://github.com/shk0x/cpx_proftpd)
- [nootropics/propane](https://github.com/nootropics/propane)
- [cved-sources/cve-2015-3306](https://github.com/cved-sources/cve-2015-3306)
- [hackarada/cve-2015-3306](https://github.com/hackarada/cve-2015-3306)
- [0xm4ud/ProFTPD_CVE-2015-3306](https://github.com/0xm4ud/ProFTPD_CVE-2015-3306)
- [jptr218/proftpd_bypass](https://github.com/jptr218/proftpd_bypass)
- [JoseLRC97/ProFTPd-1.3.5-mod_copy-Remote-Command-Execution](https://github.com/JoseLRC97/ProFTPd-1.3.5-mod_copy-Remote-Command-Execution)

### CVE-2015-3456 (2015-05-13)

<code>The Floppy Disk Controller (FDC) in QEMU, as used in Xen 4.5.x and earlier and KVM, allows local guest users to cause a denial of service (out-of-bounds write and guest crash) or possibly execute arbitrary code via the (1) FD_CMD_READ_ID, (2) FD_CMD_DRIVE_SPECIFICATION_COMMAND, or other unspecified commands, aka VENOM.
</code>

- [vincentbernat/cve-2015-3456](https://github.com/vincentbernat/cve-2015-3456)

### CVE-2015-3636 (2015-08-06)

<code>The ping_unhash function in net/ipv4/ping.c in the Linux kernel before 4.0.3 does not initialize a certain list data structure during an unhash operation, which allows local users to gain privileges or cause a denial of service (use-after-free and system crash) by leveraging the ability to make a SOCK_DGRAM socket system call for the IPPROTO_ICMP or IPPROTO_ICMPV6 protocol, and then making a connect system call after a disconnect.
</code>

- [betalphafai/cve-2015-3636_crash](https://github.com/betalphafai/cve-2015-3636_crash)
- [askk/libping_unhash_exploit_POC](https://github.com/askk/libping_unhash_exploit_POC)
- [ludongxu/cve-2015-3636](https://github.com/ludongxu/cve-2015-3636)
- [fi01/CVE-2015-3636](https://github.com/fi01/CVE-2015-3636)
- [android-rooting-tools/libpingpong_exploit](https://github.com/android-rooting-tools/libpingpong_exploit)

### CVE-2015-3864 (2015-10-01)

<code>Integer underflow in the MPEG4Extractor::parseChunk function in MPEG4Extractor.cpp in libstagefright in mediaserver in Android before 5.1.1 LMY48M allows remote attackers to execute arbitrary code via crafted MPEG-4 data, aka internal bug 23034759.  NOTE: this vulnerability exists because of an incomplete fix for CVE-2015-3824.
</code>

- [pwnaccelerator/stagefright-cve-2015-3864](https://github.com/pwnaccelerator/stagefright-cve-2015-3864)
- [eudemonics/scaredycat](https://github.com/eudemonics/scaredycat)
- [Bhathiya404/Exploiting-Stagefright-Vulnerability-CVE-2015-3864](https://github.com/Bhathiya404/Exploiting-Stagefright-Vulnerability-CVE-2015-3864)
- [Cmadhushanka/CVE-2015-3864-Exploitation](https://github.com/Cmadhushanka/CVE-2015-3864-Exploitation)

### CVE-2015-4000 (2015-05-21)

<code>The TLS protocol 1.2 and earlier, when a DHE_EXPORT ciphersuite is enabled on a server but not on a client, does not properly convey a DHE_EXPORT choice, which allows man-in-the-middle attackers to conduct cipher-downgrade attacks by rewriting a ClientHello with DHE replaced by DHE_EXPORT and then rewriting a ServerHello with DHE_EXPORT replaced by DHE, aka the &quot;Logjam&quot; issue.
</code>

- [fatlan/HAProxy-Keepalived-Sec-HighLoads](https://github.com/fatlan/HAProxy-Keepalived-Sec-HighLoads)

### CVE-2015-4495 (2015-08-08)

<code>The PDF reader in Mozilla Firefox before 39.0.3, Firefox ESR 38.x before 38.1.1, and Firefox OS before 2.2 allows remote attackers to bypass the Same Origin Policy, and read arbitrary files or gain privileges, via vectors involving crafted JavaScript code and a native setter, as exploited in the wild in August 2015.
</code>

- [vincd/CVE-2015-4495](https://github.com/vincd/CVE-2015-4495)

### CVE-2015-4843 (2015-10-21)

<code>Unspecified vulnerability in Oracle Java SE 6u101, 7u85, and 8u60, and Java SE Embedded 8u51, allows remote attackers to affect confidentiality, integrity, and availability via unknown vectors related to Libraries.
</code>

- [Soteria-Research/cve-2015-4843-type-confusion-phrack](https://github.com/Soteria-Research/cve-2015-4843-type-confusion-phrack)

### CVE-2015-5119 (2015-07-08)

<code>Use-after-free vulnerability in the ByteArray class in the ActionScript 3 (AS3) implementation in Adobe Flash Player 13.x through 13.0.0.296 and 14.x through 18.0.0.194 on Windows and OS X and 11.x through 11.2.202.468 on Linux allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via crafted Flash content that overrides a valueOf function, as exploited in the wild in July 2015.
</code>

- [jvazquez-r7/CVE-2015-5119](https://github.com/jvazquez-r7/CVE-2015-5119)
- [CiscoCXSecurity/CVE-2015-5119_walkthrough](https://github.com/CiscoCXSecurity/CVE-2015-5119_walkthrough)

### CVE-2015-5254 (2016-01-08)

<code>Apache ActiveMQ 5.x before 5.13.0 does not restrict the classes that can be serialized in the broker, which allows remote attackers to execute arbitrary code via a crafted serialized Java Message Service (JMS) ObjectMessage object.
</code>

- [guigui237/Exploitation-de-la-vuln-rabilit-CVE-2015-5254-](https://github.com/guigui237/Exploitation-de-la-vuln-rabilit-CVE-2015-5254-)

### CVE-2015-5347 (2016-04-12)

<code>Cross-site scripting (XSS) vulnerability in the getWindowOpenJavaScript function in org.apache.wicket.extensions.ajax.markup.html.modal.ModalWindow in Apache Wicket 1.5.x before 1.5.15, 6.x before 6.22.0, and 7.x before 7.2.0 might allow remote attackers to inject arbitrary web script or HTML via a ModalWindow title.
</code>

- [alexanderkjall/wicker-cve-2015-5347](https://github.com/alexanderkjall/wicker-cve-2015-5347)

### CVE-2015-5377 (2018-03-06)

<code>Elasticsearch before 1.6.1 allows remote attackers to execute arbitrary code via unspecified vectors involving the transport protocol.  NOTE: ZDI appears to claim that CVE-2015-3253 and CVE-2015-5377 are the same vulnerability
</code>

- [fi3ro/CVE-2015-5377](https://github.com/fi3ro/CVE-2015-5377)

### CVE-2015-5477 (2015-07-29)

<code>named in ISC BIND 9.x before 9.9.7-P2 and 9.10.x before 9.10.2-P3 allows remote attackers to cause a denial of service (REQUIRE assertion failure and daemon exit) via TKEY queries.
</code>

- [robertdavidgraham/cve-2015-5477](https://github.com/robertdavidgraham/cve-2015-5477)
- [elceef/tkeypoc](https://github.com/elceef/tkeypoc)
- [hmlio/vaas-cve-2015-5477](https://github.com/hmlio/vaas-cve-2015-5477)
- [knqyf263/cve-2015-5477](https://github.com/knqyf263/cve-2015-5477)
- [ilanyu/cve-2015-5477](https://github.com/ilanyu/cve-2015-5477)

### CVE-2015-5531 (2015-08-17)

<code>Directory traversal vulnerability in Elasticsearch before 1.6.1 allows remote attackers to read arbitrary files via unspecified vectors related to snapshot API calls.
</code>

- [xpgdgit/CVE-2015-5531](https://github.com/xpgdgit/CVE-2015-5531)
- [M0ge/CVE-2015-5531-POC](https://github.com/M0ge/CVE-2015-5531-POC)

### CVE-2015-5602 (2015-11-17)

<code>sudoedit in Sudo before 1.8.15 allows local users to gain privileges via a symlink attack on a file whose full path is defined using multiple wildcards in /etc/sudoers, as demonstrated by &quot;/home/*/*/file.txt.&quot;
</code>

- [cved-sources/cve-2015-5602](https://github.com/cved-sources/cve-2015-5602)

### CVE-2015-5932 (2015-10-23)

<code>The kernel in Apple OS X before 10.11.1 allows local users to gain privileges by leveraging an unspecified &quot;type confusion&quot; during Mach task processing.
</code>

- [jndok/tpwn-bis](https://github.com/jndok/tpwn-bis)

### CVE-2015-6357 (2015-11-18)

<code>The rule-update feature in Cisco FireSIGHT Management Center (MC) 5.2 through 5.4.0.1 does not verify the X.509 certificate of the support.sourcefire.com SSL server, which allows man-in-the-middle attackers to spoof this server and provide an invalid package, and consequently execute arbitrary code, via a crafted certificate, aka Bug ID CSCuw06444.
</code>

- [mattimustang/firepwner](https://github.com/mattimustang/firepwner)

### CVE-2015-6576 (2017-10-02)

<code>Bamboo 2.2 before 5.8.5 and 5.9.x before 5.9.7 allows remote attackers with access to the Bamboo web interface to execute arbitrary Java code via an unspecified resource.
</code>

- [CallMeJonas/CVE-2015-6576](https://github.com/CallMeJonas/CVE-2015-6576)

### CVE-2015-6612 (2015-11-03)

<code>libmedia in Android before 5.1.1 LMY48X and 6.0 before 2015-11-01 allows attackers to gain privileges via a crafted application, aka internal bug 23540426.
</code>

- [secmob/CVE-2015-6612](https://github.com/secmob/CVE-2015-6612)
- [flankerhqd/cve-2015-6612poc-forM](https://github.com/flankerhqd/cve-2015-6612poc-forM)

### CVE-2015-6620 (2015-12-08)

<code>libstagefright in Android before 5.1.1 LMY48Z and 6.0 before 2015-12-01 allows attackers to gain privileges via a crafted application, as demonstrated by obtaining Signature or SignatureOrSystem access, aka internal bugs 24123723 and 24445127.
</code>

- [flankerhqd/CVE-2015-6620-POC](https://github.com/flankerhqd/CVE-2015-6620-POC)

### CVE-2015-6668 (2017-10-19)

<code>The Job Manager plugin before 0.7.25 allows remote attackers to read arbitrary CV files via a brute force attack to the WordPress upload directory structure, related to an insecure direct object reference.
</code>

- [G01d3nW01f/CVE-2015-6668](https://github.com/G01d3nW01f/CVE-2015-6668)
- [n3rdh4x0r/CVE-2015-6668](https://github.com/n3rdh4x0r/CVE-2015-6668)
- [jimdiroffii/CVE-2015-6668](https://github.com/jimdiroffii/CVE-2015-6668)

### CVE-2015-6748 (2017-09-25)

<code>Cross-site scripting (XSS) vulnerability in jsoup before 1.8.3.
</code>

- [epicosy/VUL4J-59](https://github.com/epicosy/VUL4J-59)

### CVE-2015-6835 (2016-05-16)

<code>The session deserializer in PHP before 5.4.45, 5.5.x before 5.5.29, and 5.6.x before 5.6.13 mishandles multiple php_var_unserialize calls, which allow remote attackers to execute arbitrary code or cause a denial of service (use-after-free) via crafted session content.
</code>

- [ockeghem/CVE-2015-6835-checker](https://github.com/ockeghem/CVE-2015-6835-checker)

### CVE-2015-6967 (2015-09-16)

<code>Unrestricted file upload vulnerability in the My Image plugin in Nibbleblog before 4.0.5 allows remote administrators to execute arbitrary code by uploading a file with an executable extension, then accessing it via a direct request to the file in content/private/plugins/my_image/image.php.
</code>

- [dix0nym/CVE-2015-6967](https://github.com/dix0nym/CVE-2015-6967)
- [FredBrave/CVE-2015-6967](https://github.com/FredBrave/CVE-2015-6967)
- [3mpir3Albert/HTB_Nibbles](https://github.com/3mpir3Albert/HTB_Nibbles)

### CVE-2015-7297 (2015-10-29)

<code>SQL injection vulnerability in Joomla! 3.2 before 3.4.4 allows remote attackers to execute arbitrary SQL commands via unspecified vectors, a different vulnerability than CVE-2015-7858.
</code>

- [CCrashBandicot/ContentHistory](https://github.com/CCrashBandicot/ContentHistory)
- [Cappricio-Securities/CVE-2015-7297](https://github.com/Cappricio-Securities/CVE-2015-7297)

### CVE-2015-7545 (2016-04-13)

<code>The (1) git-remote-ext and (2) unspecified other remote helper programs in Git before 2.3.10, 2.4.x before 2.4.10, 2.5.x before 2.5.4, and 2.6.x before 2.6.1 do not properly restrict the allowed protocols, which might allow remote attackers to execute arbitrary code via a URL in a (a) .gitmodules file or (b) unknown other sources in a submodule.
</code>

- [avuserow/bug-free-chainsaw](https://github.com/avuserow/bug-free-chainsaw)

### CVE-2015-7547 (2016-02-18)

<code>Multiple stack-based buffer overflows in the (1) send_dg and (2) send_vc functions in the libresolv library in the GNU C Library (aka glibc or libc6) before 2.23 allow remote attackers to cause a denial of service (crash) or possibly execute arbitrary code via a crafted DNS response that triggers a call to the getaddrinfo function with the AF_UNSPEC or AF_INET6 address family, related to performing &quot;dual A/AAAA DNS queries&quot; and the libnss_dns.so.2 NSS module.
</code>

- [Stick-U235/CVE-2015-7547-Research](https://github.com/Stick-U235/CVE-2015-7547-Research)

### CVE-2015-7755 (2015-12-19)

<code>Juniper ScreenOS 6.2.0r15 through 6.2.0r18, 6.3.0r12 before 6.3.0r12b, 6.3.0r13 before 6.3.0r13b, 6.3.0r14 before 6.3.0r14b, 6.3.0r15 before 6.3.0r15b, 6.3.0r16 before 6.3.0r16b, 6.3.0r17 before 6.3.0r17b, 6.3.0r18 before 6.3.0r18b, 6.3.0r19 before 6.3.0r19b, and 6.3.0r20 before 6.3.0r21 allows remote attackers to obtain administrative access by entering an unspecified password during a (1) SSH or (2) TELNET session.
</code>

- [hdm/juniper-cve-2015-7755](https://github.com/hdm/juniper-cve-2015-7755)

### CVE-2015-7808 (2015-11-24)

<code>The vB_Api_Hook::decodeArguments method in vBulletin 5 Connect 5.1.2 through 5.1.9 allows remote attackers to conduct PHP object injection attacks and execute arbitrary PHP code via a crafted serialized object in the arguments parameter to ajax/api/hook/decodeArguments.
</code>

- [Prajithp/CVE-2015-7808](https://github.com/Prajithp/CVE-2015-7808)

### CVE-2015-8088 (2016-01-12)

<code>Heap-based buffer overflow in the HIFI driver in Huawei Mate 7 phones with software MT7-UL00 before MT7-UL00C17B354, MT7-TL10 before MT7-TL10C00B354, MT7-TL00 before MT7-TL00C01B354, and MT7-CL00 before MT7-CL00C92B354 and P8 phones with software GRA-TL00 before GRA-TL00C01B220SP01, GRA-CL00 before GRA-CL00C92B220, GRA-CL10 before GRA-CL10C92B220, GRA-UL00 before GRA-UL00C00B220, and GRA-UL10 before GRA-UL10C00B220 allows attackers to cause a denial of service (reboot) or execute arbitrary code via a crafted application.
</code>

- [Pray3r/CVE-2015-8088](https://github.com/Pray3r/CVE-2015-8088)

### CVE-2015-8103 (2015-11-25)

<code>The Jenkins CLI subsystem in Jenkins before 1.638 and LTS before 1.625.2 allows remote attackers to execute arbitrary code via a crafted serialized Java object, related to a problematic webapps/ROOT/WEB-INF/lib/commons-collections-*.jar file and the &quot;Groovy variant in 'ysoserial'&quot;.
</code>

- [cved-sources/cve-2015-8103](https://github.com/cved-sources/cve-2015-8103)
- [r00t4dm/Jenkins-CVE-2015-8103](https://github.com/r00t4dm/Jenkins-CVE-2015-8103)

### CVE-2015-8239 (2017-10-10)

<code>The SHA-2 digest support in the sudoers plugin in sudo after 1.8.7 allows local users with write permissions to parts of the called command to replace them before it is executed.
</code>

- [justinsteven/sudo_digest_toctou_poc_CVE-2015-8239](https://github.com/justinsteven/sudo_digest_toctou_poc_CVE-2015-8239)

### CVE-2015-8351 (2017-09-11)

<code>PHP remote file inclusion vulnerability in the Gwolle Guestbook plugin before 1.5.4 for WordPress, when allow_url_include is enabled, allows remote authenticated users to execute arbitrary PHP code via a URL in the abspath parameter to frontend/captcha/ajaxresponse.php.  NOTE: this can also be leveraged to include and execute arbitrary local files via directory traversal sequences regardless of whether allow_url_include is enabled.
</code>

- [G01d3nW01f/CVE-2015-8351](https://github.com/G01d3nW01f/CVE-2015-8351)
- [G4sp4rCS/exploit-CVE-2015-8351](https://github.com/G4sp4rCS/exploit-CVE-2015-8351)

### CVE-2015-8562 (2015-12-16)

<code>Joomla! 1.5.x, 2.x, and 3.x before 3.4.6 allow remote attackers to conduct PHP object injection attacks and execute arbitrary PHP code via the HTTP User-Agent header, as exploited in the wild in December 2015.
</code>

- [VoidSec/Joomla_CVE-2015-8562](https://github.com/VoidSec/Joomla_CVE-2015-8562)
- [lorenzodegiorgi/setup-cve-2015-8562](https://github.com/lorenzodegiorgi/setup-cve-2015-8562)
- [Caihuar/Joomla-cve-2015-8562](https://github.com/Caihuar/Joomla-cve-2015-8562)

### CVE-2015-8660 (2015-12-28)

<code>The ovl_setattr function in fs/overlayfs/inode.c in the Linux kernel through 4.3.3 attempts to merge distinct setattr operations, which allows local users to bypass intended access restrictions and modify the attributes of arbitrary overlay files via a crafted application.
</code>

- [nhamle2/CVE-2015-8660](https://github.com/nhamle2/CVE-2015-8660)
- [carradolly/CVE-2015-8660](https://github.com/carradolly/CVE-2015-8660)

### CVE-2015-9235 (2018-05-29)

<code>In jsonwebtoken node module before 4.2.2 it is possible for an attacker to bypass verification when a token digitally signed with an asymmetric key (RS/ES family) of algorithms but instead the attacker send a token digitally signed with a symmetric algorithm (HS* family).
</code>

- [aalex954/jwt-key-confusion-poc](https://github.com/aalex954/jwt-key-confusion-poc)
- [WinDyAlphA/CVE-2015-9235_JWT_key_confusion](https://github.com/WinDyAlphA/CVE-2015-9235_JWT_key_confusion)
- [z-bool/Venom-JWT](https://github.com/z-bool/Venom-JWT)

### CVE-2015-9238 (2018-05-31)

<code>secure-compare 3.0.0 and below do not actually compare two strings properly. compare was actually comparing the first argument with itself, meaning the check passed for any two strings of the same length.
</code>

- [JamesDarf/wargame-turkey_in_2](https://github.com/JamesDarf/wargame-turkey_in_2)

### CVE-2015-9251 (2018-01-18)

<code>jQuery before 3.0.0 is vulnerable to Cross-site Scripting (XSS) attacks when a cross-domain Ajax request is performed without the dataType option, causing text/javascript responses to be executed.
</code>

- [moften/CVE-2015-9251](https://github.com/moften/CVE-2015-9251)
- [hackgiver/CVE-2015-9251](https://github.com/hackgiver/CVE-2015-9251)

### CVE-2015-10034 (2023-01-09)

<code>In j-nowak workout-organizer wurde eine kritische Schwachstelle gefunden. Hierbei betrifft es unbekannten Programmcode. Mit der Manipulation mit unbekannten Daten kann eine sql injection-Schwachstelle ausgenutzt werden. Der Patch wird als 13cd6c3d1210640bfdb39872b2bb3597aa991279 bezeichnet. Als bestmögliche Massnahme wird Patching empfohlen.
</code>

- [andrenasx/CVE-2015-10034](https://github.com/andrenasx/CVE-2015-10034)

### CVE-2015-20107 (2022-04-13)

<code>In Python (aka CPython) up to 3.10.8, the mailcap module does not add escape characters into commands discovered in the system mailcap file. This may allow attackers to inject shell commands into applications that call mailcap.findmatch with untrusted input (if they lack validation of user-provided filenames or arguments). The fix is also back-ported to 3.7, 3.8, 3.9
</code>

- [codeskipper/python-patrol](https://github.com/codeskipper/python-patrol)

### CVE-2015-57115
- [TrixSec/CVE-2015-57115](https://github.com/TrixSec/CVE-2015-57115)


## 2014
### CVE-2014-0038 (2014-02-06)

<code>The compat_sys_recvmmsg function in net/compat.c in the Linux kernel before 3.13.2, when CONFIG_X86_X32 is enabled, allows local users to gain privileges via a recvmmsg system call with a crafted timeout pointer parameter.
</code>

- [saelo/cve-2014-0038](https://github.com/saelo/cve-2014-0038)

### CVE-2014-0094 (2014-03-10)

<code>The ParametersInterceptor in Apache Struts before 2.3.16.2 allows remote attackers to &quot;manipulate&quot; the ClassLoader via the class parameter, which is passed to the getClass method.
</code>

- [HasegawaTadamitsu/CVE-2014-0094-test-program-for-struts1](https://github.com/HasegawaTadamitsu/CVE-2014-0094-test-program-for-struts1)

### CVE-2014-0114 (2014-04-30)

<code>Apache Commons BeanUtils, as distributed in lib/commons-beanutils-1.8.0.jar in Apache Struts 1.x through 1.3.10 and in other products requiring commons-beanutils through 1.9.2, does not suppress the class property, which allows remote attackers to &quot;manipulate&quot; the ClassLoader and execute arbitrary code via the class parameter, as demonstrated by the passing of this parameter to the getClass method of the ActionForm object in Struts 1.
</code>

- [rgielen/struts1filter](https://github.com/rgielen/struts1filter)
- [ricedu/struts1-patch](https://github.com/ricedu/struts1-patch)

### CVE-2014-0130 (2014-05-07)

<code>Directory traversal vulnerability in actionpack/lib/abstract_controller/base.rb in the implicit-render implementation in Ruby on Rails before 3.2.18, 4.0.x before 4.0.5, and 4.1.x before 4.1.1, when certain route globbing configurations are enabled, allows remote attackers to read arbitrary files via a crafted request.
</code>

- [omarkurt/cve-2014-0130](https://github.com/omarkurt/cve-2014-0130)

### CVE-2014-0160 (2014-04-07)

<code>The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.
</code>

- [FiloSottile/Heartbleed](https://github.com/FiloSottile/Heartbleed)
- [titanous/heartbleeder](https://github.com/titanous/heartbleeder)
- [DominikTo/bleed](https://github.com/DominikTo/bleed)
- [cyphar/heartthreader](https://github.com/cyphar/heartthreader)
- [jdauphant/patch-openssl-CVE-2014-0160](https://github.com/jdauphant/patch-openssl-CVE-2014-0160)
- [musalbas/heartbleed-masstest](https://github.com/musalbas/heartbleed-masstest)
- [obayesshelton/CVE-2014-0160-Scanner](https://github.com/obayesshelton/CVE-2014-0160-Scanner)
- [Lekensteyn/pacemaker](https://github.com/Lekensteyn/pacemaker)
- [isgroup/openmagic](https://github.com/isgroup/openmagic)
- [fb1h2s/CVE-2014-0160](https://github.com/fb1h2s/CVE-2014-0160)
- [takeshixx/ssl-heartbleed.nse](https://github.com/takeshixx/ssl-heartbleed.nse)
- [roganartu/heartbleedchecker-chrome](https://github.com/roganartu/heartbleedchecker-chrome)
- [zouguangxian/heartbleed](https://github.com/zouguangxian/heartbleed)
- [sensepost/heartbleed-poc](https://github.com/sensepost/heartbleed-poc)
- [proactiveRISK/heartbleed-extention](https://github.com/proactiveRISK/heartbleed-extention)
- [amerine/coronary](https://github.com/amerine/coronary)
- [0x90/CVE-2014-0160](https://github.com/0x90/CVE-2014-0160)
- [ice-security88/CVE-2014-0160](https://github.com/ice-security88/CVE-2014-0160)
- [waqasjamal-zz/HeartBleed-Vulnerability-Checker](https://github.com/waqasjamal-zz/HeartBleed-Vulnerability-Checker)
- [siddolo/knockbleed](https://github.com/siddolo/knockbleed)
- [sammyfung/openssl-heartbleed-fix](https://github.com/sammyfung/openssl-heartbleed-fix)
- [a0726h77/heartbleed-test](https://github.com/a0726h77/heartbleed-test)
- [pblittle/aws-suture](https://github.com/pblittle/aws-suture)
- [hreese/heartbleed-dtls](https://github.com/hreese/heartbleed-dtls)
- [wwwiretap/bleeding_onions](https://github.com/wwwiretap/bleeding_onions)
- [idkqh7/heatbleeding](https://github.com/idkqh7/heatbleeding)
- [GeeksXtreme/ssl-heartbleed.nse](https://github.com/GeeksXtreme/ssl-heartbleed.nse)
- [xlucas/heartbleed](https://github.com/xlucas/heartbleed)
- [indiw0rm/-Heartbleed-](https://github.com/indiw0rm/-Heartbleed-)
- [einaros/heartbleed-tools](https://github.com/einaros/heartbleed-tools)
- [mozilla-services/Heartbleed](https://github.com/mozilla-services/Heartbleed)
- [yryz/heartbleed.js](https://github.com/yryz/heartbleed.js)
- [DisK0nn3cT/MaltegoHeartbleed](https://github.com/DisK0nn3cT/MaltegoHeartbleed)
- [OffensivePython/HeartLeak](https://github.com/OffensivePython/HeartLeak)
- [vortextube/ssl_scanner](https://github.com/vortextube/ssl_scanner)

### CVE-2014-0166 (2014-04-09)

<code>The wp_validate_auth_cookie function in wp-includes/pluggable.php in WordPress before 3.7.2 and 3.8.x before 3.8.2 does not properly determine the validity of authentication cookies, which makes it easier for remote attackers to obtain access via a forged cookie.
</code>

- [Ettack/POC-CVE-2014-0166](https://github.com/Ettack/POC-CVE-2014-0166)

### CVE-2014-0195 (2014-06-05)

<code>The dtls1_reassemble_fragment function in d1_both.c in OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h does not properly validate fragment lengths in DTLS ClientHello messages, which allows remote attackers to execute arbitrary code or cause a denial of service (buffer overflow and application crash) via a long non-initial fragment.
</code>

- [ricedu/CVE-2014-0195](https://github.com/ricedu/CVE-2014-0195)

### CVE-2014-0196 (2014-05-07)

<code>The n_tty_write function in drivers/tty/n_tty.c in the Linux kernel through 3.14.3 does not properly manage tty driver access in the &quot;LECHO &amp; !OPOST&quot; case, which allows local users to cause a denial of service (memory corruption and system crash) or gain privileges by triggering a race condition involving read and write operations with long strings.
</code>

- [SunRain/CVE-2014-0196](https://github.com/SunRain/CVE-2014-0196)
- [tempbottle/CVE-2014-0196](https://github.com/tempbottle/CVE-2014-0196)

### CVE-2014-0224 (2014-06-05)

<code>OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h does not properly restrict processing of ChangeCipherSpec messages, which allows man-in-the-middle attackers to trigger use of a zero-length master key in certain OpenSSL-to-OpenSSL communications, and consequently hijack sessions or obtain sensitive information, via a crafted TLS handshake, aka the &quot;CCS Injection&quot; vulnerability.
</code>

- [Tripwire/OpenSSL-CCS-Inject-Test](https://github.com/Tripwire/OpenSSL-CCS-Inject-Test)
- [iph0n3/CVE-2014-0224](https://github.com/iph0n3/CVE-2014-0224)
- [droptables/ccs-eval](https://github.com/droptables/ccs-eval)
- [ssllabs/openssl-ccs-cve-2014-0224](https://github.com/ssllabs/openssl-ccs-cve-2014-0224)
- [secretnonempty/CVE-2014-0224](https://github.com/secretnonempty/CVE-2014-0224)

### CVE-2014-0521 (2014-05-14)

<code>Adobe Reader and Acrobat 10.x before 10.1.10 and 11.x before 11.0.07 on Windows and OS X do not properly implement JavaScript APIs, which allows remote attackers to obtain sensitive information via a crafted PDF document.
</code>

- [molnarg/cve-2014-0521](https://github.com/molnarg/cve-2014-0521)

### CVE-2014-0816 (2014-02-27)

<code>Unspecified vulnerability in Norman Security Suite 10.1 and earlier allows local users to gain privileges via unknown vectors.
</code>

- [tandasat/CVE-2014-0816](https://github.com/tandasat/CVE-2014-0816)

### CVE-2014-0993 (2014-09-15)

<code>Buffer overflow in the Vcl.Graphics.TPicture.Bitmap implementation in the Visual Component Library (VCL) in Embarcadero Delphi XE6 20.0.15596.9843 and C++ Builder XE6 20.0.15596.9843 allows remote attackers to execute arbitrary code via a crafted BMP file.
</code>

- [helpsystems/Embarcadero-Workaround](https://github.com/helpsystems/Embarcadero-Workaround)

### CVE-2014-160
- [menrcom/CVE-2014-160](https://github.com/menrcom/CVE-2014-160)
- [GitMirar/heartbleed_exploit](https://github.com/GitMirar/heartbleed_exploit)

### CVE-2014-1266 (2014-02-22)

<code>The SSLVerifySignedServerKeyExchange function in libsecurity_ssl/lib/sslKeyExchange.c in the Secure Transport feature in the Data Security component in Apple iOS 6.x before 6.1.6 and 7.x before 7.0.6, Apple TV 6.x before 6.0.2, and Apple OS X 10.9.x before 10.9.2 does not check the signature in a TLS Server Key Exchange message, which allows man-in-the-middle attackers to spoof SSL servers by (1) using an arbitrary private key for the signing step or (2) omitting the signing step.
</code>

- [landonf/Testability-CVE-2014-1266](https://github.com/landonf/Testability-CVE-2014-1266)
- [linusyang/SSLPatch](https://github.com/linusyang/SSLPatch)
- [gabrielg/CVE-2014-1266-poc](https://github.com/gabrielg/CVE-2014-1266-poc)

### CVE-2014-1677 (2017-04-03)

<code>Technicolor TC7200 with firmware STD6.01.12 could allow remote attackers to obtain sensitive information.
</code>

- [tihmstar/freePW_tc7200Eploit](https://github.com/tihmstar/freePW_tc7200Eploit)

### CVE-2014-2734 (2014-04-24)

<code>The openssl extension in Ruby 2.x does not properly maintain the state of process memory after a file is reopened, which allows remote attackers to spoof signatures within the context of a Ruby script that attempts signature verification after performing a certain sequence of filesystem operations.  NOTE: this issue has been disputed by the Ruby OpenSSL team and third parties, who state that the original demonstration PoC contains errors and redundant or unnecessarily-complex code that does not appear to be related to a demonstration of the issue. As of 20140502, CVE is not aware of any public comment by the original researcher
</code>

- [gdisneyleugers/CVE-2014-2734](https://github.com/gdisneyleugers/CVE-2014-2734)
- [adrienthebo/cve-2014-2734](https://github.com/adrienthebo/cve-2014-2734)

### CVE-2014-3120 (2014-07-28)

<code>The default configuration in Elasticsearch before 1.2 enables dynamic scripting, which allows remote attackers to execute arbitrary MVEL expressions and Java code via the source parameter to _search.  NOTE: this only violates the vendor's intended security policy if the user does not run Elasticsearch in its own independent virtual machine.
</code>

- [jeffgeiger/es_inject](https://github.com/jeffgeiger/es_inject)
- [echohtp/ElasticSearch-CVE-2014-3120](https://github.com/echohtp/ElasticSearch-CVE-2014-3120)

### CVE-2014-3153 (2014-06-07)

<code>The futex_requeue function in kernel/futex.c in the Linux kernel through 3.14.5 does not ensure that calls have two different futex addresses, which allows local users to gain privileges via a crafted FUTEX_REQUEUE command that facilitates unsafe waiter modification.
</code>

- [timwr/CVE-2014-3153](https://github.com/timwr/CVE-2014-3153)
- [android-rooting-tools/libfutex_exploit](https://github.com/android-rooting-tools/libfutex_exploit)
- [geekben/towelroot](https://github.com/geekben/towelroot)

### CVE-2014-3341 (2014-08-19)

<code>The SNMP module in Cisco NX-OS 7.0(3)N1(1) and earlier on Nexus 5000 and 6000 devices provides different error messages for invalid requests depending on whether the VLAN ID exists, which allows remote attackers to enumerate VLANs via a series of requests, aka Bug ID CSCup85616.
</code>

- [ehabhussein/snmpvlan](https://github.com/ehabhussein/snmpvlan)

### CVE-2014-3466 (2014-06-03)

<code>Buffer overflow in the read_server_hello function in lib/gnutls_handshake.c in GnuTLS before 3.1.25, 3.2.x before 3.2.15, and 3.3.x before 3.3.4 allows remote servers to cause a denial of service (memory corruption) or possibly execute arbitrary code via a long session id in a ServerHello message.
</code>

- [azet/CVE-2014-3466_PoC](https://github.com/azet/CVE-2014-3466_PoC)

### CVE-2014-3566 (2014-10-15)

<code>The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other products, uses nondeterministic CBC padding, which makes it easier for man-in-the-middle attackers to obtain cleartext data via a padding-oracle attack, aka the &quot;POODLE&quot; issue.
</code>

- [mikesplain/CVE-2014-3566-poodle-cookbook](https://github.com/mikesplain/CVE-2014-3566-poodle-cookbook)
- [stdevel/poodle_protector](https://github.com/stdevel/poodle_protector)
- [cloudpassage/mangy-beast](https://github.com/cloudpassage/mangy-beast)

### CVE-2014-4113 (2014-10-15)

<code>win32k.sys in the kernel-mode drivers in Microsoft Windows Server 2003 SP2, Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, and Windows RT Gold and 8.1 allows local users to gain privileges via a crafted application, as exploited in the wild in October 2014, aka &quot;Win32k.sys Elevation of Privilege Vulnerability.&quot;
</code>

- [johnjohnsp1/CVE-2014-4113](https://github.com/johnjohnsp1/CVE-2014-4113)

### CVE-2014-4377 (2014-09-18)

<code>Integer overflow in CoreGraphics in Apple iOS before 8 and Apple TV before 7 allows remote attackers to execute arbitrary code or cause a denial of service (application crash) via a crafted PDF document.
</code>

- [feliam/CVE-2014-4377](https://github.com/feliam/CVE-2014-4377)
- [davidmurray/CVE-2014-4377](https://github.com/davidmurray/CVE-2014-4377)

### CVE-2014-4378 (2014-09-18)

<code>CoreGraphics in Apple iOS before 8 and Apple TV before 7 allows remote attackers to obtain sensitive information or cause a denial of service (out-of-bounds read and application crash) via a crafted PDF document.
</code>

- [feliam/CVE-2014-4378](https://github.com/feliam/CVE-2014-4378)

### CVE-2014-4936 (2014-12-16)

<code>The upgrade functionality in Malwarebytes Anti-Malware (MBAM) consumer before 2.0.3 and Malwarebytes Anti-Exploit (MBAE) consumer 1.04.1.1012 and earlier allow man-in-the-middle attackers to execute arbitrary code by spoofing the update server and uploading an executable.
</code>

- [0x3a/CVE-2014-4936](https://github.com/0x3a/CVE-2014-4936)

### CVE-2014-6271 (2014-09-24)

<code>GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka &quot;ShellShock.&quot;  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.
</code>

- [dlitz/bash-cve-2014-6271-fixes](https://github.com/dlitz/bash-cve-2014-6271-fixes)
- [npm/ansible-bashpocalypse](https://github.com/npm/ansible-bashpocalypse)
- [ryancnelson/patched-bash-4.3](https://github.com/ryancnelson/patched-bash-4.3)
- [jblaine/cookbook-bash-CVE-2014-6271](https://github.com/jblaine/cookbook-bash-CVE-2014-6271)
- [rrreeeyyy/cve-2014-6271-spec](https://github.com/rrreeeyyy/cve-2014-6271-spec)
- [scottjpack/shellshock_scanner](https://github.com/scottjpack/shellshock_scanner)
- [Anklebiter87/Cgi-bin_bash_Reverse](https://github.com/Anklebiter87/Cgi-bin_bash_Reverse)
- [justzx2011/bash-up](https://github.com/justzx2011/bash-up)
- [mattclegg/CVE-2014-6271](https://github.com/mattclegg/CVE-2014-6271)
- [ilismal/Nessus_CVE-2014-6271_check](https://github.com/ilismal/Nessus_CVE-2014-6271_check)
- [RainMak3r/Rainstorm](https://github.com/RainMak3r/Rainstorm)
- [gabemarshall/shocknaww](https://github.com/gabemarshall/shocknaww)
- [woltage/CVE-2014-6271](https://github.com/woltage/CVE-2014-6271)
- [ariarijp/vagrant-shellshock](https://github.com/ariarijp/vagrant-shellshock)
- [themson/shellshock](https://github.com/themson/shellshock)
- [securusglobal/BadBash](https://github.com/securusglobal/BadBash)
- [villadora/CVE-2014-6271](https://github.com/villadora/CVE-2014-6271)
- [APSL/salt-shellshock](https://github.com/APSL/salt-shellshock)
- [teedeedubya/bash-fix-exploit](https://github.com/teedeedubya/bash-fix-exploit)
- [internero/debian-lenny-bash_3.2.52-cve-2014-6271](https://github.com/internero/debian-lenny-bash_3.2.52-cve-2014-6271)
- [u20024804/bash-3.2-fixed-CVE-2014-6271](https://github.com/u20024804/bash-3.2-fixed-CVE-2014-6271)
- [u20024804/bash-4.2-fixed-CVE-2014-6271](https://github.com/u20024804/bash-4.2-fixed-CVE-2014-6271)
- [u20024804/bash-4.3-fixed-CVE-2014-6271](https://github.com/u20024804/bash-4.3-fixed-CVE-2014-6271)
- [francisck/shellshock-cgi](https://github.com/francisck/shellshock-cgi)
- [proclnas/ShellShock-CGI-Scan](https://github.com/proclnas/ShellShock-CGI-Scan)
- [sch3m4/RIS](https://github.com/sch3m4/RIS)
- [ryeyao/CVE-2014-6271_Test](https://github.com/ryeyao/CVE-2014-6271_Test)
- [cj1324/CGIShell](https://github.com/cj1324/CGIShell)
- [renanvicente/puppet-shellshock](https://github.com/renanvicente/puppet-shellshock)
- [indiandragon/Shellshock-Vulnerability-Scan](https://github.com/indiandragon/Shellshock-Vulnerability-Scan)
- [ramnes/pyshellshock](https://github.com/ramnes/pyshellshock)

### CVE-2014-6332 (2014-11-11)

<code>OleAut32.dll in OLE in Microsoft Windows Server 2003 SP2, Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, and Windows RT Gold and 8.1 allows remote attackers to execute arbitrary code via a crafted web site, as demonstrated by an array-redimensioning attempt that triggers improper handling of a size value in the SafeArrayDimen function, aka &quot;Windows OLE Automation Array Remote Code Execution Vulnerability.&quot;
</code>

- [MarkoArmitage/metasploit-framework](https://github.com/MarkoArmitage/metasploit-framework)

### CVE-2014-7169 (2014-09-25)

<code>GNU Bash through 4.3 bash43-025 processes trailing strings after certain malformed function definitions in the values of environment variables, which allows remote attackers to write to files or possibly have unknown other impact via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution.  NOTE: this vulnerability exists because of an incomplete fix for CVE-2014-6271.
</code>

- [chef-boneyard/bash-shellshock](https://github.com/chef-boneyard/bash-shellshock)

### CVE-2014-7236 (2020-02-17)

<code>Eval injection vulnerability in lib/TWiki/Plugins.pm in TWiki before 6.0.1 allows remote attackers to execute arbitrary Perl code via the debugenableplugins parameter to do/view/Main/WebHome.
</code>

- [m0nad/CVE-2014-7236_Exploit](https://github.com/m0nad/CVE-2014-7236_Exploit)

### CVE-2014-9016 (2014-11-24)

<code>The password hashing API in Drupal 7.x before 7.34 and the Secure Password Hashes (aka phpass) module 6.x-2.x before 6.x-2.1 for Drupal allows remote attackers to cause a denial of service (CPU and memory consumption) via a crafted request.
</code>

- [c0r3dump3d/wp_drupal_timing_attack](https://github.com/c0r3dump3d/wp_drupal_timing_attack)

### CVE-2014-9295 (2014-12-20)

<code>Multiple stack-based buffer overflows in ntpd in NTP before 4.2.8 allow remote attackers to execute arbitrary code via a crafted packet, related to (1) the crypto_recv function when the Autokey Authentication feature is used, (2) the ctl_putdata function, and (3) the configure function.
</code>

- [MacMiniVault/NTPUpdateSnowLeopard](https://github.com/MacMiniVault/NTPUpdateSnowLeopard)

### CVE-2014-9390 (2020-02-12)

<code>Git before 1.8.5.6, 1.9.x before 1.9.5, 2.0.x before 2.0.5, 2.1.x before 2.1.4, and 2.2.x before 2.2.1 on Windows and OS X; Mercurial before 3.2.3 on Windows and OS X; Apple Xcode before 6.2 beta 3; mine all versions before 08-12-2014; libgit2 all versions up to 0.21.2; Egit all versions before 08-12-2014; and JGit all versions before 08-12-2014 allow remote Git servers to execute arbitrary commands via a tree containing a crafted .git/config file with (1) an ignorable Unicode codepoint, (2) a git~1/config representation, or (3) mixed case that is improperly handled on a case-insensitive filesystem.
</code>

- [hakatashi/CVE-2014-9390](https://github.com/hakatashi/CVE-2014-9390)


## 2013
### CVE-2013-0156 (2013-01-13)

<code>active_support/core_ext/hash/conversions.rb in Ruby on Rails before 2.3.15, 3.0.x before 3.0.19, 3.1.x before 3.1.10, and 3.2.x before 3.2.11 does not properly restrict casts of string values, which allows remote attackers to conduct object-injection attacks and execute arbitrary code, or cause a denial of service (memory and CPU consumption) involving nested XML entity references, by leveraging Action Pack support for (1) YAML type conversion or (2) Symbol type conversion.
</code>

- [terracatta/name_reverser](https://github.com/terracatta/name_reverser)
- [heroku/heroku-CVE-2013-0156](https://github.com/heroku/heroku-CVE-2013-0156)
- [josal/crack-0.1.8-fixed](https://github.com/josal/crack-0.1.8-fixed)
- [bsodmike/rails-exploit-cve-2013-0156](https://github.com/bsodmike/rails-exploit-cve-2013-0156)
- [R3dKn33-zz/CVE-2013-0156](https://github.com/R3dKn33-zz/CVE-2013-0156)
- [Jjdt12/kuang_grade_mk11](https://github.com/Jjdt12/kuang_grade_mk11)
- [oxben10/CVE-2013-0156](https://github.com/oxben10/CVE-2013-0156)

### CVE-2013-0212 (2013-02-24)

<code>store/swift.py in OpenStack Glance Essex (2012.1), Folsom (2012.2) before 2012.2.3, and Grizzly, when in Swift single tenant mode, logs the Swift endpoint's user name and password in cleartext when the endpoint is misconfigured or unusable, allows remote authenticated users to obtain sensitive information by reading the error messages.
</code>

- [LogSec/CVE-2013-0212](https://github.com/LogSec/CVE-2013-0212)

### CVE-2013-0229 (2013-01-31)

<code>The ProcessSSDPRequest function in minissdp.c in the SSDP handler in MiniUPnP MiniUPnPd before 1.4 allows remote attackers to cause a denial of service (service crash) via a crafted request that triggers a buffer over-read.
</code>

- [lochiiconnectivity/vulnupnp](https://github.com/lochiiconnectivity/vulnupnp)

### CVE-2013-0269 (2013-02-13)

<code>The JSON gem before 1.5.5, 1.6.x before 1.6.8, and 1.7.x before 1.7.7 for Ruby allows remote attackers to cause a denial of service (resource consumption) or bypass the mass assignment protection mechanism via a crafted JSON document that triggers the creation of arbitrary Ruby symbols or certain internal objects, as demonstrated by conducting a SQL injection attack against Ruby on Rails, aka &quot;Unsafe Object Creation Vulnerability.&quot;
</code>

- [heroku/heroku-CVE-2013-0269](https://github.com/heroku/heroku-CVE-2013-0269)

### CVE-2013-0303 (2014-03-23)

<code>Unspecified vulnerability in core/ajax/translations.php in ownCloud before 4.0.12 and 4.5.x before 4.5.6 allows remote authenticated users to execute arbitrary PHP code via unknown vectors.  NOTE: this entry has been SPLIT due to different affected versions. The core/settings.php issue is covered by CVE-2013-7344.
</code>

- [CiscoCXSecurity/ownCloud_RCE_CVE-2013-0303](https://github.com/CiscoCXSecurity/ownCloud_RCE_CVE-2013-0303)

### CVE-2013-0333 (2013-01-30)

<code>lib/active_support/json/backends/yaml.rb in Ruby on Rails 2.3.x before 2.3.16 and 3.0.x before 3.0.20 does not properly convert JSON data to YAML data for processing by a YAML parser, which allows remote attackers to execute arbitrary code, conduct SQL injection attacks, or bypass authentication via crafted data that triggers unsafe decoding, a different vulnerability than CVE-2013-0156.
</code>

- [heroku/heroku-CVE-2013-0333](https://github.com/heroku/heroku-CVE-2013-0333)

### CVE-2013-225
- [PentestinGxRoot/ShellEvil](https://github.com/PentestinGxRoot/ShellEvil)

### CVE-2013-1081 (2013-03-11)

<code>Directory traversal vulnerability in MDM.php in Novell ZENworks Mobile Management (ZMM) 2.6.1 and 2.7.0 allows remote attackers to include and execute arbitrary local files via the language parameter.
</code>

- [steponequit/CVE-2013-1081](https://github.com/steponequit/CVE-2013-1081)

### CVE-2013-1300 (2013-07-10)

<code>win32k.sys in the kernel-mode drivers in Microsoft Windows XP SP2 and SP3, Windows Server 2003 SP2, Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows Server 2012, and Windows RT does not properly handle objects in memory, which allows local users to gain privileges via a crafted application, aka &quot;Win32k Memory Allocation Vulnerability.&quot;
</code>

- [Meatballs1/cve-2013-1300](https://github.com/Meatballs1/cve-2013-1300)

### CVE-2013-1488 (2013-03-08)

<code>The Java Runtime Environment (JRE) component in Oracle Java SE 7 Update 17 and earlier, and OpenJDK 6 and 7, allows remote attackers to execute arbitrary code via unspecified vectors involving reflection, Libraries, &quot;improper toString calls,&quot; and the JDBC driver manager, as demonstrated by James Forshaw during a Pwn2Own competition at CanSecWest 2013.
</code>

- [v-p-b/buherablog-cve-2013-1488](https://github.com/v-p-b/buherablog-cve-2013-1488)

### CVE-2013-1491 (2013-03-08)

<code>The Java Runtime Environment (JRE) component in Oracle Java SE 7 Update 17 and earlier, 6 Update 43 and earlier, 5.0 Update 41 and earlier, and JavaFX 2.2.7 and earlier allows remote attackers to execute arbitrary code via vectors related to 2D, as demonstrated by Joshua Drake during a Pwn2Own competition at CanSecWest 2013.
</code>

- [guhe120/CVE20131491-JIT](https://github.com/guhe120/CVE20131491-JIT)

### CVE-2013-1690 (2013-06-26)

<code>Mozilla Firefox before 22.0, Firefox ESR 17.x before 17.0.7, Thunderbird before 17.0.7, and Thunderbird ESR 17.x before 17.0.7 do not properly handle onreadystatechange events in conjunction with page reloading, which allows remote attackers to cause a denial of service (application crash) or possibly execute arbitrary code via a crafted web site that triggers an attempt to execute data at an unmapped memory location.
</code>

- [vlad902/annotated-fbi-tbb-exploit](https://github.com/vlad902/annotated-fbi-tbb-exploit)

### CVE-2013-1763 (2013-02-28)

<code>Array index error in the __sock_diag_rcv_msg function in net/core/sock_diag.c in the Linux kernel before 3.7.10 allows local users to gain privileges via a large family value in a Netlink message.
</code>

- [qkrtjsrbs315/CVE-2013-1763](https://github.com/qkrtjsrbs315/CVE-2013-1763)

### CVE-2013-1775 (2013-03-04)

<code>sudo 1.6.0 through 1.7.10p6 and sudo 1.8.0 through 1.8.6p6 allows local users or physically proximate attackers to bypass intended time restrictions and retain privileges without re-authenticating by setting the system clock and sudo user timestamp to the epoch.
</code>

- [bekhzod0725/perl-CVE-2013-1775](https://github.com/bekhzod0725/perl-CVE-2013-1775)

### CVE-2013-1965 (2013-07-10)

<code>Apache Struts Showcase App 2.0.0 through 2.3.13, as used in Struts 2 before 2.3.14.3, allows remote attackers to execute arbitrary OGNL code via a crafted parameter name that is not properly handled when invoking a redirect.
</code>

- [cinno/CVE-2013-1965](https://github.com/cinno/CVE-2013-1965)

### CVE-2013-2006 (2013-05-21)

<code>OpenStack Identity (Keystone) Grizzly 2013.1.1, when DEBUG mode logging is enabled, logs the (1) admin_token and (2) LDAP password in plaintext, which allows local users to obtain sensitive by reading the log file.
</code>

- [LogSec/CVE-2013-2006](https://github.com/LogSec/CVE-2013-2006)

### CVE-2013-2028 (2013-07-18)

<code>The ngx_http_parse_chunked function in http/ngx_http_parse.c in nginx 1.3.9 through 1.4.0 allows remote attackers to cause a denial of service (crash) and execute arbitrary code via a chunked Transfer-Encoding request with a large chunk size, which triggers an integer signedness error and a stack-based buffer overflow.
</code>

- [danghvu/nginx-1.4.0](https://github.com/danghvu/nginx-1.4.0)
- [kitctf/nginxpwn](https://github.com/kitctf/nginxpwn)
- [tachibana51/CVE-2013-2028-x64-bypass-ssp-and-pie-PoC](https://github.com/tachibana51/CVE-2013-2028-x64-bypass-ssp-and-pie-PoC)
- [m4drat/CVE-2013-2028-Exploit](https://github.com/m4drat/CVE-2013-2028-Exploit)
- [jptr218/nginxhack](https://github.com/jptr218/nginxhack)
- [Sunqiz/CVE-2013-2028-reproduction](https://github.com/Sunqiz/CVE-2013-2028-reproduction)
- [xiw1ll/CVE-2013-2028_Checker](https://github.com/xiw1ll/CVE-2013-2028_Checker)

### CVE-2013-2094 (2013-05-14)

<code>The perf_swevent_init function in kernel/events/core.c in the Linux kernel before 3.8.9 uses an incorrect integer data type, which allows local users to gain privileges via a crafted perf_event_open system call.
</code>

- [realtalk/cve-2013-2094](https://github.com/realtalk/cve-2013-2094)
- [hiikezoe/libperf_event_exploit](https://github.com/hiikezoe/libperf_event_exploit)
- [Pashkela/CVE-2013-2094](https://github.com/Pashkela/CVE-2013-2094)
- [tarunyadav/fix-cve-2013-2094](https://github.com/tarunyadav/fix-cve-2013-2094)
- [timhsutw/cve-2013-2094](https://github.com/timhsutw/cve-2013-2094)
- [vnik5287/CVE-2013-2094](https://github.com/vnik5287/CVE-2013-2094)

### CVE-2013-2165 (2013-07-22)

<code>ResourceBuilderImpl.java in the RichFaces 3.x through 5.x implementation in Red Hat JBoss Web Framework Kit before 2.3.0, Red Hat JBoss Web Platform through 5.2.0, Red Hat JBoss Enterprise Application Platform through 4.3.0 CP10 and 5.x through 5.2.0, Red Hat JBoss BRMS through 5.3.1, Red Hat JBoss SOA Platform through 4.3.0 CP05 and 5.x through 5.3.1, Red Hat JBoss Portal through 4.3 CP07 and 5.x through 5.2.2, and Red Hat JBoss Operations Network through 2.4.2 and 3.x through 3.1.2 does not restrict the classes for which deserialization methods can be called, which allows remote attackers to execute arbitrary code via crafted serialized data.
</code>

- [Pastea/CVE-2013-2165](https://github.com/Pastea/CVE-2013-2165)

### CVE-2013-2171 (2013-07-02)

<code>The vm_map_lookup function in sys/vm/vm_map.c in the mmap implementation in the kernel in FreeBSD 9.0 through 9.1-RELEASE-p4 does not properly determine whether a task should have write access to a memory location, which allows local users to bypass filesystem write permissions and consequently gain privileges via a crafted application that leverages read permissions, and makes mmap and ptrace system calls.
</code>

- [0xGabe/FreeBSD-9.0-9.1-Privilege-Escalation](https://github.com/0xGabe/FreeBSD-9.0-9.1-Privilege-Escalation)

### CVE-2013-2186 (2013-10-28)

<code>The DiskFileItem class in Apache Commons FileUpload, as used in Red Hat JBoss BRMS 5.3.1; JBoss Portal 4.3 CP07, 5.2.2, and 6.0.0; and Red Hat JBoss Web Server 1.0.2 allows remote attackers to write to arbitrary files via a NULL byte in a file name in a serialized instance.
</code>

- [GrrrDog/ACEDcup](https://github.com/GrrrDog/ACEDcup)
- [sa1g0n1337/Payload_CVE_2013_2186](https://github.com/sa1g0n1337/Payload_CVE_2013_2186)
- [sa1g0n1337/CVE_2013_2186](https://github.com/sa1g0n1337/CVE_2013_2186)

### CVE-2013-2217 (2013-09-23)

<code>cache.py in Suds 0.4, when tempdir is set to None, allows local users to redirect SOAP queries and possibly have other unspecified impact via a symlink attack on a cache file with a predictable name in /tmp/suds/.
</code>

- [Osirium/suds](https://github.com/Osirium/suds)

### CVE-2013-2251 (2013-07-18)

<code>Apache Struts 2.0.0 through 2.3.15 allows remote attackers to execute arbitrary OGNL expressions via a parameter with a crafted (1) action:, (2) redirect:, or (3) redirectAction: prefix.
</code>

- [nth347/CVE-2013-2251](https://github.com/nth347/CVE-2013-2251)

### CVE-2013-2595 (2014-08-31)

<code>The device-initialization functionality in the MSM camera driver for the Linux kernel 2.6.x and 3.x, as used in Qualcomm Innovation Center (QuIC) Android contributions for MSM devices and other products, enables MSM_CAM_IOCTL_SET_MEM_MAP_INFO ioctl calls for an unrestricted mmap interface, which allows attackers to gain privileges via a crafted application.
</code>

- [fi01/libmsm_cameraconfig_exploit](https://github.com/fi01/libmsm_cameraconfig_exploit)

### CVE-2013-2596 (2013-04-13)

<code>Integer overflow in the fb_mmap function in drivers/video/fbmem.c in the Linux kernel before 3.8.9, as used in a certain Motorola build of Android 4.1.2 and other products, allows local users to create a read-write memory mapping for the entirety of kernel memory, and consequently gain privileges, via crafted /dev/graphics/fb0 mmap2 system calls, as demonstrated by the Motochopper pwn program.
</code>

- [hiikezoe/libfb_mem_exploit](https://github.com/hiikezoe/libfb_mem_exploit)

### CVE-2013-2597 (2014-08-31)

<code>Stack-based buffer overflow in the acdb_ioctl function in audio_acdb.c in the acdb audio driver for the Linux kernel 2.6.x and 3.x, as used in Qualcomm Innovation Center (QuIC) Android contributions for MSM devices and other products, allows attackers to gain privileges via an application that leverages /dev/msm_acdb access and provides a large size value in an ioctl argument.
</code>

- [fi01/libmsm_acdb_exploit](https://github.com/fi01/libmsm_acdb_exploit)

### CVE-2013-2729 (2013-05-16)

<code>Integer overflow in Adobe Reader and Acrobat 9.x before 9.5.5, 10.x before 10.1.7, and 11.x before 11.0.03 allows attackers to execute arbitrary code via unspecified vectors, a different vulnerability than CVE-2013-2727.
</code>

- [feliam/CVE-2013-2729](https://github.com/feliam/CVE-2013-2729)

### CVE-2013-2730 (2013-05-16)

<code>Buffer overflow in Adobe Reader and Acrobat 9.x before 9.5.5, 10.x before 10.1.7, and 11.x before 11.0.03 allows attackers to execute arbitrary code via unspecified vectors, a different vulnerability than CVE-2013-2733.
</code>

- [feliam/CVE-2013-2730](https://github.com/feliam/CVE-2013-2730)

### CVE-2013-2842 (2013-05-22)

<code>Use-after-free vulnerability in Google Chrome before 27.0.1453.93 allows remote attackers to cause a denial of service or possibly have unspecified other impact via vectors related to the handling of widgets.
</code>

- [173210/spider](https://github.com/173210/spider)

### CVE-2013-2977 (2013-05-10)

<code>Integer overflow in IBM Notes 8.5.x before 8.5.3 FP4 Interim Fix 1 and 9.x before 9.0 Interim Fix 1 on Windows, and 8.5.x before 8.5.3 FP5 and 9.x before 9.0.1 on Linux, allows remote attackers to execute arbitrary code via a malformed PNG image in a previewed e-mail message, aka SPR NPEI96K82Q.
</code>

- [defrancescojp/CVE-2013-2977](https://github.com/defrancescojp/CVE-2013-2977)

### CVE-2013-3214 (2020-01-28)

<code>vtiger CRM 5.4.0 and earlier contain a PHP Code Injection Vulnerability in 'vtigerolservice.php'.
</code>

- [shadofren/CVE-2013-3214](https://github.com/shadofren/CVE-2013-3214)

### CVE-2013-3319 (2013-08-16)

<code>The GetComputerSystem method in the HostControl service in SAP Netweaver 7.03 allows remote attackers to obtain sensitive information via a crafted SOAP request to TCP port 1128.
</code>

- [devoteam-cybertrust/cve-2013-3319](https://github.com/devoteam-cybertrust/cve-2013-3319)

### CVE-2013-3651 (2013-06-29)

<code>LOCKON EC-CUBE 2.11.2 through 2.12.4 allows remote attackers to conduct unspecified PHP code-injection attacks via a crafted string, related to data/class/SC_CheckError.php and data/class/SC_FormParam.php.
</code>

- [motikan2010/CVE-2013-3651](https://github.com/motikan2010/CVE-2013-3651)

### CVE-2013-3660 (2013-05-24)

<code>The EPATHOBJ::pprFlattenRec function in win32k.sys in the kernel-mode drivers in Microsoft Windows XP SP2 and SP3, Windows Server 2003 SP2, Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, and Windows Server 2012 does not properly initialize a pointer for the next object in a certain list, which allows local users to obtain write access to the PATHRECORD chain, and consequently gain privileges, by triggering excessive consumption of paged memory and then making many FlattenPath function calls, aka &quot;Win32k Read AV Vulnerability.&quot;
</code>

- [ExploitCN/CVE-2013-3660-x64-WIN7](https://github.com/ExploitCN/CVE-2013-3660-x64-WIN7)

### CVE-2013-3664 (2014-07-01)

<code>Trimble SketchUp (formerly Google SketchUp) before 2013 (13.0.3689) allows remote attackers to execute arbitrary code via a crafted color palette table in a MAC Pict texture, which triggers an out-of-bounds stack write.  NOTE: this vulnerability exists because of an incomplete fix for CVE-2013-3662.  NOTE: this issue was SPLIT due to different affected products and codebases (ADT1); CVE-2013-7388 has been assigned to the paintlib issue.
</code>

- [defrancescojp/CVE-2013-3664_MAC](https://github.com/defrancescojp/CVE-2013-3664_MAC)
- [defrancescojp/CVE-2013-3664_BMP](https://github.com/defrancescojp/CVE-2013-3664_BMP)

### CVE-2013-3827 (2013-10-16)

<code>Unspecified vulnerability in the Oracle GlassFish Server component in Oracle Fusion Middleware 2.1.1, 3.0.1, and 3.1.2; the Oracle JDeveloper component in Oracle Fusion Middleware 11.1.2.3.0, 11.1.2.4.0, and 12.1.2.0.0; and the Oracle WebLogic Server component in Oracle Fusion Middleware 10.3.6.0 and 12.1.1 allows remote attackers to affect confidentiality via unknown vectors related to Java Server Faces or Web Container.
</code>

- [thistehneisen/CVE-2013-3827](https://github.com/thistehneisen/CVE-2013-3827)

### CVE-2013-3900 (2013-12-11)

<code>Why is Microsoft republishing a CVE from 2013?\nWe are republishing CVE-2013-3900 in the Security Update Guide to update the Security Updates table and to inform customers that the EnableCertPaddingCheck is available in all currently supported versions of Windows 10 and Windows 11. While the format is different from the original CVE published in 2013, except for clarifications about how to configure the EnableCertPaddingCheck registry value, the information herein remains unchanged from the original text published on December 10, 2013,\nMicrosoft does not plan to enforce the stricter verification behavior as a default functionality on supported releases of Microsoft Windows. This behavior remains available as an opt-in feature via reg key setting, and is available on supported editions of Windows released since December 10, 2013. This includes all currently supported versions of Windows 10 and Windows 11. The supporting code for this reg key was incorporated at the time of release for Windows 10 and Windows 11, so no security update is required; however, the reg key must be set. See the Security Updates table for the list of affected software.\nVulnerability Description\nA remote code execution vulnerability exists in the way that the WinVerifyTrust function handles Windows Authenticode signature verification for portable executable (PE) files. An anonymous attacker could exploit the vulnerability by modifying an existing signed executable file to leverage unverified portions of the file in such a way as to add malicious code to the file without invalidating the signature. An attacker who successfully exploited this vulnerability could take complete control of an affected system. An attacker could then install programs; view, change, or delete data; or create new accounts with full user rights.\nIf a user is logged on with administrative user rights, an attacker who successfully exploited this vulnerability could take complete control of an affected system. An attacker could then install programs; view, change, or delete data; or create new accounts with full user rights. Users whose accounts are configured to have fewer user rights on the system could be less impacted than users who operate with administrative user rights.\nExploitation of this vulnerability requires that a user or application run or install a specially crafted, signed PE file. An attacker could modify an... See more at https://msrc.microsoft.com/update-guide/vulnerability/CVE-2013-3900
</code>

- [snoopopsec/vulnerability-CVE-2013-3900](https://github.com/snoopopsec/vulnerability-CVE-2013-3900)
- [CyberCondor/Fix-WinVerifyTrustSignatureValidationVuln](https://github.com/CyberCondor/Fix-WinVerifyTrustSignatureValidationVuln)
- [Securenetology/CVE-2013-3900](https://github.com/Securenetology/CVE-2013-3900)
- [OtisSymbos/CVE-2013-3900-WinTrustVerify](https://github.com/OtisSymbos/CVE-2013-3900-WinTrustVerify)
- [AdenilsonSantos/WinVerifyTrust](https://github.com/AdenilsonSantos/WinVerifyTrust)

### CVE-2013-4002 (2013-07-23)

<code>XMLscanner.java in Apache Xerces2 Java Parser before 2.12.0, as used in the Java Runtime Environment (JRE) in IBM Java 5.0 before 5.0 SR16-FP3, 6 before 6 SR14, 6.0.1 before 6.0.1 SR6, and 7 before 7 SR5 as well as Oracle Java SE 7u40 and earlier, Java SE 6u60 and earlier, Java SE 5.0u51 and earlier, JRockit R28.2.8 and earlier, JRockit R27.7.6 and earlier, Java SE Embedded 7u40 and earlier, and possibly other products allows remote attackers to cause a denial of service via vectors related to XML attribute names.
</code>

- [tafamace/CVE-2013-4002](https://github.com/tafamace/CVE-2013-4002)

### CVE-2013-4175 (2020-01-23)

<code>MySecureShell 1.31 has a Local Denial of Service Vulnerability
</code>

- [hartwork/mysecureshell-issues](https://github.com/hartwork/mysecureshell-issues)

### CVE-2013-4362 (2013-09-30)

<code>WEB-DAV Linux File System (davfs2) 1.4.6 and 1.4.7 allow local users to gain privileges via unknown attack vectors in (1) kernel_interface.c and (2) mount_davfs.c, related to the &quot;system&quot; function.
</code>

- [notclement/Automatic-davfs2-1.4.6-1.4.7-Local-Privilege-Escalation](https://github.com/notclement/Automatic-davfs2-1.4.6-1.4.7-Local-Privilege-Escalation)

### CVE-2013-4378 (2013-09-30)

<code>Cross-site scripting (XSS) vulnerability in HtmlSessionInformationsReport.java in JavaMelody 1.46 and earlier allows remote attackers to inject arbitrary web script or HTML via a crafted X-Forwarded-For header.
</code>

- [theratpack/grails-javamelody-sample-app](https://github.com/theratpack/grails-javamelody-sample-app)
- [epicosy/VUL4J-50](https://github.com/epicosy/VUL4J-50)

### CVE-2013-4434 (2013-10-25)

<code>Dropbear SSH Server before 2013.59 generates error messages for a failed logon attempt with different time delays depending on whether the user account exists, which allows remote attackers to discover valid usernames.
</code>

- [styx00/Dropbear_CVE-2013-4434](https://github.com/styx00/Dropbear_CVE-2013-4434)

### CVE-2013-4547 (2013-11-23)

<code>nginx 0.8.41 through 1.4.3 and 1.5.x before 1.5.7 allows remote attackers to bypass intended restrictions via an unescaped space character in a URI.
</code>

- [cyberharsh/Nginx-CVE-2013-4547](https://github.com/cyberharsh/Nginx-CVE-2013-4547)

### CVE-2013-4710 (2014-03-03)

<code>Android 3.0 through 4.1.x on Disney Mobile, eAccess, KDDI, NTT DOCOMO, SoftBank, and other devices does not properly implement the WebView class, which allows remote attackers to execute arbitrary methods of Java objects or cause a denial of service (reboot) via a crafted web page, as demonstrated by use of the WebView.addJavascriptInterface method, a related issue to CVE-2012-6636.
</code>

- [Snip3R69/CVE-2013-4710-WebView-RCE-Vulnerability](https://github.com/Snip3R69/CVE-2013-4710-WebView-RCE-Vulnerability)

### CVE-2013-4730 (2014-05-15)

<code>Buffer overflow in PCMan's FTP Server 2.0.7 allows remote attackers to execute arbitrary code via a long string in a USER command.
</code>

- [t0rt3ll1n0/PCmanBoF](https://github.com/t0rt3ll1n0/PCmanBoF)

### CVE-2013-4784 (2013-07-08)

<code>The HP Integrated Lights-Out (iLO) BMC implementation allows remote attackers to bypass authentication and execute arbitrary IPMI commands by using cipher suite 0 (aka cipher zero) and an arbitrary password.
</code>

- [alexoslabs/ipmitest](https://github.com/alexoslabs/ipmitest)

### CVE-2013-4786 (2013-07-08)

<code>The IPMI 2.0 specification supports RMCP+ Authenticated Key-Exchange Protocol (RAKP) authentication, which allows remote attackers to obtain password hashes and conduct offline password guessing attacks by obtaining the HMAC from a RAKP message 2 response from a BMC.
</code>

- [fin3ss3g0d/CosmicRakp](https://github.com/fin3ss3g0d/CosmicRakp)

### CVE-2013-5065 (2013-11-27)

<code>NDProxy.sys in the kernel in Microsoft Windows XP SP2 and SP3 and Server 2003 SP2 allows local users to gain privileges via a crafted application, as exploited in the wild in November 2013.
</code>

- [Friarfukd/RobbinHood](https://github.com/Friarfukd/RobbinHood)

### CVE-2013-5211 (2014-01-02)

<code>The monlist feature in ntp_request.c in ntpd in NTP before 4.2.7p26 allows remote attackers to cause a denial of service (traffic amplification) via forged (1) REQ_MON_GETLIST or (2) REQ_MON_GETLIST_1 requests, as exploited in the wild in December 2013.
</code>

- [dani87/ntpscanner](https://github.com/dani87/ntpscanner)
- [suedadam/ntpscanner](https://github.com/suedadam/ntpscanner)
- [sepehrdaddev/ntpdos](https://github.com/sepehrdaddev/ntpdos)
- [0xhav0c/CVE-2013-5211](https://github.com/0xhav0c/CVE-2013-5211)
- [requiempentest/-exploit-check-CVE-2013-5211](https://github.com/requiempentest/-exploit-check-CVE-2013-5211)
- [requiempentest/NTP_CVE-2013-5211](https://github.com/requiempentest/NTP_CVE-2013-5211)

### CVE-2013-5664 (2013-08-31)

<code>Cross-site scripting (XSS) vulnerability in the web-based device-management API browser in Palo Alto Networks PAN-OS before 4.1.13 and 5.0.x before 5.0.6 allows remote attackers to inject arbitrary web script or HTML via crafted data, aka Ref ID 50908.
</code>

- [phusion/rails-cve-2012-5664-test](https://github.com/phusion/rails-cve-2012-5664-test)

### CVE-2013-5842 (2013-10-16)

<code>Unspecified vulnerability in Oracle Java SE 7u40 and earlier, Java SE 6u60 and earlier, Java SE 5.0u51 and earlier, and Java SE Embedded 7u40 and earlier allows remote attackers to affect confidentiality, integrity, and availability via unknown vectors related to Libraries, a different vulnerability than CVE-2013-5850.
</code>

- [guhe120/CVE-2013-5842](https://github.com/guhe120/CVE-2013-5842)

### CVE-2013-6117 (2014-07-11)

<code>Dahua DVR 2.608.0000.0 and 2.608.GV00.0 allows remote attackers to bypass authentication and obtain sensitive information including user credentials, change user passwords, clear log files, and perform other actions via a request to TCP port 37777.
</code>

- [milo2012/CVE-2013-6117](https://github.com/milo2012/CVE-2013-6117)

### CVE-2013-6282 (2013-11-19)

<code>The (1) get_user and (2) put_user API functions in the Linux kernel before 3.5.5 on the v6k and v7 ARM platforms do not validate certain addresses, which allows attackers to read or modify the contents of arbitrary kernel memory locations via a crafted application, as exploited in the wild against Android devices in October and November 2013.
</code>

- [fi01/libput_user_exploit](https://github.com/fi01/libput_user_exploit)
- [fi01/libget_user_exploit](https://github.com/fi01/libget_user_exploit)
- [jeboo/bypasslkm](https://github.com/jeboo/bypasslkm)
- [timwr/CVE-2013-6282](https://github.com/timwr/CVE-2013-6282)

### CVE-2013-6375 (2013-11-23)

<code>Xen 4.2.x and 4.3.x, when using Intel VT-d for PCI passthrough, does not properly flush the TLB after clearing a present translation table entry, which allows local guest administrators to cause a denial of service or gain privileges via unspecified vectors related to an &quot;inverted boolean parameter.&quot;
</code>

- [bl4ck5un/cve-2013-6375](https://github.com/bl4ck5un/cve-2013-6375)

### CVE-2013-6490 (2014-02-06)

<code>The SIMPLE protocol functionality in Pidgin before 2.10.8 allows remote attackers to have an unspecified impact via a negative Content-Length header, which triggers a buffer overflow.
</code>

- [Everdoh/CVE-2013-6490](https://github.com/Everdoh/CVE-2013-6490)

### CVE-2013-6668 (2014-03-05)

<code>Multiple unspecified vulnerabilities in Google V8 before 3.24.35.10, as used in Google Chrome before 33.0.1750.146, allow attackers to cause a denial of service or possibly have other impact via unknown vectors.
</code>

- [sdneon/CveTest](https://github.com/sdneon/CveTest)

### CVE-2013-6987 (2013-12-31)

<code>Multiple directory traversal vulnerabilities in the FileBrowser components in Synology DiskStation Manager (DSM) before 4.3-3810 Update 3 allow remote attackers to read, write, and delete arbitrary files via a .. (dot dot) in the (1) path parameter to file_delete.cgi or (2) folder_path parameter to file_share.cgi in webapi/FileStation/; (3) dlink parameter to fbdownload/; or unspecified parameters to (4) html5_upload.cgi, (5) file_download.cgi, (6) file_sharing.cgi, (7) file_MVCP.cgi, or (8) file_rename.cgi in webapi/FileStation/.
</code>

- [stoicboomer/CVE-2013-6987](https://github.com/stoicboomer/CVE-2013-6987)


## 2012
### CVE-2012-0002 (2012-03-13)

<code>The Remote Desktop Protocol (RDP) implementation in Microsoft Windows XP SP2 and SP3, Windows Server 2003 SP2, Windows Vista SP2, Windows Server 2008 SP2, R2, and R2 SP1, and Windows 7 Gold and SP1 does not properly process packets in memory, which allows remote attackers to execute arbitrary code by sending crafted RDP packets triggering access to an object that (1) was not properly initialized or (2) is deleted, aka &quot;Remote Desktop Protocol Vulnerability.&quot;
</code>

- [zhangkaibin0921/MS12-020-CVE-2012-0002](https://github.com/zhangkaibin0921/MS12-020-CVE-2012-0002)

### CVE-2012-0003 (2012-01-10)

<code>Unspecified vulnerability in winmm.dll in Windows Multimedia Library in Windows Media Player (WMP) in Microsoft Windows XP SP2 and SP3, Server 2003 SP2, Vista SP2, and Server 2008 SP2 allows remote attackers to execute arbitrary code via a crafted MIDI file, aka &quot;MIDI Remote Code Execution Vulnerability.&quot;
</code>

- [k0keoyo/CVE-2012-0003_eXP](https://github.com/k0keoyo/CVE-2012-0003_eXP)

### CVE-2012-0056 (2012-01-27)

<code>The mem_write function in the Linux kernel before 3.2.2, when ASLR is disabled, does not properly check permissions when writing to /proc/&lt;pid&gt;/mem, which allows local users to gain privileges by modifying process memory, as demonstrated by Mempodipper.
</code>

- [pythonone/CVE-2012-0056](https://github.com/pythonone/CVE-2012-0056)

### CVE-2012-0152 (2012-03-13)

<code>The Remote Desktop Protocol (RDP) service in Microsoft Windows Server 2008 R2 and R2 SP1 and Windows 7 Gold and SP1 allows remote attackers to cause a denial of service (application hang) via a series of crafted packets, aka &quot;Terminal Server Denial of Service Vulnerability.&quot;
</code>

- [rutvijjethwa/RDP_jammer](https://github.com/rutvijjethwa/RDP_jammer)

### CVE-2012-0158 (2012-04-10)

<code>The (1) ListView, (2) ListView2, (3) TreeView, and (4) TreeView2 ActiveX controls in MSCOMCTL.OCX in the Common Controls in Microsoft Office 2003 SP3, 2007 SP2 and SP3, and 2010 Gold and SP1; Office 2003 Web Components SP3; SQL Server 2000 SP4, 2005 SP4, and 2008 SP2, SP3, and R2; BizTalk Server 2002 SP1; Commerce Server 2002 SP4, 2007 SP2, and 2009 Gold and R2; Visual FoxPro 8.0 SP1 and 9.0 SP2; and Visual Basic 6.0 Runtime allow remote attackers to execute arbitrary code via a crafted (a) web site, (b) Office document, or (c) .rtf file that triggers &quot;system state&quot; corruption, as exploited in the wild in April 2012, aka &quot;MSCOMCTL.OCX RCE Vulnerability.&quot;
</code>

- [RobertoLeonFR-ES/Exploit-Win32.CVE-2012-0158.F.doc](https://github.com/RobertoLeonFR-ES/Exploit-Win32.CVE-2012-0158.F.doc)
- [Sunqiz/CVE-2012-0158-reproduction](https://github.com/Sunqiz/CVE-2012-0158-reproduction)

### CVE-2012-1495 (2020-01-27)

<code>install/index.php in WebCalendar before 1.2.5 allows remote attackers to execute arbitrary code via the form_single_user_login parameter.
</code>

- [axelbankole/CVE-2012-1495-Webcalendar-](https://github.com/axelbankole/CVE-2012-1495-Webcalendar-)

### CVE-2012-1675 (2012-05-08)

<code>The TNS Listener, as used in Oracle Database 11g 11.1.0.7, 11.2.0.2, and 11.2.0.3, and 10g 10.2.0.3, 10.2.0.4, and 10.2.0.5, as used in Oracle Fusion Middleware, Enterprise Manager, E-Business Suite, and possibly other products, allows remote attackers to execute arbitrary database commands by performing a remote registration of a database (1) instance or (2) service name that already exists, then conducting a man-in-the-middle (MITM) attack to hijack database connections, aka &quot;TNS Poison.&quot;
</code>

- [bongbongco/CVE-2012-1675](https://github.com/bongbongco/CVE-2012-1675)

### CVE-2012-1723 (2012-06-16)

<code>Unspecified vulnerability in the Java Runtime Environment (JRE) component in Oracle Java SE 7 update 4 and earlier, 6 update 32 and earlier, 5 update 35 and earlier, and 1.4.2_37 and earlier allows remote attackers to affect confidentiality, integrity, and availability via unknown vectors related to Hotspot.
</code>

- [EthanNJC/CVE-2012-1723](https://github.com/EthanNJC/CVE-2012-1723)

### CVE-2012-1823 (2012-05-11)

<code>sapi/cgi/cgi_main.c in PHP before 5.3.12 and 5.4.x before 5.4.2, when configured as a CGI script (aka php-cgi), does not properly handle query strings that lack an = (equals sign) character, which allows remote attackers to execute arbitrary code by placing command-line options in the query string, related to lack of skipping a certain php_getopt for the 'd' case.
</code>

- [drone789/CVE-2012-1823](https://github.com/drone789/CVE-2012-1823)
- [tardummy01/oscp_scripts-1](https://github.com/tardummy01/oscp_scripts-1)
- [Unix13/metasploitable2](https://github.com/Unix13/metasploitable2)
- [cyberharsh/PHP_CVE-2012-1823](https://github.com/cyberharsh/PHP_CVE-2012-1823)
- [0xl0k1/CVE-2012-1823](https://github.com/0xl0k1/CVE-2012-1823)
- [Jimmy01240397/CVE-2012-1823-Analyze](https://github.com/Jimmy01240397/CVE-2012-1823-Analyze)
- [JasonHobs/CVE-2012-1823-exploit-for-https-user-password-web](https://github.com/JasonHobs/CVE-2012-1823-exploit-for-https-user-password-web)

### CVE-2012-1831 (2012-07-05)

<code>Heap-based buffer overflow in WellinTech KingView 6.53 allows remote attackers to execute arbitrary code via a crafted packet to TCP port 555.
</code>

- [Astrowmist/POC-CVE-2012-1831](https://github.com/Astrowmist/POC-CVE-2012-1831)

### CVE-2012-1870 (2012-07-10)

<code>The CBC mode in the TLS protocol, as used in Microsoft Windows XP SP2 and SP3, Windows Server 2003 SP2, Windows Vista SP2, Windows Server 2008 SP2, R2, and R2 SP1, Windows 7 Gold and SP1, and other products, allows remote web servers to obtain plaintext data by triggering multiple requests to a third-party HTTPS server and sniffing the network during the resulting HTTPS session, aka &quot;TLS Protocol Vulnerability.&quot;
</code>

- [dja2TaqkGEEfA45/CVE-2012-1870](https://github.com/dja2TaqkGEEfA45/CVE-2012-1870)

### CVE-2012-1876 (2012-06-12)

<code>Microsoft Internet Explorer 6 through 9, and 10 Consumer Preview, does not properly handle objects in memory, which allows remote attackers to execute arbitrary code by attempting to access a nonexistent object, leading to a heap-based buffer overflow, aka &quot;Col Element Remote Code Execution Vulnerability,&quot; as demonstrated by VUPEN during a Pwn2Own competition at CanSecWest 2012.
</code>

- [WizardVan/CVE-2012-1876](https://github.com/WizardVan/CVE-2012-1876)
- [ExploitCN/CVE-2012-1876-win7_x86_and_win7x64](https://github.com/ExploitCN/CVE-2012-1876-win7_x86_and_win7x64)

### CVE-2012-1889 (2012-06-13)

<code>Microsoft XML Core Services 3.0, 4.0, 5.0, and 6.0 accesses uninitialized memory locations, which allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted web site.
</code>

- [whu-enjoy/CVE-2012-1889](https://github.com/whu-enjoy/CVE-2012-1889)
- [l-iberty/cve-2012-1889](https://github.com/l-iberty/cve-2012-1889)

### CVE-2012-2122 (2012-06-26)

<code>sql/password.c in Oracle MySQL 5.1.x before 5.1.63, 5.5.x before 5.5.24, and 5.6.x before 5.6.6, and MariaDB 5.1.x before 5.1.62, 5.2.x before 5.2.12, 5.3.x before 5.3.6, and 5.5.x before 5.5.23, when running in certain environments with certain implementations of the memcmp function, allows remote attackers to bypass authentication by repeatedly authenticating with the same incorrect password, which eventually causes a token comparison to succeed due to an improperly-checked return value.
</code>

- [Avinza/CVE-2012-2122-scanner](https://github.com/Avinza/CVE-2012-2122-scanner)
- [cyberharsh/Oracle-mysql-CVE-2012-2122](https://github.com/cyberharsh/Oracle-mysql-CVE-2012-2122)
- [zhangkaibin0921/CVE-2012-2122](https://github.com/zhangkaibin0921/CVE-2012-2122)

### CVE-2012-2593 (2020-02-06)

<code>Cross-site scripting (XSS) vulnerability in the administrative interface in Atmail Webmail Server 6.4 allows remote attackers to inject arbitrary web script or HTML via the Date field of an email.
</code>

- [AndrewTrube/CVE-2012-2593](https://github.com/AndrewTrube/CVE-2012-2593)

### CVE-2012-2661 (2012-06-22)

<code>The Active Record component in Ruby on Rails 3.0.x before 3.0.13, 3.1.x before 3.1.5, and 3.2.x before 3.2.4 does not properly implement the passing of request data to a where method in an ActiveRecord class, which allows remote attackers to conduct certain SQL injection attacks via nested query parameters that leverage unintended recursion, a related issue to CVE-2012-2695.
</code>

- [r4x0r1337/-CVE-2012-2661-ActiveRecord-SQL-injection-](https://github.com/r4x0r1337/-CVE-2012-2661-ActiveRecord-SQL-injection-)

### CVE-2012-2688 (2012-07-20)

<code>Unspecified vulnerability in the _php_stream_scandir function in the stream implementation in PHP before 5.3.15 and 5.4.x before 5.4.5 has unknown impact and remote attack vectors, related to an &quot;overflow.&quot;
</code>

- [shelld3v/CVE-2012-2688](https://github.com/shelld3v/CVE-2012-2688)

### CVE-2012-2982 (2012-09-11)

<code>file/show.cgi in Webmin 1.590 and earlier allows remote authenticated users to execute arbitrary commands via an invalid character in a pathname, as demonstrated by a | (pipe) character.
</code>

- [cd6629/CVE-2012-2982-Python-PoC](https://github.com/cd6629/CVE-2012-2982-Python-PoC)
- [OstojaOfficial/CVE-2012-2982](https://github.com/OstojaOfficial/CVE-2012-2982)
- [AlexJS6/CVE-2012-2982_Python](https://github.com/AlexJS6/CVE-2012-2982_Python)
- [Ari-Weinberg/CVE-2012-2982](https://github.com/Ari-Weinberg/CVE-2012-2982)
- [JohnHammond/CVE-2012-2982](https://github.com/JohnHammond/CVE-2012-2982)
- [R00tendo/CVE-2012-2982](https://github.com/R00tendo/CVE-2012-2982)
- [blu3ming/CVE-2012-2982](https://github.com/blu3ming/CVE-2012-2982)
- [0xF331-D3AD/CVE-2012-2982](https://github.com/0xF331-D3AD/CVE-2012-2982)
- [0xTas/CVE-2012-2982](https://github.com/0xTas/CVE-2012-2982)
- [LeDucKhiem/CVE-2012-2982](https://github.com/LeDucKhiem/CVE-2012-2982)
- [CpyRe/CVE-2012-2982](https://github.com/CpyRe/CVE-2012-2982)
- [Shadow-Spinner/CVE-2012-2982_python](https://github.com/Shadow-Spinner/CVE-2012-2982_python)
- [elliotosama/CVE-2012-2982](https://github.com/elliotosama/CVE-2012-2982)
- [SieGer05/CVE-2012-2982-Webmin-Exploit](https://github.com/SieGer05/CVE-2012-2982-Webmin-Exploit)

### CVE-2012-3137 (2012-09-21)

<code>The authentication protocol in Oracle Database Server 10.2.0.3, 10.2.0.4, 10.2.0.5, 11.1.0.7, 11.2.0.2, and 11.2.0.3 allows remote attackers to obtain the session key and salt for arbitrary users, which leaks information about the cryptographic hash and makes it easier to conduct brute force password guessing attacks, aka &quot;stealth password cracking vulnerability.&quot;
</code>

- [hantwister/o5logon-fetch](https://github.com/hantwister/o5logon-fetch)
- [r1-/cve-2012-3137](https://github.com/r1-/cve-2012-3137)

### CVE-2012-3153 (2012-10-16)

<code>Unspecified vulnerability in the Oracle Reports Developer component in Oracle Fusion Middleware 11.1.1.4, 11.1.1.6, and 11.1.2.0 allows remote attackers to affect confidentiality and integrity via unknown vectors related to Servlet.  NOTE: the previous information is from the October 2012 CPU. Oracle has not commented on claims from the original researcher that the PARSEQUERY function allows remote attackers to obtain database credentials via reports/rwservlet/parsequery, and that this issue occurs in earlier versions.  NOTE: this can be leveraged with CVE-2012-3152 to execute arbitrary code by uploading a .jsp file.
</code>

- [Mekanismen/pwnacle-fusion](https://github.com/Mekanismen/pwnacle-fusion)

### CVE-2012-3716 (2012-09-20)

<code>CoreText in Apple Mac OS X 10.7.x before 10.7.5 allows remote attackers to execute arbitrary code or cause a denial of service (out-of-bounds write or read) via a crafted text glyph.
</code>

- [d4rkcat/killosx](https://github.com/d4rkcat/killosx)

### CVE-2012-4220 (2012-11-30)

<code>diagchar_core.c in the Qualcomm Innovation Center (QuIC) Diagnostics (aka DIAG) kernel-mode driver for Android 2.3 through 4.2 allows attackers to execute arbitrary code or cause a denial of service (incorrect pointer dereference) via an application that uses crafted arguments in a local diagchar_ioctl call.
</code>

- [hiikezoe/diaggetroot](https://github.com/hiikezoe/diaggetroot)
- [poliva/root-zte-open](https://github.com/poliva/root-zte-open)

### CVE-2012-4431 (2012-12-19)

<code>org/apache/catalina/filters/CsrfPreventionFilter.java in Apache Tomcat 6.x before 6.0.36 and 7.x before 7.0.32 allows remote attackers to bypass the cross-site request forgery (CSRF) protection mechanism via a request that lacks a session identifier.
</code>

- [imjdl/CVE-2012-4431](https://github.com/imjdl/CVE-2012-4431)

### CVE-2012-4681 (2012-08-28)

<code>Multiple vulnerabilities in the Java Runtime Environment (JRE) component in Oracle Java SE 7 Update 6 and earlier allow remote attackers to execute arbitrary code via a crafted applet that bypasses SecurityManager restrictions by (1) using com.sun.beans.finder.ClassFinder.findClass and leveraging an exception with the forName method to access restricted classes from arbitrary packages such as sun.awt.SunToolkit, then (2) using &quot;reflection with a trusted immediate caller&quot; to leverage the getField method to access and modify private fields, as exploited in the wild in August 2012 using Gondzz.class and Gondvv.class.
</code>

- [benjholla/CVE-2012-4681-Armoring](https://github.com/benjholla/CVE-2012-4681-Armoring)
- [ZH3FENG/PoCs-CVE_2012_4681](https://github.com/ZH3FENG/PoCs-CVE_2012_4681)

### CVE-2012-4792 (2012-12-30)

<code>Use-after-free vulnerability in Microsoft Internet Explorer 6 through 8 allows remote attackers to execute arbitrary code via a crafted web site that triggers access to an object that (1) was not properly allocated or (2) is deleted, as demonstrated by a CDwnBindInfo object, and exploited in the wild in December 2012.
</code>

- [WizardVan/CVE-2012-4792](https://github.com/WizardVan/CVE-2012-4792)

### CVE-2012-4869 (2012-09-06)

<code>The callme_startcall function in recordings/misc/callme_page.php in FreePBX 2.9, 2.10, and earlier allows remote attackers to execute arbitrary commands via the callmenum parameter in a c action.
</code>

- [bitc0de/Elastix-Remote-Code-Execution](https://github.com/bitc0de/Elastix-Remote-Code-Execution)

### CVE-2012-4929 (2012-09-15)

<code>The TLS protocol 1.2 and earlier, as used in Mozilla Firefox, Google Chrome, Qt, and other products, can encrypt compressed data without properly obfuscating the length of the unencrypted data, which allows man-in-the-middle attackers to obtain plaintext HTTP headers by observing length differences during a series of guesses in which a string in an HTTP request potentially matches an unknown string in an HTTP header, aka a &quot;CRIME&quot; attack.
</code>

- [mpgn/CRIME-poc](https://github.com/mpgn/CRIME-poc)
- [anthophilee/A2SV--SSL-VUL-Scan](https://github.com/anthophilee/A2SV--SSL-VUL-Scan)

### CVE-2012-4960 (2013-06-20)

<code>The Huawei NE5000E, MA5200G, NE40E, NE80E, ATN, NE40, NE80, NE20E-X6, NE20, ME60, CX600, CX200, CX300, ACU, WLAN AC 6605, S9300, S7700, S2300, S3300, S5300, S3300HI, S5300HI, S5306, S6300, S2700, S3700, S5700, S6700, AR G3, H3C AR(OEM IN), AR 19, AR 29, AR 49, Eudemon100E, Eudemon200, Eudemon300, Eudemon500, Eudemon1000, Eudemon1000E-U/USG5300, Eudemon1000E-X/USG5500, Eudemon8080E/USG9300, Eudemon8160E/USG9300, Eudemon8000E-X/USG9500, E200E-C/USG2200, E200E-X3/USG2200, E200E-X5/USG2200, E200E-X7/USG2200, E200E-C/USG5100, E200E-X3/USG5100, E200E-X5/USG5100, E200E-X7/USG5100, E200E-B/USG2100, E200E-X1/USG2100, E200E-X2/USG2100, SVN5300, SVN2000, SVN5000, SVN3000, NIP100, NIP200, NIP1000, NIP2100, NIP2200, and NIP5100 use the DES algorithm for stored passwords, which makes it easier for context-dependent attackers to obtain cleartext passwords via a brute-force attack.
</code>

- [ghcohu/Decrypt-passwords-for-Huawei-routers-and-switches-CVE-2012-4960](https://github.com/ghcohu/Decrypt-passwords-for-Huawei-routers-and-switches-CVE-2012-4960)

### CVE-2012-5106 (2014-06-20)

<code>Stack-based buffer overflow in FreeFloat FTP Server 1.0 allows remote authenticated users to execute arbitrary code via a long string in a PUT command.
</code>

- [war4uthor/CVE-2012-5106](https://github.com/war4uthor/CVE-2012-5106)

### CVE-2012-5321 (2012-10-08)

<code>tiki-featured_link.php in TikiWiki CMS/Groupware 8.3 allows remote attackers to load arbitrary web site pages into frames and conduct phishing attacks via the url parameter, aka &quot;frame injection.&quot;
</code>

- [Cappricio-Securities/CVE-2012-5321](https://github.com/Cappricio-Securities/CVE-2012-5321)

### CVE-2012-5519 (2012-11-20)

<code>CUPS 1.4.4, when running in certain Linux distributions such as Debian GNU/Linux, stores the web interface administrator key in /var/run/cups/certs/0 using certain permissions, which allows local users in the lpadmin group to read or write arbitrary files as root by leveraging the web interface.
</code>

- [p1ckzi/CVE-2012-5519](https://github.com/p1ckzi/CVE-2012-5519)

### CVE-2012-5575 (2013-08-19)

<code>Apache CXF 2.5.x before 2.5.10, 2.6.x before CXF 2.6.7, and 2.7.x before CXF 2.7.4 does not verify that a specified cryptographic algorithm is allowed by the WS-SecurityPolicy AlgorithmSuite definition before decrypting, which allows remote attackers to force CXF to use weaker cryptographic algorithms than intended and makes it easier to decrypt communications, aka &quot;XML Encryption backwards compatibility attack.&quot;
</code>

- [tafamace/CVE-2012-5575](https://github.com/tafamace/CVE-2012-5575)

### CVE-2012-5613 (2012-12-03)

<code>MySQL 5.5.19 and possibly other versions, and MariaDB 5.5.28a and possibly other versions, when configured to assign the FILE privilege to users who should not have administrative privileges, allows remote authenticated users to gain privileges by leveraging the FILE privilege to create files as the MySQL administrator. NOTE: the vendor disputes this issue, stating that this is only a vulnerability when the administrator does not follow recommendations in the product's installation documentation. NOTE: it could be argued that this should not be included in CVE because it is a configuration issue.
</code>

- [Hood3dRob1n/MySQL-Fu.rb](https://github.com/Hood3dRob1n/MySQL-Fu.rb)
- [w4fz5uck5/UDFPwn-CVE-2012-5613](https://github.com/w4fz5uck5/UDFPwn-CVE-2012-5613)

### CVE-2012-5664
- [phusion/rails-cve-2012-5664-test](https://github.com/phusion/rails-cve-2012-5664-test)

### CVE-2012-5958 (2013-01-31)

<code>Stack-based buffer overflow in the unique_service_name function in ssdp/ssdp_server.c in the SSDP parser in the portable SDK for UPnP Devices (aka libupnp, formerly the Intel SDK for UPnP devices) before 1.6.18 allows remote attackers to execute arbitrary code via a UDP packet with a crafted string that is not properly handled after a certain pointer subtraction.
</code>

- [lochiiconnectivity/vulnupnp](https://github.com/lochiiconnectivity/vulnupnp)

### CVE-2012-5960 (2013-01-31)

<code>Stack-based buffer overflow in the unique_service_name function in ssdp/ssdp_server.c in the SSDP parser in the portable SDK for UPnP Devices (aka libupnp, formerly the Intel SDK for UPnP devices) before 1.6.18 allows remote attackers to execute arbitrary code via a long UDN (aka upnp:rootdevice) field in a UDP packet.
</code>

- [finn79426/CVE-2012-5960-PoC](https://github.com/finn79426/CVE-2012-5960-PoC)

### CVE-2012-6066 (2012-12-04)

<code>freeSSHd.exe in freeSSHd through 1.2.6 allows remote attackers to bypass authentication via a crafted session, as demonstrated by an OpenSSH client with modified versions of ssh.c and sshconnect2.c.
</code>

- [bongbongco/CVE-2012-6066](https://github.com/bongbongco/CVE-2012-6066)

### CVE-2012-6636 (2014-03-03)

<code>The Android API before 17 does not properly restrict the WebView.addJavascriptInterface method, which allows remote attackers to execute arbitrary methods of Java objects by using the Java Reflection API within crafted JavaScript code that is loaded into the WebView component in an application targeted to API level 16 or earlier, a related issue to CVE-2013-4710.
</code>

- [xckevin/AndroidWebviewInjectDemo](https://github.com/xckevin/AndroidWebviewInjectDemo)
- [Snip3R69/CVE-2013-4710-WebView-RCE-Vulnerability](https://github.com/Snip3R69/CVE-2013-4710-WebView-RCE-Vulnerability)


## 2011
### CVE-2011-0228 (2011-08-29)

<code>The Data Security component in Apple iOS before 4.2.10 and 4.3.x before 4.3.5 does not check the basicConstraints parameter during validation of X.509 certificate chains, which allows man-in-the-middle attackers to spoof an SSL server by using a non-CA certificate to sign a certificate for an arbitrary domain.
</code>

- [jan0/isslfix](https://github.com/jan0/isslfix)

### CVE-2011-3192 (2011-08-29)

<code>The byterange filter in the Apache HTTP Server 1.3.x, 2.0.x through 2.0.64, and 2.2.x through 2.2.19 allows remote attackers to cause a denial of service (memory and CPU consumption) via a Range header that expresses multiple overlapping ranges, as exploited in the wild in August 2011, a different vulnerability than CVE-2007-0086.
</code>

- [tkisason/KillApachePy](https://github.com/tkisason/KillApachePy)

### CVE-2011-3872 (2011-10-27)

<code>Puppet 2.6.x before 2.6.12 and 2.7.x before 2.7.6, and Puppet Enterprise (PE) Users 1.0, 1.1, and 1.2 before 1.2.4, when signing an agent certificate, adds the Puppet master's certdnsnames values to the X.509 Subject Alternative Name field of the certificate, which allows remote attackers to spoof a Puppet master via a man-in-the-middle (MITM) attack against an agent that uses an alternate DNS name for the master, aka &quot;AltNames Vulnerability.&quot;
</code>

- [puppetlabs-toy-chest/puppetlabs-cve20113872](https://github.com/puppetlabs-toy-chest/puppetlabs-cve20113872)


## 2010
### CVE-2010-0219 (2010-10-18)

<code>Apache Axis2, as used in dswsbobje.war in SAP BusinessObjects Enterprise XI 3.2, CA ARCserve D2D r15, and other products, has a default password of axis2 for the admin account, which makes it easier for remote attackers to execute arbitrary code by uploading a crafted web service.
</code>

- [veritas-rt/CVE-2010-0219](https://github.com/veritas-rt/CVE-2010-0219)

### CVE-2010-0232 (2010-01-21)

<code>The kernel in Microsoft Windows NT 3.1 through Windows 7, including Windows 2000 SP4, Windows XP SP2 and SP3, Windows Server 2003 SP2, Windows Vista Gold, SP1, and SP2, and Windows Server 2008 Gold and SP2, when access to 16-bit applications is enabled on a 32-bit x86 platform, does not properly validate certain BIOS calls, which allows local users to gain privileges by crafting a VDM_TIB data structure in the Thread Environment Block (TEB), and then calling the NtVdmControl function to start the Windows Virtual DOS Machine (aka NTVDM) subsystem, leading to improperly handled exceptions involving the #GP trap handler (nt!KiTrap0D), aka &quot;Windows Kernel Exception Handler Vulnerability.&quot;
</code>

- [azorfus/CVE-2010-0232](https://github.com/azorfus/CVE-2010-0232)

### CVE-2010-0426 (2010-02-24)

<code>sudo 1.6.x before 1.6.9p21 and 1.7.x before 1.7.2p4, when a pseudo-command is enabled, permits a match between the name of the pseudo-command and the name of an executable file in an arbitrary directory, which allows local users to gain privileges via a crafted executable file, as demonstrated by a file named sudoedit in a user's home directory.
</code>

- [t0kx/privesc-CVE-2010-0426](https://github.com/t0kx/privesc-CVE-2010-0426)
- [cved-sources/cve-2010-0426](https://github.com/cved-sources/cve-2010-0426)
- [g1vi/CVE-2010-0426](https://github.com/g1vi/CVE-2010-0426)

### CVE-2010-0738 (2010-04-28)

<code>The JMX-Console web application in JBossAs in Red Hat JBoss Enterprise Application Platform (aka JBoss EAP or JBEAP) 4.2 before 4.2.0.CP09 and 4.3 before 4.3.0.CP08 performs access control only for the GET and POST methods, which allows remote attackers to send requests to this application's GET handler by using a different method.
</code>

- [1872892142/jboss-autopwn-1](https://github.com/1872892142/jboss-autopwn-1)
- [gitcollect/jboss-autopwn](https://github.com/gitcollect/jboss-autopwn)

### CVE-2010-1205 (2010-06-30)

<code>Buffer overflow in pngpread.c in libpng before 1.2.44 and 1.4.x before 1.4.3, as used in progressive applications, might allow remote attackers to execute arbitrary code via a PNG image that triggers an additional data row.
</code>

- [mk219533/CVE-2010-1205](https://github.com/mk219533/CVE-2010-1205)

### CVE-2010-1240 (2010-04-05)

<code>Adobe Reader and Acrobat 9.x before 9.3.3, and 8.x before 8.2.3 on Windows and Mac OS X, do not restrict the contents of one text field in the Launch File warning dialog, which makes it easier for remote attackers to trick users into executing an arbitrary local program that was specified in a PDF document, as demonstrated by a text field that claims that the Open button will enable the user to read an encrypted message.
</code>

- [Jasmoon99/Embedded-PDF](https://github.com/Jasmoon99/Embedded-PDF)
- [omarothmann/Embedded-Backdoor-Connection](https://github.com/omarothmann/Embedded-Backdoor-Connection)
- [asepsaepdin/CVE-2010-1240](https://github.com/asepsaepdin/CVE-2010-1240)

### CVE-2010-1411 (2010-06-17)

<code>Multiple integer overflows in the Fax3SetupState function in tif_fax3.c in the FAX3 decoder in LibTIFF before 3.9.3, as used in ImageIO in Apple Mac OS X 10.5.8 and Mac OS X 10.6 before 10.6.4, allow remote attackers to execute arbitrary code or cause a denial of service (application crash) via a crafted TIFF file that triggers a heap-based buffer overflow.
</code>

- [MAVProxyUser/httpfuzz-robomiller](https://github.com/MAVProxyUser/httpfuzz-robomiller)

### CVE-2010-1622 (2010-06-21)

<code>SpringSource Spring Framework 2.5.x before 2.5.6.SEC02, 2.5.7 before 2.5.7.SR01, and 3.0.x before 3.0.3 allows remote attackers to execute arbitrary code via an HTTP request containing class.classLoader.URLs[0]=jar: followed by a URL of a crafted .jar file.
</code>

- [DDuarte/springshell-rce-poc](https://github.com/DDuarte/springshell-rce-poc)
- [strainerart/Spring4Shell](https://github.com/strainerart/Spring4Shell)
- [HandsomeCat00/Spring-CVE-2010-1622](https://github.com/HandsomeCat00/Spring-CVE-2010-1622)
- [E-bounce/cve-2010-1622_learning_environment](https://github.com/E-bounce/cve-2010-1622_learning_environment)

### CVE-2010-1938 (2010-05-28)

<code>Off-by-one error in the __opiereadrec function in readrec.c in libopie in OPIE 2.4.1-test1 and earlier, as used on FreeBSD 6.4 through 8.1-PRERELEASE and other platforms, allows remote attackers to cause a denial of service (daemon crash) or possibly execute arbitrary code via a long username, as demonstrated by a long USER command to the FreeBSD 8.0 ftpd.
</code>

- [Nexxus67/cve-2010-1938](https://github.com/Nexxus67/cve-2010-1938)

### CVE-2010-2075 (2010-06-15)

<code>UnrealIRCd 3.2.8.1, as distributed on certain mirror sites from November 2009 through June 2010, contains an externally introduced modification (Trojan Horse) in the DEBUG3_DOLOG_SYSTEM macro, which allows remote attackers to execute arbitrary commands.
</code>

- [MFernstrom/OffensivePascal-CVE-2010-2075](https://github.com/MFernstrom/OffensivePascal-CVE-2010-2075)
- [chancej715/UnrealIRCd-3.2.8.1-Backdoor-Command-Execution](https://github.com/chancej715/UnrealIRCd-3.2.8.1-Backdoor-Command-Execution)
- [FredBrave/CVE-2010-2075-UnrealIRCd-3.2.8.1](https://github.com/FredBrave/CVE-2010-2075-UnrealIRCd-3.2.8.1)
- [JoseLRC97/UnrealIRCd-3.2.8.1-Backdoor-Command-Execution](https://github.com/JoseLRC97/UnrealIRCd-3.2.8.1-Backdoor-Command-Execution)
- [abhinavcybersec/PenTest-Lab](https://github.com/abhinavcybersec/PenTest-Lab)

### CVE-2010-2387 (2012-12-21)

<code>vicious-extensions/ve-misc.c in GNOME Display Manager (gdm) 2.20.x before 2.20.11, when GDM debug is enabled, logs the user password when it contains invalid UTF8 encoded characters, which might allow local users to gain privileges by reading the information from syslog logs.
</code>

- [LogSec/CVE-2010-2387](https://github.com/LogSec/CVE-2010-2387)

### CVE-2010-2553 (2010-08-11)

<code>The Cinepak codec in Microsoft Windows XP SP2 and SP3, Windows Vista SP1 and SP2, and Windows 7 does not properly decompress media files, which allows remote attackers to execute arbitrary code via a crafted file, aka &quot;Cinepak Codec Decompression Vulnerability.&quot;
</code>

- [Sunqiz/cve-2010-2553-reproduction](https://github.com/Sunqiz/cve-2010-2553-reproduction)

### CVE-2010-3124 (2010-08-26)

<code>Untrusted search path vulnerability in bin/winvlc.c in VLC Media Player 1.1.3 and earlier allows local users, and possibly remote attackers, to execute arbitrary code and conduct DLL hijacking attacks via a Trojan horse wintab32.dll that is located in the same folder as a .mp3 file.
</code>

- [Nhom6KTLT/CVE-2010-3124](https://github.com/Nhom6KTLT/CVE-2010-3124)
- [KOBUKOVUI/DLL_Injection_On_VLC](https://github.com/KOBUKOVUI/DLL_Injection_On_VLC)

### CVE-2010-3332 (2010-09-22)

<code>Microsoft .NET Framework 1.1 SP1, 2.0 SP1 and SP2, 3.5, 3.5 SP1, 3.5.1, and 4.0, as used for ASP.NET in Microsoft Internet Information Services (IIS), provides detailed error codes during decryption attempts, which allows remote attackers to decrypt and modify encrypted View State (aka __VIEWSTATE) form data, and possibly forge cookies or read application files, via a padding oracle attack, aka &quot;ASP.NET Padding Oracle Vulnerability.&quot;
</code>

- [bongbongco/MS10-070](https://github.com/bongbongco/MS10-070)

### CVE-2010-3333 (2010-11-10)

<code>Stack-based buffer overflow in Microsoft Office XP SP3, Office 2003 SP3, Office 2007 SP2, Office 2010, Office 2004 and 2008 for Mac, Office for Mac 2011, and Open XML File Format Converter for Mac allows remote attackers to execute arbitrary code via crafted RTF data, aka &quot;RTF Stack Buffer Overflow Vulnerability.&quot;
</code>

- [whiteHat001/cve-2010-3333](https://github.com/whiteHat001/cve-2010-3333)
- [Sunqiz/CVE-2010-3333-reproduction](https://github.com/Sunqiz/CVE-2010-3333-reproduction)

### CVE-2010-3490 (2010-09-28)

<code>Directory traversal vulnerability in page.recordings.php in the System Recordings component in the configuration interface in FreePBX 2.8.0 and earlier allows remote authenticated administrators to create arbitrary files via a .. (dot dot) in the usersnum parameter to admin/config.php, as demonstrated by creating a .php file under the web root.
</code>

- [moayadalmalat/CVE-2010-3490](https://github.com/moayadalmalat/CVE-2010-3490)

### CVE-2010-3600 (2011-01-19)

<code>Unspecified vulnerability in the Client System Analyzer component in Oracle Database Server 11.1.0.7 and 11.2.0.1 and Enterprise Manager Grid Control 10.2.0.5 allows remote attackers to affect confidentiality, integrity, and availability via unknown vectors. NOTE: the previous information was obtained from the January 2011 CPU.  Oracle has not commented on claims from a reliable third party coordinator that this issue involves an exposed JSP script that accepts XML uploads in conjunction with NULL bytes in an unspecified parameter that allow execution of arbitrary code.
</code>

- [LAITRUNGMINHDUC/CVE-2010-3600-PythonHackOracle11gR2](https://github.com/LAITRUNGMINHDUC/CVE-2010-3600-PythonHackOracle11gR2)

### CVE-2010-3847 (2011-01-07)

<code>elf/dl-load.c in ld.so in the GNU C Library (aka glibc or libc6) through 2.11.2, and 2.12.x through 2.12.1, does not properly handle a value of $ORIGIN for the LD_AUDIT environment variable, which allows local users to gain privileges via a crafted dynamic shared object (DSO) located in an arbitrary directory.
</code>

- [magisterquis/cve-2010-3847](https://github.com/magisterquis/cve-2010-3847)

### CVE-2010-3904 (2010-12-06)

<code>The rds_page_copy_user function in net/rds/page.c in the Reliable Datagram Sockets (RDS) protocol implementation in the Linux kernel before 2.6.36 does not properly validate addresses obtained from user space, which allows local users to gain privileges via crafted use of the sendmsg and recvmsg system calls.
</code>

- [redhatkaty/-cve-2010-3904-report](https://github.com/redhatkaty/-cve-2010-3904-report)

### CVE-2010-3971 (2010-12-22)

<code>Use-after-free vulnerability in the CSharedStyleSheet::Notify function in the Cascading Style Sheets (CSS) parser in mshtml.dll, as used in Microsoft Internet Explorer 6 through 8 and other products, allows remote attackers to execute arbitrary code or cause a denial of service (application crash) via a self-referential @import rule in a stylesheet, aka &quot;CSS Memory Corruption Vulnerability.&quot;
</code>

- [nektra/CVE-2010-3971-hotpatch](https://github.com/nektra/CVE-2010-3971-hotpatch)

### CVE-2010-4221 (2010-11-09)

<code>Multiple stack-based buffer overflows in the pr_netio_telnet_gets function in netio.c in ProFTPD before 1.3.3c allow remote attackers to execute arbitrary code via vectors involving a TELNET IAC escape character to a (1) FTP or (2) FTPS server.
</code>

- [M41doror/cve-2010-4221](https://github.com/M41doror/cve-2010-4221)

### CVE-2010-4231 (2010-11-16)

<code>Directory traversal vulnerability in the web-based administration interface on the Camtron CMNC-200 Full HD IP Camera and TecVoz CMNC-200 Megapixel IP Camera with firmware 1.102A-008 allows remote attackers to read arbitrary files via a .. (dot dot) in the URI.
</code>

- [K3ysTr0K3R/CVE-2010-4231-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2010-4231-EXPLOIT)

### CVE-2010-4476 (2011-02-17)

<code>The Double.parseDouble method in Java Runtime Environment (JRE) in Oracle Java SE and Java for Business 6 Update 23 and earlier, 5.0 Update 27 and earlier, and 1.4.2_29 and earlier, as used in OpenJDK, Apache, JBossweb, and other products, allows remote attackers to cause a denial of service via a crafted string that triggers an infinite loop of estimations during conversion to a double-precision binary floating-point number, as demonstrated using 2.2250738585072012e-308.
</code>

- [grzegorzblaszczyk/CVE-2010-4476-check](https://github.com/grzegorzblaszczyk/CVE-2010-4476-check)

### CVE-2010-4669 (2011-01-07)

<code>The Neighbor Discovery (ND) protocol implementation in the IPv6 stack in Microsoft Windows XP, Windows Server 2003, Windows Vista, Windows Server 2008, and Windows 7 allows remote attackers to cause a denial of service (CPU consumption and system hang) by sending many Router Advertisement (RA) messages with different source addresses, as demonstrated by the flood_router6 program in the thc-ipv6 package.
</code>

- [wrong-commit/CVE-2010-4669](https://github.com/wrong-commit/CVE-2010-4669)

### CVE-2010-4804 (2011-06-09)

<code>The Android browser in Android before 2.3.4 allows remote attackers to obtain SD card contents via crafted content:// URIs, related to (1) BrowserActivity.java and (2) BrowserSettings.java in com/android/browser/.
</code>

- [thomascannon/android-cve-2010-4804](https://github.com/thomascannon/android-cve-2010-4804)

### CVE-2010-5230 (2012-09-07)

<code>Multiple untrusted search path vulnerabilities in MicroStation 7.1 allow local users to gain privileges via a Trojan horse (1) mptools.dll, (2) baseman.dll, (3) wintab32.dll, or (4) wintab.dll file in the current working directory, as demonstrated by a directory that contains a .hln or .rdl file.  NOTE: some of these details are obtained from third party information.
</code>

- [otofoto/CVE-2010-5230](https://github.com/otofoto/CVE-2010-5230)

### CVE-2010-5301 (2014-06-13)

<code>Stack-based buffer overflow in Kolibri 2.0 allows remote attackers to execute arbitrary code via a long URI in a HEAD request.
</code>

- [lem0nSec/CVE-2010-5301](https://github.com/lem0nSec/CVE-2010-5301)


## 2009
### CVE-2009-0182 (2009-01-20)

<code>Buffer overflow in VUPlayer 2.49 and earlier allows user-assisted attackers to execute arbitrary code via a long URL in a File line in a .pls file, as demonstrated by an http URL on a File1 line.
</code>

- [nobodyatall648/CVE-2009-0182](https://github.com/nobodyatall648/CVE-2009-0182)

### CVE-2009-0229 (2009-06-10)

<code>The Windows Printing Service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP2, Vista Gold, SP1, and SP2, and Server 2008 SP2 allows local users to read arbitrary files via a crafted separator page, aka &quot;Print Spooler Read File Vulnerability.&quot;
</code>

- [zveriu/CVE-2009-0229-PoC](https://github.com/zveriu/CVE-2009-0229-PoC)

### CVE-2009-0347 (2009-01-29)

<code>Open redirect vulnerability in cs.html in the Autonomy (formerly Verity) Ultraseek search engine allows remote attackers to redirect users to arbitrary web sites and conduct phishing attacks via the url parameter.
</code>

- [Cappricio-Securities/CVE-2009-0347](https://github.com/Cappricio-Securities/CVE-2009-0347)

### CVE-2009-0473 (2009-02-06)

<code>Open redirect vulnerability in the web interface in the Rockwell Automation ControlLogix 1756-ENBT/A EtherNet/IP Bridge Module allows remote attackers to redirect users to arbitrary web sites and conduct phishing attacks via unspecified vectors.
</code>

- [akbarq/CVE-2009-0473-check](https://github.com/akbarq/CVE-2009-0473-check)

### CVE-2009-0689 (2009-07-01)

<code>Array index error in the (1) dtoa implementation in dtoa.c (aka pdtoa.c) and the (2) gdtoa (aka new dtoa) implementation in gdtoa/misc.c in libc, as used in multiple operating systems and products including in FreeBSD 6.4 and 7.2, NetBSD 5.0, OpenBSD 4.5, Mozilla Firefox 3.0.x before 3.0.15 and 3.5.x before 3.5.4, K-Meleon 1.5.3, SeaMonkey 1.1.8, and other products, allows context-dependent attackers to cause a denial of service (application crash) and possibly execute arbitrary code via a large precision value in the format argument to a printf function, which triggers incorrect memory allocation and a heap-based buffer overflow during conversion to a floating-point number.
</code>

- [Fullmetal5/str2hax](https://github.com/Fullmetal5/str2hax)

### CVE-2009-1151 (2009-03-26)

<code>Static code injection vulnerability in setup.php in phpMyAdmin 2.11.x before 2.11.9.5 and 3.x before 3.1.3.1 allows remote attackers to inject arbitrary PHP code into a configuration file via the save action.
</code>

- [pagvac/pocs](https://github.com/pagvac/pocs)
- [e-Thug/PhpMyAdmin](https://github.com/e-Thug/PhpMyAdmin)

### CVE-2009-1244 (2009-04-13)

<code>Unspecified vulnerability in the virtual machine display function in VMware Workstation 6.5.1 and earlier; VMware Player 2.5.1 and earlier; VMware ACE 2.5.1 and earlier; VMware Server 1.x before 1.0.9 build 156507 and 2.x before 2.0.1 build 156745; VMware Fusion before 2.0.4 build 159196; VMware ESXi 3.5; and VMware ESX 3.0.2, 3.0.3, and 3.5 allows guest OS users to execute arbitrary code on the host OS via unknown vectors, a different vulnerability than CVE-2008-4916.
</code>

- [piotrbania/vmware_exploit_pack_CVE-2009-1244](https://github.com/piotrbania/vmware_exploit_pack_CVE-2009-1244)

### CVE-2009-1324 (2009-04-17)

<code>Stack-based buffer overflow in Mini-stream ASX to MP3 Converter 3.0.0.7 allows remote attackers to execute arbitrary code via a long URI in a playlist (.m3u) file.
</code>

- [war4uthor/CVE-2009-1324](https://github.com/war4uthor/CVE-2009-1324)

### CVE-2009-1330 (2009-04-17)

<code>Stack-based buffer overflow in Easy RM to MP3 Converter allows remote attackers to execute arbitrary code via a long filename in a playlist (.pls) file.
</code>

- [adenkiewicz/CVE-2009-1330](https://github.com/adenkiewicz/CVE-2009-1330)
- [war4uthor/CVE-2009-1330](https://github.com/war4uthor/CVE-2009-1330)
- [exploitwritter/CVE-2009-1330_EasyRMToMp3Converter](https://github.com/exploitwritter/CVE-2009-1330_EasyRMToMp3Converter)

### CVE-2009-1437 (2009-04-27)

<code>Stack-based buffer overflow in PortableApps CoolPlayer Portable (aka CoolPlayer+ Portable) 2.19.6 and earlier allows remote attackers to execute arbitrary code via a long string in a malformed playlist (.m3u) file. NOTE: this may overlap CVE-2008-3408.
</code>

- [HanseSecure/CVE-2009-1437](https://github.com/HanseSecure/CVE-2009-1437)

### CVE-2009-1904 (2009-06-11)

<code>The BigDecimal library in Ruby 1.8.6 before p369 and 1.8.7 before p173 allows context-dependent attackers to cause a denial of service (application crash) via a string argument that represents a large number, as demonstrated by an attempted conversion to the Float data type.
</code>

- [NZKoz/bigdecimal-segfault-fix](https://github.com/NZKoz/bigdecimal-segfault-fix)

### CVE-2009-2265 (2009-07-05)

<code>Multiple directory traversal vulnerabilities in FCKeditor before 2.6.4.1 allow remote attackers to create executable files in arbitrary directories via directory traversal sequences in the input to unspecified connector modules, as exploited in the wild for remote code execution in July 2009, related to the file browser and the editor/filemanager/connectors/ directory.
</code>

- [zaphoxx/zaphoxx-coldfusion](https://github.com/zaphoxx/zaphoxx-coldfusion)
- [n3rdh4x0r/CVE-2009-2265](https://github.com/n3rdh4x0r/CVE-2009-2265)
- [p1ckzi/CVE-2009-2265](https://github.com/p1ckzi/CVE-2009-2265)
- [0xDTC/Adobe-ColdFusion-8-RCE-CVE-2009-2265](https://github.com/0xDTC/Adobe-ColdFusion-8-RCE-CVE-2009-2265)

### CVE-2009-2692 (2009-08-14)

<code>The Linux kernel 2.6.0 through 2.6.30.4, and 2.4.4 through 2.4.37.4, does not initialize all function pointers for socket operations in proto_ops structures, which allows local users to trigger a NULL pointer dereference and gain privileges by using mmap to map page zero, placing arbitrary code on this page, and then invoking an unavailable operation, as demonstrated by the sendpage operation (sock_sendpage function) on a PF_PPPOX socket.
</code>

- [jdvalentini/CVE-2009-2692](https://github.com/jdvalentini/CVE-2009-2692)

### CVE-2009-2698 (2009-08-27)

<code>The udp_sendmsg function in the UDP implementation in (1) net/ipv4/udp.c and (2) net/ipv6/udp.c in the Linux kernel before 2.6.19 allows local users to gain privileges or cause a denial of service (NULL pointer dereference and system crash) via vectors involving the MSG_MORE flag and a UDP socket.
</code>

- [xiaoxiaoleo/CVE-2009-2698](https://github.com/xiaoxiaoleo/CVE-2009-2698)

### CVE-2009-3036 (2010-02-23)

<code>Cross-site scripting (XSS) vulnerability in the console in Symantec IM Manager 8.3 and 8.4 before 8.4.13 allows remote attackers to inject arbitrary web script or HTML via unspecified vectors.
</code>

- [brinhosa/CVE-2009-3036](https://github.com/brinhosa/CVE-2009-3036)

### CVE-2009-3103 (2009-09-08)

<code>Array index error in the SMBv2 protocol implementation in srv2.sys in Microsoft Windows Vista Gold, SP1, and SP2, Windows Server 2008 Gold and SP2, and Windows 7 RC allows remote attackers to execute arbitrary code or cause a denial of service (system crash) via an &amp; (ampersand) character in a Process ID High header field in a NEGOTIATE PROTOCOL REQUEST packet, which triggers an attempted dereference of an out-of-bounds memory location, aka &quot;SMBv2 Negotiation Vulnerability.&quot; NOTE: some of these details are obtained from third party information.
</code>

- [sooklalad/ms09050](https://github.com/sooklalad/ms09050)
- [sec13b/ms09-050_CVE-2009-3103](https://github.com/sec13b/ms09-050_CVE-2009-3103)
- [Sic4rio/CVE-2009-3103---srv2.sys-SMB-Code-Execution-Python-MS09-050-](https://github.com/Sic4rio/CVE-2009-3103---srv2.sys-SMB-Code-Execution-Python-MS09-050-)

### CVE-2009-3555 (2009-11-09)

<code>The TLS protocol, and the SSL protocol 3.0 and possibly earlier, as used in Microsoft Internet Information Services (IIS) 7.0, mod_ssl in the Apache HTTP Server 2.2.14 and earlier, OpenSSL before 0.9.8l, GnuTLS 2.8.5 and earlier, Mozilla Network Security Services (NSS) 3.12.4 and earlier, multiple Cisco products, and other products, does not properly associate renegotiation handshakes with an existing connection, which allows man-in-the-middle attackers to insert data into HTTPS sessions, and possibly other types of sessions protected by TLS or SSL, by sending an unauthenticated request that is processed retroactively by a server in a post-renegotiation context, related to a &quot;plaintext injection&quot; attack, aka the &quot;Project Mogul&quot; issue.
</code>

- [johnwchadwick/cve-2009-3555-test-server](https://github.com/johnwchadwick/cve-2009-3555-test-server)

### CVE-2009-4049 (2009-11-23)

<code>Heap-based buffer overflow in aswRdr.sys (aka the TDI RDR driver) in avast! Home and Professional 4.8.1356.0 allows local users to cause a denial of service (memory corruption) or possibly gain privileges via crafted arguments to IOCTL 0x80002024.
</code>

- [fengjixuchui/CVE-2009-4049](https://github.com/fengjixuchui/CVE-2009-4049)

### CVE-2009-4092 (2009-11-27)

<code>Cross-site request forgery (CSRF) vulnerability in user.php in Simplog 0.9.3.2, and possibly earlier, allows remote attackers to hijack the authentication of administrators and users for requests that change passwords.
</code>

- [xiaoyu-iid/Simplog-Exploit](https://github.com/xiaoyu-iid/Simplog-Exploit)

### CVE-2009-4118 (2009-12-01)

<code>The StartServiceCtrlDispatcher function in the cvpnd service (cvpnd.exe) in Cisco VPN client for Windows before 5.0.06.0100 does not properly handle an ERROR_FAILED_SERVICE_CONTROLLER_CONNECT error, which allows local users to cause a denial of service (service crash and VPN connection loss) via a manual start of cvpnd.exe while the cvpnd service is running.
</code>

- [alt3kx/CVE-2009-4118](https://github.com/alt3kx/CVE-2009-4118)

### CVE-2009-4137 (2009-12-24)

<code>The loadContentFromCookie function in core/Cookie.php in Piwik before 0.5 does not validate strings obtained from cookies before calling the unserialize function, which allows remote attackers to execute arbitrary code or upload arbitrary files via vectors related to the __destruct function in the Piwik_Config class; php://filter URIs; the __destruct functions in Zend Framework, as demonstrated by the Zend_Log destructor; the shutdown functions in Zend Framework, as demonstrated by the Zend_Log_Writer_Mail class; the render function in the Piwik_View class; Smarty templates; and the _eval function in Smarty.
</code>

- [Alexeyan/CVE-2009-4137](https://github.com/Alexeyan/CVE-2009-4137)

### CVE-2009-4623 (2010-01-18)

<code>Multiple PHP remote file inclusion vulnerabilities in Advanced Comment System 1.0 allow remote attackers to execute arbitrary PHP code via a URL in the ACS_path parameter to (1) index.php and (2) admin.php in advanced_comment_system/. NOTE: this might only be a vulnerability when the administrator has not followed installation instructions in install.php. NOTE: this might be the same as CVE-2020-35598.
</code>

- [hupe1980/CVE-2009-4623](https://github.com/hupe1980/CVE-2009-4623)
- [kernel-cyber/CVE-2009-4623](https://github.com/kernel-cyber/CVE-2009-4623)
- [MonsempesSamuel/CVE-2009-4623](https://github.com/MonsempesSamuel/CVE-2009-4623)

### CVE-2009-4660 (2010-03-03)

<code>Stack-based buffer overflow in the AntServer Module (AntServer.exe) in BigAnt IM Server 2.50 allows remote attackers to execute arbitrary code via a long GET request to TCP port 6660.
</code>

- [war4uthor/CVE-2009-4660](https://github.com/war4uthor/CVE-2009-4660)

### CVE-2009-5147 (2017-03-29)

<code>DL::dlopen in Ruby 1.8, 1.9.0, 1.9.2, 1.9.3, 2.0.0 before patchlevel 648, and 2.1 before 2.1.8 opens libraries with tainted names.
</code>

- [vpereira/CVE-2009-5147](https://github.com/vpereira/CVE-2009-5147)
- [zhangyongbo100/-Ruby-dl-handle.c-CVE-2009-5147-](https://github.com/zhangyongbo100/-Ruby-dl-handle.c-CVE-2009-5147-)


## 2008
### CVE-2008-0128 (2008-01-23)

<code>The SingleSignOn Valve (org.apache.catalina.authenticator.SingleSignOn) in Apache Tomcat before 5.5.21 does not set the secure flag for the JSESSIONIDSSO cookie in an https session, which can cause the cookie to be sent in http requests and make it easier for remote attackers to capture this cookie.
</code>

- [ngyanch/4062-1](https://github.com/ngyanch/4062-1)

### CVE-2008-0166 (2008-05-13)

<code>OpenSSL 0.9.8c-1 up to versions before 0.9.8g-9 on Debian-based operating systems uses a random number generator that generates predictable numbers, which makes it easier for remote attackers to conduct brute force guessing attacks against cryptographic keys.
</code>

- [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)
- [avarx/vulnkeys](https://github.com/avarx/vulnkeys)
- [badkeys/debianopenssl](https://github.com/badkeys/debianopenssl)
- [demining/Vulnerable-to-Debian-OpenSSL-bug-CVE-2008-0166](https://github.com/demining/Vulnerable-to-Debian-OpenSSL-bug-CVE-2008-0166)

### CVE-2008-0228 (2008-01-10)

<code>Cross-site request forgery (CSRF) vulnerability in apply.cgi in the Linksys WRT54GL Wireless-G Broadband Router with firmware 4.30.9 allows remote attackers to perform actions as administrators.
</code>

- [SpiderLabs/TWSL2011-007_iOS_code_workaround](https://github.com/SpiderLabs/TWSL2011-007_iOS_code_workaround)

### CVE-2008-1611 (2008-04-01)

<code>Stack-based buffer overflow in TFTP Server SP 1.4 for Windows allows remote attackers to cause a denial of service or execute arbitrary code via a long filename in a read or write request.
</code>

- [Axua/CVE-2008-1611](https://github.com/Axua/CVE-2008-1611)

### CVE-2008-1613 (2008-04-21)

<code>SQL injection vulnerability in ioRD.asp in RedDot CMS 7.5 Build 7.5.0.48, and possibly other versions including 6.5 and 7.0, allows remote attackers to execute arbitrary SQL commands via the LngId parameter.
</code>

- [SECFORCE/CVE-2008-1613](https://github.com/SECFORCE/CVE-2008-1613)

### CVE-2008-2019 (2008-04-30)

<code>Simple Machines Forum (SMF), probably 1.1.4, relies on &quot;randomly generated static&quot; to hinder brute-force attacks on the WAV file (aka audio) CAPTCHA, which allows remote attackers to pass the CAPTCHA test via an automated attack that considers Hamming distances.  NOTE: this issue reportedly exists because of an insufficient fix for CVE-2007-3308.
</code>

- [TheRook/AudioCaptchaBypass-CVE-2008-2019](https://github.com/TheRook/AudioCaptchaBypass-CVE-2008-2019)

### CVE-2008-2938 (2008-08-13)

<code>Directory traversal vulnerability in Apache Tomcat 4.1.0 through 4.1.37, 5.5.0 through 5.5.26, and 6.0.0 through 6.0.16, when allowLinking and UTF-8 are enabled, allows remote attackers to read arbitrary files via encoded directory traversal sequences in the URI, a different vulnerability than CVE-2008-2370.  NOTE: versions earlier than 6.0.18 were reported affected, but the vendor advisory lists 6.0.16 as the last affected version.
</code>

- [Naramsim/Offensive](https://github.com/Naramsim/Offensive)

### CVE-2008-3531 (2008-09-05)

<code>Stack-based buffer overflow in sys/kern/vfs_mount.c in the kernel in FreeBSD 7.0 and 7.1, when vfs.usermount is enabled, allows local users to gain privileges via a crafted (1) mount or (2) nmount system call, related to copying of &quot;user defined data&quot; in &quot;certain error conditions.&quot;
</code>

- [test-one9/ps4-11.50.github.io](https://github.com/test-one9/ps4-11.50.github.io)

### CVE-2008-4109 (2008-09-17)

<code>A certain Debian patch for OpenSSH before 4.3p2-9etch3 on etch; before 4.6p1-1 on sid and lenny; and on other distributions such as SUSE uses functions that are not async-signal-safe in the signal handler for login timeouts, which allows remote attackers to cause a denial of service (connection slot exhaustion) via multiple login attempts. NOTE: this issue exists because of an incorrect fix for CVE-2006-5051.
</code>

- [bigb0x/CVE-2024-6387](https://github.com/bigb0x/CVE-2024-6387)

### CVE-2008-4250 (2008-10-23)

<code>The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2, Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary code via a crafted RPC request that triggers the overflow during path canonicalization, as exploited in the wild by Gimmiv.A in October 2008, aka &quot;Server Service Vulnerability.&quot;
</code>

- [thunderstrike9090/Conflicker_analysis_scripts](https://github.com/thunderstrike9090/Conflicker_analysis_scripts)

### CVE-2008-4609 (2008-10-20)

<code>The TCP implementation in (1) Linux, (2) platforms based on BSD Unix, (3) Microsoft Windows, (4) Cisco products, and probably other operating systems allows remote attackers to cause a denial of service (connection queue exhaustion) via multiple vectors that manipulate information in the TCP state table, as demonstrated by sockstress.
</code>

- [mrclki/sockstress](https://github.com/mrclki/sockstress)

### CVE-2008-4654 (2008-10-21)

<code>Stack-based buffer overflow in the parse_master function in the Ty demux plugin (modules/demux/ty.c) in VLC Media Player 0.9.0 through 0.9.4 allows remote attackers to execute arbitrary code via a TiVo TY media file with a header containing a crafted size value.
</code>

- [bongbongco/CVE-2008-4654](https://github.com/bongbongco/CVE-2008-4654)
- [KernelErr/VLC-CVE-2008-4654-Exploit](https://github.com/KernelErr/VLC-CVE-2008-4654-Exploit)
- [rnnsz/CVE-2008-4654](https://github.com/rnnsz/CVE-2008-4654)
- [Hexastrike/CVE-2008-4654](https://github.com/Hexastrike/CVE-2008-4654)

### CVE-2008-4687 (2008-10-22)

<code>manage_proj_page.php in Mantis before 1.1.4 allows remote authenticated users to execute arbitrary code via a sort parameter containing PHP sequences, which are processed by create_function within the multi_sort function in core/utility_api.php.
</code>

- [nmurilo/CVE-2008-4687-exploit](https://github.com/nmurilo/CVE-2008-4687-exploit)
- [twisted007/mantis_rce](https://github.com/twisted007/mantis_rce)

### CVE-2008-5416 (2008-12-10)

<code>Heap-based buffer overflow in Microsoft SQL Server 2000 SP4, 8.00.2050, 8.00.2039, and earlier; SQL Server 2000 Desktop Engine (MSDE 2000) SP4; SQL Server 2005 SP2 and 9.00.1399.06; SQL Server 2000 Desktop Engine (WMSDE) on Windows Server 2003 SP1 and SP2; and Windows Internal Database (WYukon) SP2 allows remote authenticated users to cause a denial of service (access violation exception) or execute arbitrary code by calling the sp_replwritetovarbin extended stored procedure with a set of invalid parameters that trigger memory overwrite, aka &quot;SQL Server sp_replwritetovarbin Limited Memory Overwrite Vulnerability.&quot;
</code>

- [SECFORCE/CVE-2008-5416](https://github.com/SECFORCE/CVE-2008-5416)

### CVE-2008-5862 (2009-01-06)

<code>Directory traversal vulnerability in webcamXP 5.3.2.375 and 5.3.2.410 build 2132 allows remote attackers to read arbitrary files via a ..%2F (encoded dot dot slash) in the URI.
</code>

- [K3ysTr0K3R/CVE-2008-5862-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2008-5862-EXPLOIT)

### CVE-2008-6806 (2009-05-12)

<code>Unrestricted file upload vulnerability in includes/imageupload.php in 7Shop 1.1 and earlier allows remote attackers to execute arbitrary code by uploading a file with an executable extension, then accessing it via a direct request to the file in images/artikel/.
</code>

- [threatcode/CVE-2008-6806](https://github.com/threatcode/CVE-2008-6806)

### CVE-2008-6827 (2009-06-08)

<code>The ListView control in the Client GUI (AClient.exe) in Symantec Altiris Deployment Solution 6.x before 6.9.355 SP1 allows local users to gain SYSTEM privileges and execute arbitrary commands via a &quot;Shatter&quot; style attack on the &quot;command prompt&quot; hidden GUI button to (1) overwrite the CommandLine parameter to cmd.exe to use SYSTEM privileges and (2) modify the DLL that is loaded using the LoadLibrary API function.
</code>

- [alt3kx/CVE-2008-6827](https://github.com/alt3kx/CVE-2008-6827)

### CVE-2008-6970 (2009-08-13)

<code>SQL injection vulnerability in dosearch.inc.php in UBB.threads 7.3.1 and earlier allows remote attackers to execute arbitrary SQL commands via the Forum[] array parameter.
</code>

- [KyomaHooin/CVE-2008-6970](https://github.com/KyomaHooin/CVE-2008-6970)

### CVE-2008-7220 (2009-09-13)

<code>Unspecified vulnerability in Prototype JavaScript framework (prototypejs) before 1.6.0.2 allows attackers to make &quot;cross-site ajax requests&quot; via unknown vectors.
</code>

- [followboy1999/CVE-2008-7220](https://github.com/followboy1999/CVE-2008-7220)


## 2007
### CVE-2007-0038 (2007-03-30)

<code>Stack-based buffer overflow in the animated cursor code in Microsoft Windows 2000 SP4 through Vista allows remote attackers to execute arbitrary code or cause a denial of service (persistent reboot) via a large length value in the second (or later) anih block of a RIFF .ANI, cur, or .ico file, which results in memory corruption when processing cursors, animated cursors, and icons, a variant of CVE-2005-0416, as originally demonstrated using Internet Explorer 6 and 7. NOTE: this might be a duplicate of CVE-2007-1765; if so, then CVE-2007-0038 should be preferred.
</code>

- [Axua/CVE-2007-0038](https://github.com/Axua/CVE-2007-0038)

### CVE-2007-0843 (2007-02-23)

<code>The ReadDirectoryChangesW API function on Microsoft Windows 2000, XP, Server 2003, and Vista does not check permissions for child objects, which allows local users to bypass permissions by opening a directory with LIST (READ) access and using ReadDirectoryChangesW to monitor changes of files that do not have LIST permissions, which can be leveraged to determine filenames, access times, and other sensitive information.
</code>

- [z3APA3A/spydir](https://github.com/z3APA3A/spydir)

### CVE-2007-1567 (2007-03-21)

<code>Stack-based buffer overflow in War FTP Daemon 1.65, and possibly earlier, allows remote attackers to cause a denial of service or execute arbitrary code via unspecified vectors, as demonstrated by warftp_165.tar by Immunity.  NOTE: this might be the same issue as CVE-1999-0256, CVE-2000-0131, or CVE-2006-2171, but due to Immunity's lack of details, this cannot be certain.
</code>

- [war4uthor/CVE-2007-1567](https://github.com/war4uthor/CVE-2007-1567)

### CVE-2007-1858 (2007-05-09)

<code>The default SSL cipher configuration in Apache Tomcat 4.1.28 through 4.1.31, 5.0.0 through 5.0.30, and 5.5.0 through 5.5.17 uses certain insecure ciphers, including the anonymous cipher, which allows remote attackers to obtain sensitive information or have other, unspecified impacts.
</code>

- [anthophilee/A2SV--SSL-VUL-Scan](https://github.com/anthophilee/A2SV--SSL-VUL-Scan)

### CVE-2007-2447 (2007-05-14)

<code>The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters involving the (1) SamrChangePassword function, when the &quot;username map script&quot; smb.conf option is enabled, and allows remote authenticated users to execute commands via shell metacharacters involving other MS-RPC functions in the (2) remote printer and (3) file share management.
</code>

- [amriunix/CVE-2007-2447](https://github.com/amriunix/CVE-2007-2447)
- [Unix13/metasploitable2](https://github.com/Unix13/metasploitable2)
- [b1fair/smb_usermap](https://github.com/b1fair/smb_usermap)
- [JoseBarrios/CVE-2007-2447](https://github.com/JoseBarrios/CVE-2007-2447)
- [3x1t1um/CVE-2007-2447](https://github.com/3x1t1um/CVE-2007-2447)
- [xlcc4096/exploit-CVE-2007-2447](https://github.com/xlcc4096/exploit-CVE-2007-2447)
- [WildfootW/CVE-2007-2447_Samba_3.0.25rc3](https://github.com/WildfootW/CVE-2007-2447_Samba_3.0.25rc3)
- [Ziemni/CVE-2007-2447-in-Python](https://github.com/Ziemni/CVE-2007-2447-in-Python)
- [0xKn/CVE-2007-2447](https://github.com/0xKn/CVE-2007-2447)
- [ozuma/CVE-2007-2447](https://github.com/ozuma/CVE-2007-2447)
- [G01d3nW01f/CVE-2007-2447](https://github.com/G01d3nW01f/CVE-2007-2447)
- [cherrera0001/CVE-2007-2447](https://github.com/cherrera0001/CVE-2007-2447)
- [Alien0ne/CVE-2007-2447](https://github.com/Alien0ne/CVE-2007-2447)
- [3t4n/samba-3.0.24-CVE-2007-2447-vunerable-](https://github.com/3t4n/samba-3.0.24-CVE-2007-2447-vunerable-)
- [xbufu/CVE-2007-2447](https://github.com/xbufu/CVE-2007-2447)
- [s4msec/CVE-2007-2447](https://github.com/s4msec/CVE-2007-2447)
- [Nosferatuvjr/Samba-Usermap-exploit](https://github.com/Nosferatuvjr/Samba-Usermap-exploit)
- [testaross4/CVE-2007-2447](https://github.com/testaross4/CVE-2007-2447)
- [b33m0x00/CVE-2007-2447](https://github.com/b33m0x00/CVE-2007-2447)
- [HerculesRD/PyUsernameMapScriptRCE](https://github.com/HerculesRD/PyUsernameMapScriptRCE)
- [Aviksaikat/CVE-2007-2447](https://github.com/Aviksaikat/CVE-2007-2447)
- [n3rdh4x0r/CVE-2007-2447](https://github.com/n3rdh4x0r/CVE-2007-2447)
- [bdunlap9/CVE-2007-2447_python](https://github.com/bdunlap9/CVE-2007-2447_python)
- [MikeRega7/CVE-2007-2447-RCE](https://github.com/MikeRega7/CVE-2007-2447-RCE)
- [ShivamDey/Samba-CVE-2007-2447-Exploit](https://github.com/ShivamDey/Samba-CVE-2007-2447-Exploit)
- [Juantos/cve-2007-2447](https://github.com/Juantos/cve-2007-2447)
- [IamLucif3r/CVE-2007-2447-Exploit](https://github.com/IamLucif3r/CVE-2007-2447-Exploit)
- [foudadev/CVE-2007-2447](https://github.com/foudadev/CVE-2007-2447)

### CVE-2007-3280 (2007-06-19)

<code>The Database Link library (dblink) in PostgreSQL 8.1 implements functions via CREATE statements that map to arbitrary libraries based on the C programming language, which allows remote authenticated superusers to map and execute a function from any library, as demonstrated by using the system function in libc.so.6 to gain shell access.
</code>

- [DenuwanJayasekara/CVE-Exploitation-Reports](https://github.com/DenuwanJayasekara/CVE-Exploitation-Reports)

### CVE-2007-3830 (2007-07-17)

<code>Cross-site scripting (XSS) vulnerability in alert.php in ISS Proventia Network IPS GX5108 1.3 and GX5008 1.5 allows remote attackers to inject arbitrary web script or HTML via the reminder parameter.
</code>

- [alt3kx/CVE-2007-3830](https://github.com/alt3kx/CVE-2007-3830)

### CVE-2007-3831 (2007-07-17)

<code>PHP remote file inclusion in main.php in ISS Proventia Network IPS GX5108 1.3 and GX5008 1.5 allows remote attackers to execute arbitrary PHP code via a URL in the page parameter.
</code>

- [alt3kx/CVE-2007-3831](https://github.com/alt3kx/CVE-2007-3831)

### CVE-2007-4559 (2007-08-28)

<code>Directory traversal vulnerability in the (1) extract and (2) extractall functions in the tarfile module in Python allows user-assisted remote attackers to overwrite arbitrary files via a .. (dot dot) sequence in filenames in a TAR archive, a related issue to CVE-2001-1267.
</code>

- [advanced-threat-research/Creosote](https://github.com/advanced-threat-research/Creosote)
- [Ooscaar/MALW](https://github.com/Ooscaar/MALW)
- [davidholiday/CVE-2007-4559](https://github.com/davidholiday/CVE-2007-4559)
- [luigigubello/trellix-tarslip-patch-bypass](https://github.com/luigigubello/trellix-tarslip-patch-bypass)
- [JamesDarf/wargame-tarpioka](https://github.com/JamesDarf/wargame-tarpioka)

### CVE-2007-4560 (2007-08-28)

<code>clamav-milter in ClamAV before 0.91.2, when run in black hole mode, allows remote attackers to execute arbitrary commands via shell metacharacters that are used in a certain popen call, involving the &quot;recipient field of sendmail.&quot;
</code>

- [0x1sac/ClamAV-Milter-Sendmail-0.91.2-Remote-Code-Execution](https://github.com/0x1sac/ClamAV-Milter-Sendmail-0.91.2-Remote-Code-Execution)

### CVE-2007-4607 (2007-08-31)

<code>Buffer overflow in the EasyMailSMTPObj ActiveX control in emsmtp.dll 6.0.1 in the Quiksoft EasyMail SMTP Object, as used in Postcast Server Pro 3.0.61 and other products, allows remote attackers to execute arbitrary code via a long argument to the SubmitToExpress method, a different vulnerability than CVE-2007-1029. NOTE: this may have been fixed in version 6.0.3.15.
</code>

- [joeyrideout/CVE-2007-4607](https://github.com/joeyrideout/CVE-2007-4607)

### CVE-2007-5036 (2007-09-24)

<code>Multiple buffer overflows in the AirDefense Airsensor M520 with firmware 4.3.1.1 and 4.4.1.4 allow remote authenticated users to cause a denial of service (HTTPS service outage) via a crafted query string in an HTTPS request to (1) adLog.cgi, (2) post.cgi, or (3) ad.cgi, related to the &quot;files filter.&quot;
</code>

- [alt3kx/CVE-2007-5036](https://github.com/alt3kx/CVE-2007-5036)

### CVE-2007-5962 (2008-05-22)

<code>Memory leak in a certain Red Hat patch, applied to vsftpd 2.0.5 on Red Hat Enterprise Linux (RHEL) 5 and Fedora 6 through 8, and on Foresight Linux and rPath appliances, allows remote attackers to cause a denial of service (memory consumption) via a large number of CWD commands, as demonstrated by an attack on a daemon with the deny_file configuration option.
</code>

- [antogit-sys/CVE-2007-5962](https://github.com/antogit-sys/CVE-2007-5962)

### CVE-2007-6377 (2007-12-15)

<code>Stack-based buffer overflow in the PassThru functionality in ext.dll in BadBlue 2.72b and earlier allows remote attackers to execute arbitrary code via a long query string.
</code>

- [Nicoslo/Windows-exploitation-BadBlue-2.7-CVE-2007-6377](https://github.com/Nicoslo/Windows-exploitation-BadBlue-2.7-CVE-2007-6377)

### CVE-2007-6638 (2008-01-04)

<code>March Networks DVR 3204 stores sensitive information under the web root with insufficient access control, which allows remote attackers to obtain usernames, passwords, device names, and IP addresses via a direct request for scripts/logfiles.tar.gz.
</code>

- [alt3kx/CVE-2007-6638](https://github.com/alt3kx/CVE-2007-6638)

### CVE-2007-6750 (2011-12-27)

<code>The Apache HTTP Server 1.x and 2.x allows remote attackers to cause a denial of service (daemon outage) via partial HTTP requests, as demonstrated by Slowloris, related to the lack of the mod_reqtimeout module in versions before 2.2.15.
</code>

- [Jeanpseven/slowl0ris](https://github.com/Jeanpseven/slowl0ris)


## 2006
### CVE-2006-0450 (2006-01-27)

<code>phpBB 2.0.19 and earlier allows remote attackers to cause a denial of service (application crash) by (1) registering many users through profile.php or (2) using search.php to search in a certain way that confuses the database.
</code>

- [Parcer0/CVE-2006-0450-phpBB-2.0.15-Multiple-DoS-Vulnerabilities](https://github.com/Parcer0/CVE-2006-0450-phpBB-2.0.15-Multiple-DoS-Vulnerabilities)

### CVE-2006-0987 (2006-03-03)

<code>The default configuration of ISC BIND before 9.4.1-P1, when configured as a caching name server, allows recursive queries and provides additional delegation information to arbitrary IP addresses, which allows remote attackers to cause a denial of service (traffic amplification) via DNS queries with spoofed source IP addresses.
</code>

- [pcastagnaro/dns_amplification_scanner](https://github.com/pcastagnaro/dns_amplification_scanner)

### CVE-2006-1236 (2006-03-15)

<code>Buffer overflow in the SetUp function in socket/request.c in CrossFire 1.9.0 allows remote attackers to execute arbitrary code via a long setup sound command, a different vulnerability than CVE-2006-1010.
</code>

- [Axua/CVE-2006-1236](https://github.com/Axua/CVE-2006-1236)

### CVE-2006-2842 (2006-06-06)

<code>PHP remote file inclusion vulnerability in functions/plugin.php in SquirrelMail 1.4.6 and earlier, if register_globals is enabled and magic_quotes_gpc is disabled, allows remote attackers to execute arbitrary PHP code via a URL in the plugins array parameter.  NOTE: this issue has been disputed by third parties, who state that Squirrelmail provides prominent warnings to the administrator when register_globals is enabled.  Since the varieties of administrator negligence are uncountable, perhaps this type of issue should not be included in CVE.  However, the original developer has posted a security advisory, so there might be relevant real-world environments under which this vulnerability is applicable
</code>

- [karthi-the-hacker/CVE-2006-2842](https://github.com/karthi-the-hacker/CVE-2006-2842)

### CVE-2006-3392 (2006-07-06)

<code>Webmin before 1.290 and Usermin before 1.220 calls the simplify_path function before decoding HTML, which allows remote attackers to read arbitrary files, as demonstrated using &quot;..%01&quot; sequences, which bypass the removal of &quot;../&quot; sequences before bytes such as &quot;%01&quot; are removed from the filename.  NOTE: This is a different issue than CVE-2006-3274.
</code>

- [0xtz/CVE-2006-3392](https://github.com/0xtz/CVE-2006-3392)
- [IvanGlinkin/CVE-2006-3392](https://github.com/IvanGlinkin/CVE-2006-3392)
- [Adel-kaka-dz/CVE-2006-3392](https://github.com/Adel-kaka-dz/CVE-2006-3392)
- [gb21oc/ExploitWebmin](https://github.com/gb21oc/ExploitWebmin)
- [kernel-cyber/CVE-2006-3392](https://github.com/kernel-cyber/CVE-2006-3392)
- [g1vi/CVE-2006-3392](https://github.com/g1vi/CVE-2006-3392)
- [brosck/CVE-2006-3392](https://github.com/brosck/CVE-2006-3392)

### CVE-2006-3592 (2006-07-14)

<code>Unspecified vulnerability in the command line interface (CLI) in Cisco Unified CallManager (CUCM) 5.0(1) through 5.0(3a) allows local users to execute arbitrary commands with elevated privileges via unspecified vectors, involving &quot;certain CLI commands,&quot; aka bug CSCse11005.
</code>

- [adenkiewicz/CVE-2006-3592](https://github.com/adenkiewicz/CVE-2006-3592)

### CVE-2006-3747 (2006-07-28)

<code>Off-by-one error in the ldap scheme handling in the Rewrite module (mod_rewrite) in Apache 1.3 from 1.3.28, 2.0.46 and other versions before 2.0.59, and 2.2, when RewriteEngine is enabled, allows remote attackers to cause a denial of service (application crash) and possibly execute arbitrary code via crafted URLs that are not properly handled using certain rewrite rules.
</code>

- [defensahacker/CVE-2006-3747](https://github.com/defensahacker/CVE-2006-3747)

### CVE-2006-4777 (2006-09-14)

<code>Heap-based buffer overflow in the DirectAnimation Path Control (DirectAnimation.PathControl) COM object (daxctle.ocx) for Internet Explorer 6.0 SP1, on Chinese and possibly other Windows distributions, allows remote attackers to execute arbitrary code via unknown manipulations in arguments to the KeyFrame method, possibly related to an integer overflow, as demonstrated by daxctle2, and a different vulnerability than CVE-2006-4446.
</code>

- [Mario1234/js-driveby-download-CVE-2006-4777](https://github.com/Mario1234/js-driveby-download-CVE-2006-4777)

### CVE-2006-4814 (2006-12-20)

<code>The mincore function in the Linux kernel before 2.4.33.6 does not properly lock access to user space, which has unspecified impact and attack vectors, possibly related to a deadlock.
</code>

- [tagatac/linux-CVE-2006-4814](https://github.com/tagatac/linux-CVE-2006-4814)

### CVE-2006-5051 (2006-09-27)

<code>Signal handler race condition in OpenSSH before 4.4 allows remote attackers to cause a denial of service (crash), and possibly execute arbitrary code if GSSAPI authentication is enabled, via unspecified vectors that lead to a double-free.
</code>

- [bigb0x/CVE-2024-6387](https://github.com/bigb0x/CVE-2024-6387)
- [sardine-web/CVE-2024-6387_Check](https://github.com/sardine-web/CVE-2024-6387_Check)
- [anhvutuan/CVE-2024-6387-poc-1](https://github.com/anhvutuan/CVE-2024-6387-poc-1)

### CVE-2006-6184 (2006-12-01)

<code>Multiple stack-based buffer overflows in Allied Telesyn TFTP Server (AT-TFTP) 1.9, and possibly earlier, allow remote attackers to cause a denial of service (crash) or execute arbitrary code via a long filename in a (1) GET or (2) PUT command.
</code>

- [shauntdergrigorian/cve-2006-6184](https://github.com/shauntdergrigorian/cve-2006-6184)
- [b03902043/CVE-2006-6184](https://github.com/b03902043/CVE-2006-6184)

### CVE-2006-20001 (2023-01-17)

<code>A carefully crafted If: request header can cause a memory read, or write of a single zero byte, in a pool (heap) memory location beyond the header value sent. This could cause the process to crash.\n\nThis issue affects Apache HTTP Server 2.4.54 and earlier.
</code>

- [r1az4r/CVE-2006-20001](https://github.com/r1az4r/CVE-2006-20001)


## 2005
### CVE-2005-0575 (2005-02-27)

<code>Buffer overflow in Stormy Studios Knet 1.04c and earlier allows remote attackers to cause a denial of service and possibly execute arbitrary code via a long HTTP GET request.
</code>

- [3t3rn4lv01d/CVE-2005-0575](https://github.com/3t3rn4lv01d/CVE-2005-0575)

### CVE-2005-0603 (2005-03-01)

<code>viewtopic.php in phpBB 2.0.12 and earlier allows remote attackers to obtain sensitive information via a highlight parameter containing invalid regular expression syntax, which reveals the path in a PHP error message.
</code>

- [Parcer0/CVE-2005-0603-phpBB-2.0.12-Full-path-disclosure](https://github.com/Parcer0/CVE-2005-0603-phpBB-2.0.12-Full-path-disclosure)

### CVE-2005-1125 (2005-04-16)

<code>Race condition in libsafe 2.0.16 and earlier, when running in multi-threaded applications, allows attackers to bypass libsafe protection and exploit other vulnerabilities before the _libsafe_die function call is completed.
</code>

- [tagatac/libsafe-CVE-2005-1125](https://github.com/tagatac/libsafe-CVE-2005-1125)

### CVE-2005-1794 (2005-06-01)

<code>Microsoft Terminal Server using Remote Desktop Protocol (RDP) 5.2 stores an RSA private key in mstlsapi.dll and uses it to sign a certificate, which allows remote attackers to spoof public keys of legitimate servers and conduct man-in-the-middle attacks.
</code>

- [InitRoot/CVE-2005-1794Scanner](https://github.com/InitRoot/CVE-2005-1794Scanner)

### CVE-2005-2428 (2005-08-03)

<code>Lotus Domino R5 and R6 WebMail, with &quot;Generate HTML for all fields&quot; enabled, stores sensitive data from names.nsf in hidden form fields, which allows remote attackers to read the HTML source to obtain sensitive information such as (1) the password hash in the HTTPPassword field, (2) the password change date in the HTTPPasswordChangeDate field, (3) the client platform in the ClntPltfrm field, (4) the client machine name in the ClntMachine field, and (5) the client Lotus Domino release in the ClntBld field, a different vulnerability than CVE-2005-2696.
</code>

- [schwankner/CVE-2005-2428-IBM-Lotus-Domino-R8-Password-Hash-Extraction-Exploit](https://github.com/schwankner/CVE-2005-2428-IBM-Lotus-Domino-R8-Password-Hash-Extraction-Exploit)

### CVE-2005-3299 (2005-10-23)

<code>PHP file inclusion vulnerability in grab_globals.lib.php in phpMyAdmin 2.6.4 and 2.6.4-pl1 allows remote attackers to include local files via the $__redirect parameter, possibly involving the subform array.
</code>

- [RizeKishimaro/CVE-2005-3299](https://github.com/RizeKishimaro/CVE-2005-3299)
- [Cr0w-ui/-CVE-2005-3299-](https://github.com/Cr0w-ui/-CVE-2005-3299-)


## 2004
### CVE-2004-0558 (2004-09-17)

<code>The Internet Printing Protocol (IPP) implementation in CUPS before 1.1.21 allows remote attackers to cause a denial of service (service hang) via a certain UDP packet to the IPP port.
</code>

- [fibonascii/CVE-2004-0558](https://github.com/fibonascii/CVE-2004-0558)

### CVE-2004-1561 (2005-02-20)

<code>Buffer overflow in Icecast 2.0.1 and earlier allows remote attackers to execute arbitrary code via an HTTP request with a large number of headers.
</code>

- [ivanitlearning/CVE-2004-1561](https://github.com/ivanitlearning/CVE-2004-1561)
- [ratiros01/CVE-2004-1561](https://github.com/ratiros01/CVE-2004-1561)
- [darrynb89/CVE-2004-1561](https://github.com/darrynb89/CVE-2004-1561)
- [thel1nus/CVE-2004-1561-Notes](https://github.com/thel1nus/CVE-2004-1561-Notes)
- [Danyw24/CVE-2004-1561-Icecast-Header-Overwrite-buffer-overflow-RCE-2.0.1-Win32-](https://github.com/Danyw24/CVE-2004-1561-Icecast-Header-Overwrite-buffer-overflow-RCE-2.0.1-Win32-)

### CVE-2004-1769 (2005-03-10)

<code>The &quot;Allow cPanel users to reset their password via email&quot; feature in cPanel 9.1.0 build 34 and earlier, including 8.x, allows remote attackers to execute arbitrary code via the user parameter to resetpass.
</code>

- [sinkaroid/shiguresh](https://github.com/sinkaroid/shiguresh)
- [Redsplit/shiguresh](https://github.com/Redsplit/shiguresh)

### CVE-2004-2167 (2005-07-10)

<code>Multiple buffer overflows in LaTeX2rtf 1.9.15, and possibly other versions, allow remote attackers to execute arbitrary code via (1) the expandmacro function, and possibly (2) Environments and (3) TranslateCommand.
</code>

- [uzzzval/cve-2004-2167](https://github.com/uzzzval/cve-2004-2167)

### CVE-2004-2271 (2005-07-19)

<code>Buffer overflow in MiniShare 1.4.1 and earlier allows remote attackers to execute arbitrary code via a long HTTP GET request.
</code>

- [kkirsche/CVE-2004-2271](https://github.com/kkirsche/CVE-2004-2271)
- [PercussiveElbow/CVE-2004-2271-MiniShare-1.4.1-Buffer-Overflow](https://github.com/PercussiveElbow/CVE-2004-2271-MiniShare-1.4.1-Buffer-Overflow)
- [war4uthor/CVE-2004-2271](https://github.com/war4uthor/CVE-2004-2271)
- [pwncone/CVE-2004-2271-MiniShare-1.4.1-BOF](https://github.com/pwncone/CVE-2004-2271-MiniShare-1.4.1-BOF)

### CVE-2004-2449 (2005-08-20)

<code>Roger Wilco 1.4.1.6 and earlier or Roger Wilco Base Station 0.30a and earlier allows remote attackers to cause a denial of service (application crash) via a long, malformed UDP datagram.
</code>

- [ParallelVisions/DoSTool](https://github.com/ParallelVisions/DoSTool)

### CVE-2004-2549 (2005-11-21)

<code>Nortel Wireless LAN (WLAN) Access Point (AP) 2220, 2221, and 2225 allow remote attackers to cause a denial of service (service crash) via a TCP request with a large string, followed by 8 newline characters, to (1) the Telnet service on TCP port 23 and (2) the HTTP service on TCP port 80, possibly due to a buffer overflow.
</code>

- [alt3kx/CVE-2004-2549](https://github.com/alt3kx/CVE-2004-2549)

### CVE-2004-2687 (2007-09-23)

<code>distcc 2.x, as used in XCode 1.5 and others, when not configured to restrict access to the server port, allows remote attackers to execute arbitrary commands via compilation jobs, which are executed by the server without authorization checks.
</code>

- [n3rdh4x0r/distccd_rce_CVE-2004-2687](https://github.com/n3rdh4x0r/distccd_rce_CVE-2004-2687)
- [k4miyo/CVE-2004-2687](https://github.com/k4miyo/CVE-2004-2687)
- [ss0wl/CVE-2004-2687_distcc_v1](https://github.com/ss0wl/CVE-2004-2687_distcc_v1)

### CVE-2004-6768
- [yougboiz/Metasploit-CVE-2004-6768](https://github.com/yougboiz/Metasploit-CVE-2004-6768)


## 2003

## 2002
### CVE-2002-0200 (2002-05-03)

<code>Cyberstop Web Server for Windows 0.1 allows remote attackers to cause a denial of service via an HTTP request for an MS-DOS device name.
</code>

- [alt3kx/CVE-2002-0200](https://github.com/alt3kx/CVE-2002-0200)

### CVE-2002-0201 (2002-05-03)

<code>Cyberstop Web Server for Windows 0.1 allows remote attackers to cause a denial of service (crash) and possibly execute arbitrary code via a long HTTP GET request, possibly triggering a buffer overflow.
</code>

- [alt3kx/CVE-2002-0201](https://github.com/alt3kx/CVE-2002-0201)

### CVE-2002-0288 (2002-05-03)

<code>Directory traversal vulnerability in Phusion web server 1.0 allows remote attackers to read arbitrary files via a ... (triple dot dot) in the HTTP request.
</code>

- [alt3kx/CVE-2002-0288](https://github.com/alt3kx/CVE-2002-0288)

### CVE-2002-0289 (2002-05-03)

<code>Buffer overflow in Phusion web server 1.0 allows remote attackers to cause a denial of service and execute arbitrary code via a long HTTP request.
</code>

- [alt3kx/CVE-2002-0289](https://github.com/alt3kx/CVE-2002-0289)

### CVE-2002-0346 (2002-05-03)

<code>Cross-site scripting vulnerability in Cobalt RAQ 4 allows remote attackers to execute arbitrary script as other Cobalt users via Javascript in a URL to (1) service.cgi or (2) alert.cgi.
</code>

- [alt3kx/CVE-2002-0346](https://github.com/alt3kx/CVE-2002-0346)

### CVE-2002-0347 (2002-05-03)

<code>Directory traversal vulnerability in Cobalt RAQ 4 allows remote attackers to read password-protected files, and possibly files outside the web root, via a .. (dot dot) in an HTTP request.
</code>

- [alt3kx/CVE-2002-0347](https://github.com/alt3kx/CVE-2002-0347)

### CVE-2002-0348 (2002-05-03)

<code>service.cgi in Cobalt RAQ 4 allows remote attackers to cause a denial of service, and possibly execute arbitrary code, via a long service argument.
</code>

- [alt3kx/CVE-2002-0348](https://github.com/alt3kx/CVE-2002-0348)

### CVE-2002-0448 (2002-06-11)

<code>Xerver Free Web Server 2.10 and earlier allows remote attackers to cause a denial of service (crash) via an HTTP request that contains many &quot;C:/&quot; sequences.
</code>

- [alt3kx/CVE-2002-0448](https://github.com/alt3kx/CVE-2002-0448)

### CVE-2002-0740 (2002-07-26)

<code>Buffer overflow in slrnpull for the SLRN package, when installed setuid or setgid, allows local users to gain privileges via a long -d (SPOOLDIR) argument.
</code>

- [alt3kx/CVE-2002-0740](https://github.com/alt3kx/CVE-2002-0740)

### CVE-2002-0748 (2003-04-02)

<code>LabVIEW Web Server 5.1.1 through 6.1 allows remote attackers to cause a denial of service (crash) via an HTTP GET request that ends in two newline characters, instead of the expected carriage return/newline combinations.
</code>

- [fauzanwijaya/CVE-2002-0748](https://github.com/fauzanwijaya/CVE-2002-0748)

### CVE-2002-0991 (2002-08-31)

<code>Buffer overflows in the cifslogin command for HP CIFS/9000 Client A.01.06 and earlier, based on the Sharity package, allows local users to gain root privileges via long (1) -U, (2) -D, (3) -P, (4) -S, (5) -N, or (6) -u parameters.
</code>

- [alt3kx/CVE-2002-0991](https://github.com/alt3kx/CVE-2002-0991)

### CVE-2002-1614 (2005-03-25)

<code>Buffer overflow in HP Tru64 UNIX allows local users to execute arbitrary code via a long argument to /usr/bin/at.
</code>

- [wlensinas/CVE-2002-1614](https://github.com/wlensinas/CVE-2002-1614)

### CVE-2002-2420 (2007-11-01)

<code>site_searcher.cgi in Super Site Searcher allows remote attackers to execute arbitrary commands via shell metacharacters in the page parameter.
</code>

- [krdsploit/CVE-2002-2420](https://github.com/krdsploit/CVE-2002-2420)

### CVE-2002-20001 (2021-11-11)

<code>The Diffie-Hellman Key Agreement Protocol allows remote attackers (from the client side) to send arbitrary numbers that are actually not public keys, and trigger expensive server-side DHE modular-exponentiation calculations, aka a D(HE)at or D(HE)ater attack. The client needs very little CPU resources and network bandwidth. The attack may be more disruptive in cases where a client can require a server to select its largest supported key size. The basic attack scenario is that the client must claim that it can only communicate with DHE, and the server must be configured to allow DHE.
</code>

- [c0r0n3r/dheater](https://github.com/c0r0n3r/dheater)


## 2001
### CVE-2001-0550 (2002-06-25)

<code>wu-ftpd 2.6.1 allows remote attackers to execute arbitrary commands via a &quot;~{&quot; argument to commands such as CWD, which is not properly handled by the glob function (ftpglob).
</code>

- [gilberto47831/Network-Filesystem-Forensics](https://github.com/gilberto47831/Network-Filesystem-Forensics)

### CVE-2001-0680 (2002-03-09)

<code>Directory traversal vulnerability in ftpd in QPC QVT/Net 4.0 and AVT/Term 5.0 allows a remote attacker to traverse directories on the web server via a &quot;dot dot&quot; attack in a LIST (ls) command.
</code>

- [alt3kx/CVE-2001-0680](https://github.com/alt3kx/CVE-2001-0680)

### CVE-2001-0758 (2001-10-12)

<code>Directory traversal vulnerability in Shambala 4.5 allows remote attackers to escape the FTP root directory via &quot;CWD ...&quot;  command.
</code>

- [alt3kx/CVE-2001-0758](https://github.com/alt3kx/CVE-2001-0758)

### CVE-2001-0931 (2002-02-02)

<code>Directory traversal vulnerability in Cooolsoft PowerFTP Server 2.03 allows attackers to list or read arbitrary files and directories via a .. (dot dot) in (1) LS or (2) GET.
</code>

- [alt3kx/CVE-2001-0931](https://github.com/alt3kx/CVE-2001-0931)

### CVE-2001-0932 (2002-02-02)

<code>Buffer overflow in Cooolsoft PowerFTP Server 2.03 allows remote attackers to cause a denial of service and possibly execute arbitrary code via a long command.
</code>

- [alt3kx/CVE-2001-0932](https://github.com/alt3kx/CVE-2001-0932)

### CVE-2001-0933 (2002-02-02)

<code>Cooolsoft PowerFTP Server 2.03 allows remote attackers to list the contents of arbitrary drives via a ls (LIST) command that includes the drive letter as an argument, e.g. &quot;ls C:&quot;.
</code>

- [alt3kx/CVE-2001-0933](https://github.com/alt3kx/CVE-2001-0933)

### CVE-2001-0934 (2002-02-02)

<code>Cooolsoft PowerFTP Server 2.03 allows remote attackers to obtain the physical path of the server root via the pwd command, which lists the full pathname.
</code>

- [alt3kx/CVE-2001-0934](https://github.com/alt3kx/CVE-2001-0934)

### CVE-2001-1442 (2005-04-21)

<code>Buffer overflow in innfeed for ISC InterNetNews (INN) before 2.3.0 allows local users in the &quot;news&quot; group to gain privileges via a long -c command line argument.
</code>

- [alt3kx/CVE-2001-1442](https://github.com/alt3kx/CVE-2001-1442)

### CVE-2001-3389
- [becrevex/Gaston](https://github.com/becrevex/Gaston)


## 2000
### CVE-2000-0114 (2000-02-08)

<code>Frontpage Server Extensions allows remote attackers to determine the name of the anonymous account via an RPC POST request to shtml.dll in the /_vti_bin/ virtual directory.
</code>

- [Cappricio-Securities/CVE-2000-0114](https://github.com/Cappricio-Securities/CVE-2000-0114)
- [Josekutty-K/frontpage-server-extensions-vulnerability-scanner](https://github.com/Josekutty-K/frontpage-server-extensions-vulnerability-scanner)
- [adhamelhansye/CVE-2000-0114](https://github.com/adhamelhansye/CVE-2000-0114)

### CVE-2000-0170 (2000-04-10)

<code>Buffer overflow in the man program in Linux allows local users to gain privileges via the MANPAGER environmental variable.
</code>

- [mike182/exploit](https://github.com/mike182/exploit)

### CVE-2000-0649 (2000-08-03)

<code>IIS 4.0 allows remote attackers to obtain the internal IP address of the server via an HTTP 1.0 request for a web page which is protected by basic authentication and has no realm defined.
</code>

- [rafaelh/CVE-2000-0649](https://github.com/rafaelh/CVE-2000-0649)
- [stevenvegar/cve-2000-0649](https://github.com/stevenvegar/cve-2000-0649)
- [Downgraderz/PoC-CVE-2000-0649](https://github.com/Downgraderz/PoC-CVE-2000-0649)

### CVE-2000-0979 (2001-01-22)

<code>File and Print Sharing service in Windows 95, Windows 98, and Windows Me does not properly check the password for a file share, which allows remote attackers to bypass share access controls by sending a 1-byte password that matches the first character of the real password, aka the &quot;Share Level Password&quot; vulnerability.
</code>

- [Z6543/CVE-2000-0979](https://github.com/Z6543/CVE-2000-0979)


## 1999
### CVE-1999-0016 (1999-09-29)

<code>Land IP denial of service.
</code>

- [pexmee/CVE-1999-0016-Land-DOS-tool](https://github.com/pexmee/CVE-1999-0016-Land-DOS-tool)
- [Pommaq/CVE-1999-0016-POC](https://github.com/Pommaq/CVE-1999-0016-POC)

### CVE-1999-0524 (2000-02-04)

<code>ICMP information such as (1) netmask and (2) timestamp is allowed from arbitrary hosts.
</code>

- [threatlabindonesia/CVE-1999-0524-ICMP-Timestamp-and-Address-Mask-Request-Exploit](https://github.com/threatlabindonesia/CVE-1999-0524-ICMP-Timestamp-and-Address-Mask-Request-Exploit)

### CVE-1999-0532 (2000-02-04)

<code>A DNS server allows zone transfers.
</code>

- [websecnl/Bulk_CVE-1999-0532_Scanner](https://github.com/websecnl/Bulk_CVE-1999-0532_Scanner)
- [Rodney-O-C-Melby/dns-zone-transfer-test](https://github.com/Rodney-O-C-Melby/dns-zone-transfer-test)

### CVE-1999-1053 (2001-09-12)

<code>guestbook.pl cleanses user-inserted SSI commands by removing text between &quot;&lt;!--&quot; and &quot;--&gt;&quot; separators, which allows remote attackers to execute arbitrary commands when guestbook.pl is run on Apache 1.3.9 and possibly other versions, since Apache allows other closing sequences besides &quot;--&gt;&quot;.
</code>

- [siunam321/CVE-1999-1053-PoC](https://github.com/siunam321/CVE-1999-1053-PoC)


