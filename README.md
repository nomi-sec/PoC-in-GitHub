# PoC in GitHub

## 2020
### CVE-2020-0022

<code>
In reassemble_and_dispatch of packet_fragmenter.cc, there is possible out of bounds write due to an incorrect bounds calculation. This could lead to remote code execution over Bluetooth with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-8.0 Android-8.1 Android-9 Android-10Android ID: A-143894715
</code>

- [marcinguy/CVE-2020-0022](https://github.com/marcinguy/CVE-2020-0022)
- [leommxj/cve-2020-0022](https://github.com/leommxj/cve-2020-0022)

### CVE-2020-0041

<code>
In binder_transaction of binder.c, there is a possible out of bounds write due to an incorrect bounds check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-145988638References: Upstream kernel
</code>

- [bluefrostsecurity/CVE-2020-0041](https://github.com/bluefrostsecurity/CVE-2020-0041)

### CVE-2020-0069

<code>
In the ioctl handlers of the Mediatek Command Queue driver, there is a possible out of bounds write due to insufficient input sanitization and missing SELinux restrictions. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-147882143References: M-ALPS04356754
</code>

- [R0rt1z2/AutomatedRoot](https://github.com/R0rt1z2/AutomatedRoot)
- [TheRealJunior/mtk-su-reverse-cve-2020-0069](https://github.com/TheRealJunior/mtk-su-reverse-cve-2020-0069)
- [yanglingxi1993/CVE-2020-0069](https://github.com/yanglingxi1993/CVE-2020-0069)
- [quarkslab/CVE-2020-0069_poc](https://github.com/quarkslab/CVE-2020-0069_poc)

### CVE-2020-0551

<code>
Load value injection in some Intel(R) Processors utilizing speculative execution may allow an authenticated user to potentially enable information disclosure via a side channel with local access. The list of affected products is provided in intel-sa-00334: https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00334.html
</code>

- [bitdefender/lvi-lfb-attack-poc](https://github.com/bitdefender/lvi-lfb-attack-poc)

### CVE-2020-0557

<code>
Insecure inherited permissions in Intel(R) PROSet/Wireless WiFi products before version 21.70 on Windows 10 may allow an authenticated user to potentially enable escalation of privilege via local access.
</code>

- [hessandrew/CVE-2020-0557_INTEL-SA-00338](https://github.com/hessandrew/CVE-2020-0557_INTEL-SA-00338)

### CVE-2020-0568

<code>
Race condition in the Intel(R) Driver and Support Assistant before version 20.1.5 may allow an authenticated user to potentially enable denial of service via local access.
</code>

- [hessandrew/CVE-2020-0568_INTEL-SA-00344](https://github.com/hessandrew/CVE-2020-0568_INTEL-SA-00344)

### CVE-2020-0601

<code>
A spoofing vulnerability exists in the way Windows CryptoAPI (Crypt32.dll) validates Elliptic Curve Cryptography (ECC) certificates.An attacker could exploit the vulnerability by using a spoofed code-signing certificate to sign a malicious executable, making it appear the file was from a trusted, legitimate source, aka 'Windows CryptoAPI Spoofing Vulnerability'.
</code>

- [nissan-sudo/CVE-2020-0601](https://github.com/nissan-sudo/CVE-2020-0601)
- [0xxon/cve-2020-0601](https://github.com/0xxon/cve-2020-0601)
- [SherlockSec/CVE-2020-0601](https://github.com/SherlockSec/CVE-2020-0601)
- [JPurrier/CVE-2020-0601](https://github.com/JPurrier/CVE-2020-0601)
- [0xxon/cve-2020-0601-plugin](https://github.com/0xxon/cve-2020-0601-plugin)
- [ollypwn/CurveBall](https://github.com/ollypwn/CurveBall)
- [kudelskisecurity/chainoffools](https://github.com/kudelskisecurity/chainoffools)
- [RrUZi/Awesome-CVE-2020-0601](https://github.com/RrUZi/Awesome-CVE-2020-0601)
- [BleepSec/CVE-2020-0601](https://github.com/BleepSec/CVE-2020-0601)
- [apmunch/CVE-2020-0601](https://github.com/apmunch/CVE-2020-0601)
- [saleemrashid/badecparams](https://github.com/saleemrashid/badecparams)
- [0xxon/cve-2020-0601-utils](https://github.com/0xxon/cve-2020-0601-utils)
- [Doug-Moody/Windows10_Cumulative_Updates_PowerShell](https://github.com/Doug-Moody/Windows10_Cumulative_Updates_PowerShell)
- [MarkusZehnle/CVE-2020-0601](https://github.com/MarkusZehnle/CVE-2020-0601)
- [YoannDqr/CVE-2020-0601](https://github.com/YoannDqr/CVE-2020-0601)
- [thimelp/cve-2020-0601-Perl](https://github.com/thimelp/cve-2020-0601-Perl)
- [dlee35/curveball_lua](https://github.com/dlee35/curveball_lua)
- [IIICTECH/-CVE-2020-0601-ECC---EXPLOIT](https://github.com/IIICTECH/-CVE-2020-0601-ECC---EXPLOIT)
- [Ash112121/CVE-2020-0601](https://github.com/Ash112121/CVE-2020-0601)
- [gentilkiwi/curveball](https://github.com/gentilkiwi/curveball)
- [Hans-MartinHannibalLauridsen/CurveBall](https://github.com/Hans-MartinHannibalLauridsen/CurveBall)
- [apodlosky/PoC_CurveBall](https://github.com/apodlosky/PoC_CurveBall)
- [ioncodes/Curveball](https://github.com/ioncodes/Curveball)
- [amlweems/gringotts](https://github.com/amlweems/gringotts)
- [aloswoya/CVE-2020-0601](https://github.com/aloswoya/CVE-2020-0601)
- [talbeerysec/CurveBallDetection](https://github.com/talbeerysec/CurveBallDetection)
- [david4599/CurveballCertTool](https://github.com/david4599/CurveballCertTool)
- [eastmountyxz/CVE-2020-0601-EXP](https://github.com/eastmountyxz/CVE-2020-0601-EXP)
- [eastmountyxz/CVE-2018-20250-WinRAR](https://github.com/eastmountyxz/CVE-2018-20250-WinRAR)
- [gremwell/cve-2020-0601_poc](https://github.com/gremwell/cve-2020-0601_poc)
- [bsides-rijeka/meetup-2-curveball](https://github.com/bsides-rijeka/meetup-2-curveball)
- [TechHexagon/CVE-2020-0601-spoofkey](https://github.com/TechHexagon/CVE-2020-0601-spoofkey)
- [ShayNehmad/twoplustwo](https://github.com/ShayNehmad/twoplustwo)

### CVE-2020-0609

<code>
A remote code execution vulnerability exists in Windows Remote Desktop Gateway (RD Gateway) when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests, aka 'Windows Remote Desktop Gateway (RD Gateway) Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2020-0610.
</code>

- [2d4d/rdg_scanner_cve-2020-0609](https://github.com/2d4d/rdg_scanner_cve-2020-0609)
- [ollypwn/BlueGate](https://github.com/ollypwn/BlueGate)
- [MalwareTech/RDGScanner](https://github.com/MalwareTech/RDGScanner)
- [Bechsen/CVE-2020-0609](https://github.com/Bechsen/CVE-2020-0609)
- [ioncodes/BlueGate](https://github.com/ioncodes/BlueGate)

### CVE-2020-0618

<code>
A remote code execution vulnerability exists in Microsoft SQL Server Reporting Services when it incorrectly handles page requests, aka 'Microsoft SQL Server Reporting Services Remote Code Execution Vulnerability'.
</code>

- [euphrat1ca/CVE-2020-0618](https://github.com/euphrat1ca/CVE-2020-0618)
- [wortell/cve-2020-0618](https://github.com/wortell/cve-2020-0618)

### CVE-2020-0624

<code>
An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-0642.
</code>

- [james0x40/CVE-2020-0624](https://github.com/james0x40/CVE-2020-0624)

### CVE-2020-0668

<code>
An elevation of privilege vulnerability exists in the way that the Windows Kernel handles objects in memory, aka 'Windows Kernel Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-0669, CVE-2020-0670, CVE-2020-0671, CVE-2020-0672.
</code>

- [itm4n/SysTracingPoc](https://github.com/itm4n/SysTracingPoc)
- [RedCursorSecurityConsulting/CVE-2020-0668](https://github.com/RedCursorSecurityConsulting/CVE-2020-0668)
- [Nan3r/CVE-2020-0668](https://github.com/Nan3r/CVE-2020-0668)

### CVE-2020-0674

<code>
A remote code execution vulnerability exists in the way that the scripting engine handles objects in memory in Internet Explorer, aka 'Scripting Engine Memory Corruption Vulnerability'. This CVE ID is unique from CVE-2020-0673, CVE-2020-0710, CVE-2020-0711, CVE-2020-0712, CVE-2020-0713, CVE-2020-0767.
</code>

- [binaryfigments/CVE-2020-0674](https://github.com/binaryfigments/CVE-2020-0674)
- [maxpl0it/CVE-2020-0674-Exploit](https://github.com/maxpl0it/CVE-2020-0674-Exploit)

### CVE-2020-0683

<code>
An elevation of privilege vulnerability exists in the Windows Installer when MSI packages process symbolic links, aka 'Windows Installer Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-0686.
</code>

- [padovah4ck/CVE-2020-0683](https://github.com/padovah4ck/CVE-2020-0683)

### CVE-2020-0688

<code>
A remote code execution vulnerability exists in Microsoft Exchange software when the software fails to properly handle objects in memory, aka 'Microsoft Exchange Memory Corruption Vulnerability'.
</code>

- [random-robbie/cve-2020-0688](https://github.com/random-robbie/cve-2020-0688)
- [Jumbo-WJB/CVE-2020-0688](https://github.com/Jumbo-WJB/CVE-2020-0688)
- [Ridter/cve-2020-0688](https://github.com/Ridter/cve-2020-0688)
- [Yt1g3r/CVE-2020-0688_EXP](https://github.com/Yt1g3r/CVE-2020-0688_EXP)
- [righter83/CVE-2020-0688](https://github.com/righter83/CVE-2020-0688)
- [truongtn/cve-2020-0688](https://github.com/truongtn/cve-2020-0688)
- [onSec-fr/CVE-2020-0688-Scanner](https://github.com/onSec-fr/CVE-2020-0688-Scanner)
- [youncyb/CVE-2020-0688](https://github.com/youncyb/CVE-2020-0688)
- [zcgonvh/CVE-2020-0688](https://github.com/zcgonvh/CVE-2020-0688)
- [justin-p/PSForgot2kEyXCHANGE](https://github.com/justin-p/PSForgot2kEyXCHANGE)
- [cert-lv/CVE-2020-0688](https://github.com/cert-lv/CVE-2020-0688)
- [ravinacademy/CVE-2020-0688](https://github.com/ravinacademy/CVE-2020-0688)
- [mahyarx/Exploit_CVE-2020-0688](https://github.com/mahyarx/Exploit_CVE-2020-0688)
- [ktpdpro/CVE-2020-0688](https://github.com/ktpdpro/CVE-2020-0688)

### CVE-2020-0692

<code>
An elevation of privilege vulnerability exists in Microsoft Exchange Server, aka 'Microsoft Exchange Server Elevation of Privilege Vulnerability'.
</code>

- [githubassets/CVE-2020-0692](https://github.com/githubassets/CVE-2020-0692)

### CVE-2020-0728

<code>
An information vulnerability exists when Windows Modules Installer Service improperly discloses file information, aka 'Windows Modules Installer Service Information Disclosure Vulnerability'.
</code>

- [irsl/CVE-2020-0728](https://github.com/irsl/CVE-2020-0728)

### CVE-2020-0753

<code>
An elevation of privilege vulnerability exists in Windows Error Reporting (WER) when WER handles and executes files, aka 'Windows Error Reporting Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-0754.
</code>

- [afang5472/CVE-2020-0753-and-CVE-2020-0754](https://github.com/afang5472/CVE-2020-0753-and-CVE-2020-0754)
- [VikasVarshney/CVE-2020-0753-and-CVE-2020-0754](https://github.com/VikasVarshney/CVE-2020-0753-and-CVE-2020-0754)

### CVE-2020-0796

<code>
A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.
</code>

- [Aekras1a/CVE-2020-0796-PoC](https://github.com/Aekras1a/CVE-2020-0796-PoC)
- [technion/DisableSMBCompression](https://github.com/technion/DisableSMBCompression)
- [T13nn3s/CVE-2020-0796](https://github.com/T13nn3s/CVE-2020-0796)
- [ollypwn/SMBGhost](https://github.com/ollypwn/SMBGhost)
- [joaozietolie/CVE-2020-0796-Checker](https://github.com/joaozietolie/CVE-2020-0796-Checker)
- [pr4jwal/CVE-2020-0796](https://github.com/pr4jwal/CVE-2020-0796)
- [ButrintKomoni/cve-2020-0796](https://github.com/ButrintKomoni/cve-2020-0796)
- [dickens88/cve-2020-0796-scanner](https://github.com/dickens88/cve-2020-0796-scanner)
- [kn6869610/CVE-2020-0796](https://github.com/kn6869610/CVE-2020-0796)
- [awareseven/eternalghosttest](https://github.com/awareseven/eternalghosttest)
- [weidutech/CVE-2020-0796-PoC](https://github.com/weidutech/CVE-2020-0796-PoC)
- [OfJAAH/CVE-2020-0796](https://github.com/OfJAAH/CVE-2020-0796)
- [xax007/CVE-2020-0796-Scanner](https://github.com/xax007/CVE-2020-0796-Scanner)
- [Dhoomralochana/Scanners-for-CVE-2020-0796-Testing](https://github.com/Dhoomralochana/Scanners-for-CVE-2020-0796-Testing)
- [UraSecTeam/smbee](https://github.com/UraSecTeam/smbee)
- [0xtobu/CVE-2020-0796](https://github.com/0xtobu/CVE-2020-0796)
- [netscylla/SMBGhost](https://github.com/netscylla/SMBGhost)
- [eerykitty/CVE-2020-0796-PoC](https://github.com/eerykitty/CVE-2020-0796-PoC)
- [wneessen/SMBCompScan](https://github.com/wneessen/SMBCompScan)
- [ioncodes/SMBGhost](https://github.com/ioncodes/SMBGhost)
- [laolisafe/CVE-2020-0796](https://github.com/laolisafe/CVE-2020-0796)
- [gabimarti/SMBScanner](https://github.com/gabimarti/SMBScanner)
- [Almorabea/SMBGhost-WorkaroundApplier](https://github.com/Almorabea/SMBGhost-WorkaroundApplier)
- [IAreKyleW00t/SMBGhosts](https://github.com/IAreKyleW00t/SMBGhosts)
- [vysecurity/CVE-2020-0796](https://github.com/vysecurity/CVE-2020-0796)
- [marcinguy/CVE-2020-0796](https://github.com/marcinguy/CVE-2020-0796)
- [plorinquer/cve-2020-0796](https://github.com/plorinquer/cve-2020-0796)
- [BinaryShadow94/SMBv3.1.1-scan---CVE-2020-0796](https://github.com/BinaryShadow94/SMBv3.1.1-scan---CVE-2020-0796)
- [x1n5h3n/SMBGhost](https://github.com/x1n5h3n/SMBGhost)
- [wsfengfan/CVE-2020-0796](https://github.com/wsfengfan/CVE-2020-0796)
- [miraizeroday/CVE-2020-0796](https://github.com/miraizeroday/CVE-2020-0796)
- [GuoKerS/aioScan_CVE-2020-0796](https://github.com/GuoKerS/aioScan_CVE-2020-0796)
- [jiansiting/CVE-2020-0796-Scanner](https://github.com/jiansiting/CVE-2020-0796-Scanner)
- [maxpl0it/Unauthenticated-CVE-2020-0796-PoC](https://github.com/maxpl0it/Unauthenticated-CVE-2020-0796-PoC)
- [ran-sama/CVE-2020-0796](https://github.com/ran-sama/CVE-2020-0796)
- [sujitawake/smbghost](https://github.com/sujitawake/smbghost)
- [julixsalas/CVE-2020-0796](https://github.com/julixsalas/CVE-2020-0796)
- [insightglacier/SMBGhost_Crash_Poc](https://github.com/insightglacier/SMBGhost_Crash_Poc)
- [5l1v3r1/CVE-2020-0796-PoC-and-Scan](https://github.com/5l1v3r1/CVE-2020-0796-PoC-and-Scan)
- [cory-zajicek/CVE-2020-0796-DoS](https://github.com/cory-zajicek/CVE-2020-0796-DoS)
- [tripledd/cve-2020-0796-vuln](https://github.com/tripledd/cve-2020-0796-vuln)
- [danigargu/CVE-2020-0796](https://github.com/danigargu/CVE-2020-0796)
- [ZecOps/CVE-2020-0796-LPE-POC](https://github.com/ZecOps/CVE-2020-0796-LPE-POC)
- [TinToSer/CVE-2020-0796-LPE](https://github.com/TinToSer/CVE-2020-0796-LPE)
- [f1tz/CVE-2020-0796-LPE-EXP](https://github.com/f1tz/CVE-2020-0796-LPE-EXP)
- [tango-j/CVE-2020-0796](https://github.com/tango-j/CVE-2020-0796)
- [jiansiting/CVE-2020-0796](https://github.com/jiansiting/CVE-2020-0796)
- [eastmountyxz/CVE-2020-0796-SMB](https://github.com/eastmountyxz/CVE-2020-0796-SMB)
- [LabDookhtegan/CVE-2020-0796-EXP](https://github.com/LabDookhtegan/CVE-2020-0796-EXP)
- [Rvn0xsy/CVE_2020_0796_CNA](https://github.com/Rvn0xsy/CVE_2020_0796_CNA)
- [0xeb-bp/cve-2020-0796](https://github.com/0xeb-bp/cve-2020-0796)
- [intelliroot-tech/cve-2020-0796-Scanner](https://github.com/intelliroot-tech/cve-2020-0796-Scanner)
- [thelostworldFree/CVE-2020-0796](https://github.com/thelostworldFree/CVE-2020-0796)
- [syadg123/CVE-2020-0796](https://github.com/syadg123/CVE-2020-0796)
- [section-c/CVE-2020-0796](https://github.com/section-c/CVE-2020-0796)
- [bacth0san96/SMBGhostScanner](https://github.com/bacth0san96/SMBGhostScanner)

### CVE-2020-0798

<code>
An elevation of privilege vulnerability exists in the Windows Installer when the Windows Installer fails to properly sanitize input leading to an insecure library loading behavior.A locally authenticated attacker could run arbitrary code with elevated system privileges, aka 'Windows Installer Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-0779, CVE-2020-0814, CVE-2020-0842, CVE-2020-0843.
</code>

- [githubassets/CVE-2020-0798](https://github.com/githubassets/CVE-2020-0798)

### CVE-2020-0814

<code>
An elevation of privilege vulnerability exists in Windows Installer because of the way Windows Installer handles certain filesystem operations.To exploit the vulnerability, an attacker would require unprivileged execution on the victim system, aka 'Windows Installer Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-0779, CVE-2020-0798, CVE-2020-0842, CVE-2020-0843.
</code>

- [klinix5/CVE-2020-0814](https://github.com/klinix5/CVE-2020-0814)

### CVE-2020-0883

<code>
A remote code execution vulnerability exists in the way that the Windows Graphics Device Interface (GDI) handles objects in the memory, aka 'GDI+ Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2020-0881.
</code>

- [githubassets/CVE-2020-0883](https://github.com/githubassets/CVE-2020-0883)
- [thelostworldFree/CVE-2020-0883](https://github.com/thelostworldFree/CVE-2020-0883)
- [syadg123/CVE-2020-0883](https://github.com/syadg123/CVE-2020-0883)

### CVE-2020-0905

<code>
An remote code execution vulnerability exists in Microsoft Dynamics Business Central, aka 'Dynamics Business Central Remote Code Execution Vulnerability'.
</code>

- [githubassets/CVE-2020-0905](https://github.com/githubassets/CVE-2020-0905)

### CVE-2020-0910

<code>
A remote code execution vulnerability exists when Windows Hyper-V on a host server fails to properly validate input from an authenticated user on a guest operating system, aka 'Windows Hyper-V Remote Code Execution Vulnerability'.
</code>

- [inetshell/CVE-2020-0910](https://github.com/inetshell/CVE-2020-0910)

### CVE-2020-0976

<code>
A spoofing vulnerability exists when Microsoft SharePoint Server does not properly sanitize a specially crafted web request to an affected SharePoint server, aka 'Microsoft SharePoint Spoofing Vulnerability'. This CVE ID is unique from CVE-2020-0972, CVE-2020-0975, CVE-2020-0977.
</code>

- [ericzhong2010/GUI-Check-CVE-2020-0976](https://github.com/ericzhong2010/GUI-Check-CVE-2020-0976)

### CVE-2020-1015

<code>
An elevation of privilege vulnerability exists in the way that the User-Mode Power Service (UMPS) handles objects in memory, aka 'Windows Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-0934, CVE-2020-0983, CVE-2020-1009, CVE-2020-1011.
</code>

- [0xeb-bp/cve-2020-1015](https://github.com/0xeb-bp/cve-2020-1015)

### CVE-2020-10199

<code>
Sonatype Nexus Repository before 3.21.2 allows JavaEL Injection (issue 1 of 2).
</code>

- [zhzyker/exphub](https://github.com/zhzyker/exphub)
- [wsfengfan/CVE-2020-10199-10204](https://github.com/wsfengfan/CVE-2020-10199-10204)
- [jas502n/CVE-2020-10199](https://github.com/jas502n/CVE-2020-10199)
- [magicming200/CVE-2020-10199_CVE-2020-10204](https://github.com/magicming200/CVE-2020-10199_CVE-2020-10204)
- [zhzyker/CVE-2020-10199_POC-EXP](https://github.com/zhzyker/CVE-2020-10199_POC-EXP)

### CVE-2020-10204

<code>
Sonatype Nexus Repository before 3.21.2 allows Remote Code Execution.
</code>

- [duolaoa333/CVE-2020-10204](https://github.com/duolaoa333/CVE-2020-10204)

### CVE-2020-10238

<code>
An issue was discovered in Joomla! before 3.9.16. Various actions in com_templates lack the required ACL checks, leading to various potential attack vectors.
</code>

- [HoangKien1020/CVE-2020-10238](https://github.com/HoangKien1020/CVE-2020-10238)

### CVE-2020-10239

<code>
An issue was discovered in Joomla! before 3.9.16. Incorrect Access Control in the SQL fieldtype of com_fields allows access for non-superadmin users.
</code>

- [HoangKien1020/CVE-2020-10239](https://github.com/HoangKien1020/CVE-2020-10239)

### CVE-2020-1048
- [zveriu/CVE-2009-0229-PoC](https://github.com/zveriu/CVE-2009-0229-PoC)

### CVE-2020-10551

<code>
QQBrowser before 10.5.3870.400 installs a Windows service TsService.exe. This file is writable by anyone belonging to the NT AUTHORITY\Authenticated Users group, which includes all local and remote users. This can be abused by local attackers to escalate privileges to NT AUTHORITY\SYSTEM by writing a malicious executable to the location of TsService.
</code>

- [seqred-s-a/CVE-2020-10551](https://github.com/seqred-s-a/CVE-2020-10551)

### CVE-2020-10558

<code>
The driving interface of Tesla Model 3 vehicles in any release before 2020.4.10 allows Denial of Service to occur due to improper process separation, which allows attackers to disable the speedometer, web browser, climate controls, turn signal visual and sounds, navigation, autopilot notifications, along with other miscellaneous functions from the main screen.
</code>

- [nuzzl/CVE-2020-10558](https://github.com/nuzzl/CVE-2020-10558)

### CVE-2020-10560

<code>
An issue was discovered in Open Source Social Network (OSSN) through 5.3. A user-controlled file path with a weak cryptographic rand() can be used to read any file with the permissions of the webserver. This can lead to further compromise. The attacker must conduct a brute-force attack against the SiteKey to insert into a crafted URL for components/OssnComments/ossn_com.php and/or libraries/ossn.lib.upgrade.php.
</code>

- [LucidUnicorn/CVE-2020-10560-Key-Recovery](https://github.com/LucidUnicorn/CVE-2020-10560-Key-Recovery)
- [kevthehermit/CVE-2020-10560](https://github.com/kevthehermit/CVE-2020-10560)

### CVE-2020-10663

<code>
The JSON gem through 2.2.0 for Ruby, as used in Ruby 2.4 through 2.4.9, 2.5 through 2.5.7, and 2.6 through 2.6.5, has an Unsafe Object Creation Vulnerability. This is quite similar to CVE-2013-0269, but does not rely on poor garbage-collection behavior within Ruby. Specifically, use of JSON parsing methods can lead to creation of a malicious object within the interpreter, with adverse effects that are application-dependent.
</code>

- [rails-lts/json_cve_2020_10663](https://github.com/rails-lts/json_cve_2020_10663)

### CVE-2020-10673

<code>
FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to com.caucho.config.types.ResourceRef (aka caucho-quercus).
</code>

- [0nise/CVE-2020-10673](https://github.com/0nise/CVE-2020-10673)

### CVE-2020-1102
- [DanielRuf/snyk-js-jquery-565129](https://github.com/DanielRuf/snyk-js-jquery-565129)

### CVE-2020-11107

<code>
An issue was discovered in XAMPP before 7.2.29, 7.3.x before 7.3.16 , and 7.4.x before 7.4.4 on Windows. An unprivileged user can change a .exe configuration in xampp-contol.ini for all users (including admins) to enable arbitrary command execution.
</code>

- [S1lkys/CVE-2020-11107](https://github.com/S1lkys/CVE-2020-11107)
- [andripwn/CVE-2020-11107](https://github.com/andripwn/CVE-2020-11107)

### CVE-2020-11108

<code>
The Gravity updater in Pi-hole through 4.4 allows an authenticated adversary to upload arbitrary files. This can be abused for Remote Code Execution by writing to a PHP file in the web directory. (Also, it can be used in conjunction with the sudo rule for the www-data user to escalate privileges to root.) The code error is in gravity_DownloadBlocklistFromUrl in gravity.sh.
</code>

- [Frichetten/CVE-2020-11108-PoC](https://github.com/Frichetten/CVE-2020-11108-PoC)

### CVE-2020-11539

<code>
An issue was discovered on Tata Sonata Smart SF Rush 1.12 devices. It has been identified that the smart band has no pairing (mode 0 Bluetooth LE security level) The data being transmitted over the air is not encrypted. Adding to this, the data being sent to the smart band doesn't have any authentication or signature verification. Thus, any attacker can control a parameter of the device.
</code>

- [the-girl-who-lived/CVE-2020-11539](https://github.com/the-girl-who-lived/CVE-2020-11539)

### CVE-2020-11650

<code>
An issue was discovered in iXsystems FreeNAS (and TrueNAS) 11.2 before 11.2-u8 and 11.3 before 11.3-U1. It allows a denial of service. The login authentication component has no limits on the length of an authentication message or the rate at which such messages are sent.
</code>

- [weinull/CVE-2020-11650](https://github.com/weinull/CVE-2020-11650)

### CVE-2020-11651

<code>
An issue was discovered in SaltStack Salt before 2019.2.4 and 3000 before 3000.2. The salt-master process ClearFuncs class does not properly validate method calls. This allows a remote user to access some methods without authentication. These methods can be used to retrieve user tokens from the salt master and/or run arbitrary commands on salt minions.
</code>

- [chef-cft/salt-vulnerabilities](https://github.com/chef-cft/salt-vulnerabilities)
- [rossengeorgiev/salt-security-backports](https://github.com/rossengeorgiev/salt-security-backports)
- [dozernz/cve-2020-11651](https://github.com/dozernz/cve-2020-11651)
- [0xc0d/CVE-2020-11651](https://github.com/0xc0d/CVE-2020-11651)
- [jasperla/CVE-2020-11651-poc](https://github.com/jasperla/CVE-2020-11651-poc)
- [Imanfeng/SaltStack-Exp](https://github.com/Imanfeng/SaltStack-Exp)
- [bravery9/SaltStack-Exp](https://github.com/bravery9/SaltStack-Exp)
- [kevthehermit/CVE-2020-11651](https://github.com/kevthehermit/CVE-2020-11651)
- [lovelyjuice/cve-2020-11651-exp-plus](https://github.com/lovelyjuice/cve-2020-11651-exp-plus)
- [heikanet/CVE-2020-11651-CVE-2020-11652-EXP](https://github.com/heikanet/CVE-2020-11651-CVE-2020-11652-EXP)
- [RakhithJK/CVE-2020-11651](https://github.com/RakhithJK/CVE-2020-11651)

### CVE-2020-11794
- [w4cky/CVE-2020-11794](https://github.com/w4cky/CVE-2020-11794)

### CVE-2020-11890

<code>
An issue was discovered in Joomla! before 3.9.17. Improper input validations in the usergroup table class could lead to a broken ACL configuration.
</code>

- [HoangKien1020/CVE-2020-11890](https://github.com/HoangKien1020/CVE-2020-11890)

### CVE-2020-11932

<code>
It was discovered that the Subiquity installer for Ubuntu Server logged the LUKS full disk encryption password if one was entered.
</code>

- [ProjectorBUg/CVE-2020-11932](https://github.com/ProjectorBUg/CVE-2020-11932)
- [Staubgeborener/CVE-2020-11932](https://github.com/Staubgeborener/CVE-2020-11932)

### CVE-2020-12078

<code>
An issue was discovered in Open-AudIT 3.3.1. There is shell metacharacter injection via attributes to an open-audit/configuration/ URI. An attacker can exploit this by adding an excluded IP address to the global discovery settings (internally called exclude_ip). This exclude_ip value is passed to the exec function in the discoveries_helper.php file (inside the all_ip_list function) without being filtered, which means that the attacker can provide a payload instead of a valid IP address.
</code>

- [mhaskar/CVE-2020-12078](https://github.com/mhaskar/CVE-2020-12078)

### CVE-2020-12112

<code>
BigBlueButton before 2.2.5 allows remote attackers to obtain sensitive files via Local File Inclusion.
</code>

- [tchenu/CVE-2020-12112](https://github.com/tchenu/CVE-2020-12112)

### CVE-2020-12116

<code>
Zoho ManageEngine OpManager Stable build before 124196 and Released build before 125125 allows an unauthenticated attacker to read arbitrary files on the server by sending a crafted request.
</code>

- [BeetleChunks/CVE-2020-12116](https://github.com/BeetleChunks/CVE-2020-12116)

### CVE-2020-12122
- [FULLSHADE/CVE-2020-12122](https://github.com/FULLSHADE/CVE-2020-12122)

### CVE-2020-123456789
- [mrknow001/CVE-2020-123456789](https://github.com/mrknow001/CVE-2020-123456789)

### CVE-2020-12629

<code>
include/class.sla.php in osTicket before 1.14.2 allows XSS via the SLA Name.
</code>

- [mkelepce/CVE-2020-12629](https://github.com/mkelepce/CVE-2020-12629)

### CVE-2020-12696

<code>
The iframe plugin before 4.5 for WordPress does not sanitize a URL.
</code>

- [g-rubert/CVE-2020-12696](https://github.com/g-rubert/CVE-2020-12696)

### CVE-2020-12717

<code>
The COVIDSafe (Australia) app 1.0 and 1.1 for iOS allows a remote attacker to crash the app, and consequently interfere with COVID-19 contact tracing, via a Bluetooth advertisement containing manufacturer data that is too short. This occurs because of an erroneous OpenTrace manuData.subdata call. The ABTraceTogether (Alberta), ProteGO (Poland), and TraceTogether (Singapore) apps were also affected.
</code>

- [wabzqem/covidsafe-CVE-2020-12717-exploit](https://github.com/wabzqem/covidsafe-CVE-2020-12717-exploit)

### CVE-2020-12800
- [amartinsec/CVE-2020-12800](https://github.com/amartinsec/CVE-2020-12800)

### CVE-2020-12856
- [alwentiu/COVIDSafe-CVE-2020-12856](https://github.com/alwentiu/COVIDSafe-CVE-2020-12856)

### CVE-2020-1611

<code>
A Local File Inclusion vulnerability in Juniper Networks Junos Space allows an attacker to view all files on the target when the device receives malicious HTTP packets. This issue affects: Juniper Networks Junos Space versions prior to 19.4R1.
</code>

- [Ibonok/CVE-2020-1611](https://github.com/Ibonok/CVE-2020-1611)

### CVE-2020-1938

<code>
When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.
</code>

- [0nise/CVE-2020-1938](https://github.com/0nise/CVE-2020-1938)
- [xindongzhuaizhuai/CVE-2020-1938](https://github.com/xindongzhuaizhuai/CVE-2020-1938)
- [nibiwodong/CNVD-2020-10487-Tomcat-ajp-POC](https://github.com/nibiwodong/CNVD-2020-10487-Tomcat-ajp-POC)
- [Kit4y/CNVD-2020-10487-Tomcat-Ajp-lfi-Scanner](https://github.com/Kit4y/CNVD-2020-10487-Tomcat-Ajp-lfi-Scanner)
- [laolisafe/CVE-2020-1938](https://github.com/laolisafe/CVE-2020-1938)
- [DaemonShao/CVE-2020-1938](https://github.com/DaemonShao/CVE-2020-1938)
- [sv3nbeast/CVE-2020-1938-Tomact-file_include-file_read](https://github.com/sv3nbeast/CVE-2020-1938-Tomact-file_include-file_read)
- [fairyming/CVE-2020-1938](https://github.com/fairyming/CVE-2020-1938)
- [dacade/cve-2020-1938](https://github.com/dacade/cve-2020-1938)
- [woaiqiukui/CVE-2020-1938TomcatAjpScanner](https://github.com/woaiqiukui/CVE-2020-1938TomcatAjpScanner)
- [fatal0/tomcat-cve-2020-1938-check](https://github.com/fatal0/tomcat-cve-2020-1938-check)
- [ze0r/GhostCat-LFI-exp](https://github.com/ze0r/GhostCat-LFI-exp)
- [delsadan/CNVD-2020-10487-Bulk-verification](https://github.com/delsadan/CNVD-2020-10487-Bulk-verification)
- [00theway/Ghostcat-CNVD-2020-10487](https://github.com/00theway/Ghostcat-CNVD-2020-10487)
- [shaunmclernon/ghostcat-verification](https://github.com/shaunmclernon/ghostcat-verification)
- [Zaziki1337/Ghostcat-CVE-2020-1938](https://github.com/Zaziki1337/Ghostcat-CVE-2020-1938)
- [w4fz5uck5/CVE-2020-1938-Clean-Version](https://github.com/w4fz5uck5/CVE-2020-1938-Clean-Version)
- [syncxx/CVE-2020-1938-Tool](https://github.com/syncxx/CVE-2020-1938-Tool)
- [ZhengHaoCHeng/CNVD-2020-10487](https://github.com/ZhengHaoCHeng/CNVD-2020-10487)
- [I-Runtime-Error/CVE-2020-1938](https://github.com/I-Runtime-Error/CVE-2020-1938)
- [Umesh2807/Ghostcat](https://github.com/Umesh2807/Ghostcat)

### CVE-2020-1947

<code>
In Apache ShardingSphere(incubator) 4.0.0-RC3 and 4.0.0, the ShardingSphere's web console uses the SnakeYAML library for parsing YAML inputs to load datasource configuration. SnakeYAML allows to unmarshal data to a Java type By using the YAML tag. Unmarshalling untrusted data can lead to security flaws of RCE.
</code>

- [Imanfeng/CVE-2020-1947](https://github.com/Imanfeng/CVE-2020-1947)
- [jas502n/CVE-2020-1947](https://github.com/jas502n/CVE-2020-1947)
- [wsfengfan/CVE-2020-1947](https://github.com/wsfengfan/CVE-2020-1947)
- [shadowsock5/ShardingSphere_CVE-2020-1947](https://github.com/shadowsock5/ShardingSphere_CVE-2020-1947)

### CVE-2020-1958

<code>
When LDAP authentication is enabled in Apache Druid 0.17.0, callers of Druid APIs with a valid set of LDAP credentials can bypass the credentialsValidator.userSearch filter barrier that determines if a valid LDAP user is allowed to authenticate with Druid. They are still subject to role-based authorization checks, if configured. Callers of Druid APIs can also retrieve any LDAP attribute values of users that exist on the LDAP server, so long as that information is visible to the Druid server. This information disclosure does not require the caller itself to be a valid LDAP user.
</code>

- [ggolawski/CVE-2020-1958](https://github.com/ggolawski/CVE-2020-1958)

### CVE-2020-1967

<code>
Server or client applications that call the SSL_check_chain() function during or after a TLS 1.3 handshake may crash due to a NULL pointer dereference as a result of incorrect handling of the &quot;signature_algorithms_cert&quot; TLS extension. The crash occurs if an invalid or unrecognised signature algorithm is received from the peer. This could be exploited by a malicious peer in a Denial of Service attack. OpenSSL version 1.1.1d, 1.1.1e, and 1.1.1f are affected by this issue. This issue did not affect OpenSSL versions prior to 1.1.1d. Fixed in OpenSSL 1.1.1g (Affected 1.1.1d-1.1.1f).
</code>

- [irsl/CVE-2020-1967](https://github.com/irsl/CVE-2020-1967)

### CVE-2020-2333
- [section-c/CVE-2020-2333](https://github.com/section-c/CVE-2020-2333)

### CVE-2020-2546

<code>
Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Application Container - JavaEE). Supported versions that are affected are 10.3.6.0.0 and 12.1.3.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
</code>

- [hktalent/CVE_2020_2546](https://github.com/hktalent/CVE_2020_2546)

### CVE-2020-2551

<code>
Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: WLS Core Components). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
</code>

- [0xn0ne/weblogicScanner](https://github.com/0xn0ne/weblogicScanner)
- [jas502n/CVE-2020-2551](https://github.com/jas502n/CVE-2020-2551)
- [hktalent/CVE-2020-2551](https://github.com/hktalent/CVE-2020-2551)
- [0nise/CVE-2020-2551](https://github.com/0nise/CVE-2020-2551)
- [Y4er/CVE-2020-2551](https://github.com/Y4er/CVE-2020-2551)
- [Gspider7/rmi-iiop](https://github.com/Gspider7/rmi-iiop)
- [cnsimo/CVE-2020-2551](https://github.com/cnsimo/CVE-2020-2551)

### CVE-2020-2555

<code>
Vulnerability in the Oracle Coherence product of Oracle Fusion Middleware (component: Caching,CacheStore,Invocation). Supported versions that are affected are 3.7.1.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle Coherence. Successful attacks of this vulnerability can result in takeover of Oracle Coherence. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
</code>

- [Hu3sky/CVE-2020-2555](https://github.com/Hu3sky/CVE-2020-2555)
- [wsfengfan/CVE-2020-2555](https://github.com/wsfengfan/CVE-2020-2555)
- [0nise/CVE-2020-2555](https://github.com/0nise/CVE-2020-2555)
- [Y4er/CVE-2020-2555](https://github.com/Y4er/CVE-2020-2555)
- [Maskhe/cve-2020-2555](https://github.com/Maskhe/cve-2020-2555)

### CVE-2020-2655

<code>
Vulnerability in the Java SE product of Oracle Java SE (component: JSSE). Supported versions that are affected are Java SE: 11.0.5 and 13.0.1. Difficult to exploit vulnerability allows unauthenticated attacker with network access via HTTPS to compromise Java SE. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Java SE accessible data as well as unauthorized read access to a subset of Java SE accessible data. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. CVSS 3.0 Base Score 4.8 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N).
</code>

- [RUB-NDS/CVE-2020-2655-DemoServer](https://github.com/RUB-NDS/CVE-2020-2655-DemoServer)

### CVE-2020-2883

<code>
Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
</code>

- [Y4er/CVE-2020-2883](https://github.com/Y4er/CVE-2020-2883)
- [MagicZer0/Weblogic_CVE-2020-2883_POC](https://github.com/MagicZer0/Weblogic_CVE-2020-2883_POC)

### CVE-2020-3153

<code>
A vulnerability in the installer component of Cisco AnyConnect Secure Mobility Client for Windows could allow an authenticated local attacker to copy user-supplied files to system level directories with system level privileges. The vulnerability is due to the incorrect handling of directory paths. An attacker could exploit this vulnerability by creating a malicious file and copying the file to a system directory. An exploit could allow the attacker to copy malicious files to arbitrary locations with system level privileges. This could include DLL pre-loading, DLL hijacking, and other related attacks. To exploit this vulnerability, the attacker needs valid credentials on the Windows system.
</code>

- [shubham0d/CVE-2020-3153](https://github.com/shubham0d/CVE-2020-3153)

### CVE-2020-3766

<code>
Adobe Genuine Integrity Service versions Version 6.4 and earlier have an insecure file permissions vulnerability. Successful exploitation could lead to privilege escalation.
</code>

- [hessandrew/CVE-2020-3766_APSB20-12](https://github.com/hessandrew/CVE-2020-3766_APSB20-12)

### CVE-2020-3833

<code>
An inconsistent user interface issue was addressed with improved state management. This issue is fixed in Safari 13.0.5. Visiting a malicious website may lead to address bar spoofing.
</code>

- [c0d3G33k/Safari-Address-Bar-Spoof-CVE-2020-3833-](https://github.com/c0d3G33k/Safari-Address-Bar-Spoof-CVE-2020-3833-)

### CVE-2020-3952

<code>
Under certain conditions, vmdir that ships with VMware vCenter Server, as part of an embedded or external Platform Services Controller (PSC), does not correctly implement access controls.
</code>

- [commandermoon/CVE-2020-3952](https://github.com/commandermoon/CVE-2020-3952)
- [frustreated/CVE-2020-3952](https://github.com/frustreated/CVE-2020-3952)
- [guardicore/vmware_vcenter_cve_2020_3952](https://github.com/guardicore/vmware_vcenter_cve_2020_3952)
- [gelim/CVE-2020-3952](https://github.com/gelim/CVE-2020-3952)
- [Fa1c0n35/vmware_vcenter_cve_2020_3952](https://github.com/Fa1c0n35/vmware_vcenter_cve_2020_3952)

### CVE-2020-4276

<code>
IBM WebSphere Application Server 7.0, 8.0, 8.5, and 9.0 traditional is vulnerable to a privilege escalation vulnerability when using token-based authentication in an admin request over the SOAP connector. X-Force ID: 175984.
</code>

- [mekoko/CVE-2020-4276](https://github.com/mekoko/CVE-2020-4276)

### CVE-2020-5236

<code>
Waitress version 1.4.2 allows a DOS attack When waitress receives a header that contains invalid characters. When a header like &quot;Bad-header: xxxxxxxxxxxxxxx\x10&quot; is received, it will cause the regular expression engine to catastrophically backtrack causing the process to use 100% CPU time and blocking any other interactions. This allows an attacker to send a single request with an invalid header and take the service offline. This issue was introduced in version 1.4.2 when the regular expression was updated to attempt to match the behaviour required by errata associated with RFC7230. The regular expression that is used to validate incoming headers has been updated in version 1.4.3, it is recommended that people upgrade to the new version of Waitress as soon as possible.
</code>

- [motikan2010/CVE-2020-5236](https://github.com/motikan2010/CVE-2020-5236)

### CVE-2020-5250

<code>
In PrestaShop before version 1.7.6.4, when a customer edits their address, they can freely change the id_address in the form, and thus steal someone else's address. It is the same with CustomerForm, you are able to change the id_customer and change all information of all accounts. The problem is patched in version 1.7.6.4.
</code>

- [drkbcn/lblfixer_cve2020_5250](https://github.com/drkbcn/lblfixer_cve2020_5250)

### CVE-2020-5254

<code>
In NetHack before 3.6.6, some out-of-bound values for the hilite_status option can be exploited. NetHack 3.6.6 resolves this issue.
</code>

- [dpmdpm2/CVE-2020-5254](https://github.com/dpmdpm2/CVE-2020-5254)

### CVE-2020-5260

<code>
Affected versions of Git have a vulnerability whereby Git can be tricked into sending private credentials to a host controlled by an attacker. Git uses external &quot;credential helper&quot; programs to store and retrieve passwords or other credentials from secure storage provided by the operating system. Specially-crafted URLs that contain an encoded newline can inject unintended values into the credential helper protocol stream, causing the credential helper to retrieve the password for one server (e.g., good.example.com) for an HTTP request being made to another server (e.g., evil.example.com), resulting in credentials for the former being sent to the latter. There are no restrictions on the relationship between the two, meaning that an attacker can craft a URL that will present stored credentials for any host to a host of their choosing. The vulnerability can be triggered by feeding a malicious URL to git clone. However, the affected URLs look rather suspicious; the likely vector would be through systems which automatically clone URLs not visible to the user, such as Git submodules, or package systems built around Git. The problem has been patched in the versions published on April 14th, 2020, going back to v2.17.x. Anyone wishing to backport the change further can do so by applying commit 9a6bbee (the full release includes extra checks for git fsck, but that commit is sufficient to protect clients against the vulnerability). The patched versions are: 2.17.4, 2.18.3, 2.19.4, 2.20.3, 2.21.2, 2.22.3, 2.23.2, 2.24.2, 2.25.3, 2.26.1.
</code>

- [brompwnie/cve-2020-5260](https://github.com/brompwnie/cve-2020-5260)
- [Asgavar/CVE-2020-5260](https://github.com/Asgavar/CVE-2020-5260)
- [sv3nbeast/CVE-2020-5260](https://github.com/sv3nbeast/CVE-2020-5260)

### CVE-2020-5267

<code>
In ActionView before versions 6.0.2.2 and 5.2.4.2, there is a possible XSS vulnerability in ActionView's JavaScript literal escape helpers. Views that use the `j` or `escape_javascript` methods may be susceptible to XSS attacks. The issue is fixed in versions 6.0.2.2 and 5.2.4.2.
</code>

- [GUI/legacy-rails-CVE-2020-5267-patch](https://github.com/GUI/legacy-rails-CVE-2020-5267-patch)

### CVE-2020-5398

<code>
In Spring Framework, versions 5.2.x prior to 5.2.3, versions 5.1.x prior to 5.1.13, and versions 5.0.x prior to 5.0.16, an application is vulnerable to a reflected file download (RFD) attack when it sets a &quot;Content-Disposition&quot; header in the response where the filename attribute is derived from user supplied input.
</code>

- [motikan2010/CVE-2020-5398](https://github.com/motikan2010/CVE-2020-5398)

### CVE-2020-5509

<code>
PHPGurukul Car Rental Project v1.0 allows Remote Code Execution via an executable file in an upload of a new profile image.
</code>

- [FULLSHADE/CVE-2020-5509](https://github.com/FULLSHADE/CVE-2020-5509)

### CVE-2020-5837

<code>
Symantec Endpoint Protection, prior to 14.3, may not respect file permissions when writing to log files that are replaced by symbolic links, which can lead to a potential elevation of privilege.
</code>

- [RedyOpsResearchLabs/SEP-14.2-Arbitrary-Write](https://github.com/RedyOpsResearchLabs/SEP-14.2-Arbitrary-Write)

### CVE-2020-5844

<code>
index.php?sec=godmode/extensions&amp;sec2=extensions/files_repo in Pandora FMS v7.0 NG allows authenticated administrators to upload malicious PHP scripts, and execute them via base64 decoding of the file location. This affects v7.0NG.742_FIX_PERL2020.
</code>

- [TheCyberGeek/CVE-2020-5844](https://github.com/TheCyberGeek/CVE-2020-5844)

### CVE-2020-6418

<code>
Type confusion in V8 in Google Chrome prior to 80.0.3987.122 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.
</code>

- [ChoKyuWon/CVE-2020-6418](https://github.com/ChoKyuWon/CVE-2020-6418)

### CVE-2020-6650

<code>
UPS companion software v1.05 &amp; Prior is affected by ‘Eval Injection’ vulnerability. The software does not neutralize or incorrectly neutralizes code syntax before using the input in a dynamic evaluation call e.g.”eval” in “Update Manager” class when software attempts to see if there are updates available. This results in arbitrary code execution on the machine where software is installed.
</code>

- [RavSS/Eaton-UPS-Companion-Exploit](https://github.com/RavSS/Eaton-UPS-Companion-Exploit)

### CVE-2020-6861

<code>
A flawed protocol design in the Ledger Monero app before 1.5.1 for Ledger Nano and Ledger S devices allows a local attacker to extract the master spending key by sending crafted messages to this app selected on a PIN-entered Ledger connected to a host PC.
</code>

- [ph4r05/ledger-app-monero-1.42-vuln](https://github.com/ph4r05/ledger-app-monero-1.42-vuln)

### CVE-2020-6888
- [section-c/CVE-2020-6888](https://github.com/section-c/CVE-2020-6888)

### CVE-2020-72381
- [jdordonezn/CVE-2020-72381](https://github.com/jdordonezn/CVE-2020-72381)

### CVE-2020-7246

<code>
A remote code execution (RCE) vulnerability exists in qdPM 9.1 and earlier. An attacker can upload a malicious PHP code file via the profile photo functionality, by leveraging a path traversal vulnerability in the users['photop_preview'] delete photo feature, allowing bypass of .htaccess protection. NOTE: this issue exists because of an incomplete fix for CVE-2015-3884.
</code>

- [lnxcrew/CVE-2020-7246](https://github.com/lnxcrew/CVE-2020-7246)

### CVE-2020-7247

<code>
smtp_mailaddr in smtp_session.c in OpenSMTPD 6.6, as used in OpenBSD 6.6 and other products, allows remote attackers to execute arbitrary commands as root via a crafted SMTP session, as demonstrated by shell metacharacters in a MAIL FROM field. This affects the &quot;uncommented&quot; default configuration. The issue exists because of an incorrect return value upon failure of input validation.
</code>

- [FiroSolutions/cve-2020-7247-exploit](https://github.com/FiroSolutions/cve-2020-7247-exploit)
- [superzerosec/cve-2020-7247](https://github.com/superzerosec/cve-2020-7247)
- [r0lh/CVE-2020-7247](https://github.com/r0lh/CVE-2020-7247)

### CVE-2020-7471

<code>
Django 1.11 before 1.11.28, 2.2 before 2.2.10, and 3.0 before 3.0.3 allows SQL Injection if untrusted data is used as a StringAgg delimiter (e.g., in Django applications that offer downloads of data as a series of rows with a user-specified column delimiter). By passing a suitably crafted delimiter to a contrib.postgres.aggregates.StringAgg instance, it was possible to break escaping and inject malicious SQL.
</code>

- [Saferman/CVE-2020-7471](https://github.com/Saferman/CVE-2020-7471)
- [secoba/DjVul_StringAgg](https://github.com/secoba/DjVul_StringAgg)
- [SNCKER/CVE-2020-7471](https://github.com/SNCKER/CVE-2020-7471)

### CVE-2020-7473

<code>
In certain situations, all versions of Citrix ShareFile StorageZones (aka storage zones) Controller, including the most recent 5.10.x releases as of May 2020, allow unauthenticated attackers to access the documents and folders of ShareFile users. NOTE: unlike most CVEs, exploitability depends on the product version that was in use when a particular setup step was performed, NOT the product version that is in use during a current assessment of a CVE consumer's product inventory. Specifically, the vulnerability can be exploited if a storage zone was created by one of these product versions: 5.9.0, 5.8.0, 5.7.0, 5.6.0, 5.5.0, or earlier. This CVE differs from CVE-2020-8982 and CVE-2020-8983 but has essentially the same risk.
</code>

- [DimitriNL/CTX-CVE-2020-7473](https://github.com/DimitriNL/CTX-CVE-2020-7473)

### CVE-2020-7799

<code>
An issue was discovered in FusionAuth before 1.11.0. An authenticated user, allowed to edit e-mail templates (Home -&gt; Settings -&gt; Email Templates) or themes (Home -&gt; Settings -&gt; Themes), can execute commands on the underlying operating system by abusing freemarker.template.utility.Execute in the Apache FreeMarker engine that processes custom templates.
</code>

- [Pikaqi/cve-2020-7799](https://github.com/Pikaqi/cve-2020-7799)
- [ianxtianxt/CVE-2020-7799](https://github.com/ianxtianxt/CVE-2020-7799)

### CVE-2020-7931

<code>
In JFrog Artifactory 5.x and 6.x, insecure FreeMarker template processing leads to remote code execution, e.g., by modifying a .ssh/authorized_keys file. Patches are available for various versions between 5.11.8 and 6.16.0. The issue exists because use of the DefaultObjectWrapper class makes certain Java functions accessible to a template.
</code>

- [gquere/CVE-2020-7931](https://github.com/gquere/CVE-2020-7931)

### CVE-2020-7961

<code>
Deserialization of Untrusted Data in Liferay Portal prior to 7.2.1 CE GA2 allows remote attackers to execute arbitrary code via JSON web services (JSONWS).
</code>

- [mzer0one/CVE-2020-7961-POC](https://github.com/mzer0one/CVE-2020-7961-POC)
- [Thisisfarhadzadeh/CVE-2020-7961-payloads](https://github.com/Thisisfarhadzadeh/CVE-2020-7961-payloads)
- [wcxxxxx/CVE-2020-7961](https://github.com/wcxxxxx/CVE-2020-7961)

### CVE-2020-7980

<code>
Intellian Aptus Web 1.24 allows remote attackers to execute arbitrary OS commands via the Q field within JSON data to the cgi-bin/libagent.cgi URI. NOTE: a valid sid cookie for a login to the intellian default account might be needed.
</code>

- [Xh4H/Satellian-CVE-2020-7980](https://github.com/Xh4H/Satellian-CVE-2020-7980)

### CVE-2020-8004

<code>
STMicroelectronics STM32F1 devices have Incorrect Access Control.
</code>

- [wuxx/CVE-2020-8004](https://github.com/wuxx/CVE-2020-8004)

### CVE-2020-8012

<code>
CA Unified Infrastructure Management (Nimsoft/UIM) 9.20 and below contains a buffer overflow vulnerability in the robot (controller) component. A remote attacker can execute arbitrary code.
</code>

- [wetw0rk/Exploit-Development](https://github.com/wetw0rk/Exploit-Development)

### CVE-2020-8417

<code>
The Code Snippets plugin before 2.14.0 for WordPress allows CSRF because of the lack of a Referer check on the import menu.
</code>

- [vulncrate/wp-codesnippets-cve-2020-8417](https://github.com/vulncrate/wp-codesnippets-cve-2020-8417)
- [waleweewe12/CVE-2020-8417](https://github.com/waleweewe12/CVE-2020-8417)

### CVE-2020-8515

<code>
DrayTek Vigor2960 1.3.1_Beta, Vigor3900 1.4.4_Beta, and Vigor300B 1.3.3_Beta, 1.4.2.1_Beta, and 1.4.4_Beta devices allow remote code execution as root (without authentication) via shell metacharacters to the cgi-bin/mainfunction.cgi URI. This issue has been fixed in Vigor3900/2960/300B v1.5.1.
</code>

- [imjdl/CVE-2020-8515-PoC](https://github.com/imjdl/CVE-2020-8515-PoC)
- [truerandom/nmap_draytek_rce](https://github.com/truerandom/nmap_draytek_rce)

### CVE-2020-8597

<code>
eap.c in pppd in ppp 2.4.2 through 2.4.8 has an rhostname buffer overflow in the eap_request and eap_response functions.
</code>

- [marcinguy/CVE-2020-8597](https://github.com/marcinguy/CVE-2020-8597)
- [mentalburden/MrsEAPers](https://github.com/mentalburden/MrsEAPers)
- [WinMin/CVE-2020-8597](https://github.com/WinMin/CVE-2020-8597)
- [Dilan-Diaz/Point-to-Point-Protocol-Daemon-RCE-Vulnerability-CVE-2020-8597-](https://github.com/Dilan-Diaz/Point-to-Point-Protocol-Daemon-RCE-Vulnerability-CVE-2020-8597-)

### CVE-2020-8809

<code>
Gurux GXDLMS Director prior to 8.5.1905.1301 downloads updates to add-ins and OBIS code over an unencrypted HTTP connection. A man-in-the-middle attacker can prompt the user to download updates by modifying the contents of gurux.fi/obis/files.xml and gurux.fi/updates/updates.xml. Then, the attacker can modify the contents of downloaded files. In the case of add-ins (if the user is using those), this will lead to code execution. In case of OBIS codes (which the user is always using as they are needed to communicate with the energy meters), this can lead to code execution when combined with CVE-2020-8810.
</code>

- [seqred-s-a/gxdlmsdirector-cve](https://github.com/seqred-s-a/gxdlmsdirector-cve)

### CVE-2020-8813

<code>
graph_realtime.php in Cacti 1.2.8 allows remote attackers to execute arbitrary OS commands via shell metacharacters in a cookie, if a guest user has the graph real-time privilege.
</code>

- [mhaskar/CVE-2020-8813](https://github.com/mhaskar/CVE-2020-8813)

### CVE-2020-8816
- [AndreyRainchik/CVE-2020-8816](https://github.com/AndreyRainchik/CVE-2020-8816)

### CVE-2020-8825

<code>
index.php?p=/dashboard/settings/branding in Vanilla 2.6.3 allows stored XSS.
</code>

- [hacky1997/CVE-2020-8825](https://github.com/hacky1997/CVE-2020-8825)

### CVE-2020-8835

<code>
In the Linux kernel 5.5.0 and newer, the bpf verifier (kernel/bpf/verifier.c) did not properly restrict the register bounds for 32-bit operations, leading to out-of-bounds reads and writes in kernel memory. The vulnerability also affects the Linux 5.4 stable series, starting with v5.4.7, as the introducing commit was backported to that branch. This vulnerability was fixed in 5.6.1, 5.5.14, and 5.4.29. (issue is aka ZDI-CAN-10780)
</code>

- [Prabhashaka/IT19147192-CVE-2020-8835](https://github.com/Prabhashaka/IT19147192-CVE-2020-8835)

### CVE-2020-8840

<code>
FasterXML jackson-databind 2.0.0 through 2.9.10.2 lacks certain xbean-reflect/JNDI blocking, as demonstrated by org.apache.xbean.propertyeditor.JndiConverter.
</code>

- [jas502n/CVE-2020-8840](https://github.com/jas502n/CVE-2020-8840)
- [Wfzsec/FastJson1.2.62-RCE](https://github.com/Wfzsec/FastJson1.2.62-RCE)
- [fairyming/CVE-2020-8840](https://github.com/fairyming/CVE-2020-8840)
- [0nise/CVE-2020-8840](https://github.com/0nise/CVE-2020-8840)

### CVE-2020-8950

<code>
The AUEPLauncher service in Radeon AMD User Experience Program Launcher through 1.0.0.1 on Windows allows elevation of privilege by placing a crafted file in %PROGRAMDATA%\AMD\PPC\upload and then creating a symbolic link in %PROGRAMDATA%\AMD\PPC\temp that points to an arbitrary folder with an arbitrary file name.
</code>

- [sailay1996/amd_eop_poc](https://github.com/sailay1996/amd_eop_poc)

### CVE-2020-9008

<code>
Stored Cross-site scripting (XSS) vulnerability in Blackboard Learn/PeopleTool v9.1 allows users to inject arbitrary web script via the Tile widget in the People Tool profile editor.
</code>

- [kyletimmermans/blackboard-xss](https://github.com/kyletimmermans/blackboard-xss)

### CVE-2020-9038

<code>
Joplin through 1.0.184 allows Arbitrary File Read via XSS.
</code>

- [JavierOlmedo/CVE-2020-9038](https://github.com/JavierOlmedo/CVE-2020-9038)

### CVE-2020-9375

<code>
TP-Link Archer C50 V3 devices before Build 200318 Rel. 62209 allows remote attackers to cause a denial of service via a crafted HTTP Header containing an unexpected Referer field.
</code>

- [thewhiteh4t/cve-2020-9375](https://github.com/thewhiteh4t/cve-2020-9375)

### CVE-2020-9380

<code>
IPTV Smarters WEB TV PLAYER through 2020-02-22 allows attackers to execute OS commands by uploading a script.
</code>

- [migueltarga/CVE-2020-9380](https://github.com/migueltarga/CVE-2020-9380)

### CVE-2020-9442

<code>
OpenVPN Connect 3.1.0.361 on Windows has Insecure Permissions for %PROGRAMDATA%\OpenVPN Connect\drivers\tap\amd64\win10, which allows local users to gain privileges by copying a malicious drvstore.dll there.
</code>

- [hessandrew/CVE-2020-9442](https://github.com/hessandrew/CVE-2020-9442)

### CVE-2020-9453
- [FULLSHADE/CVE-2020-9453_-_CVE-2020-9014](https://github.com/FULLSHADE/CVE-2020-9453_-_CVE-2020-9014)

### CVE-2020-9460

<code>
Octech Oempro 4.7 through 4.11 allow XSS by an authenticated user. The parameter CampaignName in Campaign.Create is vulnerable.
</code>

- [g-rubert/CVE-2020-9460](https://github.com/g-rubert/CVE-2020-9460)

### CVE-2020-9461

<code>
Octech Oempro 4.7 through 4.11 allow stored XSS by an authenticated user. The FolderName parameter of the Media.CreateFolder command is vulnerable.
</code>

- [g-rubert/CVE-2020-9461](https://github.com/g-rubert/CVE-2020-9461)

### CVE-2020-9547

<code>
FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig (aka ibatis-sqlmap).
</code>

- [fairyming/CVE-2020-9547](https://github.com/fairyming/CVE-2020-9547)

### CVE-2020-9548

<code>
FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to br.com.anteros.dbcp.AnterosDBCPConfig (aka anteros-core).
</code>

- [fairyming/CVE-2020-9548](https://github.com/fairyming/CVE-2020-9548)

### CVE-2020-9758

<code>
An issue was discovered in chat.php in LiveZilla Live Chat 8.0.1.3 (Helpdesk). A blind JavaScript injection lies in the name parameter. Triggering this can fetch the username and passwords of the helpdesk employees in the URI. This leads to a privilege escalation, from unauthenticated to user-level access, leading to full account takeover. The attack fetches multiple credentials because they are stored in the database (stored XSS). This affects the mobile/chat URI via the lgn and psswrd parameters.
</code>

- [ari034/CVE-2020-9758](https://github.com/ari034/CVE-2020-9758)

### CVE-2020-9768

<code>
A use after free issue was addressed with improved memory management. This issue is fixed in iOS 13.4 and iPadOS 13.4, tvOS 13.4, watchOS 6.2. An application may be able to execute arbitrary code with system privileges.
</code>

- [MrKris99/CVE-2020-9768](https://github.com/MrKris99/CVE-2020-9768)

### CVE-2020-9781

<code>
The issue was addressed by clearing website permission prompts after navigation. This issue is fixed in iOS 13.4 and iPadOS 13.4. A user may grant website permissions to a site they didn't intend to.
</code>

- [c0d3G33k/Safari-Video-Permission-Spoof-CVE-2020-9781](https://github.com/c0d3G33k/Safari-Video-Permission-Spoof-CVE-2020-9781)

### CVE-2020-98989
- [tdcoming/CVE-2020-98989](https://github.com/tdcoming/CVE-2020-98989)

### CVE-2020-9999
- [tdcoming/CVE-2020-9999](https://github.com/tdcoming/CVE-2020-9999)


## 2019
### CVE-2019-0053

<code>
Insufficient validation of environment variables in the telnet client supplied in Junos OS can lead to stack-based buffer overflows, which can be exploited to bypass veriexec restrictions on Junos OS. A stack-based overflow is present in the handling of environment variables when connecting via the telnet client to remote telnet servers. This issue only affects the telnet client — accessible from the CLI or shell — in Junos OS. Inbound telnet services are not affected by this issue. This issue affects: Juniper Networks Junos OS: 12.3 versions prior to 12.3R12-S13; 12.3X48 versions prior to 12.3X48-D80; 14.1X53 versions prior to 14.1X53-D130, 14.1X53-D49; 15.1 versions prior to 15.1F6-S12, 15.1R7-S4; 15.1X49 versions prior to 15.1X49-D170; 15.1X53 versions prior to 15.1X53-D237, 15.1X53-D496, 15.1X53-D591, 15.1X53-D69; 16.1 versions prior to 16.1R3-S11, 16.1R7-S4; 16.2 versions prior to 16.2R2-S9; 17.1 versions prior to 17.1R3; 17.2 versions prior to 17.2R1-S8, 17.2R2-S7, 17.2R3-S1; 17.3 versions prior to 17.3R3-S4; 17.4 versions prior to 17.4R1-S6, 17.4R2-S3, 17.4R3; 18.1 versions prior to 18.1R2-S4, 18.1R3-S3; 18.2 versions prior to 18.2R1-S5, 18.2R2-S2, 18.2R3; 18.2X75 versions prior to 18.2X75-D40; 18.3 versions prior to 18.3R1-S3, 18.3R2; 18.4 versions prior to 18.4R1-S2, 18.4R2.
</code>

- [dreamsmasher/inetutils-CVE-2019-0053-Patched-PKGBUILD](https://github.com/dreamsmasher/inetutils-CVE-2019-0053-Patched-PKGBUILD)

### CVE-2019-0192

<code>
In Apache Solr versions 5.0.0 to 5.5.5 and 6.0.0 to 6.6.5, the Config API allows to configure the JMX server via an HTTP POST request. By pointing it to a malicious RMI server, an attacker could take advantage of Solr's unsafe deserialization to trigger remote code execution on the Solr side.
</code>

- [mpgn/CVE-2019-0192](https://github.com/mpgn/CVE-2019-0192)
- [Rapidsafeguard/Solr-RCE-CVE-2019-0192](https://github.com/Rapidsafeguard/Solr-RCE-CVE-2019-0192)

### CVE-2019-0193

<code>
In Apache Solr, the DataImportHandler, an optional but popular module to pull in data from databases and other sources, has a feature in which the whole DIH configuration can come from a request's &quot;dataConfig&quot; parameter. The debug mode of the DIH admin screen uses this to allow convenient debugging / development of a DIH config. Since a DIH config can contain scripts, this parameter is a security risk. Starting with version 8.2.0 of Solr, use of this parameter requires setting the Java System property &quot;enable.dih.dataConfigParam&quot; to true.
</code>

- [xConsoIe/CVE-2019-0193](https://github.com/xConsoIe/CVE-2019-0193)
- [jas502n/CVE-2019-0193](https://github.com/jas502n/CVE-2019-0193)
- [1135/solr_exploit](https://github.com/1135/solr_exploit)
- [jaychouzzk/CVE-2019-0193-exp](https://github.com/jaychouzzk/CVE-2019-0193-exp)

### CVE-2019-0211

<code>
In Apache HTTP Server 2.4 releases 2.4.17 to 2.4.38, with MPM event, worker or prefork, code executing in less-privileged child processes or threads (including scripts executed by an in-process scripting interpreter) could execute arbitrary code with the privileges of the parent process (usually root) by manipulating the scoreboard. Non-Unix systems are not affected.
</code>

- [ozkanbilge/Apache-Exploit-2019](https://github.com/ozkanbilge/Apache-Exploit-2019)

### CVE-2019-0227

<code>
A Server Side Request Forgery (SSRF) vulnerability affected the Apache Axis 1.4 distribution that was last released in 2006. Security and bug commits commits continue in the projects Axis 1.x Subversion repository, legacy users are encouraged to build from source. The successor to Axis 1.x is Axis2, the latest version is 1.7.9 and is not vulnerable to this issue.
</code>

- [ianxtianxt/cve-2019-0227](https://github.com/ianxtianxt/cve-2019-0227)

### CVE-2019-0232

<code>
When running on Windows with enableCmdLineArguments enabled, the CGI Servlet in Apache Tomcat 9.0.0.M1 to 9.0.17, 8.5.0 to 8.5.39 and 7.0.0 to 7.0.93 is vulnerable to Remote Code Execution due to a bug in the way the JRE passes command line arguments to Windows. The CGI Servlet is disabled by default. The CGI option enableCmdLineArguments is disable by default in Tomcat 9.0.x (and will be disabled by default in all versions in response to this vulnerability). For a detailed explanation of the JRE behaviour, see Markus Wulftange's blog (https://codewhitesec.blogspot.com/2016/02/java-and-command-line-injections-in-windows.html) and this archived MSDN blog (https://web.archive.org/web/20161228144344/https://blogs.msdn.microsoft.com/twistylittlepassagesallalike/2011/04/23/everyone-quotes-command-line-arguments-the-wrong-way/).
</code>

- [pyn3rd/CVE-2019-0232](https://github.com/pyn3rd/CVE-2019-0232)
- [jas502n/CVE-2019-0232](https://github.com/jas502n/CVE-2019-0232)
- [CherishHair/CVE-2019-0232-EXP](https://github.com/CherishHair/CVE-2019-0232-EXP)
- [setrus/CVE-2019-0232](https://github.com/setrus/CVE-2019-0232)

### CVE-2019-0539

<code>
A remote code execution vulnerability exists in the way that the Chakra scripting engine handles objects in memory in Microsoft Edge, aka &quot;Chakra Scripting Engine Memory Corruption Vulnerability.&quot; This affects Microsoft Edge, ChakraCore. This CVE ID is unique from CVE-2019-0567, CVE-2019-0568.
</code>

- [0x43434343/CVE-2019-0539](https://github.com/0x43434343/CVE-2019-0539)

### CVE-2019-0604

<code>
A remote code execution vulnerability exists in Microsoft SharePoint when the software fails to check the source markup of an application package, aka 'Microsoft SharePoint Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2019-0594.
</code>

- [linhlhq/CVE-2019-0604](https://github.com/linhlhq/CVE-2019-0604)
- [denmilu/CVE-2019-0604_sharepoint_CVE](https://github.com/denmilu/CVE-2019-0604_sharepoint_CVE)
- [k8gege/CVE-2019-0604](https://github.com/k8gege/CVE-2019-0604)
- [m5050/CVE-2019-0604](https://github.com/m5050/CVE-2019-0604)
- [boxhg/CVE-2019-0604](https://github.com/boxhg/CVE-2019-0604)

### CVE-2019-0678

<code>
An elevation of privilege vulnerability exists when Microsoft Edge does not properly enforce cross-domain policies, which could allow an attacker to access information from one domain and inject it into another domain.In a web-based attack scenario, an attacker could host a website that is used to attempt to exploit the vulnerability, aka 'Microsoft Edge Elevation of Privilege Vulnerability'.
</code>

- [c0d3G33k/CVE-2019-0678](https://github.com/c0d3G33k/CVE-2019-0678)

### CVE-2019-0708

<code>
A remote code execution vulnerability exists in Remote Desktop Services formerly known as Terminal Services when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests, aka 'Remote Desktop Services Remote Code Execution Vulnerability'.
</code>

- [hook-s3c/CVE-2019-0708-poc](https://github.com/hook-s3c/CVE-2019-0708-poc)
- [SherlockSec/CVE-2019-0708](https://github.com/SherlockSec/CVE-2019-0708)
- [yetiddbb/CVE-2019-0708-PoC](https://github.com/yetiddbb/CVE-2019-0708-PoC)
- [p0p0p0/CVE-2019-0708-exploit](https://github.com/p0p0p0/CVE-2019-0708-exploit)
- [rockmelodies/CVE-2019-0708-Exploit](https://github.com/rockmelodies/CVE-2019-0708-Exploit)
- [matengfei000/CVE-2019-0708](https://github.com/matengfei000/CVE-2019-0708)
- [xiyangzuishuai/Dark-Network-CVE-2019-0708](https://github.com/xiyangzuishuai/Dark-Network-CVE-2019-0708)
- [temp-user-2014/CVE-2019-0708](https://github.com/temp-user-2014/CVE-2019-0708)
- [areusecure/CVE-2019-0708](https://github.com/areusecure/CVE-2019-0708)
- [pry0cc/cve-2019-0708-2](https://github.com/pry0cc/cve-2019-0708-2)
- [sbkcbig/CVE-2019-0708-EXPloit](https://github.com/sbkcbig/CVE-2019-0708-EXPloit)
- [sbkcbig/CVE-2019-0708-EXPloit-3389](https://github.com/sbkcbig/CVE-2019-0708-EXPloit-3389)
- [YSheldon/MS_T120](https://github.com/YSheldon/MS_T120)
- [k8gege/CVE-2019-0708](https://github.com/k8gege/CVE-2019-0708)
- [hotdog777714/RDS_CVE-2019-0708](https://github.com/hotdog777714/RDS_CVE-2019-0708)
- [jiansiting/CVE-2019-0708](https://github.com/jiansiting/CVE-2019-0708)
- [NullByteSuiteDevs/CVE-2019-0708](https://github.com/NullByteSuiteDevs/CVE-2019-0708)
- [heaphopopotamus/CVE-2019-0708](https://github.com/heaphopopotamus/CVE-2019-0708)
- [thugcrowd/CVE-2019-0708](https://github.com/thugcrowd/CVE-2019-0708)
- [omaidf/CVE-2019-0708-PoC](https://github.com/omaidf/CVE-2019-0708-PoC)
- [blacksunwen/CVE-2019-0708](https://github.com/blacksunwen/CVE-2019-0708)
- [infenet/CVE-2019-0708](https://github.com/infenet/CVE-2019-0708)
- [n0auth/CVE-2019-0708](https://github.com/n0auth/CVE-2019-0708)
- [gildaaa/CVE-2019-0708](https://github.com/gildaaa/CVE-2019-0708)
- [sbkcbig/CVE-2019-0708-Poc-exploit](https://github.com/sbkcbig/CVE-2019-0708-Poc-exploit)
- [HackerJ0e/CVE-2019-0708](https://github.com/HackerJ0e/CVE-2019-0708)
- [syriusbughunt/CVE-2019-0708](https://github.com/syriusbughunt/CVE-2019-0708)
- [Barry-McCockiner/CVE-2019-0708](https://github.com/Barry-McCockiner/CVE-2019-0708)
- [ShadowBrokers-ExploitLeak/CVE-2019-0708](https://github.com/ShadowBrokers-ExploitLeak/CVE-2019-0708)
- [shumtheone/CVE-2019-0708](https://github.com/shumtheone/CVE-2019-0708)
- [safly/CVE-2019-0708](https://github.com/safly/CVE-2019-0708)
- [Jaky5155/cve-2019-0708-exp](https://github.com/Jaky5155/cve-2019-0708-exp)
- [fourtwizzy/CVE-2019-0708-Check-Device-Patch-Status](https://github.com/fourtwizzy/CVE-2019-0708-Check-Device-Patch-Status)
- [303sec/CVE-2019-0708](https://github.com/303sec/CVE-2019-0708)
- [f8al/CVE-2019-0708-POC](https://github.com/f8al/CVE-2019-0708-POC)
- [blockchainguard/CVE-2019-0708](https://github.com/blockchainguard/CVE-2019-0708)
- [haoge8090/CVE-2019-0708](https://github.com/haoge8090/CVE-2019-0708)
- [branbot1000/CVE-2019-0708](https://github.com/branbot1000/CVE-2019-0708)
- [yushiro/CVE-2019-0708](https://github.com/yushiro/CVE-2019-0708)
- [bilawalzardaer/CVE-2019-0708](https://github.com/bilawalzardaer/CVE-2019-0708)
- [skyshell20082008/CVE-2019-0708-PoC-Hitting-Path](https://github.com/skyshell20082008/CVE-2019-0708-PoC-Hitting-Path)
- [ttsite/CVE-2019-0708-](https://github.com/ttsite/CVE-2019-0708-)
- [ttsite/CVE-2019-0708](https://github.com/ttsite/CVE-2019-0708)
- [biggerwing/CVE-2019-0708-poc](https://github.com/biggerwing/CVE-2019-0708-poc)
- [n1xbyte/CVE-2019-0708](https://github.com/n1xbyte/CVE-2019-0708)
- [freeide/CVE-2019-0708](https://github.com/freeide/CVE-2019-0708)
- [edvacco/CVE-2019-0708-POC](https://github.com/edvacco/CVE-2019-0708-POC)
- [pry0cc/BlueKeepTracker](https://github.com/pry0cc/BlueKeepTracker)
- [zjw88282740/CVE-2019-0708-win7](https://github.com/zjw88282740/CVE-2019-0708-win7)
- [zerosum0x0/CVE-2019-0708](https://github.com/zerosum0x0/CVE-2019-0708)
- [herhe/CVE-2019-0708poc](https://github.com/herhe/CVE-2019-0708poc)
- [l9c/rdp0708scanner](https://github.com/l9c/rdp0708scanner)
- [major203/cve-2019-0708-scan](https://github.com/major203/cve-2019-0708-scan)
- [SugiB3o/Check-vuln-CVE-2019-0708](https://github.com/SugiB3o/Check-vuln-CVE-2019-0708)
- [gobysec/CVE-2019-0708](https://github.com/gobysec/CVE-2019-0708)
- [adalenv/CVE-2019-0708-Tool](https://github.com/adalenv/CVE-2019-0708-Tool)
- [smallFunction/CVE-2019-0708-POC](https://github.com/smallFunction/CVE-2019-0708-POC)
- [freeide/CVE-2019-0708-PoC-Exploit](https://github.com/freeide/CVE-2019-0708-PoC-Exploit)
- [robertdavidgraham/rdpscan](https://github.com/robertdavidgraham/rdpscan)
- [closethe/CVE-2019-0708-POC](https://github.com/closethe/CVE-2019-0708-POC)
- [krivegasa/Mass-scanner-for-CVE-2019-0708-RDP-RCE-Exploit](https://github.com/krivegasa/Mass-scanner-for-CVE-2019-0708-RDP-RCE-Exploit)
- [Rostelecom-CERT/bluekeepscan](https://github.com/Rostelecom-CERT/bluekeepscan)
- [Leoid/CVE-2019-0708](https://github.com/Leoid/CVE-2019-0708)
- [ht0Ruial/CVE-2019-0708Poc-BatchScanning](https://github.com/ht0Ruial/CVE-2019-0708Poc-BatchScanning)
- [oneoy/BlueKeep](https://github.com/oneoy/BlueKeep)
- [infiniti-team/CVE-2019-0708](https://github.com/infiniti-team/CVE-2019-0708)
- [haishanzheng/CVE-2019-0708-generate-hosts](https://github.com/haishanzheng/CVE-2019-0708-generate-hosts)
- [Ekultek/BlueKeep](https://github.com/Ekultek/BlueKeep)
- [UraSecTeam/CVE-2019-0708](https://github.com/UraSecTeam/CVE-2019-0708)
- [Gh0st0ne/rdpscan-BlueKeep](https://github.com/Gh0st0ne/rdpscan-BlueKeep)
- [algo7/bluekeep_CVE-2019-0708_poc_to_exploit](https://github.com/algo7/bluekeep_CVE-2019-0708_poc_to_exploit)
- [JasonLOU/CVE-2019-0708](https://github.com/JasonLOU/CVE-2019-0708)
- [shun-gg/CVE-2019-0708](https://github.com/shun-gg/CVE-2019-0708)
- [AdministratorGithub/CVE-2019-0708](https://github.com/AdministratorGithub/CVE-2019-0708)
- [umarfarook882/CVE-2019-0708](https://github.com/umarfarook882/CVE-2019-0708)
- [HynekPetrak/detect_bluekeep.py](https://github.com/HynekPetrak/detect_bluekeep.py)
- [Wileysec/CVE-2019-0708-Batch-Blue-Screen](https://github.com/Wileysec/CVE-2019-0708-Batch-Blue-Screen)
- [Pa55w0rd/CVE-2019-0708](https://github.com/Pa55w0rd/CVE-2019-0708)
- [at0mik/CVE-2019-0708-PoC](https://github.com/at0mik/CVE-2019-0708-PoC)
- [cream492/CVE-2019-0708-Msf--](https://github.com/cream492/CVE-2019-0708-Msf--)
- [wdfcc/CVE-2019-0708](https://github.com/wdfcc/CVE-2019-0708)
- [cvencoder/cve-2019-0708](https://github.com/cvencoder/cve-2019-0708)
- [ze0r/CVE-2019-0708-exp](https://github.com/ze0r/CVE-2019-0708-exp)
- [mekhalleh/cve-2019-0708](https://github.com/mekhalleh/cve-2019-0708)
- [cve-2019-0708-poc/cve-2019-0708](https://github.com/cve-2019-0708-poc/cve-2019-0708)
- [andripwn/CVE-2019-0708](https://github.com/andripwn/CVE-2019-0708)
- [0xeb-bp/bluekeep](https://github.com/0xeb-bp/bluekeep)
- [ntkernel0/CVE-2019-0708](https://github.com/ntkernel0/CVE-2019-0708)
- [dorkerdevil/Remote-Desktop-Services-Remote-Code-Execution-Vulnerability-CVE-2019-0708-](https://github.com/dorkerdevil/Remote-Desktop-Services-Remote-Code-Execution-Vulnerability-CVE-2019-0708-)
- [turingcompl33t/bluekeep](https://github.com/turingcompl33t/bluekeep)
- [fade-vivida/CVE-2019-0708-test](https://github.com/fade-vivida/CVE-2019-0708-test)
- [skommando/CVE-2019-0708](https://github.com/skommando/CVE-2019-0708)
- [RickGeex/msf-module-CVE-2019-0708](https://github.com/RickGeex/msf-module-CVE-2019-0708)
- [wqsemc/CVE-2019-0708](https://github.com/wqsemc/CVE-2019-0708)
- [mai-lang-chai/CVE-2019-0708-RCE](https://github.com/mai-lang-chai/CVE-2019-0708-RCE)
- [Micr067/CVE-2019-0708RDP-MSF](https://github.com/Micr067/CVE-2019-0708RDP-MSF)
- [adkinguzi/CVE-2019-0708-BlueKeep](https://github.com/adkinguzi/CVE-2019-0708-BlueKeep)
- [FrostsaberX/CVE-2019-0708](https://github.com/FrostsaberX/CVE-2019-0708)
- [qinggegeya/CVE-2019-0708-EXP-MSF-](https://github.com/qinggegeya/CVE-2019-0708-EXP-MSF-)
- [distance-vector/CVE-2019-0708](https://github.com/distance-vector/CVE-2019-0708)
- [0xFlag/CVE-2019-0708-test](https://github.com/0xFlag/CVE-2019-0708-test)
- [1aa87148377/CVE-2019-0708](https://github.com/1aa87148377/CVE-2019-0708)
- [coolboy4me/cve-2019-0708_bluekeep_rce](https://github.com/coolboy4me/cve-2019-0708_bluekeep_rce)
- [Cyb0r9/ispy](https://github.com/Cyb0r9/ispy)
- [shishibabyq/CVE-2019-0708](https://github.com/shishibabyq/CVE-2019-0708)
- [pwnhacker0x18/Wincrash](https://github.com/pwnhacker0x18/Wincrash)
- [R4v3nG/CVE-2019-0708-DOS](https://github.com/R4v3nG/CVE-2019-0708-DOS)
- [ulisesrc/-2-CVE-2019-0708](https://github.com/ulisesrc/-2-CVE-2019-0708)
- [worawit/CVE-2019-0708](https://github.com/worawit/CVE-2019-0708)
- [cbwang505/CVE-2019-0708-EXP-Windows](https://github.com/cbwang505/CVE-2019-0708-EXP-Windows)
- [eastmountyxz/CVE-2019-0708-Windows](https://github.com/eastmountyxz/CVE-2019-0708-Windows)
- [JSec1337/Scanner-CVE-2019-0708](https://github.com/JSec1337/Scanner-CVE-2019-0708)
- [wanghuohuobutailao/cve-2019-0708](https://github.com/wanghuohuobutailao/cve-2019-0708)

### CVE-2019-0709

<code>
A remote code execution vulnerability exists when Windows Hyper-V on a host server fails to properly validate input from an authenticated user on a guest operating system, aka 'Windows Hyper-V Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2019-0620, CVE-2019-0722.
</code>

- [YHZX2013/CVE-2019-0709](https://github.com/YHZX2013/CVE-2019-0709)
- [qq431169079/CVE-2019-0709](https://github.com/qq431169079/CVE-2019-0709)

### CVE-2019-0768

<code>
A security feature bypass vulnerability exists when Internet Explorer VBScript execution policy does not properly restrict VBScript under specific conditions, and to allow requests that should otherwise be ignored, aka 'Internet Explorer Security Feature Bypass Vulnerability'. This CVE ID is unique from CVE-2019-0761.
</code>

- [ruthlezs/ie11_vbscript_exploit](https://github.com/ruthlezs/ie11_vbscript_exploit)

### CVE-2019-0785

<code>
A memory corruption vulnerability exists in the Windows Server DHCP service when an attacker sends specially crafted packets to a DHCP failover server, aka 'Windows DHCP Server Remote Code Execution Vulnerability'.
</code>

- [Jaky5155/CVE-2019-0785](https://github.com/Jaky5155/CVE-2019-0785)

### CVE-2019-0803

<code>
An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-0685, CVE-2019-0859.
</code>

- [ExpLife0011/CVE-2019-0803](https://github.com/ExpLife0011/CVE-2019-0803)

### CVE-2019-0808

<code>
An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-0797.
</code>

- [ze0r/cve-2019-0808-poc](https://github.com/ze0r/cve-2019-0808-poc)
- [rakesh143/CVE-2019-0808](https://github.com/rakesh143/CVE-2019-0808)
- [exodusintel/CVE-2019-0808](https://github.com/exodusintel/CVE-2019-0808)

### CVE-2019-0841

<code>
An elevation of privilege vulnerability exists when Windows AppX Deployment Service (AppXSVC) improperly handles hard links, aka 'Windows Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-0730, CVE-2019-0731, CVE-2019-0796, CVE-2019-0805, CVE-2019-0836.
</code>

- [rogue-kdc/CVE-2019-0841](https://github.com/rogue-kdc/CVE-2019-0841)
- [denmilu/CVE-2019-0841](https://github.com/denmilu/CVE-2019-0841)
- [0x00-0x00/CVE-2019-0841-BYPASS](https://github.com/0x00-0x00/CVE-2019-0841-BYPASS)

### CVE-2019-0859

<code>
An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-0685, CVE-2019-0803.
</code>

- [Sheisback/CVE-2019-0859-1day-Exploit](https://github.com/Sheisback/CVE-2019-0859-1day-Exploit)

### CVE-2019-0888

<code>
A remote code execution vulnerability exists in the way that ActiveX Data Objects (ADO) handle objects in memory, aka 'ActiveX Data Objects (ADO) Remote Code Execution Vulnerability'.
</code>

- [sophoslabs/CVE-2019-0888](https://github.com/sophoslabs/CVE-2019-0888)

### CVE-2019-0986

<code>
An elevation of privilege vulnerability exists when the Windows User Profile Service (ProfSvc) improperly handles symlinks, aka 'Windows User Profile Service Elevation of Privilege Vulnerability'.
</code>

- [padovah4ck/CVE-2019-0986](https://github.com/padovah4ck/CVE-2019-0986)

### CVE-2019-10008

<code>
Zoho ManageEngine ServiceDesk 9.3 allows session hijacking and privilege escalation because an established guest session is automatically converted into an established administrator session when the guest user enters the administrator username, with an arbitrary incorrect password, in an mc/ login attempt within a different browser tab.
</code>

- [FlameOfIgnis/CVE-2019-10008](https://github.com/FlameOfIgnis/CVE-2019-10008)

### CVE-2019-1002101

<code>
The kubectl cp command allows copying files between containers and the user machine. To copy files from a container, Kubernetes creates a tar inside the container, copies it over the network, and kubectl unpacks it on the user’s machine. If the tar binary in the container is malicious, it could run any code and output unexpected, malicious results. An attacker could use this to write files to any path on the user’s machine when kubectl cp is called, limited only by the system permissions of the local user. The untar function can both create and follow symbolic links. The issue is resolved in kubectl v1.11.9, v1.12.7, v1.13.5, and v1.14.0.
</code>

- [brompwnie/CVE-2019-1002101-Helpers](https://github.com/brompwnie/CVE-2019-1002101-Helpers)

### CVE-2019-1003000

<code>
A sandbox bypass vulnerability exists in Script Security Plugin 1.49 and earlier in src/main/java/org/jenkinsci/plugins/scriptsecurity/sandbox/groovy/GroovySandbox.java that allows attackers with the ability to provide sandboxed scripts to execute arbitrary code on the Jenkins master JVM.
</code>

- [wetw0rk/Exploit-Development](https://github.com/wetw0rk/Exploit-Development)
- [adamyordan/cve-2019-1003000-jenkins-rce-poc](https://github.com/adamyordan/cve-2019-1003000-jenkins-rce-poc)
- [0xtavian/CVE-2019-1003000-and-CVE-2018-1999002-Pre-Auth-RCE-Jenkins](https://github.com/0xtavian/CVE-2019-1003000-and-CVE-2018-1999002-Pre-Auth-RCE-Jenkins)
- [1NTheKut/CVE-2019-1003000_RCE-DETECTION](https://github.com/1NTheKut/CVE-2019-1003000_RCE-DETECTION)

### CVE-2019-10086

<code>
In Apache Commons Beanutils 1.9.2, a special BeanIntrospector class was added which allows suppressing the ability for an attacker to access the classloader via the class property available on all Java objects. We, however were not using this by default characteristic of the PropertyUtilsBean.
</code>

- [evilangelplus/CVE-2019-10086](https://github.com/evilangelplus/CVE-2019-10086)

### CVE-2019-10092

<code>
In Apache HTTP Server 2.4.0-2.4.39, a limited cross-site scripting issue was reported affecting the mod_proxy error page. An attacker could cause the link on the error page to be malformed and instead point to a page of their choice. This would only be exploitable where a server was set up with proxying enabled but was misconfigured in such a way that the Proxy Error page was displayed.
</code>

- [motikan2010/CVE-2019-10092_Docker](https://github.com/motikan2010/CVE-2019-10092_Docker)

### CVE-2019-1010054

<code>
Dolibarr 7.0.0 is affected by: Cross Site Request Forgery (CSRF). The impact is: allow malitious html to change user password, disable users and disable password encryptation. The component is: Function User password change, user disable and password encryptation. The attack vector is: admin access malitious urls.
</code>

- [chaizeg/CSRF-breach](https://github.com/chaizeg/CSRF-breach)

### CVE-2019-1010298

<code>
Linaro/OP-TEE OP-TEE 3.3.0 and earlier is affected by: Buffer Overflow. The impact is: Code execution in the context of TEE core (kernel). The component is: optee_os. The fixed version is: 3.4.0 and later.
</code>

- [RKX1209/CVE-2019-1010298](https://github.com/RKX1209/CVE-2019-1010298)

### CVE-2019-10149

<code>
A flaw was found in Exim versions 4.87 to 4.91 (inclusive). Improper validation of recipient address in deliver_message() function in /src/deliver.c may lead to remote command execution.
</code>

- [bananaphones/exim-rce-quickfix](https://github.com/bananaphones/exim-rce-quickfix)
- [cowbe0x004/eximrce-CVE-2019-10149](https://github.com/cowbe0x004/eximrce-CVE-2019-10149)
- [MNEMO-CERT/PoC--CVE-2019-10149_Exim](https://github.com/MNEMO-CERT/PoC--CVE-2019-10149_Exim)
- [aishee/CVE-2019-10149-quick](https://github.com/aishee/CVE-2019-10149-quick)
- [AzizMea/CVE-2019-10149-privilege-escalation](https://github.com/AzizMea/CVE-2019-10149-privilege-escalation)
- [Brets0150/StickyExim](https://github.com/Brets0150/StickyExim)
- [ChrissHack/exim.exp](https://github.com/ChrissHack/exim.exp)
- [darsigovrustam/CVE-2019-10149](https://github.com/darsigovrustam/CVE-2019-10149)
- [Diefunction/CVE-2019-10149](https://github.com/Diefunction/CVE-2019-10149)
- [Dilshan-Eranda/CVE-2019-10149](https://github.com/Dilshan-Eranda/CVE-2019-10149)

### CVE-2019-10207

<code>
A flaw was found in the Linux kernel's Bluetooth implementation of UART, all versions kernel 3.x.x before 4.18.0 and kernel 5.x.x. An attacker with local access and write permissions to the Bluetooth hardware could use this flaw to issue a specially crafted ioctl function call and cause the system to crash.
</code>

- [butterflyhack/CVE-2019-10207](https://github.com/butterflyhack/CVE-2019-10207)

### CVE-2019-10392

<code>
Jenkins Git Client Plugin 2.8.4 and earlier and 3.0.0-rc did not properly restrict values passed as URL argument to an invocation of 'git ls-remote', resulting in OS command injection.
</code>

- [jas502n/CVE-2019-10392](https://github.com/jas502n/CVE-2019-10392)
- [ftk-sostupid/CVE-2019-10392_EXP](https://github.com/ftk-sostupid/CVE-2019-10392_EXP)

### CVE-2019-1040

<code>
A tampering vulnerability exists in Microsoft Windows when a man-in-the-middle attacker is able to successfully bypass the NTLM MIC (Message Integrity Check) protection, aka 'Windows NTLM Tampering Vulnerability'.
</code>

- [Ridter/CVE-2019-1040](https://github.com/Ridter/CVE-2019-1040)
- [lazaars/UltraRealy_with_CVE-2019-1040](https://github.com/lazaars/UltraRealy_with_CVE-2019-1040)
- [fox-it/cve-2019-1040-scanner](https://github.com/fox-it/cve-2019-1040-scanner)
- [wzxmt/CVE-2019-1040](https://github.com/wzxmt/CVE-2019-1040)

### CVE-2019-10475

<code>
A reflected cross-site scripting vulnerability in Jenkins build-metrics Plugin allows attackers to inject arbitrary HTML and JavaScript into web pages provided by this plugin.
</code>

- [vesche/CVE-2019-10475](https://github.com/vesche/CVE-2019-10475)

### CVE-2019-1064

<code>
An elevation of privilege vulnerability exists when Windows AppX Deployment Service (AppXSVC) improperly handles hard links, aka 'Windows Elevation of Privilege Vulnerability'.
</code>

- [RythmStick/CVE-2019-1064](https://github.com/RythmStick/CVE-2019-1064)
- [0x00-0x00/CVE-2019-1064](https://github.com/0x00-0x00/CVE-2019-1064)
- [attackgithub/CVE-2019-1064](https://github.com/attackgithub/CVE-2019-1064)

### CVE-2019-10678

<code>
Domoticz before 4.10579 neglects to categorize \n and \r as insecure argument options.
</code>

- [cved-sources/cve-2019-10678](https://github.com/cved-sources/cve-2019-10678)

### CVE-2019-10685

<code>
A Reflected Cross Site Scripting (XSS) Vulnerability was discovered in Heidelberg Prinect Archiver v2013 release 1.0.
</code>

- [alt3kx/CVE-2019-10685](https://github.com/alt3kx/CVE-2019-10685)

### CVE-2019-1069

<code>
An elevation of privilege vulnerability exists in the way the Task Scheduler Service validates certain file operations, aka 'Task Scheduler Elevation of Privilege Vulnerability'.
</code>

- [S3cur3Th1sSh1t/SharpPolarBear](https://github.com/S3cur3Th1sSh1t/SharpPolarBear)

### CVE-2019-10708

<code>
S-CMS PHP v1.0 has SQL injection via the 4/js/scms.php?action=unlike id parameter.
</code>

- [stavhaygn/CVE-2019-10708](https://github.com/stavhaygn/CVE-2019-10708)

### CVE-2019-10758

<code>
mongo-express before 0.54.0 is vulnerable to Remote Code Execution via endpoints that uses the `toBSON` method. A misuse of the `vm` dependency to perform `exec` commands in a non-safe environment.
</code>

- [masahiro331/CVE-2019-10758](https://github.com/masahiro331/CVE-2019-10758)
- [lp008/CVE-2019-10758](https://github.com/lp008/CVE-2019-10758)

### CVE-2019-1083

<code>
A denial of service vulnerability exists when Microsoft Common Object Runtime Library improperly handles web requests, aka '.NET Denial of Service Vulnerability'.
</code>

- [stevenseeley/HowCVE-2019-1083Works](https://github.com/stevenseeley/HowCVE-2019-1083Works)

### CVE-2019-10869

<code>
Path Traversal and Unrestricted File Upload exists in the Ninja Forms plugin before 3.0.23 for WordPress (when the Uploads add-on is activated). This allows an attacker to traverse the file system to access files and execute code via the includes/fields/upload.php (aka upload/submit page) name and tmp_name parameters.
</code>

- [KTN1990/CVE-2019-10869](https://github.com/KTN1990/CVE-2019-10869)

### CVE-2019-10915

<code>
A vulnerability has been identified in TIA Administrator (All versions &lt; V1.0 SP1 Upd1). The integrated configuration web application (TIA Administrator) allows to execute certain application commands without proper authentication. The vulnerability could be exploited by an attacker with local access to the affected system. Successful exploitation requires no privileges and no user interaction. An attacker could use the vulnerability to compromise confidentiality and integrity and availability of the affected system. At the time of advisory publication no public exploitation of this security vulnerability was known.
</code>

- [jiansiting/CVE-2019-10915](https://github.com/jiansiting/CVE-2019-10915)

### CVE-2019-1096

<code>
An information disclosure vulnerability exists when the win32k component improperly provides kernel information, aka 'Win32k Information Disclosure Vulnerability'.
</code>

- [ze0r/cve-2019-1096-poc](https://github.com/ze0r/cve-2019-1096-poc)

### CVE-2019-10999

<code>
The D-Link DCS series of Wi-Fi cameras contains a stack-based buffer overflow in alphapd, the camera's web server. The overflow allows a remotely authenticated attacker to execute arbitrary code by providing a long string in the WEPEncryption parameter when requesting wireless.htm. Vulnerable devices include DCS-5009L (1.08.11 and below), DCS-5010L (1.14.09 and below), DCS-5020L (1.15.12 and below), DCS-5025L (1.03.07 and below), DCS-5030L (1.04.10 and below), DCS-930L (2.16.01 and below), DCS-931L (1.14.11 and below), DCS-932L (2.17.01 and below), DCS-933L (1.14.11 and below), and DCS-934L (1.05.04 and below).
</code>

- [fuzzywalls/CVE-2019-10999](https://github.com/fuzzywalls/CVE-2019-10999)

### CVE-2019-11043

<code>
In PHP versions 7.1.x below 7.1.33, 7.2.x below 7.2.24 and 7.3.x below 7.3.11 in certain configurations of FPM setup it is possible to cause FPM module to write past allocated buffers into the space reserved for FCGI protocol data, thus opening the possibility of remote code execution.
</code>

- [neex/phuip-fpizdam](https://github.com/neex/phuip-fpizdam)
- [B1gd0g/CVE-2019-11043](https://github.com/B1gd0g/CVE-2019-11043)
- [tinker-li/CVE-2019-11043](https://github.com/tinker-li/CVE-2019-11043)
- [jas502n/CVE-2019-11043](https://github.com/jas502n/CVE-2019-11043)
- [AleWong/PHP-FPM-Remote-Code-Execution-Vulnerability-CVE-2019-11043-](https://github.com/AleWong/PHP-FPM-Remote-Code-Execution-Vulnerability-CVE-2019-11043-)
- [ianxtianxt/CVE-2019-11043](https://github.com/ianxtianxt/CVE-2019-11043)
- [fairyming/CVE-2019-11043](https://github.com/fairyming/CVE-2019-11043)
- [akamajoris/CVE-2019-11043-Docker](https://github.com/akamajoris/CVE-2019-11043-Docker)
- [theMiddleBlue/CVE-2019-11043](https://github.com/theMiddleBlue/CVE-2019-11043)
- [shadow-horse/cve-2019-11043](https://github.com/shadow-horse/cve-2019-11043)
- [huowen/CVE-2019-11043](https://github.com/huowen/CVE-2019-11043)
- [ypereirareis/docker-CVE-2019-11043](https://github.com/ypereirareis/docker-CVE-2019-11043)
- [MRdoulestar/CVE-2019-11043](https://github.com/MRdoulestar/CVE-2019-11043)
- [0th3rs-Security-Team/CVE-2019-11043](https://github.com/0th3rs-Security-Team/CVE-2019-11043)
- [k8gege/CVE-2019-11043](https://github.com/k8gege/CVE-2019-11043)
- [moniik/CVE-2019-11043_env](https://github.com/moniik/CVE-2019-11043_env)
- [scgs66/CVE-2019-11043](https://github.com/scgs66/CVE-2019-11043)
- [alokaranasinghe/cve-2019-11043](https://github.com/alokaranasinghe/cve-2019-11043)

### CVE-2019-11061

<code>
A broken access control vulnerability in HG100 firmware versions up to 4.00.06 allows an attacker in the same local area network to control IoT devices that connect with itself via http://[target]/smarthome/devicecontrol without any authentication. CVSS 3.0 base score 10 (Confidentiality, Integrity and Availability impacts). CVSS vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H).
</code>

- [tim124058/ASUS-SmartHome-Exploit](https://github.com/tim124058/ASUS-SmartHome-Exploit)

### CVE-2019-11076

<code>
Cribl UI 1.5.0 allows remote attackers to run arbitrary commands via an unauthenticated web request.
</code>

- [livehybrid/poc-cribl-rce](https://github.com/livehybrid/poc-cribl-rce)

### CVE-2019-1108

<code>
An information disclosure vulnerability exists when the Windows RDP client improperly discloses the contents of its memory, aka 'Remote Desktop Protocol Client Information Disclosure Vulnerability'.
</code>

- [Lanph3re/cve-2019-1108](https://github.com/Lanph3re/cve-2019-1108)

### CVE-2019-11157

<code>
Improper conditions check in voltage settings for some Intel(R) Processors may allow a privileged user to potentially enable escalation of privilege and/or information disclosure via local access.
</code>

- [zkenjar/v0ltpwn](https://github.com/zkenjar/v0ltpwn)

### CVE-2019-11223

<code>
An Unrestricted File Upload Vulnerability in the SupportCandy plugin through 2.0.0 for WordPress allows remote attackers to execute arbitrary code by uploading a file with an executable extension.
</code>

- [AngelCtulhu/CVE-2019-11223](https://github.com/AngelCtulhu/CVE-2019-11223)

### CVE-2019-1125

<code>
An information disclosure vulnerability exists when certain central processing units (CPU) speculatively access memory, aka 'Windows Kernel Information Disclosure Vulnerability'. This CVE ID is unique from CVE-2019-1071, CVE-2019-1073.
</code>

- [bitdefender/swapgs-attack-poc](https://github.com/bitdefender/swapgs-attack-poc)

### CVE-2019-1132

<code>
An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'.
</code>

- [Vlad-tri/CVE-2019-1132](https://github.com/Vlad-tri/CVE-2019-1132)
- [petercc/CVE-2019-1132](https://github.com/petercc/CVE-2019-1132)

### CVE-2019-11358

<code>
jQuery before 3.4.0, as used in Drupal, Backdrop CMS, and other products, mishandles jQuery.extend(true, {}, ...) because of Object.prototype pollution. If an unsanitized source object contained an enumerable __proto__ property, it could extend the native Object.prototype.
</code>

- [DanielRuf/snyk-js-jquery-174006](https://github.com/DanielRuf/snyk-js-jquery-174006)
- [bitnesswise/jquery-prototype-pollution-fix](https://github.com/bitnesswise/jquery-prototype-pollution-fix)
- [DanielRuf/snyk-js-jquery-565129](https://github.com/DanielRuf/snyk-js-jquery-565129)

### CVE-2019-11477

<code>
Jonathan Looney discovered that the TCP_SKB_CB(skb)-&gt;tcp_gso_segs value was subject to an integer overflow in the Linux kernel when handling TCP Selective Acknowledgments (SACKs). A remote attacker could use this to cause a denial of service. This has been fixed in stable kernel releases 4.4.182, 4.9.182, 4.14.127, 4.19.52, 5.1.11, and is fixed in commit 3b4929f65b0d8249f19a50245cd88ed1a2f78cff.
</code>

- [sasqwatch/cve-2019-11477-poc](https://github.com/sasqwatch/cve-2019-11477-poc)

### CVE-2019-11510

<code>
In Pulse Secure Pulse Connect Secure (PCS) 8.2 before 8.2R12.1, 8.3 before 8.3R7.1, and 9.0 before 9.0R3.4, an unauthenticated remote attacker can send a specially crafted URI to perform an arbitrary file reading vulnerability .
</code>

- [projectzeroindia/CVE-2019-11510](https://github.com/projectzeroindia/CVE-2019-11510)
- [ladyleet1337/Pulse](https://github.com/ladyleet1337/Pulse)
- [imjdl/CVE-2019-11510-poc](https://github.com/imjdl/CVE-2019-11510-poc)
- [es0/CVE-2019-11510_poc](https://github.com/es0/CVE-2019-11510_poc)
- [r00tpgp/http-pulse_ssl_vpn.nse](https://github.com/r00tpgp/http-pulse_ssl_vpn.nse)
- [jas502n/CVE-2019-11510-1](https://github.com/jas502n/CVE-2019-11510-1)
- [jason3e7/CVE-2019-11510](https://github.com/jason3e7/CVE-2019-11510)
- [BishopFox/pwn-pulse](https://github.com/BishopFox/pwn-pulse)
- [aqhmal/pulsexploit](https://github.com/aqhmal/pulsexploit)
- [cisagov/check-your-pulse](https://github.com/cisagov/check-your-pulse)

### CVE-2019-11523

<code>
Anviz Global M3 Outdoor RFID Access Control executes any command received from any source. No authentication/encryption is done. Attackers can fully interact with the device: for example, send the &quot;open door&quot; command, download the users list (which includes RFID codes and passcodes in cleartext), or update/create users. The same attack can be executed on a local network and over the internet (if the device is exposed on a public IP address).
</code>

- [wizlab-it/anviz-m3-rfid-cve-2019-11523-poc](https://github.com/wizlab-it/anviz-m3-rfid-cve-2019-11523-poc)

### CVE-2019-11539

<code>
In Pulse Secure Pulse Connect Secure version 9.0RX before 9.0R3.4, 8.3RX before 8.3R7.1, 8.2RX before 8.2R12.1, and 8.1RX before 8.1R15.1 and Pulse Policy Secure version 9.0RX before 9.0R3.2, 5.4RX before 5.4R7.1, 5.3RX before 5.3R12.1, 5.2RX before 5.2R12.1, and 5.1RX before 5.1R15.1, the admin web interface allows an authenticated attacker to inject and execute commands.
</code>

- [0xDezzy/CVE-2019-11539](https://github.com/0xDezzy/CVE-2019-11539)

### CVE-2019-11580

<code>
Atlassian Crowd and Crowd Data Center had the pdkinstall development plugin incorrectly enabled in release builds. Attackers who can send unauthenticated or authenticated requests to a Crowd or Crowd Data Center instance can exploit this vulnerability to install arbitrary plugins, which permits remote code execution on systems running a vulnerable version of Crowd or Crowd Data Center. All versions of Crowd from version 2.1.0 before 3.0.5 (the fixed version for 3.0.x), from version 3.1.0 before 3.1.6 (the fixed version for 3.1.x), from version 3.2.0 before 3.2.8 (the fixed version for 3.2.x), from version 3.3.0 before 3.3.5 (the fixed version for 3.3.x), and from version 3.4.0 before 3.4.4 (the fixed version for 3.4.x) are affected by this vulnerability.
</code>

- [jas502n/CVE-2019-11580](https://github.com/jas502n/CVE-2019-11580)
- [shelld3v/CVE-2019-11580](https://github.com/shelld3v/CVE-2019-11580)

### CVE-2019-11581

<code>
There was a server-side template injection vulnerability in Jira Server and Data Center, in the ContactAdministrators and the SendBulkMail actions. An attacker is able to remotely execute code on systems that run a vulnerable version of Jira Server or Data Center. All versions of Jira Server and Data Center from 4.4.0 before 7.6.14, from 7.7.0 before 7.13.5, from 8.0.0 before 8.0.3, from 8.1.0 before 8.1.2, and from 8.2.0 before 8.2.3 are affected by this vulnerability.
</code>

- [jas502n/CVE-2019-11581](https://github.com/jas502n/CVE-2019-11581)
- [kobs0N/CVE-2019-11581](https://github.com/kobs0N/CVE-2019-11581)

### CVE-2019-11687

<code>
An issue was discovered in the DICOM Part 10 File Format in the NEMA DICOM Standard 1995 through 2019b. The preamble of a DICOM file that complies with this specification can contain the header for an executable file, such as Portable Executable (PE) malware. This space is left unspecified so that dual-purpose files can be created. (For example, dual-purpose TIFF/DICOM files are used in digital whole slide imaging for applications in medicine.) To exploit this vulnerability, someone must execute a maliciously crafted file that is encoded in the DICOM Part 10 File Format. PE/DICOM files are executable even with the .dcm file extension. Anti-malware configurations at healthcare facilities often ignore medical imagery. Also, anti-malware tools and business processes could violate regulatory frameworks (such as HIPAA) when processing suspicious DICOM files.
</code>

- [kosmokato/bad-dicom](https://github.com/kosmokato/bad-dicom)

### CVE-2019-11707

<code>
A type confusion vulnerability can occur when manipulating JavaScript objects due to issues in Array.pop. This can allow for an exploitable crash. We are aware of targeted attacks in the wild abusing this flaw. This vulnerability affects Firefox ESR &lt; 60.7.1, Firefox &lt; 67.0.3, and Thunderbird &lt; 60.7.2.
</code>

- [vigneshsrao/CVE-2019-11707](https://github.com/vigneshsrao/CVE-2019-11707)
- [tunnelshade/cve-2019-11707](https://github.com/tunnelshade/cve-2019-11707)

### CVE-2019-11708

<code>
Insufficient vetting of parameters passed with the Prompt:Open IPC message between child and parent processes can result in the non-sandboxed parent process opening web content chosen by a compromised child process. When combined with additional vulnerabilities this could result in executing arbitrary code on the user's computer. This vulnerability affects Firefox ESR &lt; 60.7.2, Firefox &lt; 67.0.4, and Thunderbird &lt; 60.7.2.
</code>

- [0vercl0k/CVE-2019-11708](https://github.com/0vercl0k/CVE-2019-11708)

### CVE-2019-11730

<code>
A vulnerability exists where if a user opens a locally saved HTML file, this file can use file: URIs to access other files in the same directory or sub-directories if the names are known or guessed. The Fetch API can then be used to read the contents of any files stored in these directories and they may uploaded to a server. It was demonstrated that in combination with a popular Android messaging app, if a malicious HTML attachment is sent to a user and they opened that attachment in Firefox, due to that app's predictable pattern for locally-saved file names, it is possible to read attachments the victim received from other correspondents. This vulnerability affects Firefox ESR &lt; 60.8, Firefox &lt; 68, and Thunderbird &lt; 60.8.
</code>

- [alidnf/CVE-2019-11730](https://github.com/alidnf/CVE-2019-11730)

### CVE-2019-1181

<code>
A remote code execution vulnerability exists in Remote Desktop Services â€“ formerly known as Terminal Services â€“ when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests, aka 'Remote Desktop ServicesÂ Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2019-1182, CVE-2019-1222, CVE-2019-1226.
</code>

- [major203/cve-2019-1181](https://github.com/major203/cve-2019-1181)

### CVE-2019-11881

<code>
A vulnerability exists in Rancher 2.1.4 in the login component, where the errorMsg parameter can be tampered to display arbitrary content, filtering tags but not special characters or symbols. There's no other limitation of the message, allowing malicious users to lure legitimate users to visit phishing sites with scare tactics, e.g., displaying a &quot;This version of Rancher is outdated, please visit https://malicious.rancher.site/upgrading&quot; message.
</code>

- [MauroEldritch/VanCleef](https://github.com/MauroEldritch/VanCleef)

### CVE-2019-11931

<code>
A stack-based buffer overflow could be triggered in WhatsApp by sending a specially crafted MP4 file to a WhatsApp user. The issue was present in parsing the elementary stream metadata of an MP4 file and could result in a DoS or RCE. This affects Android versions prior to 2.19.274, iOS versions prior to 2.19.100, Enterprise Client versions prior to 2.25.3, Business for Android versions prior to 2.19.104 and Business for iOS versions prior to 2.19.100.
</code>

- [kasif-dekel/whatsapp-rce-patched](https://github.com/kasif-dekel/whatsapp-rce-patched)
- [nop-team/CVE-2019-11931](https://github.com/nop-team/CVE-2019-11931)

### CVE-2019-11932

<code>
A double free vulnerability in the DDGifSlurp function in decoding.c in the android-gif-drawable library before version 1.2.18, as used in WhatsApp for Android before version 2.19.244 and many other Android applications, allows remote attackers to execute arbitrary code or cause a denial of service when the library is used to parse a specially crafted GIF image.
</code>

- [dorkerdevil/CVE-2019-11932](https://github.com/dorkerdevil/CVE-2019-11932)
- [KeepWannabe/WhatsRCE](https://github.com/KeepWannabe/WhatsRCE)
- [awakened1712/CVE-2019-11932](https://github.com/awakened1712/CVE-2019-11932)
- [TulungagungCyberLink/CVE-2019-11932](https://github.com/TulungagungCyberLink/CVE-2019-11932)
- [infiniteLoopers/CVE-2019-11932](https://github.com/infiniteLoopers/CVE-2019-11932)
- [alexanderstonec/CVE-2019-11932](https://github.com/alexanderstonec/CVE-2019-11932)
- [valbrux/CVE-2019-11932-SupportApp](https://github.com/valbrux/CVE-2019-11932-SupportApp)
- [fastmo/CVE-2019-11932](https://github.com/fastmo/CVE-2019-11932)
- [mRanonyMousTZ/CVE-2019-11932-whatsApp-exploit](https://github.com/mRanonyMousTZ/CVE-2019-11932-whatsApp-exploit)
- [SmoZy92/CVE-2019-11932](https://github.com/SmoZy92/CVE-2019-11932)
- [dashtic172/https-github.com-awakened171](https://github.com/dashtic172/https-github.com-awakened171)
- [Err0r-ICA/WhatsPayloadRCE](https://github.com/Err0r-ICA/WhatsPayloadRCE)

### CVE-2019-12086

<code>
A Polymorphic Typing issue was discovered in FasterXML jackson-databind 2.x before 2.9.9. When Default Typing is enabled (either globally or for a specific property) for an externally exposed JSON endpoint, the service has the mysql-connector-java jar (8.0.14 or earlier) in the classpath, and an attacker can host a crafted MySQL server reachable by the victim, an attacker can send a crafted JSON message that allows them to read arbitrary local files on the server. This occurs because of missing com.mysql.cj.jdbc.admin.MiniAdmin validation.
</code>

- [codeplutos/CVE-2019-12086-jackson-databind-file-read](https://github.com/codeplutos/CVE-2019-12086-jackson-databind-file-read)

### CVE-2019-1215

<code>
An elevation of privilege vulnerability exists in the way that ws2ifsl.sys (Winsock) handles objects in memory, aka 'Windows Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-1253, CVE-2019-1278, CVE-2019-1303.
</code>

- [bluefrostsecurity/CVE-2019-1215](https://github.com/bluefrostsecurity/CVE-2019-1215)

### CVE-2019-12169

<code>
ATutor 2.2.4 allows Arbitrary File Upload and Directory Traversal, resulting in remote code execution via a &quot;..&quot; pathname in a ZIP archive to the mods/_core/languages/language_import.php (aka Import New Language) or mods/_standard/patcher/index_admin.php (aka Patcher) component.
</code>

- [fuzzlove/ATutor-2.2.4-Language-Exploit](https://github.com/fuzzlove/ATutor-2.2.4-Language-Exploit)

### CVE-2019-12170

<code>
ATutor through 2.2.4 is vulnerable to arbitrary file uploads via the mods/_core/backups/upload.php (aka backup) component. This may result in remote command execution. An attacker can use the instructor account to fully compromise the system using a crafted backup ZIP archive. This will allow for PHP files to be written to the web root, and for code to execute on the remote server.
</code>

- [fuzzlove/ATutor-Instructor-Backup-Arbitrary-File](https://github.com/fuzzlove/ATutor-Instructor-Backup-Arbitrary-File)

### CVE-2019-1218

<code>
A spoofing vulnerability exists in the way Microsoft Outlook iOS software parses specifically crafted email messages, aka 'Outlook iOS Spoofing Vulnerability'.
</code>

- [d0gukank/CVE-2019-1218](https://github.com/d0gukank/CVE-2019-1218)

### CVE-2019-12180

<code>
An issue was discovered in SmartBear ReadyAPI through 2.8.2 and 3.0.0 and SoapUI through 5.5. When opening a project, the Groovy &quot;Load Script&quot; is automatically executed. This allows an attacker to execute arbitrary Groovy Language code (Java scripting language) on the victim machine by inducing it to open a malicious Project. The same issue is present in the &quot;Save Script&quot; function, which is executed automatically when saving a project.
</code>

- [0x-nope/CVE-2019-12180](https://github.com/0x-nope/CVE-2019-12180)

### CVE-2019-12181

<code>
A privilege escalation vulnerability exists in SolarWinds Serv-U before 15.1.7 for Linux.
</code>

- [guywhataguy/CVE-2019-12181](https://github.com/guywhataguy/CVE-2019-12181)

### CVE-2019-12185

<code>
eLabFTW 1.8.5 is vulnerable to arbitrary file uploads via the /app/controllers/EntityController.php component. This may result in remote command execution. An attacker can use a user account to fully compromise the system using a POST request. This will allow for PHP files to be written to the web root, and for code to execute on the remote server.
</code>

- [fuzzlove/eLabFTW-1.8.5-EntityController-Arbitrary-File-Upload-RCE](https://github.com/fuzzlove/eLabFTW-1.8.5-EntityController-Arbitrary-File-Upload-RCE)

### CVE-2019-12189

<code>
An issue was discovered in Zoho ManageEngine ServiceDesk Plus 9.3. There is XSS via the SearchN.do search field.
</code>

- [falconz/CVE-2019-12189](https://github.com/falconz/CVE-2019-12189)
- [tuyenhva/CVE-2019-12189](https://github.com/tuyenhva/CVE-2019-12189)

### CVE-2019-12190

<code>
XSS was discovered in CentOS-WebPanel.com (aka CWP) CentOS Web Panel through 0.9.8.747 via the testacc/fileManager2.php fm_current_dir or filename parameter.
</code>

- [tuyenhva/CVE-2019-12190](https://github.com/tuyenhva/CVE-2019-12190)

### CVE-2019-12252

<code>
In Zoho ManageEngine ServiceDesk Plus through 10.5, users with the lowest privileges (guest) can view an arbitrary post by appending its number to the SDNotify.do?notifyModule=Solution&amp;mode=E-Mail&amp;notifyTo=SOLFORWARD&amp;id= substring.
</code>

- [tuyenhva/CVE-2019-12252](https://github.com/tuyenhva/CVE-2019-12252)

### CVE-2019-12255

<code>
Wind River VxWorks has a Buffer Overflow in the TCP component (issue 1 of 4). This is a IPNET security vulnerability: TCP Urgent Pointer = 0 that leads to an integer underflow.
</code>

- [sud0woodo/Urgent11-Suricata-LUA-scripts](https://github.com/sud0woodo/Urgent11-Suricata-LUA-scripts)

### CVE-2019-12272

<code>
In OpenWrt LuCI through 0.10, the endpoints admin/status/realtime/bandwidth_status and admin/status/realtime/wireless_status of the web application are affected by a command injection vulnerability.
</code>

- [HACHp1/LuCI_RCE_exp](https://github.com/HACHp1/LuCI_RCE_exp)
- [roguedream/lede-17.01.3](https://github.com/roguedream/lede-17.01.3)

### CVE-2019-12314

<code>
Deltek Maconomy 2.2.5 is prone to local file inclusion via absolute path traversal in the WS.macx1.W_MCS/ PATH_INFO, as demonstrated by a cgi-bin/Maconomy/MaconomyWS.macx1.W_MCS/etc/passwd URI.
</code>

- [ras313/CVE-2019-12314](https://github.com/ras313/CVE-2019-12314)

### CVE-2019-12384

<code>
FasterXML jackson-databind 2.x before 2.9.9.1 might allow attackers to have a variety of impacts by leveraging failure to block the logback-core class from polymorphic deserialization. Depending on the classpath content, remote code execution may be possible.
</code>

- [jas502n/CVE-2019-12384](https://github.com/jas502n/CVE-2019-12384)
- [MagicZer0/Jackson_RCE-CVE-2019-12384](https://github.com/MagicZer0/Jackson_RCE-CVE-2019-12384)

### CVE-2019-12409

<code>
The 8.1.1 and 8.2.0 releases of Apache Solr contain an insecure setting for the ENABLE_REMOTE_JMX_OPTS configuration option in the default solr.in.sh configuration file shipping with Solr. If you use the default solr.in.sh file from the affected releases, then JMX monitoring will be enabled and exposed on RMI_PORT (default=18983), without any authentication. If this port is opened for inbound traffic in your firewall, then anyone with network access to your Solr nodes will be able to access JMX, which may in turn allow them to upload malicious code for execution on the Solr server.
</code>

- [jas502n/CVE-2019-12409](https://github.com/jas502n/CVE-2019-12409)

### CVE-2019-12453

<code>
In MicroStrategy Web before 10.1 patch 10, stored XSS is possible in the FLTB parameter due to missing input validation.
</code>

- [undefinedmode/CVE-2019-12453](https://github.com/undefinedmode/CVE-2019-12453)

### CVE-2019-12460

<code>
Web Port 1.19.1 allows XSS via the /access/setup type parameter.
</code>

- [EmreOvunc/WebPort-v1.19.1-Reflected-XSS](https://github.com/EmreOvunc/WebPort-v1.19.1-Reflected-XSS)

### CVE-2019-12475

<code>
In MicroStrategy Web before 10.4.6, there is stored XSS in metric due to insufficient input validation.
</code>

- [undefinedmode/CVE-2019-12475](https://github.com/undefinedmode/CVE-2019-12475)

### CVE-2019-12476

<code>
An authentication bypass vulnerability in the password reset functionality in Zoho ManageEngine ADSelfService Plus before 5.0.6 allows an attacker with physical access to gain a shell with SYSTEM privileges via the restricted thick client browser. The attack uses a long sequence of crafted keyboard input.
</code>

- [0katz/CVE-2019-12476](https://github.com/0katz/CVE-2019-12476)

### CVE-2019-1253

<code>
An elevation of privilege vulnerability exists when the Windows AppX Deployment Server improperly handles junctions.To exploit this vulnerability, an attacker would first have to gain execution on the victim system, aka 'Windows Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-1215, CVE-2019-1278, CVE-2019-1303.
</code>

- [rogue-kdc/CVE-2019-1253](https://github.com/rogue-kdc/CVE-2019-1253)
- [denmilu/CVE-2019-1253](https://github.com/denmilu/CVE-2019-1253)
- [padovah4ck/CVE-2019-1253](https://github.com/padovah4ck/CVE-2019-1253)
- [sgabe/CVE-2019-1253](https://github.com/sgabe/CVE-2019-1253)

### CVE-2019-12538

<code>
An issue was discovered in Zoho ManageEngine ServiceDesk Plus 9.3. There is XSS via the SiteLookup.do search field.
</code>

- [tarantula-team/CVE-2019-12538](https://github.com/tarantula-team/CVE-2019-12538)

### CVE-2019-12541

<code>
An issue was discovered in Zoho ManageEngine ServiceDesk Plus 9.3. There is XSS via the SolutionSearch.do searchText parameter.
</code>

- [tarantula-team/CVE-2019-12541](https://github.com/tarantula-team/CVE-2019-12541)

### CVE-2019-12542

<code>
An issue was discovered in Zoho ManageEngine ServiceDesk Plus 9.3. There is XSS via the SearchN.do userConfigID parameter.
</code>

- [tarantula-team/CVE-2019-12542](https://github.com/tarantula-team/CVE-2019-12542)

### CVE-2019-12543

<code>
An issue was discovered in Zoho ManageEngine ServiceDesk Plus 9.3. There is XSS via the PurchaseRequest.do serviceRequestId parameter.
</code>

- [tarantula-team/CVE-2019-12543](https://github.com/tarantula-team/CVE-2019-12543)

### CVE-2019-12562

<code>
Stored Cross-Site Scripting in DotNetNuke (DNN) Version before 9.4.0 allows remote attackers to store and embed the malicious script into the admin notification page. The exploit could be used to perfom any action with admin privileges such as managing content, adding users, uploading backdoors to the server, etc. Successful exploitation occurs when an admin user visits a notification page with stored cross-site scripting.
</code>

- [MAYASEVEN/CVE-2019-12562](https://github.com/MAYASEVEN/CVE-2019-12562)

### CVE-2019-12586

<code>
The EAP peer implementation in Espressif ESP-IDF 2.0.0 through 4.0.0 and ESP8266_NONOS_SDK 2.2.0 through 3.1.0 processes EAP Success messages before any EAP method completion or failure, which allows attackers in radio range to cause a denial of service (crash) via a crafted message.
</code>

- [Matheus-Garbelini/esp32_esp8266_attacks](https://github.com/Matheus-Garbelini/esp32_esp8266_attacks)

### CVE-2019-12594

<code>
DOSBox 0.74-2 has Incorrect Access Control.
</code>

- [Alexandre-Bartel/CVE-2019-12594](https://github.com/Alexandre-Bartel/CVE-2019-12594)

### CVE-2019-12735

<code>
getchar.c in Vim before 8.1.1365 and Neovim before 0.3.6 allows remote attackers to execute arbitrary OS commands via the :source! command in a modeline, as demonstrated by execute in Vim, and assert_fails or nvim_input in Neovim.
</code>

- [pcy190/ace-vim-neovim](https://github.com/pcy190/ace-vim-neovim)
- [oldthree3/CVE-2019-12735-VIM-NEOVIM](https://github.com/oldthree3/CVE-2019-12735-VIM-NEOVIM)

### CVE-2019-12750

<code>
Symantec Endpoint Protection, prior to 14.2 RU1 &amp; 12.1 RU6 MP10 and Symantec Endpoint Protection Small Business Edition, prior to 12.1 RU6 MP10c (12.1.7491.7002), may be susceptible to a privilege escalation vulnerability, which is a type of issue whereby an attacker may attempt to compromise the software application to gain elevated access to resources that are normally protected from an application or user.
</code>

- [v-p-b/cve-2019-12750](https://github.com/v-p-b/cve-2019-12750)

### CVE-2019-12796
- [PeterUpfold/CVE-2019-12796](https://github.com/PeterUpfold/CVE-2019-12796)

### CVE-2019-12815

<code>
An arbitrary file copy vulnerability in mod_copy in ProFTPD up to 1.3.5b allows for remote code execution and information disclosure without authentication, a related issue to CVE-2015-3306.
</code>

- [KTN1990/CVE-2019-12815](https://github.com/KTN1990/CVE-2019-12815)

### CVE-2019-12836

<code>
The Bobronix JEditor editor before 3.0.6 for Jira allows an attacker to add a URL/Link (to an existing issue) that can cause forgery of a request to an out-of-origin domain. This in turn may allow for a forged request that can be invoked in the context of an authenticated user, leading to stealing of session tokens and account takeover.
</code>

- [9lyph/CVE-2019-12836](https://github.com/9lyph/CVE-2019-12836)

### CVE-2019-12840

<code>
In Webmin through 1.910, any user authorized to the &quot;Package Updates&quot; module can execute arbitrary commands with root privileges via the data parameter to update.cgi.
</code>

- [bkaraceylan/CVE-2019-12840_POC](https://github.com/bkaraceylan/CVE-2019-12840_POC)
- [KrE80r/webmin_cve-2019-12840_poc](https://github.com/KrE80r/webmin_cve-2019-12840_poc)

### CVE-2019-12889

<code>
An unauthenticated privilege escalation exists in SailPoint Desktop Password Reset 7.2. A user with local access to only the Windows logon screen can escalate their privileges to NT AUTHORITY\System. An attacker would need local access to the machine for a successful exploit. The attacker must disconnect the computer from the local network / WAN and connect it to an internet facing access point / network. At that point, the attacker can execute the password-reset functionality, which will expose a web browser. Browsing to a site that calls local Windows system functions (e.g., file upload) will expose the local file system. From there an attacker can launch a privileged command shell.
</code>

- [nulsect0r/CVE-2019-12889](https://github.com/nulsect0r/CVE-2019-12889)

### CVE-2019-12890

<code>
RedwoodHQ 2.5.5 does not require any authentication for database operations, which allows remote attackers to create admin users via a con.automationframework users insert_one call.
</code>

- [EthicalHackingCOP/CVE-2019-12890](https://github.com/EthicalHackingCOP/CVE-2019-12890)

### CVE-2019-12949

<code>
In pfSense 2.4.4-p2 and 2.4.4-p3, if it is possible to trick an authenticated administrator into clicking on a button on a phishing page, an attacker can leverage XSS to upload arbitrary executable code, via diag_command.php and rrd_fetch_json.php (timePeriod parameter), to a server. Then, the remote attacker can run any command with root privileges on that server.
</code>

- [tarantula-team/CVE-2019-12949](https://github.com/tarantula-team/CVE-2019-12949)

### CVE-2019-12999

<code>
Lightning Network Daemon (lnd) before 0.7 allows attackers to trigger loss of funds because of Incorrect Access Control.
</code>

- [lightninglabs/chanleakcheck](https://github.com/lightninglabs/chanleakcheck)

### CVE-2019-13000

<code>
Eclair through 0.3 allows attackers to trigger loss of funds because of Incorrect Access Control. NOTE: README.md states &quot;it is beta-quality software and don't put too much money in it.&quot;
</code>

- [ACINQ/detection-tool-cve-2019-13000](https://github.com/ACINQ/detection-tool-cve-2019-13000)

### CVE-2019-13024

<code>
Centreon 18.x before 18.10.6, 19.x before 19.04.3, and Centreon web before 2.8.29 allows the attacker to execute arbitrary system commands by using the value &quot;init_script&quot;-&quot;Monitoring Engine Binary&quot; in main.get.php to insert a arbitrary command into the database, and execute it by calling the vulnerable page www/include/configuration/configGenerate/xml/generateFiles.php (which passes the inserted value to the database to shell_exec without sanitizing it, allowing one to execute system arbitrary commands).
</code>

- [mhaskar/CVE-2019-13024](https://github.com/mhaskar/CVE-2019-13024)
- [get-get-get-get/Centreon-RCE](https://github.com/get-get-get-get/Centreon-RCE)

### CVE-2019-13025

<code>
Compal CH7465LG CH7465LG-NCIP-6.12.18.24-5p8-NOSH devices have Incorrect Access Control because of Improper Input Validation. The attacker can send a maliciously modified POST (HTTP) request containing shell commands, which will be executed on the device, to an backend API endpoint of the cable modem.
</code>

- [x1tan/CVE-2019-13025](https://github.com/x1tan/CVE-2019-13025)

### CVE-2019-13027

<code>
Realization Concerto Critical Chain Planner (aka CCPM) 5.10.8071 has SQL Injection in at least in the taskupdt/taskdetails.aspx webpage via the projectname parameter.
</code>

- [IckoGZ/CVE-2019-13027](https://github.com/IckoGZ/CVE-2019-13027)

### CVE-2019-13051

<code>
Pi-Hole 4.3 allows Command Injection.
</code>

- [pr0tean/CVE-2019-13051](https://github.com/pr0tean/CVE-2019-13051)

### CVE-2019-13063

<code>
Within Sahi Pro 8.0.0, an attacker can send a specially crafted URL to include any victim files on the system via the script parameter on the Script_view page. This will result in file disclosure (i.e., being able to pull any file from the remote victim application). This can be used to steal and obtain sensitive config and other files. This can result in complete compromise of the application. The script parameter is vulnerable to directory traversal and both local and remote file inclusion.
</code>

- [0x6b7966/CVE-2019-13063-POC](https://github.com/0x6b7966/CVE-2019-13063-POC)

### CVE-2019-13086

<code>
core/MY_Security.php in CSZ CMS 1.2.2 before 2019-06-20 has member/login/check SQL injection by sending a crafted HTTP User-Agent header and omitting the csrf_csz parameter.
</code>

- [lingchuL/CVE_POC_test](https://github.com/lingchuL/CVE_POC_test)

### CVE-2019-13101

<code>
An issue was discovered on D-Link DIR-600M 3.02, 3.03, 3.04, and 3.06 devices. wan.htm can be accessed directly without authentication, which can lead to disclosure of information about the WAN, and can also be leveraged by an attacker to modify the data fields of the page.
</code>

- [halencarjunior/dlkploit600](https://github.com/halencarjunior/dlkploit600)

### CVE-2019-13115

<code>
In libssh2 before 1.9.0, kex_method_diffie_hellman_group_exchange_sha256_key_exchange in kex.c has an integer overflow that could lead to an out-of-bounds read in the way packets are read from the server. A remote attacker who compromises a SSH server may be able to disclose sensitive information or cause a denial of service condition on the client system when a user connects to the server. This is related to an _libssh2_check_length mistake, and is different from the various issues fixed in 1.8.1, such as CVE-2019-3855.
</code>

- [CSSProject/libssh2-Exploit](https://github.com/CSSProject/libssh2-Exploit)

### CVE-2019-13143

<code>
An HTTP parameter pollution issue was discovered on Shenzhen Dragon Brothers Fingerprint Bluetooth Round Padlock FB50 2.3. With the user ID, user name, and the lock's MAC address, anyone can unbind the existing owner of the lock, and bind themselves instead. This leads to complete takeover of the lock. The user ID, name, and MAC address are trivially obtained from APIs found within the Android or iOS application. With only the MAC address of the lock, any attacker can transfer ownership of the lock from the current user, over to the attacker's account. Thus rendering the lock completely inaccessible to the current user.
</code>

- [securelayer7/pwnfb50](https://github.com/securelayer7/pwnfb50)

### CVE-2019-1315

<code>
An elevation of privilege vulnerability exists when Windows Error Reporting manager improperly handles hard links, aka 'Windows Error Reporting Manager Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-1339, CVE-2019-1342.
</code>

- [Mayter/CVE-2019-1315](https://github.com/Mayter/CVE-2019-1315)

### CVE-2019-13272

<code>
In the Linux kernel before 5.1.17, ptrace_link in kernel/ptrace.c mishandles the recording of the credentials of a process that wants to create a ptrace relationship, which allows local users to obtain root access by leveraging certain scenarios with a parent-child process relationship, where a parent drops privileges and calls execve (potentially allowing control by an attacker). One contributing factor is an object lifetime issue (which can also cause a panic). Another contributing factor is incorrect marking of a ptrace relationship as privileged, which is exploitable through (for example) Polkit's pkexec helper with PTRACE_TRACEME. NOTE: SELinux deny_ptrace might be a usable workaround in some environments.
</code>

- [jas502n/CVE-2019-13272](https://github.com/jas502n/CVE-2019-13272)
- [Cyc1eC/CVE-2019-13272](https://github.com/Cyc1eC/CVE-2019-13272)
- [bigbigliang-malwarebenchmark/cve-2019-13272](https://github.com/bigbigliang-malwarebenchmark/cve-2019-13272)
- [oneoy/CVE-2019-13272](https://github.com/oneoy/CVE-2019-13272)
- [Huandtx/CVE-2019-13272](https://github.com/Huandtx/CVE-2019-13272)
- [polosec/CVE-2019-13272](https://github.com/polosec/CVE-2019-13272)
- [sumedhaDharmasena/-Kernel-ptrace-c-mishandles-vulnerability-CVE-2019-13272](https://github.com/sumedhaDharmasena/-Kernel-ptrace-c-mishandles-vulnerability-CVE-2019-13272)
- [Tharana/Exploiting-a-Linux-kernel-vulnerability](https://github.com/Tharana/Exploiting-a-Linux-kernel-vulnerability)
- [RashmikaEkanayake/Privilege-Escalation-CVE-2019-13272-](https://github.com/RashmikaEkanayake/Privilege-Escalation-CVE-2019-13272-)
- [Tharana/vulnerability-exploitation](https://github.com/Tharana/vulnerability-exploitation)
- [teddy47/CVE-2019-13272---Documentation](https://github.com/teddy47/CVE-2019-13272---Documentation)

### CVE-2019-13361

<code>
Smanos W100 1.0.0 devices have Insecure Permissions, exploitable by an attacker on the same Wi-Fi network.
</code>

- [lodi-g/CVE-2019-13361](https://github.com/lodi-g/CVE-2019-13361)

### CVE-2019-13403

<code>
Temenos CWX version 8.9 has an Broken Access Control vulnerability in the module /CWX/Employee/EmployeeEdit2.aspx, leading to the viewing of user information.
</code>

- [B3Bo1d/CVE-2019-13403](https://github.com/B3Bo1d/CVE-2019-13403)

### CVE-2019-13404

<code>
** DISPUTED ** The MSI installer for Python through 2.7.16 on Windows defaults to the C:\Python27 directory, which makes it easier for local users to deploy Trojan horse code. (This also affects old 3.x releases before 3.5.) NOTE: the vendor's position is that it is the user's responsibility to ensure C:\Python27 access control or choose a different directory, because backwards compatibility requires that C:\Python27 remain the default for 2.7.x.
</code>

- [alidnf/CVE-2019-13404](https://github.com/alidnf/CVE-2019-13404)

### CVE-2019-13496

<code>
One Identity Cloud Access Manager before 8.1.4 Hotfix 1 allows OTP bypass via vectors involving a man in the middle, the One Identity Defender product, and replacing a failed SAML response with a successful SAML response.
</code>

- [FurqanKhan1/CVE-2019-13496](https://github.com/FurqanKhan1/CVE-2019-13496)

### CVE-2019-13497

<code>
One Identity Cloud Access Manager before 8.1.4 Hotfix 1 allows CSRF for logout requests.
</code>

- [FurqanKhan1/CVE-2019-13497](https://github.com/FurqanKhan1/CVE-2019-13497)

### CVE-2019-13498

<code>
One Identity Cloud Access Manager 8.1.3 does not use HTTP Strict Transport Security (HSTS), which may allow man-in-the-middle (MITM) attacks. This issue is fixed in version 8.1.4.
</code>

- [FurqanKhan1/CVE-2019-13498](https://github.com/FurqanKhan1/CVE-2019-13498)

### CVE-2019-13504

<code>
There is an out-of-bounds read in Exiv2::MrwImage::readMetadata in mrwimage.cpp in Exiv2 through 0.27.2.
</code>

- [hazedic/fuzzenv-exiv2](https://github.com/hazedic/fuzzenv-exiv2)

### CVE-2019-13574

<code>
In lib/mini_magick/image.rb in MiniMagick before 4.9.4, a fetched remote image filename could cause remote command execution because Image.open input is directly passed to Kernel#open, which accepts a '|' character followed by a command.
</code>

- [masahiro331/CVE-2019-13574](https://github.com/masahiro331/CVE-2019-13574)

### CVE-2019-1367

<code>
A remote code execution vulnerability exists in the way that the scripting engine handles objects in memory in Internet Explorer, aka 'Scripting Engine Memory Corruption Vulnerability'. This CVE ID is unique from CVE-2019-1221.
</code>

- [mandarenmanman/CVE-2019-1367](https://github.com/mandarenmanman/CVE-2019-1367)

### CVE-2019-13720

<code>
Use after free in WebAudio in Google Chrome prior to 78.0.3904.87 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.
</code>

- [cve-2019-13720/cve-2019-13720](https://github.com/cve-2019-13720/cve-2019-13720)
- [ChoKyuWon/CVE-2019-13720](https://github.com/ChoKyuWon/CVE-2019-13720)

### CVE-2019-1385

<code>
An elevation of privilege vulnerability exists when the Windows AppX Deployment Extensions improperly performs privilege management, resulting in access to system files.To exploit this vulnerability, an authenticated attacker would need to run a specially crafted application to elevate privileges.The security update addresses the vulnerability by correcting how AppX Deployment Extensions manages privileges., aka 'Windows AppX Deployment Extensions Elevation of Privilege Vulnerability'.
</code>

- [klinix5/CVE-2019-1385](https://github.com/klinix5/CVE-2019-1385)

### CVE-2019-1388

<code>
An elevation of privilege vulnerability exists in the Windows Certificate Dialog when it does not properly enforce user privileges, aka 'Windows Certificate Dialog Elevation of Privilege Vulnerability'.
</code>

- [jas502n/CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [jaychouzzk/CVE-2019-1388](https://github.com/jaychouzzk/CVE-2019-1388)
- [sv3nbeast/CVE-2019-1388](https://github.com/sv3nbeast/CVE-2019-1388)

### CVE-2019-13956

<code>
Discuz!ML 3.2 through 3.4 allows remote attackers to execute arbitrary PHP code via a modified language cookie, as demonstrated by changing 4gH4_0df5_language=en to 4gH4_0df5_language=en'.phpinfo().'; (if the random prefix 4gH4_0df5_ were used).
</code>

- [rhbb/CVE-2019-13956](https://github.com/rhbb/CVE-2019-13956)

### CVE-2019-1402

<code>
An information disclosure vulnerability exists in Microsoft Office software when the software fails to properly handle objects in memory, aka 'Microsoft Office Information Disclosure Vulnerability'.
</code>

- [lauxjpn/CorruptQueryAccessWorkaround](https://github.com/lauxjpn/CorruptQueryAccessWorkaround)

### CVE-2019-14040

<code>
Using memory after being freed in qsee due to wrong implementation can lead to unexpected behavior such as execution of unknown code in Snapdragon Auto, Snapdragon Compute, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon IoT, Snapdragon Mobile, Snapdragon Voice &amp; Music, Snapdragon Wearables in APQ8009, APQ8017, APQ8053, APQ8096AU, APQ8098, MDM9150, MDM9206, MDM9207C, MDM9607, MDM9640, MDM9650, MSM8905, MSM8909W, MSM8917, MSM8920, MSM8937, MSM8940, MSM8953, MSM8996AU, MSM8998, QCS605, QM215, SDA660, SDA845, SDM429, SDM429W, SDM439, SDM450, SDM630, SDM632, SDM636, SDM660, SDM845, SDX20, SDX24, SM8150, SXR1130
</code>

- [tamirzb/CVE-2019-14040](https://github.com/tamirzb/CVE-2019-14040)

### CVE-2019-14041

<code>
During listener modified response processing, a buffer overrun occurs due to lack of buffer size verification when updating message buffer with physical address information in Snapdragon Auto, Snapdragon Compute, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon IoT, Snapdragon Mobile, Snapdragon Voice &amp; Music, Snapdragon Wearables in APQ8009, APQ8017, APQ8053, APQ8096AU, APQ8098, MDM9206, MDM9207C, MDM9607, MDM9640, MDM9650, MSM8905, MSM8909W, MSM8917, MSM8953, MSM8996AU, Nicobar, QCM2150, QCS405, QCS605, QM215, Rennell, SA6155P, Saipan, SC8180X, SDA660, SDA845, SDM429, SDM429W, SDM439, SDM450, SDM632, SDM670, SDM710, SDM845, SDX20, SDX24, SDX55, SM6150, SM7150, SM8150, SM8250, SXR1130, SXR2130
</code>

- [tamirzb/CVE-2019-14041](https://github.com/tamirzb/CVE-2019-14041)

### CVE-2019-1405

<code>
An elevation of privilege vulnerability exists when the Windows Universal Plug and Play (UPnP) service improperly allows COM object creation, aka 'Windows UPnP Service Elevation of Privilege Vulnerability'.
</code>

- [apt69/COMahawk](https://github.com/apt69/COMahawk)

### CVE-2019-14079

<code>
Access to the uninitialized variable when the driver tries to unmap the dma buffer of a request which was never mapped in the first place leading to kernel failure in Snapdragon Auto, Snapdragon Compute, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Wearables in APQ8009, APQ8053, MDM9607, MDM9640, MSM8909W, MSM8953, QCA6574AU, QCS605, SDA845, SDM429, SDM429W, SDM439, SDM450, SDM632, SDM670, SDM710, SDM845, SDX24, SM8150, SXR1130
</code>

- [parallelbeings/CVE-2019-14079](https://github.com/parallelbeings/CVE-2019-14079)

### CVE-2019-14205

<code>
A Local File Inclusion vulnerability in the Nevma Adaptive Images plugin before 0.6.67 for WordPress allows remote attackers to retrieve arbitrary files via the $REQUEST['adaptive-images-settings']['source_file'] parameter in adaptive-images-script.php.
</code>

- [security-kma/EXPLOITING-CVE-2019-14205](https://github.com/security-kma/EXPLOITING-CVE-2019-14205)

### CVE-2019-1422

<code>
An elevation of privilege vulnerability exists in the way that the iphlpsvc.dll handles file creation allowing for a file overwrite, aka 'Windows Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-1420, CVE-2019-1423.
</code>

- [ze0r/cve-2019-1422](https://github.com/ze0r/cve-2019-1422)

### CVE-2019-14220

<code>
An issue was discovered in BlueStacks 4.110 and below on macOS and on 4.120 and below on Windows. BlueStacks employs Android running in a virtual machine (VM) to enable Android apps to run on Windows or MacOS. Bug is in a local arbitrary file read through a system service call. The impacted method runs with System admin privilege and if given the file name as parameter returns you the content of file. A malicious app using the affected method can then read the content of any system file which it is not authorized to read
</code>

- [seqred-s-a/cve-2019-14220](https://github.com/seqred-s-a/cve-2019-14220)

### CVE-2019-14267

<code>
PDFResurrect 0.15 has a buffer overflow via a crafted PDF file because data associated with startxref and %%EOF is mishandled.
</code>

- [snappyJack/pdfresurrect_CVE-2019-14267](https://github.com/snappyJack/pdfresurrect_CVE-2019-14267)

### CVE-2019-14287

<code>
In Sudo before 1.8.28, an attacker with access to a Runas ALL sudoer account can bypass certain policy blacklists and session PAM modules, and can cause incorrect logging, by invoking sudo with a crafted user ID. For example, this allows bypass of !root configuration, and USER= logging, for a &quot;sudo -u \#$((0xffffffff))&quot; command.
</code>

- [FauxFaux/sudo-cve-2019-14287](https://github.com/FauxFaux/sudo-cve-2019-14287)
- [CashWilliams/CVE-2019-14287-demo](https://github.com/CashWilliams/CVE-2019-14287-demo)
- [n0w4n/CVE-2019-14287](https://github.com/n0w4n/CVE-2019-14287)
- [gurneesh/CVE-2019-14287-write-up](https://github.com/gurneesh/CVE-2019-14287-write-up)
- [shellvhack/Sudo-Security-Bypass-CVE-2019-14287](https://github.com/shellvhack/Sudo-Security-Bypass-CVE-2019-14287)
- [Janette88/cve-2019-14287sudoexp](https://github.com/Janette88/cve-2019-14287sudoexp)
- [huang919/cve-2019-14287-PPT](https://github.com/huang919/cve-2019-14287-PPT)
- [wenyu1999/sudo-](https://github.com/wenyu1999/sudo-)
- [Sindadziy/cve-2019-14287](https://github.com/Sindadziy/cve-2019-14287)
- [Sindayifu/CVE-2019-14287-CVE-2014-6271](https://github.com/Sindayifu/CVE-2019-14287-CVE-2014-6271)
- [Unam3dd/sudo-vulnerability-CVE-2019-14287](https://github.com/Unam3dd/sudo-vulnerability-CVE-2019-14287)
- [CMNatic/Dockerized-CVE-2019-14287](https://github.com/CMNatic/Dockerized-CVE-2019-14287)
- [SachinthaDeSilva-cmd/Exploit-CVE-2019-14287](https://github.com/SachinthaDeSilva-cmd/Exploit-CVE-2019-14287)
- [HussyCool/CVE-2019-14287-IT18030372-](https://github.com/HussyCool/CVE-2019-14287-IT18030372-)
- [ShianTrish/sudo-Security-Bypass-vulnerability-CVE-2019-14287](https://github.com/ShianTrish/sudo-Security-Bypass-vulnerability-CVE-2019-14287)
- [ejlevin99/Sudo-Security-Bypass-Vulnerability](https://github.com/ejlevin99/Sudo-Security-Bypass-Vulnerability)
- [thinuri99/Sudo-Security-Bypass-Vulnerability-CVE-2019-14287-](https://github.com/thinuri99/Sudo-Security-Bypass-Vulnerability-CVE-2019-14287-)
- [janod313/-CVE-2019-14287-SUDO-bypass-vulnerability](https://github.com/janod313/-CVE-2019-14287-SUDO-bypass-vulnerability)
- [DewmiApsara/CVE-2019-14287](https://github.com/DewmiApsara/CVE-2019-14287)

### CVE-2019-14314

<code>
A SQL injection vulnerability exists in the Imagely NextGEN Gallery plugin before 3.2.11 for WordPress. Successful exploitation of this vulnerability would allow a remote attacker to execute arbitrary SQL commands on the affected system via modules/nextgen_gallery_display/package.module.nextgen_gallery_display.php.
</code>

- [imthoe/CVE-2019-14314](https://github.com/imthoe/CVE-2019-14314)

### CVE-2019-14319

<code>
The TikTok (formerly Musical.ly) application 12.2.0 for Android and iOS performs unencrypted transmission of images, videos, and likes. This allows an attacker to extract private sensitive information by sniffing network traffic.
</code>

- [MelroyB/CVE-2019-14319](https://github.com/MelroyB/CVE-2019-14319)

### CVE-2019-14326

<code>
An issue was discovered in AndyOS Andy versions up to 46.11.113. By default, it starts telnet and ssh (ports 22 and 23) with root privileges in the emulated Android system. This can be exploited by remote attackers to gain full access to the device, or by malicious apps installed inside the emulator to perform privilege escalation from a normal user to root (unlike with standard methods of getting root privileges on Android - e.g., the SuperSu program - the user is not asked for consent). There is no authentication performed - access to a root shell is given upon a successful connection. NOTE: although this was originally published with a slightly different CVE ID number, the correct ID for this Andy vulnerability has always been CVE-2019-14326.
</code>

- [seqred-s-a/cve-2019-14326](https://github.com/seqred-s-a/cve-2019-14326)

### CVE-2019-14339

<code>
The ContentProvider in the Canon PRINT jp.co.canon.bsd.ad.pixmaprint 2.5.5 application for Android does not properly restrict canon.ij.printer.capability.data data access. This allows an attacker's malicious application to obtain sensitive information including factory passwords for the administrator web interface and WPA2-PSK key.
</code>

- [0x48piraj/CVE-2019-14339](https://github.com/0x48piraj/CVE-2019-14339)

### CVE-2019-14439

<code>
A Polymorphic Typing issue was discovered in FasterXML jackson-databind 2.x before 2.9.9.2. This occurs when Default Typing is enabled (either globally or for a specific property) for an externally exposed JSON endpoint and the service has the logback jar in the classpath.
</code>

- [jas502n/CVE-2019-14439](https://github.com/jas502n/CVE-2019-14439)

### CVE-2019-14514

<code>
An issue was discovered in Microvirt MEmu all versions prior to 7.0.2. A guest Android operating system inside the MEmu emulator contains a /system/bin/systemd binary that is run with root privileges on startup (this is unrelated to Red Hat's systemd init program, and is a closed-source proprietary tool that seems to be developed by Microvirt). This program opens TCP port 21509, presumably to receive installation-related commands from the host OS. Because everything after the installer:uninstall command is concatenated directly into a system() call, it is possible to execute arbitrary commands by supplying shell metacharacters.
</code>

- [seqred-s-a/cve-2019-14514](https://github.com/seqred-s-a/cve-2019-14514)

### CVE-2019-14529

<code>
OpenEMR before 5.0.2 allows SQL Injection in interface/forms/eye_mag/save.php.
</code>

- [Wezery/CVE-2019-14529](https://github.com/Wezery/CVE-2019-14529)

### CVE-2019-14530

<code>
An issue was discovered in custom/ajax_download.php in OpenEMR before 5.0.2 via the fileName parameter. An attacker can download any file (that is readable by the user www-data) from server storage. If the requested file is writable for the www-data user and the directory /var/www/openemr/sites/default/documents/cqm_qrda/ exists, it will be deleted from server.
</code>

- [Wezery/CVE-2019-14530](https://github.com/Wezery/CVE-2019-14530)

### CVE-2019-14537

<code>
YOURLS through 1.7.3 is affected by a type juggling vulnerability in the api component that can result in login bypass.
</code>

- [Wocanilo/CVE-2019-14537](https://github.com/Wocanilo/CVE-2019-14537)

### CVE-2019-14540

<code>
A Polymorphic Typing issue was discovered in FasterXML jackson-databind before 2.9.10. It is related to com.zaxxer.hikari.HikariConfig.
</code>

- [LeadroyaL/cve-2019-14540-exploit](https://github.com/LeadroyaL/cve-2019-14540-exploit)

### CVE-2019-1458

<code>
An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'.
</code>

- [piotrflorczyk/cve-2019-1458_POC](https://github.com/piotrflorczyk/cve-2019-1458_POC)
- [unamer/CVE-2019-1458](https://github.com/unamer/CVE-2019-1458)

### CVE-2019-14615

<code>
Insufficient control flow in certain data structures for some Intel(R) Processors with Intel(R) Processor Graphics may allow an unauthenticated user to potentially enable information disclosure via local access.
</code>

- [HE-Wenjian/iGPU-Leak](https://github.com/HE-Wenjian/iGPU-Leak)

### CVE-2019-14745

<code>
In radare2 before 3.7.0, a command injection vulnerability exists in bin_symbols() in libr/core/cbin.c. By using a crafted executable file, it's possible to execute arbitrary shell commands with the permissions of the victim. This vulnerability is due to improper handling of symbol names embedded in executables.
</code>

- [xooxo/CVE-2019-14745](https://github.com/xooxo/CVE-2019-14745)

### CVE-2019-14751

<code>
NLTK Downloader before 3.4.5 is vulnerable to a directory traversal, allowing attackers to write arbitrary files via a ../ (dot dot slash) in an NLTK package (ZIP archive) that is mishandled during extraction.
</code>

- [mssalvatore/CVE-2019-14751_PoC](https://github.com/mssalvatore/CVE-2019-14751_PoC)

### CVE-2019-1476

<code>
An elevation of privilege vulnerability exists when Windows AppX Deployment Service (AppXSVC) improperly handles hard links, aka 'Windows Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-1483.
</code>

- [sgabe/CVE-2019-1476](https://github.com/sgabe/CVE-2019-1476)

### CVE-2019-14830
- [Fr3d-/moodle-token-stealer](https://github.com/Fr3d-/moodle-token-stealer)

### CVE-2019-14912

<code>
An issue was discovered in PRiSE adAS 1.7.0. The OPENSSO module does not properly check the goto parameter, leading to an open redirect that leaks the session cookie.
</code>

- [Wocanilo/adaPwn](https://github.com/Wocanilo/adaPwn)

### CVE-2019-15029

<code>
FusionPBX 4.4.8 allows an attacker to execute arbitrary system commands by submitting a malicious command to the service_edit.php file (which will insert the malicious command into the database). To trigger the command, one needs to call the services.php file via a GET request with the service id followed by the parameter a=start to execute the stored command.
</code>

- [mhaskar/CVE-2019-15029](https://github.com/mhaskar/CVE-2019-15029)

### CVE-2019-15053

<code>
The &quot;HTML Include and replace macro&quot; plugin before 1.5.0 for Confluence Server allows a bypass of the includeScripts=false XSS protection mechanism via vectors involving an IFRAME element.
</code>

- [l0nax/CVE-2019-15053](https://github.com/l0nax/CVE-2019-15053)

### CVE-2019-15107

<code>
An issue was discovered in Webmin &lt;=1.920. The parameter old in password_change.cgi contains a command injection vulnerability.
</code>

- [jas502n/CVE-2019-15107](https://github.com/jas502n/CVE-2019-15107)
- [HACHp1/webmin_docker_and_exp](https://github.com/HACHp1/webmin_docker_and_exp)
- [ketlerd/CVE-2019-15107](https://github.com/ketlerd/CVE-2019-15107)
- [AdministratorGithub/CVE-2019-15107](https://github.com/AdministratorGithub/CVE-2019-15107)
- [Pichuuuuu/CVE-2019-15107](https://github.com/Pichuuuuu/CVE-2019-15107)
- [Rayferrufino/Make-and-Break](https://github.com/Rayferrufino/Make-and-Break)
- [AleWong/WebminRCE-EXP-CVE-2019-15107-](https://github.com/AleWong/WebminRCE-EXP-CVE-2019-15107-)
- [ianxtianxt/CVE-2019-15107](https://github.com/ianxtianxt/CVE-2019-15107)
- [hannob/webminex](https://github.com/hannob/webminex)
- [ChakoMoonFish/webmin_CVE-2019-15107](https://github.com/ChakoMoonFish/webmin_CVE-2019-15107)

### CVE-2019-15120

<code>
The Kunena extension before 5.1.14 for Joomla! allows XSS via BBCode.
</code>

- [h3llraiser/CVE-2019-15120](https://github.com/h3llraiser/CVE-2019-15120)

### CVE-2019-15126

<code>
An issue was discovered on Broadcom Wi-Fi client devices. Specifically timed and handcrafted traffic can cause internal errors (related to state transitions) in a WLAN device that lead to improper layer 2 Wi-Fi encryption with a consequent possibility of information disclosure over the air for a discrete set of traffic, a different vulnerability than CVE-2019-9500, CVE-2019-9501, CVE-2019-9502, and CVE-2019-9503.
</code>

- [0x13enny/kr00k](https://github.com/0x13enny/kr00k)
- [hexway/r00kie-kr00kie](https://github.com/hexway/r00kie-kr00kie)
- [akabe1/kr00ker](https://github.com/akabe1/kr00ker)
- [mustafasevim/kr00k-vulnerability](https://github.com/mustafasevim/kr00k-vulnerability)

### CVE-2019-15224

<code>
The rest-client gem 1.6.10 through 1.6.13 for Ruby, as distributed on RubyGems.org, included a code-execution backdoor inserted by a third party. Versions &lt;=1.6.9 and &gt;=1.6.14 are unaffected.
</code>

- [chef-cft/inspec_cve_2019_15224](https://github.com/chef-cft/inspec_cve_2019_15224)

### CVE-2019-15233

<code>
The Live:Text Box macro in the Old Street Live Input Macros app before 2.11 for Confluence has XSS, leading to theft of the Administrator Session Cookie.
</code>

- [l0nax/CVE-2019-15233](https://github.com/l0nax/CVE-2019-15233)

### CVE-2019-15511

<code>
An exploitable local privilege escalation vulnerability exists in the GalaxyClientService installed by GOG Galaxy. Due to Improper Access Control, an attacker can send unauthenticated local TCP packets to the service to gain SYSTEM privileges in Windows system where GOG Galaxy software is installed. All GOG Galaxy versions before 1.2.60 and all corresponding versions of GOG Galaxy 2.0 Beta are affected.
</code>

- [adenkiewicz/CVE-2019-15511](https://github.com/adenkiewicz/CVE-2019-15511)

### CVE-2019-15605

<code>
HTTP request smuggling in Node.js 10, 12, and 13 causes malicious payload delivery when transfer-encoding is malformed
</code>

- [jlcarruda/node-poc-http-smuggling](https://github.com/jlcarruda/node-poc-http-smuggling)

### CVE-2019-15642

<code>
rpc.cgi in Webmin through 1.920 allows authenticated Remote Code Execution via a crafted object name because unserialise_variable makes an eval call. NOTE: the Webmin_Servers_Index documentation states &quot;RPC can be used to run any command or modify any file on a server, which is why access to it must not be granted to un-trusted Webmin users.&quot;
</code>

- [jas502n/CVE-2019-15642](https://github.com/jas502n/CVE-2019-15642)

### CVE-2019-1579

<code>
Remote Code Execution in PAN-OS 7.1.18 and earlier, PAN-OS 8.0.11-h1 and earlier, and PAN-OS 8.1.2 and earlier with GlobalProtect Portal or GlobalProtect Gateway Interface enabled may allow an unauthenticated remote attacker to execute arbitrary code.
</code>

- [securifera/CVE-2019-1579](https://github.com/securifera/CVE-2019-1579)

### CVE-2019-15802

<code>
An issue was discovered on Zyxel GS1900 devices with firmware before 2.50(AAHH.0)C0. The firmware hashes and encrypts passwords using a hardcoded cryptographic key in sal_util_str_encrypt() in libsal.so.0.0. The parameters (salt, IV, and key data) are used to encrypt and decrypt all passwords using AES256 in CBC mode. With the parameters known, all previously encrypted passwords can be decrypted. This includes the passwords that are part of configuration backups or otherwise embedded as part of the firmware.
</code>

- [jasperla/CVE-2019-15802](https://github.com/jasperla/CVE-2019-15802)

### CVE-2019-15846

<code>
Exim before 4.92.2 allows remote attackers to execute arbitrary code as root via a trailing backslash.
</code>

- [synacktiv/Exim-CVE-2019-15846](https://github.com/synacktiv/Exim-CVE-2019-15846)

### CVE-2019-15858

<code>
admin/includes/class.import.snippet.php in the &quot;Woody ad snippets&quot; plugin before 2.2.5 for WordPress allows unauthenticated options import, as demonstrated by storing an XSS payload for remote code execution.
</code>

- [GeneralEG/CVE-2019-15858](https://github.com/GeneralEG/CVE-2019-15858)

### CVE-2019-15972

<code>
A vulnerability in the web-based management interface of Cisco Unified Communications Manager could allow an authenticated, remote attacker to conduct SQL injection attacks on an affected system. The vulnerability exists because the web-based management interface improperly validates SQL values. An attacker could exploit this vulnerability by authenticating to the application and sending malicious requests to an affected system. A successful exploit could allow the attacker to modify values on or return values from the underlying database.
</code>

- [FSecureLABS/Cisco-UCM-SQLi-Scripts](https://github.com/FSecureLABS/Cisco-UCM-SQLi-Scripts)

### CVE-2019-16097

<code>
core/api/user.go in Harbor 1.7.0 through 1.8.2 allows non-admin users to create admin accounts via the POST /api/users API, when Harbor is setup with DB as authentication backend and allow user to do self-registration. Fixed version: v1.7.6 v1.8.3. v.1.9.0. Workaround without applying the fix: configure Harbor to use non-DB authentication backend such as LDAP.
</code>

- [evilAdan0s/CVE-2019-16097](https://github.com/evilAdan0s/CVE-2019-16097)
- [rockmelodies/CVE-2019-16097-batch](https://github.com/rockmelodies/CVE-2019-16097-batch)
- [ianxtianxt/CVE-2019-16097](https://github.com/ianxtianxt/CVE-2019-16097)
- [dacade/cve-2019-16097](https://github.com/dacade/cve-2019-16097)
- [theLSA/harbor-give-me-admin](https://github.com/theLSA/harbor-give-me-admin)
- [luckybool1020/CVE-2019-16097](https://github.com/luckybool1020/CVE-2019-16097)

### CVE-2019-16098

<code>
The driver in Micro-Star MSI Afterburner 4.6.2.15658 (aka RTCore64.sys and RTCore32.sys) allows any authenticated user to read and write to arbitrary memory, I/O ports, and MSRs. This can be exploited for privilege escalation, code execution under high privileges, and information disclosure. These signed drivers can also be used to bypass the Microsoft driver-signing policy to deploy malicious code.
</code>

- [Barakat/CVE-2019-16098](https://github.com/Barakat/CVE-2019-16098)

### CVE-2019-16278

<code>
Directory Traversal in the function http_verify in nostromo nhttpd through 1.9.6 allows an attacker to achieve remote code execution via a crafted HTTP request.
</code>

- [jas502n/CVE-2019-16278](https://github.com/jas502n/CVE-2019-16278)
- [imjdl/CVE-2019-16278-PoC](https://github.com/imjdl/CVE-2019-16278-PoC)
- [ianxtianxt/CVE-2019-16278](https://github.com/ianxtianxt/CVE-2019-16278)
- [darkerego/Nostromo_Python3](https://github.com/darkerego/Nostromo_Python3)
- [AnubisSec/CVE-2019-16278](https://github.com/AnubisSec/CVE-2019-16278)
- [theRealFr13nd/CVE-2019-16278-Nostromo_1.9.6-RCE](https://github.com/theRealFr13nd/CVE-2019-16278-Nostromo_1.9.6-RCE)
- [Kr0ff/cve-2019-16278](https://github.com/Kr0ff/cve-2019-16278)
- [NHPT/CVE-2019-16278](https://github.com/NHPT/CVE-2019-16278)
- [Unam3dd/nostromo_1_9_6_rce](https://github.com/Unam3dd/nostromo_1_9_6_rce)
- [keshiba/cve-2019-16278](https://github.com/keshiba/cve-2019-16278)

### CVE-2019-16279

<code>
A memory error in the function SSL_accept in nostromo nhttpd through 1.9.6 allows an attacker to trigger a denial of service via a crafted HTTP request.
</code>

- [ianxtianxt/CVE-2019-16279](https://github.com/ianxtianxt/CVE-2019-16279)

### CVE-2019-16394

<code>
SPIP before 3.1.11 and 3.2 before 3.2.5 provides different error messages from the password-reminder page depending on whether an e-mail address exists, which might help attackers to enumerate subscribers.
</code>

- [SilentVoid13/Silent_CVE_2019_16394](https://github.com/SilentVoid13/Silent_CVE_2019_16394)

### CVE-2019-16405

<code>
Centreon Web before 2.8.30, 18.10.x before 18.10.8, 19.04.x before 19.04.5 and 19.10.x before 19.10.2 allows Remote Code Execution by an administrator who can modify Macro Expression location settings. CVE-2019-16405 and CVE-2019-17501 are similar to one another and may be the same.
</code>

- [TheCyberGeek/CVE-2019-16405.rb](https://github.com/TheCyberGeek/CVE-2019-16405.rb)

### CVE-2019-1652

<code>
A vulnerability in the web-based management interface of Cisco Small Business RV320 and RV325 Dual Gigabit WAN VPN Routers could allow an authenticated, remote attacker with administrative privileges on an affected device to execute arbitrary commands. The vulnerability is due to improper validation of user-supplied input. An attacker could exploit this vulnerability by sending malicious HTTP POST requests to the web-based management interface of an affected device. A successful exploit could allow the attacker to execute arbitrary commands on the underlying Linux shell as root. Cisco has released firmware updates that address this vulnerability.
</code>

- [0x27/CiscoRV320Dump](https://github.com/0x27/CiscoRV320Dump)

### CVE-2019-1653

<code>
A vulnerability in the web-based management interface of Cisco Small Business RV320 and RV325 Dual Gigabit WAN VPN Routers could allow an unauthenticated, remote attacker to retrieve sensitive information. The vulnerability is due to improper access controls for URLs. An attacker could exploit this vulnerability by connecting to an affected device via HTTP or HTTPS and requesting specific URLs. A successful exploit could allow the attacker to download the router configuration or detailed diagnostic information. Cisco has released firmware updates that address this vulnerability.
</code>

- [dubfr33/CVE-2019-1653](https://github.com/dubfr33/CVE-2019-1653)
- [shaheemirza/CiscoSpill](https://github.com/shaheemirza/CiscoSpill)

### CVE-2019-16662

<code>
An issue was discovered in rConfig 3.9.2. An attacker can directly execute system commands by sending a GET request to ajaxServerSettingsChk.php because the rootUname parameter is passed to the exec function without filtering, which can lead to command execution.
</code>

- [mhaskar/CVE-2019-16662](https://github.com/mhaskar/CVE-2019-16662)

### CVE-2019-16663

<code>
An issue was discovered in rConfig 3.9.2. An attacker can directly execute system commands by sending a GET request to search.crud.php because the catCommand parameter is passed to the exec function without filtering, which can lead to command execution.
</code>

- [mhaskar/CVE-2019-16663](https://github.com/mhaskar/CVE-2019-16663)

### CVE-2019-16692

<code>
phpIPAM 1.4 allows SQL injection via the app/admin/custom-fields/filter-result.php table parameter when action=add is used.
</code>

- [kkirsche/CVE-2019-16692](https://github.com/kkirsche/CVE-2019-16692)

### CVE-2019-16724

<code>
File Sharing Wizard 1.5.0 allows a remote attacker to obtain arbitrary code execution by exploiting a Structured Exception Handler (SEH) based buffer overflow in an HTTP POST parameter, a similar issue to CVE-2010-2330 and CVE-2010-2331.
</code>

- [FULLSHADE/OSCE](https://github.com/FULLSHADE/OSCE)

### CVE-2019-16759

<code>
vBulletin 5.x through 5.5.4 allows remote command execution via the widgetConfig[code] parameter in an ajax/render/widget_php routestring request.
</code>

- [M0sterHxck/CVE-2019-16759-Vbulletin-rce-exploit](https://github.com/M0sterHxck/CVE-2019-16759-Vbulletin-rce-exploit)
- [r00tpgp/http-vuln-CVE-2019-16759](https://github.com/r00tpgp/http-vuln-CVE-2019-16759)
- [jas502n/CVE-2019-16759](https://github.com/jas502n/CVE-2019-16759)
- [FarjaalAhmad/CVE-2019-16759](https://github.com/FarjaalAhmad/CVE-2019-16759)
- [andripwn/pwn-vbulletin](https://github.com/andripwn/pwn-vbulletin)
- [psychoxploit/vbull](https://github.com/psychoxploit/vbull)

### CVE-2019-16784

<code>
In PyInstaller before version 3.6, only on Windows, a local privilege escalation vulnerability is present in this particular case: If a software using PyInstaller in &quot;onefile&quot; mode is launched by a privileged user (at least more than the current one) which have his &quot;TempPath&quot; resolving to a world writable directory. This is the case for example if the software is launched as a service or as a scheduled task using a system account (TempPath will be C:\Windows\Temp). In order to be exploitable the software has to be (re)started after the attacker launch the exploit program, so for a service launched at startup, a service restart is needed (e.g. after a crash or an upgrade).
</code>

- [AlterSolutions/PyInstallerPrivEsc](https://github.com/AlterSolutions/PyInstallerPrivEsc)

### CVE-2019-16889

<code>
Ubiquiti EdgeMAX devices before 2.0.3 allow remote attackers to cause a denial of service (disk consumption) because *.cache files in /var/run/beaker/container_file/ are created when providing a valid length payload of 249 characters or fewer to the beaker.session.id cookie in a GET header. The attacker can use a long series of unique session IDs.
</code>

- [grampae/meep](https://github.com/grampae/meep)

### CVE-2019-16920

<code>
Unauthenticated remote code execution occurs in D-Link products such as DIR-655C, DIR-866L, DIR-652, and DHP-1565. The issue occurs when the attacker sends an arbitrary input to a &quot;PingTest&quot; device common gateway interface that could lead to common injection. An attacker who successfully triggers the command injection could achieve full system compromise. Later, it was independently found that these are also affected: DIR-855L, DAP-1533, DIR-862L, DIR-615, DIR-835, and DIR-825.
</code>

- [pwnhacker0x18/CVE-2019-16920-MassPwn3r](https://github.com/pwnhacker0x18/CVE-2019-16920-MassPwn3r)

### CVE-2019-16941

<code>
NSA Ghidra through 9.0.4, when experimental mode is enabled, allows arbitrary code execution if the Read XML Files feature of Bit Patterns Explorer is used with a modified XML document. This occurs in Features/BytePatterns/src/main/java/ghidra/bitpatterns/info/FileBitPatternInfoReader.java. An attack could start with an XML document that was originally created by DumpFunctionPatternInfoScript but then directly modified by an attacker (for example, to make a java.lang.Runtime.exec call).
</code>

- [purpleracc00n/CVE-2019-16941](https://github.com/purpleracc00n/CVE-2019-16941)

### CVE-2019-17080

<code>
mintinstall (aka Software Manager) 7.9.9 for Linux Mint allows code execution if a REVIEWS_CACHE file is controlled by an attacker, because an unpickle occurs. This is resolved in 8.0.0 and backports.
</code>

- [Andhrimnirr/Mintinstall-object-injection](https://github.com/Andhrimnirr/Mintinstall-object-injection)

### CVE-2019-17124

<code>
Kramer VIAware 2.5.0719.1034 has Incorrect Access Control.
</code>

- [hessandrew/CVE-2019-17124](https://github.com/hessandrew/CVE-2019-17124)

### CVE-2019-17221

<code>
PhantomJS through 2.1.1 has an arbitrary file read vulnerability, as demonstrated by an XMLHttpRequest for a file:// URI. The vulnerability exists in the page.open() function of the webpage module, which loads a specified URL and calls a given callback. An attacker can supply a specially crafted HTML file, as user input, that allows reading arbitrary files on the filesystem. For example, if page.render() is the function callback, this generates a PDF or an image of the targeted file. NOTE: this product is no longer developed.
</code>

- [h4ckologic/CVE-2019-17221](https://github.com/h4ckologic/CVE-2019-17221)

### CVE-2019-17234

<code>
includes/class-coming-soon-creator.php in the igniteup plugin through 3.4 for WordPress allows unauthenticated arbitrary file deletion.
</code>

- [administra1tor/CVE-2019-17234-Wordpress-DirStroyer](https://github.com/administra1tor/CVE-2019-17234-Wordpress-DirStroyer)

### CVE-2019-17424

<code>
A stack-based buffer overflow in the processPrivilage() function in IOS/process-general.c in nipper-ng 0.11.10 allows remote attackers (serving firewall configuration files) to achieve Remote Code Execution or Denial Of Service via a crafted file.
</code>

- [guywhataguy/CVE-2019-17424](https://github.com/guywhataguy/CVE-2019-17424)

### CVE-2019-17427

<code>
In Redmine before 3.4.11 and 4.0.x before 4.0.4, persistent XSS exists due to textile formatting errors.
</code>

- [RealLinkers/CVE-2019-17427](https://github.com/RealLinkers/CVE-2019-17427)

### CVE-2019-17495

<code>
A Cascading Style Sheets (CSS) injection vulnerability in Swagger UI before 3.23.11 allows attackers to use the Relative Path Overwrite (RPO) technique to perform CSS-based input field value exfiltration, such as exfiltration of a CSRF token value. In other words, this product intentionally allows the embedding of untrusted JSON data from remote servers, but it was not previously known that &lt;style&gt;@import within the JSON data was a functional attack method.
</code>

- [SecT0uch/CVE-2019-17495-test](https://github.com/SecT0uch/CVE-2019-17495-test)

### CVE-2019-17525

<code>
The login page on D-Link DIR-615 T1 20.10 devices allows remote attackers to bypass the CAPTCHA protection mechanism and conduct brute-force attacks.
</code>

- [huzaifahussain98/CVE-2019-17525](https://github.com/huzaifahussain98/CVE-2019-17525)

### CVE-2019-17558

<code>
Apache Solr 5.0.0 to Apache Solr 8.3.1 are vulnerable to a Remote Code Execution through the VelocityResponseWriter. A Velocity template can be provided through Velocity templates in a configset `velocity/` directory or as a parameter. A user defined configset could contain renderable, potentially malicious, templates. Parameter provided templates are disabled by default, but can be enabled by setting `params.resource.loader.enabled` by defining a response writer with that setting set to `true`. Defining a response writer requires configuration API access. Solr 8.4 removed the params resource loader entirely, and only enables the configset-provided template rendering when the configset is `trusted` (has been uploaded by an authenticated user).
</code>

- [SDNDTeam/CVE-2019-17558_Solr_Vul_Tool](https://github.com/SDNDTeam/CVE-2019-17558_Solr_Vul_Tool)
- [zhzyker/exphub](https://github.com/zhzyker/exphub)

### CVE-2019-17564

<code>
Unsafe deserialization occurs within a Dubbo application which has HTTP remoting enabled. An attacker may submit a POST request with a Java object in it to completely compromise a Provider instance of Apache Dubbo, if this instance enables HTTP. This issue affected Apache Dubbo 2.7.0 to 2.7.4, 2.6.0 to 2.6.7, and all 2.5.x versions.
</code>

- [r00t4dm/CVE-2019-17564](https://github.com/r00t4dm/CVE-2019-17564)
- [Jaky5155/CVE-2019-17564](https://github.com/Jaky5155/CVE-2019-17564)
- [Hu3sky/CVE-2019-17564](https://github.com/Hu3sky/CVE-2019-17564)
- [Exploit-3389/CVE-2019-17564](https://github.com/Exploit-3389/CVE-2019-17564)
- [Dor-Tumarkin/CVE-2019-17564-FastJson-Gadget](https://github.com/Dor-Tumarkin/CVE-2019-17564-FastJson-Gadget)
- [fairyming/CVE-2019-17564](https://github.com/fairyming/CVE-2019-17564)

### CVE-2019-17570

<code>
An untrusted deserialization was found in the org.apache.xmlrpc.parser.XmlRpcResponseParser:addResult method of Apache XML-RPC (aka ws-xmlrpc) library. A malicious XML-RPC server could target a XML-RPC client causing it to execute arbitrary code. Apache XML-RPC is no longer maintained and this issue will not be fixed.
</code>

- [r00t4dm/CVE-2019-17570](https://github.com/r00t4dm/CVE-2019-17570)
- [orangecertcc/xmlrpc-common-deserialization](https://github.com/orangecertcc/xmlrpc-common-deserialization)

### CVE-2019-17571

<code>
Included in Log4j 1.2 is a SocketServer class that is vulnerable to deserialization of untrusted data which can be exploited to remotely execute arbitrary code when combined with a deserialization gadget when listening to untrusted network traffic for log data. This affects Log4j versions up to 1.2 up to 1.2.17.
</code>

- [shadow-horse/CVE-2019-17571](https://github.com/shadow-horse/CVE-2019-17571)

### CVE-2019-17596

<code>
Go before 1.12.11 and 1.3.x before 1.13.2 can panic upon an attempt to process network traffic containing an invalid DSA public key. There are several attack scenarios, such as traffic from a client to a server that verifies client certificates.
</code>

- [pquerna/poc-dsa-verify-CVE-2019-17596](https://github.com/pquerna/poc-dsa-verify-CVE-2019-17596)

### CVE-2019-17625

<code>
There is a stored XSS in Rambox 0.6.9 that can lead to code execution. The XSS is in the name field while adding/editing a service. The problem occurs due to incorrect sanitization of the name field when being processed and stored. This allows a user to craft a payload for Node.js and Electron, such as an exec of OS commands within the onerror attribute of an IMG element.
</code>

- [Ekultek/CVE-2019-17625](https://github.com/Ekultek/CVE-2019-17625)

### CVE-2019-17633

<code>
For Eclipse Che versions 6.16 to 7.3.0, with both authentication and TLS disabled, visiting a malicious web site could trigger the start of an arbitrary Che workspace. Che with no authentication and no TLS is not usually deployed on a public network but is often used for local installations (e.g. on personal laptops). In that case, even if the Che API is not exposed externally, some javascript running in the local browser is able to send requests to it.
</code>

- [mgrube/CVE-2019-17633](https://github.com/mgrube/CVE-2019-17633)

### CVE-2019-17658

<code>
An unquoted service path vulnerability in the FortiClient FortiTray component of FortiClientWindows v6.2.2 and prior allow an attacker to gain elevated privileges via the FortiClientConsole executable service path.
</code>

- [Ibonok/CVE-2019-17658](https://github.com/Ibonok/CVE-2019-17658)

### CVE-2019-17671

<code>
In WordPress before 5.2.4, unauthenticated viewing of certain content is possible because the static query property is mishandled.
</code>

- [rhbb/CVE-2019-17671](https://github.com/rhbb/CVE-2019-17671)

### CVE-2019-1821

<code>
A vulnerability in the web-based management interface of Cisco Prime Infrastructure (PI) and Cisco Evolved Programmable Network (EPN) Manager could allow an authenticated, remote attacker to execute code with root-level privileges on the underlying operating system. This vulnerability exist because the software improperly validates user-supplied input. An attacker could exploit this vulnerability by uploading a malicious file to the administrative web interface. A successful exploit could allow the attacker to execute code with root-level privileges on the underlying operating system.
</code>

- [k8gege/CiscoExploit](https://github.com/k8gege/CiscoExploit)

### CVE-2019-18371

<code>
An issue was discovered on Xiaomi Mi WiFi R3G devices before 2.28.23-stable. There is a directory traversal vulnerability to read arbitrary files via a misconfigured NGINX alias, as demonstrated by api-third-party/download/extdisks../etc/config/account. With this vulnerability, the attacker can bypass authentication.
</code>

- [UltramanGaia/Xiaomi_Mi_WiFi_R3G_Vulnerability_POC](https://github.com/UltramanGaia/Xiaomi_Mi_WiFi_R3G_Vulnerability_POC)

### CVE-2019-18418

<code>
clonos.php in ClonOS WEB control panel 19.09 allows remote attackers to gain full access via change password requests because there is no session management.
</code>

- [Andhrimnirr/ClonOS-WEB-control-panel-multi-vulnerability](https://github.com/Andhrimnirr/ClonOS-WEB-control-panel-multi-vulnerability)

### CVE-2019-18426

<code>
A vulnerability in WhatsApp Desktop versions prior to 0.3.9309 when paired with WhatsApp for iPhone versions prior to 2.20.10 allows cross-site scripting and local file reading. Exploiting the vulnerability requires the victim to click a link preview from a specially crafted text message.
</code>

- [PerimeterX/CVE-2019-18426](https://github.com/PerimeterX/CVE-2019-18426)

### CVE-2019-18634

<code>
In Sudo before 1.8.26, if pwfeedback is enabled in /etc/sudoers, users can trigger a stack-based buffer overflow in the privileged sudo process. (pwfeedback is a default setting in Linux Mint and elementary OS; however, it is NOT the default for upstream and many other packages, and would exist only if enabled by an administrator.) The attacker needs to deliver a long string to the stdin of getln() in tgetpass.c.
</code>

- [Plazmaz/CVE-2019-18634](https://github.com/Plazmaz/CVE-2019-18634)
- [saleemrashid/sudo-cve-2019-18634](https://github.com/saleemrashid/sudo-cve-2019-18634)
- [N1et/CVE-2019-18634](https://github.com/N1et/CVE-2019-18634)
- [jeandelboux/CVE-2019-18634](https://github.com/jeandelboux/CVE-2019-18634)
- [halitAKAYDIN/sudo-cve-2019-18634](https://github.com/halitAKAYDIN/sudo-cve-2019-18634)

### CVE-2019-18683

<code>
An issue was discovered in drivers/media/platform/vivid in the Linux kernel through 5.3.8. It is exploitable for privilege escalation on some Linux distributions where local users have /dev/video0 access, but only if the driver happens to be loaded. There are multiple race conditions during streaming stopping in this driver (part of the V4L2 subsystem). These issues are caused by wrong mutex locking in vivid_stop_generating_vid_cap(), vivid_stop_generating_vid_out(), sdr_cap_stop_streaming(), and the corresponding kthreads. At least one of these race conditions leads to a use-after-free.
</code>

- [sanjana123-cloud/CVE-2019-18683](https://github.com/sanjana123-cloud/CVE-2019-18683)

### CVE-2019-18873

<code>
FUDForum 3.0.9 is vulnerable to Stored XSS via the User-Agent HTTP header. This may result in remote code execution. An attacker can use a user account to fully compromise the system via a GET request. When the admin visits user information under &quot;User Manager&quot; in the control panel, the payload will execute. This will allow for PHP files to be written to the web root, and for code to execute on the remote server. The problem is in admsession.php and admuser.php.
</code>

- [fuzzlove/FUDforum-XSS-RCE](https://github.com/fuzzlove/FUDforum-XSS-RCE)

### CVE-2019-18885

<code>
fs/btrfs/volumes.c in the Linux kernel before 5.1 allows a btrfs_verify_dev_extents NULL pointer dereference via a crafted btrfs image because fs_devices-&gt;devices is mishandled within find_device, aka CID-09ba3bc9dd15.
</code>

- [bobfuzzer/CVE-2019-18885](https://github.com/bobfuzzer/CVE-2019-18885)

### CVE-2019-18890

<code>
A SQL injection vulnerability in Redmine through 3.2.9 and 3.3.x before 3.3.10 allows Redmine users to access protected information via a crafted object query.
</code>

- [RealLinkers/CVE-2019-18890](https://github.com/RealLinkers/CVE-2019-18890)

### CVE-2019-18935

<code>
Progress Telerik UI for ASP.NET AJAX through 2019.3.1023 contains a .NET deserialization vulnerability in the RadAsyncUpload function. This is exploitable when the encryption keys are known due to the presence of CVE-2017-11317 or CVE-2017-11357, or other means. Exploitation can result in remote code execution. (As of 2020.1.114, a default setting prevents the exploit. In 2019.3.1023, but not earlier versions, a non-default setting can prevent exploitation.)
</code>

- [bao7uo/RAU_crypto](https://github.com/bao7uo/RAU_crypto)
- [noperator/CVE-2019-18935](https://github.com/noperator/CVE-2019-18935)

### CVE-2019-19012

<code>
An integer overflow in the search_in_range function in regexec.c in Oniguruma 6.x before 6.9.4_rc2 leads to an out-of-bounds read, in which the offset of this read is under the control of an attacker. (This only affects the 32-bit compiled version). Remote attackers can cause a denial-of-service or information disclosure, or possibly have unspecified other impact, via a crafted regular expression.
</code>

- [ManhNDd/CVE-2019-19012](https://github.com/ManhNDd/CVE-2019-19012)
- [tarantula-team/CVE-2019-19012](https://github.com/tarantula-team/CVE-2019-19012)

### CVE-2019-19033

<code>
Jalios JCMS 10 allows attackers to access any part of the website and the WebDAV server with administrative privileges via a backdoor account, by using any username and the hardcoded dev password.
</code>

- [ricardojoserf/CVE-2019-19033](https://github.com/ricardojoserf/CVE-2019-19033)

### CVE-2019-19203

<code>
An issue was discovered in Oniguruma 6.x before 6.9.4_rc2. In the function gb18030_mbc_enc_len in file gb18030.c, a UChar pointer is dereferenced without checking if it passed the end of the matched string. This leads to a heap-based buffer over-read.
</code>

- [ManhNDd/CVE-2019-19203](https://github.com/ManhNDd/CVE-2019-19203)
- [tarantula-team/CVE-2019-19203](https://github.com/tarantula-team/CVE-2019-19203)

### CVE-2019-19204

<code>
An issue was discovered in Oniguruma 6.x before 6.9.4_rc2. In the function fetch_interval_quantifier (formerly known as fetch_range_quantifier) in regparse.c, PFETCH is called without checking PEND. This leads to a heap-based buffer over-read.
</code>

- [ManhNDd/CVE-2019-19204](https://github.com/ManhNDd/CVE-2019-19204)
- [tarantula-team/CVE-2019-19204](https://github.com/tarantula-team/CVE-2019-19204)

### CVE-2019-19231

<code>
An insecure file access vulnerability exists in CA Client Automation 14.0, 14.1, 14.2, and 14.3 Agent for Windows that can allow a local attacker to gain escalated privileges.
</code>

- [hessandrew/CVE-2019-19231](https://github.com/hessandrew/CVE-2019-19231)

### CVE-2019-19268
- [TheCyberGeek/CVE-2019-19268](https://github.com/TheCyberGeek/CVE-2019-19268)

### CVE-2019-19315

<code>
NLSSRV32.EXE in Nalpeiron Licensing Service 7.3.4.0, as used with Nitro PDF and other products, allows Elevation of Privilege via the \\.\mailslot\nlsX86ccMailslot mailslot.
</code>

- [monoxgas/mailorder](https://github.com/monoxgas/mailorder)

### CVE-2019-19356

<code>
Netis WF2419 is vulnerable to authenticated Remote Code Execution (RCE) as root through the router Web management page. The vulnerability has been found in firmware version V1.2.31805 and V2.2.36123. After one is connected to this page, it is possible to execute system commands as root through the tracert diagnostic tool because of lack of user input sanitizing.
</code>

- [shadowgatt/CVE-2019-19356](https://github.com/shadowgatt/CVE-2019-19356)
- [qq1515406085/CVE-2019-19356](https://github.com/qq1515406085/CVE-2019-19356)

### CVE-2019-19369
- [TheCyberGeek/CVE-2019-19369](https://github.com/TheCyberGeek/CVE-2019-19369)

### CVE-2019-19383

<code>
freeFTPd 1.0.8 has a Post-Authentication Buffer Overflow via a crafted SIZE command (this is exploitable even if logging is disabled).
</code>

- [m0rph-1/CVE-2019-19383](https://github.com/m0rph-1/CVE-2019-19383)

### CVE-2019-19511
- [jra89/CVE-2019-19511](https://github.com/jra89/CVE-2019-19511)

### CVE-2019-19550

<code>
Remote Authentication Bypass in Senior Rubiweb 6.2.34.28 and 6.2.34.37 allows admin access to sensitive information of affected users using vulnerable versions. The attacker only needs to provide the correct URL.
</code>

- [underprotection/CVE-2019-19550](https://github.com/underprotection/CVE-2019-19550)

### CVE-2019-19576

<code>
class.upload.php in verot.net class.upload before 1.0.3 and 2.x before 2.0.4, as used in the K2 extension for Joomla! and other products, omits .phar from the set of dangerous file extensions.
</code>

- [jra89/CVE-2019-19576](https://github.com/jra89/CVE-2019-19576)

### CVE-2019-19633
- [jra89/CVE-2019-19633](https://github.com/jra89/CVE-2019-19633)

### CVE-2019-19634

<code>
class.upload.php in verot.net class.upload through 1.0.3 and 2.x through 2.0.4, as used in the K2 extension for Joomla! and other products, omits .pht from the set of dangerous file extensions, a similar issue to CVE-2019-19576.
</code>

- [jra89/CVE-2019-19634](https://github.com/jra89/CVE-2019-19634)

### CVE-2019-19651
- [jra89/CVE-2019-19651](https://github.com/jra89/CVE-2019-19651)

### CVE-2019-19652
- [jra89/CVE-2019-19652](https://github.com/jra89/CVE-2019-19652)

### CVE-2019-19653
- [jra89/CVE-2019-19653](https://github.com/jra89/CVE-2019-19653)

### CVE-2019-19654
- [jra89/CVE-2019-19654](https://github.com/jra89/CVE-2019-19654)

### CVE-2019-19658
- [jra89/CVE-2019-19658](https://github.com/jra89/CVE-2019-19658)

### CVE-2019-19699

<code>
There is Authenticated remote code execution in Centreon Infrastructure Monitoring Software through 19.10 via Pollers misconfiguration, leading to system compromise via apache crontab misconfiguration, This allows the apache user to modify an executable file executed by root at 22:30 every day. To exploit the vulnerability, someone must have Admin access to the Centreon Web Interface and create a custom main.php?p=60803&amp;type=3 command. The user must then set the Pollers Post-Restart Command to this previously created command via the main.php?p=60901&amp;o=c&amp;server_id=1 URI. This is triggered via an export of the Poller Configuration.
</code>

- [SpengeSec/CVE-2019-19699](https://github.com/SpengeSec/CVE-2019-19699)

### CVE-2019-19732

<code>
translation_manage_text.ajax.php and various *_manage.ajax.php in MFScripts YetiShare 3.5.2 through 4.5.3 directly insert values from the aSortDir_0 and/or sSortDir_0 parameter into a SQL string. This allows an attacker to inject their own SQL and manipulate the query, typically extracting data from the database, aka SQL Injection.
</code>

- [jra89/CVE-2019-19732](https://github.com/jra89/CVE-2019-19732)

### CVE-2019-19733

<code>
_get_all_file_server_paths.ajax.php (aka get_all_file_server_paths.ajax.php) in MFScripts YetiShare 3.5.2 through 4.5.3 does not sanitize or encode the output from the fileIds parameter on the page, which would allow an attacker to input HTML or execute scripts on the site, aka XSS.
</code>

- [jra89/CVE-2019-19733](https://github.com/jra89/CVE-2019-19733)

### CVE-2019-19734

<code>
_account_move_file_in_folder.ajax.php in MFScripts YetiShare 3.5.2 directly inserts values from the fileIds parameter into a SQL string. This allows an attacker to inject their own SQL and manipulate the query, typically extracting data from the database, aka SQL Injection.
</code>

- [jra89/CVE-2019-19734](https://github.com/jra89/CVE-2019-19734)

### CVE-2019-19735

<code>
class.userpeer.php in MFScripts YetiShare 3.5.2 through 4.5.3 uses an insecure method of creating password reset hashes (based only on microtime), which allows an attacker to guess the hash and set the password within a few hours by bruteforcing.
</code>

- [jra89/CVE-2019-19735](https://github.com/jra89/CVE-2019-19735)

### CVE-2019-19738

<code>
log_file_viewer.php in MFScripts YetiShare 3.5.2 through 4.5.3 does not sanitize or encode the output from the lFile parameter on the page, which would allow an attacker to input HTML or execute scripts on the site, aka XSS.
</code>

- [jra89/CVE-2019-19738](https://github.com/jra89/CVE-2019-19738)

### CVE-2019-19781

<code>
An issue was discovered in Citrix Application Delivery Controller (ADC) and Gateway 10.5, 11.1, 12.0, 12.1, and 13.0. They allow Directory Traversal.
</code>

- [mekoko/CVE-2019-19781](https://github.com/mekoko/CVE-2019-19781)
- [projectzeroindia/CVE-2019-19781](https://github.com/projectzeroindia/CVE-2019-19781)
- [trustedsec/cve-2019-19781](https://github.com/trustedsec/cve-2019-19781)
- [cisagov/check-cve-2019-19781](https://github.com/cisagov/check-cve-2019-19781)
- [jas502n/CVE-2019-19781](https://github.com/jas502n/CVE-2019-19781)
- [ianxtianxt/CVE-2019-19781](https://github.com/ianxtianxt/CVE-2019-19781)
- [mpgn/CVE-2019-19781](https://github.com/mpgn/CVE-2019-19781)
- [oways/CVE-2019-19781](https://github.com/oways/CVE-2019-19781)
- [becrevex/Citrix_CVE-2019-19781](https://github.com/becrevex/Citrix_CVE-2019-19781)
- [unknowndevice64/Exploits_CVE-2019-19781](https://github.com/unknowndevice64/Exploits_CVE-2019-19781)
- [bufsnake/CVE-2019-19781](https://github.com/bufsnake/CVE-2019-19781)
- [x1sec/citrixmash_scanner](https://github.com/x1sec/citrixmash_scanner)
- [Jabo-SCO/Shitrix-CVE-2019-19781](https://github.com/Jabo-SCO/Shitrix-CVE-2019-19781)
- [x1sec/CVE-2019-19781](https://github.com/x1sec/CVE-2019-19781)
- [hollerith/CVE-2019-19781](https://github.com/hollerith/CVE-2019-19781)
- [aqhmal/CVE-2019-19781](https://github.com/aqhmal/CVE-2019-19781)
- [MalwareTech/CitrixHoneypot](https://github.com/MalwareTech/CitrixHoneypot)
- [mekhalleh/citrix_dir_traversal_rce](https://github.com/mekhalleh/citrix_dir_traversal_rce)
- [zenturacp/cve-2019-19781-web](https://github.com/zenturacp/cve-2019-19781-web)
- [zgelici/CVE-2019-19781-Checker](https://github.com/zgelici/CVE-2019-19781-Checker)
- [digitalshadows/CVE-2019-19781_IOCs](https://github.com/digitalshadows/CVE-2019-19781_IOCs)
- [onSec-fr/CVE-2019-19781-Forensic](https://github.com/onSec-fr/CVE-2019-19781-Forensic)
- [DanielWep/CVE-NetScalerFileSystemCheck](https://github.com/DanielWep/CVE-NetScalerFileSystemCheck)
- [Castaldio86/Detect-CVE-2019-19781](https://github.com/Castaldio86/Detect-CVE-2019-19781)
- [j81blog/ADC-19781](https://github.com/j81blog/ADC-19781)
- [clm123321/Citrix_CVE-2019-19781](https://github.com/clm123321/Citrix_CVE-2019-19781)
- [b510/CVE-2019-19781](https://github.com/b510/CVE-2019-19781)
- [redscan/CVE-2019-19781](https://github.com/redscan/CVE-2019-19781)
- [DIVD-NL/Citrix-CVE-2019-19781](https://github.com/DIVD-NL/Citrix-CVE-2019-19781)
- [ynsmroztas/citrix.sh](https://github.com/ynsmroztas/citrix.sh)
- [digitalgangst/massCitrix](https://github.com/digitalgangst/massCitrix)
- [fireeye/ioc-scanner-CVE-2019-19781](https://github.com/fireeye/ioc-scanner-CVE-2019-19781)
- [citrix/ioc-scanner-CVE-2019-19781](https://github.com/citrix/ioc-scanner-CVE-2019-19781)
- [x1sec/citrix-honeypot](https://github.com/x1sec/citrix-honeypot)
- [L4r1k/CitrixNetscalerAnalysis](https://github.com/L4r1k/CitrixNetscalerAnalysis)
- [Azeemering/CVE-2019-19781-DFIR-Notes](https://github.com/Azeemering/CVE-2019-19781-DFIR-Notes)
- [0xams/citrixvulncheck](https://github.com/0xams/citrixvulncheck)
- [RaulCalvoLaorden/CVE-2019-19781](https://github.com/RaulCalvoLaorden/CVE-2019-19781)
- [nmanzi/webcvescanner](https://github.com/nmanzi/webcvescanner)
- [darren646/CVE-2019-19781POC](https://github.com/darren646/CVE-2019-19781POC)
- [Jerry-Swift/CVE-2019-19781-scanner](https://github.com/Jerry-Swift/CVE-2019-19781-scanner)
- [Roshi99/Remote-Code-Execution-Exploit-for-Citrix-Application-Delivery-Controller-and-Citrix-Gateway-CVE-201](https://github.com/Roshi99/Remote-Code-Execution-Exploit-for-Citrix-Application-Delivery-Controller-and-Citrix-Gateway-CVE-201)

### CVE-2019-19844

<code>
Django before 1.11.27, 2.x before 2.2.9, and 3.x before 3.0.1 allows account takeover. A suitably crafted email address (that is equal to an existing user's email address after case transformation of Unicode characters) would allow an attacker to be sent a password reset token for the matched user account. (One mitigation in the new releases is to send password reset tokens only to the registered user email address.)
</code>

- [ryu22e/django_cve_2019_19844_poc](https://github.com/ryu22e/django_cve_2019_19844_poc)
- [andripwn/django_cve201919844](https://github.com/andripwn/django_cve201919844)
- [0xsha/CVE_2019_19844](https://github.com/0xsha/CVE_2019_19844)

### CVE-2019-1987

<code>
In onSetSampleX of SkSwizzler.cpp, there is a possible out of bounds write due to a missing bounds check. This could lead to remote code execution with no additional execution privileges needed. User interaction is needed for exploitation. Product: Android. Versions: Android-7.0 Android-7.1.1 Android-7.1.2 Android-8.0 Android-8.1 Android-9. Android ID: A-118143775.
</code>

- [marcinguy/android-7-9-png-bug](https://github.com/marcinguy/android-7-9-png-bug)

### CVE-2019-19871
- [VDISEC/CVE-2019-19871-AuditGuide](https://github.com/VDISEC/CVE-2019-19871-AuditGuide)

### CVE-2019-19905

<code>
NetHack 3.6.x before 3.6.4 is prone to a buffer overflow vulnerability when reading very long lines from configuration files. This affects systems that have NetHack installed suid/sgid, and shared systems that allow users to upload their own configuration files.
</code>

- [dpmdpm2/CVE-2019-19905](https://github.com/dpmdpm2/CVE-2019-19905)

### CVE-2019-19943

<code>
The HTTP service in quickweb.exe in Pablo Quick 'n Easy Web Server 3.3.8 allows Remote Unauthenticated Heap Memory Corruption via a large host or domain parameter. It may be possible to achieve remote code execution because of a double free.
</code>

- [m0rph-1/CVE-2019-19943](https://github.com/m0rph-1/CVE-2019-19943)

### CVE-2019-20059

<code>
payment_manage.ajax.php and various *_manage.ajax.php in MFScripts YetiShare 3.5.2 through 4.5.4 directly insert values from the sSortDir_0 parameter into a SQL string. This allows an attacker to inject their own SQL and manipulate the query, typically extracting data from the database, aka SQL Injection. NOTE: this issue exists because of an incomplete fix for CVE-2019-19732.
</code>

- [jra89/CVE-2019-20059](https://github.com/jra89/CVE-2019-20059)

### CVE-2019-20085

<code>
TVT NVMS-1000 devices allow GET /.. Directory Traversal
</code>

- [AleDiBen/NVMS1000-Exploit](https://github.com/AleDiBen/NVMS1000-Exploit)

### CVE-2019-20197

<code>
In Nagios XI 5.6.9, an authenticated user is able to execute arbitrary OS commands via shell metacharacters in the id parameter to schedulereport.php, in the context of the web-server user account.
</code>

- [lp008/CVE-2019-20197](https://github.com/lp008/CVE-2019-20197)
- [jas502n/CVE-2019-20197](https://github.com/jas502n/CVE-2019-20197)

### CVE-2019-20224

<code>
netflow_get_stats in functions_netflow.php in Pandora FMS 7.0NG allows remote authenticated users to execute arbitrary OS commands via shell metacharacters in the ip_src parameter in an index.php?operation/netflow/nf_live_view request. This issue has been fixed in Pandora FMS 7.0 NG 742.
</code>

- [mhaskar/CVE-2019-20224](https://github.com/mhaskar/CVE-2019-20224)

### CVE-2019-20326

<code>
A heap-based buffer overflow in _cairo_image_surface_create_from_jpeg() in extensions/cairo_io/cairo-image-surface-jpeg.c in GNOME gThumb before 3.8.3 and Linux Mint Pix before 2.4.5 allows attackers to cause a crash and potentially execute arbitrary code via a crafted JPEG file.
</code>

- [Fysac/CVE-2019-20326](https://github.com/Fysac/CVE-2019-20326)

### CVE-2019-2107

<code>
In ihevcd_parse_pps of ihevcd_parse_headers.c, there is a possible out of bounds write due to a missing bounds check. This could lead to remote code execution with no additional execution privileges needed. User interaction is needed for exploitation. Product: Android. Versions: Android-7.0 Android-7.1.1 Android-7.1.2 Android-8.0 Android-8.1 Android-9. Android ID: A-130024844.
</code>

- [marcinguy/CVE-2019-2107](https://github.com/marcinguy/CVE-2019-2107)
- [infiniteLoopers/CVE-2019-2107](https://github.com/infiniteLoopers/CVE-2019-2107)

### CVE-2019-2196

<code>
In Download Provider, there is possible SQL injection. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-8.0 Android-8.1 Android-9 Android-10Android ID: A-135269143
</code>

- [IOActive/AOSP-DownloadProviderDbDumperSQLiLimit](https://github.com/IOActive/AOSP-DownloadProviderDbDumperSQLiLimit)

### CVE-2019-2198

<code>
In Download Provider, there is a possible SQL injection vulnerability. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-8.0 Android-8.1 Android-9 Android-10Android ID: A-135270103
</code>

- [IOActive/AOSP-DownloadProviderDbDumperSQLiWhere](https://github.com/IOActive/AOSP-DownloadProviderDbDumperSQLiWhere)

### CVE-2019-2215

<code>
A use-after-free in binder.c allows an elevation of privilege from an application to the Linux Kernel. No user interaction is required to exploit this vulnerability, however exploitation does require either the installation of a malicious local application or a separate vulnerability in a network facing application.Product: AndroidAndroid ID: A-141720095
</code>

- [timwr/CVE-2019-2215](https://github.com/timwr/CVE-2019-2215)
- [addhaloka/CVE-2019-2215](https://github.com/addhaloka/CVE-2019-2215)
- [kangtastic/cve-2019-2215](https://github.com/kangtastic/cve-2019-2215)
- [marcinguy/CVE-2019-2215](https://github.com/marcinguy/CVE-2019-2215)
- [LIznzn/CVE-2019-2215](https://github.com/LIznzn/CVE-2019-2215)
- [DimitriFourny/cve-2019-2215](https://github.com/DimitriFourny/cve-2019-2215)
- [c0n71nu3/android-kernel-exploitation-ashfaq-CVE-2019-2215](https://github.com/c0n71nu3/android-kernel-exploitation-ashfaq-CVE-2019-2215)

### CVE-2019-2525

<code>
Vulnerability in the Oracle VM VirtualBox component of Oracle Virtualization (subcomponent: Core). Supported versions that are affected are prior to 5.2.24 and prior to 6.0.2. Difficult to exploit vulnerability allows low privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle VM VirtualBox accessible data. CVSS 3.0 Base Score 5.6 (Confidentiality impacts). CVSS Vector: (CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N).
</code>

- [Phantomn/VirtualBox_CVE-2019-2525-CVE-2019-2548](https://github.com/Phantomn/VirtualBox_CVE-2019-2525-CVE-2019-2548)
- [wotmd/VirtualBox-6.0.0-Exploit-1-day](https://github.com/wotmd/VirtualBox-6.0.0-Exploit-1-day)

### CVE-2019-2615

<code>
Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0 and 12.2.1.3.0. Easily exploitable vulnerability allows high privileged attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.0 Base Score 4.9 (Confidentiality impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N).
</code>

- [chiaifan/CVE-2019-2615](https://github.com/chiaifan/CVE-2019-2615)

### CVE-2019-2618

<code>
Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0 and 12.2.1.3.0. Easily exploitable vulnerability allows high privileged attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data as well as unauthorized update, insert or delete access to some of Oracle WebLogic Server accessible data. CVSS 3.0 Base Score 5.5 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:L/A:N).
</code>

- [pyn3rd/CVE-2019-2618](https://github.com/pyn3rd/CVE-2019-2618)
- [jas502n/cve-2019-2618](https://github.com/jas502n/cve-2019-2618)
- [wsfengfan/CVE-2019-2618-](https://github.com/wsfengfan/CVE-2019-2618-)
- [dr0op/WeblogicScan](https://github.com/dr0op/WeblogicScan)
- [he1dan/cve-2019-2618](https://github.com/he1dan/cve-2019-2618)
- [ianxtianxt/cve-2019-2618](https://github.com/ianxtianxt/cve-2019-2618)
- [0xn0ne/weblogicScanner](https://github.com/0xn0ne/weblogicScanner)

### CVE-2019-2725

<code>
Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Web Services). Supported versions that are affected are 10.3.6.0.0 and 12.1.3.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
</code>

- [shack2/javaserializetools](https://github.com/shack2/javaserializetools)
- [SkyBlueEternal/CNVD-C-2019-48814-CNNVD-201904-961](https://github.com/SkyBlueEternal/CNVD-C-2019-48814-CNNVD-201904-961)
- [iceMatcha/CNTA-2019-0014xCVE-2019-2725](https://github.com/iceMatcha/CNTA-2019-0014xCVE-2019-2725)
- [lasensio/cve-2019-2725](https://github.com/lasensio/cve-2019-2725)
- [davidmthomsen/CVE-2019-2725](https://github.com/davidmthomsen/CVE-2019-2725)
- [leerina/CVE-2019-2725](https://github.com/leerina/CVE-2019-2725)
- [zhusx110/cve-2019-2725](https://github.com/zhusx110/cve-2019-2725)
- [lufeirider/CVE-2019-2725](https://github.com/lufeirider/CVE-2019-2725)
- [CVCLabs/cve-2019-2725](https://github.com/CVCLabs/cve-2019-2725)
- [TopScrew/CVE-2019-2725](https://github.com/TopScrew/CVE-2019-2725)
- [welove88888/CVE-2019-2725](https://github.com/welove88888/CVE-2019-2725)
- [jiansiting/CVE-2019-2725](https://github.com/jiansiting/CVE-2019-2725)
- [kerlingcode/CVE-2019-2725](https://github.com/kerlingcode/CVE-2019-2725)
- [black-mirror/Weblogic](https://github.com/black-mirror/Weblogic)
- [pimps/CVE-2019-2725](https://github.com/pimps/CVE-2019-2725)
- [ianxtianxt/CVE-2019-2725](https://github.com/ianxtianxt/CVE-2019-2725)
- [GEIGEI123/CVE-2019-2725-POC](https://github.com/GEIGEI123/CVE-2019-2725-POC)
- [GGyao/weblogic_2019_2725_wls_batch](https://github.com/GGyao/weblogic_2019_2725_wls_batch)

### CVE-2019-2729

<code>
Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Web Services). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0 and 12.2.1.3.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
</code>

- [waffl3ss/CVE-2019-2729](https://github.com/waffl3ss/CVE-2019-2729)
- [ruthlezs/CVE-2019-2729-Exploit](https://github.com/ruthlezs/CVE-2019-2729-Exploit)

### CVE-2019-2888

<code>
Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: EJB Container). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0 and 12.2.1.3.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized read access to a subset of Oracle WebLogic Server accessible data. CVSS 3.0 Base Score 5.3 (Confidentiality impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N).
</code>

- [21superman/weblogic_cve-2019-2888](https://github.com/21superman/weblogic_cve-2019-2888)
- [jas502n/CVE-2019-2888](https://github.com/jas502n/CVE-2019-2888)

### CVE-2019-2890

<code>
Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Web Services). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0 and 12.2.1.3.0. Easily exploitable vulnerability allows high privileged attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 7.2 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H).
</code>

- [ZO1RO/CVE-2019-2890](https://github.com/ZO1RO/CVE-2019-2890)
- [Ky0-HVA/CVE-2019-2890](https://github.com/Ky0-HVA/CVE-2019-2890)
- [SukaraLin/CVE-2019-2890](https://github.com/SukaraLin/CVE-2019-2890)
- [jas502n/CVE-2019-2890](https://github.com/jas502n/CVE-2019-2890)
- [ianxtianxt/CVE-2019-2890](https://github.com/ianxtianxt/CVE-2019-2890)

### CVE-2019-3010

<code>
Vulnerability in the Oracle Solaris product of Oracle Systems (component: XScreenSaver). The supported version that is affected is 11. Easily exploitable vulnerability allows low privileged attacker with logon to the infrastructure where Oracle Solaris executes to compromise Oracle Solaris. While the vulnerability is in Oracle Solaris, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in takeover of Oracle Solaris. CVSS 3.0 Base Score 8.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H).
</code>

- [chaizeg/privilege-escalation-breach](https://github.com/chaizeg/privilege-escalation-breach)

### CVE-2019-3394

<code>
There was a local file disclosure vulnerability in Confluence Server and Confluence Data Center via page exporting. An attacker with permission to editing a page is able to exploit this issue to read arbitrary file on the server under &lt;install-directory&gt;/confluence/WEB-INF directory, which may contain configuration files used for integrating with other services, which could potentially leak credentials or other sensitive information such as LDAP credentials. The LDAP credential will be potentially leaked only if the Confluence server is configured to use LDAP as user repository. All versions of Confluence Server from 6.1.0 before 6.6.16 (the fixed version for 6.6.x), from 6.7.0 before 6.13.7 (the fixed version for 6.13.x), and from 6.14.0 before 6.15.8 (the fixed version for 6.15.x) are affected by this vulnerability.
</code>

- [jas502n/CVE-2019-3394](https://github.com/jas502n/CVE-2019-3394)

### CVE-2019-3396

<code>
The Widget Connector macro in Atlassian Confluence Server before version 6.6.12 (the fixed version for 6.6.x), from version 6.7.0 before 6.12.3 (the fixed version for 6.12.x), from version 6.13.0 before 6.13.3 (the fixed version for 6.13.x), and from version 6.14.0 before 6.14.2 (the fixed version for 6.14.x), allows remote attackers to achieve path traversal and remote code execution on a Confluence Server or Data Center instance via server-side template injection.
</code>

- [dothanthitiendiettiende/CVE-2019-3396](https://github.com/dothanthitiendiettiende/CVE-2019-3396)
- [x-f1v3/CVE-2019-3396](https://github.com/x-f1v3/CVE-2019-3396)
- [shadowsock5/CVE-2019-3396](https://github.com/shadowsock5/CVE-2019-3396)
- [Yt1g3r/CVE-2019-3396_EXP](https://github.com/Yt1g3r/CVE-2019-3396_EXP)
- [jas502n/CVE-2019-3396](https://github.com/jas502n/CVE-2019-3396)
- [pyn3rd/CVE-2019-3396](https://github.com/pyn3rd/CVE-2019-3396)
- [s1xg0d/CVE-2019-3396](https://github.com/s1xg0d/CVE-2019-3396)
- [quanpt103/CVE-2019-3396](https://github.com/quanpt103/CVE-2019-3396)
- [vntest11/confluence_CVE-2019-3396](https://github.com/vntest11/confluence_CVE-2019-3396)
- [tanw923/test1](https://github.com/tanw923/test1)
- [skommando/CVE-2019-3396-confluence-poc](https://github.com/skommando/CVE-2019-3396-confluence-poc)
- [JonathanZhou348/CVE-2019-3396TEST](https://github.com/JonathanZhou348/CVE-2019-3396TEST)
- [am6539/CVE-2019-3396](https://github.com/am6539/CVE-2019-3396)
- [W2Ning/CVE-2019-3396](https://github.com/W2Ning/CVE-2019-3396)
- [123qwerqwer/CVE-2019-3396](https://github.com/123qwerqwer/CVE-2019-3396)
- [Flash1201/CVE-2019-3396](https://github.com/Flash1201/CVE-2019-3396)

### CVE-2019-3398

<code>
Confluence Server and Data Center had a path traversal vulnerability in the downloadallattachments resource. A remote attacker who has permission to add attachments to pages and / or blogs or to create a new space or a personal space or who has 'Admin' permissions for a space can exploit this path traversal vulnerability to write files to arbitrary locations which can lead to remote code execution on systems that run a vulnerable version of Confluence Server or Data Center. All versions of Confluence Server from 2.0.0 before 6.6.13 (the fixed version for 6.6.x), from 6.7.0 before 6.12.4 (the fixed version for 6.12.x), from 6.13.0 before 6.13.4 (the fixed version for 6.13.x), from 6.14.0 before 6.14.3 (the fixed version for 6.14.x), and from 6.15.0 before 6.15.2 are affected by this vulnerability.
</code>

- [superevr/cve-2019-3398](https://github.com/superevr/cve-2019-3398)

### CVE-2019-3462

<code>
Incorrect sanitation of the 302 redirect field in HTTP transport method of apt versions 1.4.8 and earlier can lead to content injection by a MITM attacker, potentially leading to remote code execution on the target machine.
</code>

- [tonejito/check_CVE-2019-3462](https://github.com/tonejito/check_CVE-2019-3462)
- [atilacastro/update-apt-package](https://github.com/atilacastro/update-apt-package)

### CVE-2019-3663

<code>
Unprotected Storage of Credentials vulnerability in McAfee Advanced Threat Defense (ATD) prior to 4.8 allows local attacker to gain access to the root password via accessing sensitive files on the system. This was originally published with a CVSS rating of High, further investigation has resulted in this being updated to Critical. The root password is common across all instances of ATD prior to 4.8. See the Security bulletin for further details
</code>

- [funoverip/mcafee_atd_CVE-2019-3663](https://github.com/funoverip/mcafee_atd_CVE-2019-3663)

### CVE-2019-3719

<code>
Dell SupportAssist Client versions prior to 3.2.0.90 contain a remote code execution vulnerability. An unauthenticated attacker, sharing the network access layer with the vulnerable system, can compromise the vulnerable system by tricking a victim user into downloading and executing arbitrary executables via SupportAssist client from attacker hosted sites.
</code>

- [jiansiting/CVE-2019-3719](https://github.com/jiansiting/CVE-2019-3719)

### CVE-2019-3778

<code>
Spring Security OAuth, versions 2.3 prior to 2.3.5, and 2.2 prior to 2.2.4, and 2.1 prior to 2.1.4, and 2.0 prior to 2.0.17, and older unsupported versions could be susceptible to an open redirector attack that can leak an authorization code. A malicious user or attacker can craft a request to the authorization endpoint using the authorization code grant type, and specify a manipulated redirection URI via the &quot;redirect_uri&quot; parameter. This can cause the authorization server to redirect the resource owner user-agent to a URI under the control of the attacker with the leaked authorization code. This vulnerability exposes applications that meet all of the following requirements: Act in the role of an Authorization Server (e.g. @EnableAuthorizationServer) and uses the DefaultRedirectResolver in the AuthorizationEndpoint. This vulnerability does not expose applications that: Act in the role of an Authorization Server and uses a different RedirectResolver implementation other than DefaultRedirectResolver, act in the role of a Resource Server only (e.g. @EnableResourceServer), act in the role of a Client only (e.g. @EnableOAuthClient).
</code>

- [BBB-man/CVE-2019-3778-Spring-Security-OAuth-2.3-Open-Redirection](https://github.com/BBB-man/CVE-2019-3778-Spring-Security-OAuth-2.3-Open-Redirection)

### CVE-2019-3799

<code>
Spring Cloud Config, versions 2.1.x prior to 2.1.2, versions 2.0.x prior to 2.0.4, and versions 1.4.x prior to 1.4.6, and older unsupported versions allow applications to serve arbitrary configuration files through the spring-cloud-config-server module. A malicious user, or attacker, can send a request using a specially crafted URL that can lead a directory traversal attack.
</code>

- [mpgn/CVE-2019-3799](https://github.com/mpgn/CVE-2019-3799)

### CVE-2019-3847

<code>
A vulnerability was found in moodle before versions 3.6.3, 3.5.5, 3.4.8 and 3.1.17. Users with the &quot;login as other users&quot; capability (such as administrators/managers) can access other users' Dashboards, but the JavaScript those other users may have added to their Dashboard was not being escaped when being viewed by the user logging in on their behalf.
</code>

- [danielthatcher/moodle-login-csrf](https://github.com/danielthatcher/moodle-login-csrf)

### CVE-2019-3929

<code>
The Crestron AM-100 firmware 1.6.0.2, Crestron AM-101 firmware 2.7.0.1, Barco wePresent WiPG-1000P firmware 2.3.0.10, Barco wePresent WiPG-1600W before firmware 2.4.1.19, Extron ShareLink 200/250 firmware 2.0.3.4, Teq AV IT WIPS710 firmware 1.1.0.7, SHARP PN-L703WA firmware 1.4.2.3, Optoma WPS-Pro firmware 1.0.0.5, Blackbox HD WPS firmware 1.0.0.5, InFocus LiteShow3 firmware 1.0.16, and InFocus LiteShow4 2.0.0.7 are vulnerable to command injection via the file_transfer.cgi HTTP endpoint. A remote, unauthenticated attacker can use this vulnerability to execute operating system commands as root.
</code>

- [xfox64x/CVE-2019-3929](https://github.com/xfox64x/CVE-2019-3929)

### CVE-2019-48814
- [wucj001/cve-2019-48814](https://github.com/wucj001/cve-2019-48814)

### CVE-2019-5010

<code>
An exploitable denial-of-service vulnerability exists in the X509 certificate parser of Python.org Python 2.7.11 / 3.6.6. A specially crafted X509 certificate can cause a NULL pointer dereference, resulting in a denial of service. An attacker can initiate or accept TLS connections using crafted certificates to trigger this vulnerability.
</code>

- [JonathanWilbur/CVE-2019-5010](https://github.com/JonathanWilbur/CVE-2019-5010)

### CVE-2019-5096

<code>
An exploitable code execution vulnerability exists in the processing of multi-part/form-data requests within the base GoAhead web server application in versions v5.0.1, v.4.1.1 and v3.6.5. A specially crafted HTTP request can lead to a use-after-free condition during the processing of this request that can be used to corrupt heap structures that could lead to full code execution. The request can be unauthenticated in the form of GET or POST requests, and does not require the requested resource to exist on the server.
</code>

- [papinnon/CVE-2019-5096-GoAhead-Web-Server-Dos-Exploit](https://github.com/papinnon/CVE-2019-5096-GoAhead-Web-Server-Dos-Exploit)

### CVE-2019-5418

<code>
There is a File Content Disclosure vulnerability in Action View &lt;5.2.2.1, &lt;5.1.6.2, &lt;5.0.7.2, &lt;4.2.11.1 and v3 where specially crafted accept headers can cause contents of arbitrary files on the target system's filesystem to be exposed.
</code>

- [mpgn/CVE-2019-5418](https://github.com/mpgn/CVE-2019-5418)
- [omarkurt/CVE-2019-5418](https://github.com/omarkurt/CVE-2019-5418)
- [brompwnie/CVE-2019-5418-Scanner](https://github.com/brompwnie/CVE-2019-5418-Scanner)
- [mpgn/Rails-doubletap-RCE](https://github.com/mpgn/Rails-doubletap-RCE)
- [takeokunn/CVE-2019-5418](https://github.com/takeokunn/CVE-2019-5418)
- [Bad3r/RailroadBandit](https://github.com/Bad3r/RailroadBandit)
- [ztgrace/CVE-2019-5418-Rails3](https://github.com/ztgrace/CVE-2019-5418-Rails3)
- [random-robbie/CVE-2019-5418](https://github.com/random-robbie/CVE-2019-5418)

### CVE-2019-5420

<code>
A remote code execution vulnerability in development mode Rails &lt;5.2.2.1, &lt;6.0.0.beta3 can allow an attacker to guess the automatically generated development mode secret token. This secret token can be used in combination with other Rails internals to escalate to a remote code execution exploit.
</code>

- [knqyf263/CVE-2019-5420](https://github.com/knqyf263/CVE-2019-5420)
- [cved-sources/cve-2019-5420](https://github.com/cved-sources/cve-2019-5420)

### CVE-2019-5475

<code>
The Nexus Yum Repository Plugin in v2 is vulnerable to Remote Code Execution when instances using CommandLineExecutor.java are supplied vulnerable data, such as the Yum Configuration Capability.
</code>

- [jaychouzzk/CVE-2019-5475-Nexus-Repository-Manager-](https://github.com/jaychouzzk/CVE-2019-5475-Nexus-Repository-Manager-)
- [rabbitmask/CVE-2019-5475-EXP](https://github.com/rabbitmask/CVE-2019-5475-EXP)

### CVE-2019-5489

<code>
The mincore() implementation in mm/mincore.c in the Linux kernel through 4.19.13 allowed local attackers to observe page cache access patterns of other processes on the same system, potentially allowing sniffing of secret information. (Fixing this affects the output of the fincore program.) Limited remote exploitation may be possible, as demonstrated by latency differences in accessing public files from an Apache HTTP Server.
</code>

- [mmxsrup/CVE-2019-5489](https://github.com/mmxsrup/CVE-2019-5489)

### CVE-2019-5624

<code>
Rapid7 Metasploit Framework suffers from an instance of CWE-22, Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in the Zip import function of Metasploit. Exploiting this vulnerability can allow an attacker to execute arbitrary code in Metasploit at the privilege level of the user running Metasploit. This issue affects: Rapid7 Metasploit Framework version 4.14.0 and prior versions.
</code>

- [VoidSec/CVE-2019-5624](https://github.com/VoidSec/CVE-2019-5624)

### CVE-2019-5630

<code>
A Cross-Site Request Forgery (CSRF) vulnerability was found in Rapid7 Nexpose InsightVM Security Console versions 6.5.0 through 6.5.68. This issue allows attackers to exploit CSRF vulnerabilities on API endpoints using Flash to circumvent a cross-domain pre-flight OPTIONS request.
</code>

- [rbeede/CVE-2019-5630](https://github.com/rbeede/CVE-2019-5630)

### CVE-2019-5700

<code>
NVIDIA Shield TV Experience prior to v8.0.1, NVIDIA Tegra software contains a vulnerability in the bootloader, where it does not validate the fields of the boot image, which may lead to code execution, denial of service, escalation of privileges, and information disclosure.
</code>

- [oscardagrach/CVE-2019-5700](https://github.com/oscardagrach/CVE-2019-5700)

### CVE-2019-5736

<code>
runc through 1.0-rc6, as used in Docker before 18.09.2 and other products, allows attackers to overwrite the host runc binary (and consequently obtain host root access) by leveraging the ability to execute a command as root within one of these types of containers: (1) a new container with an attacker-controlled image, or (2) an existing container, to which the attacker previously had write access, that can be attached with docker exec. This occurs because of file-descriptor mishandling, related to /proc/self/exe.
</code>

- [q3k/cve-2019-5736-poc](https://github.com/q3k/cve-2019-5736-poc)
- [Frichetten/CVE-2019-5736-PoC](https://github.com/Frichetten/CVE-2019-5736-PoC)
- [jas502n/CVE-2019-5736](https://github.com/jas502n/CVE-2019-5736)
- [denmilu/CVE-2019-5736](https://github.com/denmilu/CVE-2019-5736)
- [denmilu/cve-2019-5736-poc](https://github.com/denmilu/cve-2019-5736-poc)
- [agppp/cve-2019-5736-poc](https://github.com/agppp/cve-2019-5736-poc)
- [ebdecastro/poc-cve-2019-5736](https://github.com/ebdecastro/poc-cve-2019-5736)
- [twistlock/RunC-CVE-2019-5736](https://github.com/twistlock/RunC-CVE-2019-5736)
- [k-onishi/CVE-2019-5736-PoC](https://github.com/k-onishi/CVE-2019-5736-PoC)
- [k-onishi/CVE-2019-5736-PoC-0](https://github.com/k-onishi/CVE-2019-5736-PoC-0)
- [zyriuse75/CVE-2019-5736-PoC](https://github.com/zyriuse75/CVE-2019-5736-PoC)
- [stillan00b/CVE-2019-5736](https://github.com/stillan00b/CVE-2019-5736)
- [milloni/cve-2019-5736-exp](https://github.com/milloni/cve-2019-5736-exp)
- [13paulmurith/Docker-Runc-Exploit](https://github.com/13paulmurith/Docker-Runc-Exploit)
- [RyanNgWH/CVE-2019-5736-POC](https://github.com/RyanNgWH/CVE-2019-5736-POC)
- [Lee-SungYoung/cve-2019-5736-study](https://github.com/Lee-SungYoung/cve-2019-5736-study)
- [chosam2/cve-2019-5736-poc](https://github.com/chosam2/cve-2019-5736-poc)
- [epsteina16/Docker-Escape-Miner](https://github.com/epsteina16/Docker-Escape-Miner)
- [GiverOfGifts/CVE-2019-5736-Custom-Runtime](https://github.com/GiverOfGifts/CVE-2019-5736-Custom-Runtime)
- [Billith/CVE-2019-5736-PoC](https://github.com/Billith/CVE-2019-5736-PoC)
- [BBRathnayaka/POC-CVE-2019-5736](https://github.com/BBRathnayaka/POC-CVE-2019-5736)
- [shen54/IT19172088](https://github.com/shen54/IT19172088)

### CVE-2019-5737

<code>
In Node.js including 6.x before 6.17.0, 8.x before 8.15.1, 10.x before 10.15.2, and 11.x before 11.10.1, an attacker can cause a Denial of Service (DoS) by establishing an HTTP or HTTPS connection in keep-alive mode and by sending headers very slowly. This keeps the connection and associated resources alive for a long period of time. Potential attacks are mitigated by the use of a load balancer or other proxy layer. This vulnerability is an extension of CVE-2018-12121, addressed in November and impacts all active Node.js release lines including 6.x before 6.17.0, 8.x before 8.15.1, 10.x before 10.15.2, and 11.x before 11.10.1.
</code>

- [beelzebruh/cve-2019-5737](https://github.com/beelzebruh/cve-2019-5737)

### CVE-2019-5786

<code>
Object lifetime issue in Blink in Google Chrome prior to 72.0.3626.121 allowed a remote attacker to potentially perform out of bounds memory access via a crafted HTML page.
</code>

- [exodusintel/CVE-2019-5786](https://github.com/exodusintel/CVE-2019-5786)

### CVE-2019-5822

<code>
Inappropriate implementation in Blink in Google Chrome prior to 74.0.3729.108 allowed a remote attacker to bypass same origin policy via a crafted HTML page.
</code>

- [Silence-Rain/14-828_Exploitation_of_CVE-2019-5822](https://github.com/Silence-Rain/14-828_Exploitation_of_CVE-2019-5822)

### CVE-2019-5825

<code>
Out of bounds write in JavaScript in Google Chrome prior to 73.0.3683.86 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.
</code>

- [timwr/CVE-2019-5825](https://github.com/timwr/CVE-2019-5825)

### CVE-2019-5893

<code>
Nelson Open Source ERP v6.3.1 allows SQL Injection via the db/utils/query/data.xml query parameter.
</code>

- [EmreOvunc/OpenSource-ERP-SQL-Injection](https://github.com/EmreOvunc/OpenSource-ERP-SQL-Injection)

### CVE-2019-6111

<code>
An issue was discovered in OpenSSH 7.9. Due to the scp implementation being derived from 1983 rcp, the server chooses which files/directories are sent to the client. However, the scp client only performs cursory validation of the object name returned (only directory traversal attacks are prevented). A malicious scp server (or Man-in-The-Middle attacker) can overwrite arbitrary files in the scp client target directory. If recursive operation (-r) is performed, the server can manipulate subdirectories as well (for example, to overwrite the .ssh/authorized_keys file).
</code>

- [senthuHac/SNP](https://github.com/senthuHac/SNP)

### CVE-2019-6203

<code>
A logic issue was addressed with improved state management. This issue is fixed in iOS 12.2, macOS Mojave 10.14.4, tvOS 12.2. An attacker in a privileged network position may be able to intercept network traffic.
</code>

- [qingxp9/CVE-2019-6203-PoC](https://github.com/qingxp9/CVE-2019-6203-PoC)

### CVE-2019-6207

<code>
An out-of-bounds read issue existed that led to the disclosure of kernel memory. This was addressed with improved input validation. This issue is fixed in iOS 12.2, macOS Mojave 10.14.4, tvOS 12.2, watchOS 5.2. A malicious application may be able to determine kernel memory layout.
</code>

- [dothanthitiendiettiende/CVE-2019-6207](https://github.com/dothanthitiendiettiende/CVE-2019-6207)
- [maldiohead/CVE-2019-6207](https://github.com/maldiohead/CVE-2019-6207)
- [DimitriFourny/cve-2019-6207](https://github.com/DimitriFourny/cve-2019-6207)

### CVE-2019-6225

<code>
A memory corruption issue was addressed with improved validation. This issue is fixed in iOS 12.1.3, macOS Mojave 10.14.3, tvOS 12.1.2. A malicious application may be able to elevate privileges.
</code>

- [fatgrass/OsirisJailbreak12](https://github.com/fatgrass/OsirisJailbreak12)
- [TrungNguyen1909/CVE-2019-6225-macOS](https://github.com/TrungNguyen1909/CVE-2019-6225-macOS)
- [raystyle/jailbreak-iOS12](https://github.com/raystyle/jailbreak-iOS12)

### CVE-2019-6249

<code>
An issue was discovered in HuCart v5.7.4. There is a CSRF vulnerability that can add an admin account via /adminsys/index.php?load=admins&amp;act=edit_info&amp;act_type=add.
</code>

- [NMTech0x90/CVE-2019-6249_Hucart-cms](https://github.com/NMTech0x90/CVE-2019-6249_Hucart-cms)

### CVE-2019-6260

<code>
The ASPEED ast2400 and ast2500 Baseband Management Controller (BMC) hardware and firmware implement Advanced High-performance Bus (AHB) bridges, which allow arbitrary read and write access to the BMC's physical address space from the host (or from the network in unusual cases where the BMC console uart is attached to a serial concentrator). This CVE applies to the specific cases of iLPC2AHB bridge Pt I, iLPC2AHB bridge Pt II, PCIe VGA P2A bridge, DMA from/to arbitrary BMC memory via X-DMA, UART-based SoC Debug interface, LPC2AHB bridge, PCIe BMC P2A bridge, and Watchdog setup.
</code>

- [amboar/cve-2019-6260](https://github.com/amboar/cve-2019-6260)

### CVE-2019-6263

<code>
An issue was discovered in Joomla! before 3.9.2. Inadequate checks of the Global Configuration Text Filter settings allowed stored XSS.
</code>

- [praveensutar/CVE-2019-6263-Joomla-POC](https://github.com/praveensutar/CVE-2019-6263-Joomla-POC)

### CVE-2019-6329

<code>
HP Support Assistant 8.7.50 and earlier allows a user to gain system privilege and allows unauthorized modification of directories or files. Note: A different vulnerability than CVE-2019-6328.
</code>

- [ManhNDd/CVE-2019-6329](https://github.com/ManhNDd/CVE-2019-6329)

### CVE-2019-6340

<code>
Some field types do not properly sanitize data from non-form sources in Drupal 8.5.x before 8.5.11 and Drupal 8.6.x before 8.6.10. This can lead to arbitrary PHP code execution in some cases. A site is only affected by this if one of the following conditions is met: The site has the Drupal 8 core RESTful Web Services (rest) module enabled and allows PATCH or POST requests, or the site has another web services module enabled, like JSON:API in Drupal 8, or Services or RESTful Web Services in Drupal 7. (Note: The Drupal 7 Services module itself does not require an update at this time, but you should apply other contributed updates associated with this advisory if Services is in use.)
</code>

- [g0rx/Drupal-SA-CORE-2019-003](https://github.com/g0rx/Drupal-SA-CORE-2019-003)
- [knqyf263/CVE-2019-6340](https://github.com/knqyf263/CVE-2019-6340)
- [DevDungeon/CVE-2019-6340-Drupal-8.6.9-REST-Auth-Bypass](https://github.com/DevDungeon/CVE-2019-6340-Drupal-8.6.9-REST-Auth-Bypass)
- [oways/CVE-2019-6340](https://github.com/oways/CVE-2019-6340)
- [cved-sources/cve-2019-6340](https://github.com/cved-sources/cve-2019-6340)
- [d1vious/cve-2019-6340-bits](https://github.com/d1vious/cve-2019-6340-bits)
- [jas502n/CVE-2019-6340](https://github.com/jas502n/CVE-2019-6340)

### CVE-2019-6440

<code>
Zemana AntiMalware before 3.0.658 Beta mishandles update logic.
</code>

- [hexnone/CVE-2019-6440](https://github.com/hexnone/CVE-2019-6440)

### CVE-2019-6446

<code>
** DISPUTED **   An issue was discovered in NumPy 1.16.0 and earlier. It uses the pickle Python module unsafely, which allows remote attackers to execute arbitrary code via a crafted serialized object, as demonstrated by a numpy.load call. NOTE: third parties dispute this issue because it is  a behavior that might have legitimate applications in (for example)  loading serialized Python object arrays from trusted and authenticated  sources.
</code>

- [RayScri/CVE-2019-6446](https://github.com/RayScri/CVE-2019-6446)

### CVE-2019-6447

<code>
The ES File Explorer File Manager application through 4.1.9.7.4 for Android allows remote attackers to read arbitrary files or execute applications via TCP port 59777 requests on the local Wi-Fi network. This TCP port remains open after the ES application has been launched once, and responds to unauthenticated application/json data over HTTP.
</code>

- [fs0c131y/ESFileExplorerOpenPortVuln](https://github.com/fs0c131y/ESFileExplorerOpenPortVuln)
- [SandaRuFdo/ES-File-Explorer-Open-Port-Vulnerability---CVE-2019-6447](https://github.com/SandaRuFdo/ES-File-Explorer-Open-Port-Vulnerability---CVE-2019-6447)

### CVE-2019-6453

<code>
mIRC before 7.55 allows remote command execution by using argument injection through custom URI protocol handlers. The attacker can specify an irc:// URI that loads an arbitrary .ini file from a UNC share pathname. Exploitation depends on browser-specific URI handling (Chrome is not exploitable).
</code>

- [proofofcalc/cve-2019-6453-poc](https://github.com/proofofcalc/cve-2019-6453-poc)
- [andripwn/mIRC-CVE-2019-6453](https://github.com/andripwn/mIRC-CVE-2019-6453)

### CVE-2019-6467

<code>
A programming error in the nxdomain-redirect feature can cause an assertion failure in query.c if the alternate namespace used by nxdomain-redirect is a descendant of a zone that is served locally. The most likely scenario where this might occur is if the server, in addition to performing NXDOMAIN redirection for recursive clients, is also serving a local copy of the root zone or using mirroring to provide the root zone, although other configurations are also possible. Versions affected: BIND 9.12.0-&gt; 9.12.4, 9.14.0. Also affects all releases in the 9.13 development branch.
</code>

- [knqyf263/CVE-2019-6467](https://github.com/knqyf263/CVE-2019-6467)

### CVE-2019-6487

<code>
TP-Link WDR Series devices through firmware v3 (such as TL-WDR5620 V3.0) are affected by command injection (after login) leading to remote code execution, because shell metacharacters can be included in the weather get_weather_observe citycode field.
</code>

- [afang5472/TP-Link-WDR-Router-Command-injection_POC](https://github.com/afang5472/TP-Link-WDR-Router-Command-injection_POC)

### CVE-2019-6690

<code>
python-gnupg 0.4.3 allows context-dependent attackers to trick gnupg to decrypt other ciphertext than intended. To perform the attack, the passphrase to gnupg must be controlled by the adversary and the ciphertext should be trusted. Related to a &quot;CWE-20: Improper Input Validation&quot; issue affecting the affect functionality component.
</code>

- [stigtsp/CVE-2019-6690-python-gnupg-vulnerability](https://github.com/stigtsp/CVE-2019-6690-python-gnupg-vulnerability)
- [brianwrf/CVE-2019-6690](https://github.com/brianwrf/CVE-2019-6690)

### CVE-2019-6715

<code>
pub/sns.php in the W3 Total Cache plugin before 0.9.4 for WordPress allows remote attackers to read arbitrary files via the SubscribeURL field in SubscriptionConfirmation JSON data.
</code>

- [random-robbie/cve-2019-6715](https://github.com/random-robbie/cve-2019-6715)

### CVE-2019-7216

<code>
An issue was discovered in FileChucker 4.99e-free-e02. filechucker.cgi has a filter bypass that allows a malicious user to upload any type of file by using % characters within the extension, e.g., file.%ph%p becomes file.php.
</code>

- [Ekultek/CVE-2019-7216](https://github.com/Ekultek/CVE-2019-7216)

### CVE-2019-7219

<code>
Unauthenticated reflected cross-site scripting (XSS) exists in Zarafa Webapp 2.0.1.47791 and earlier. NOTE: this is a discontinued product. The issue was fixed in later Zarafa Webapp versions; however, some former Zarafa Webapp customers use the related Kopano product instead.
</code>

- [verifysecurity/CVE-2019-7219](https://github.com/verifysecurity/CVE-2019-7219)

### CVE-2019-7238

<code>
Sonatype Nexus Repository Manager before 3.15.0 has Incorrect Access Control.
</code>

- [mpgn/CVE-2019-7238](https://github.com/mpgn/CVE-2019-7238)
- [jas502n/CVE-2019-7238](https://github.com/jas502n/CVE-2019-7238)
- [verctor/nexus_rce_CVE-2019-7238](https://github.com/verctor/nexus_rce_CVE-2019-7238)
- [magicming200/CVE-2019-7238_Nexus_RCE_Tool](https://github.com/magicming200/CVE-2019-7238_Nexus_RCE_Tool)

### CVE-2019-7304

<code>
Canonical snapd before version 2.37.1 incorrectly performed socket owner validation, allowing an attacker to run arbitrary commands as root. This issue affects: Canonical snapd versions prior to 2.37.1.
</code>

- [initstring/dirty_sock](https://github.com/initstring/dirty_sock)
- [SecuritySi/CVE-2019-7304_DirtySock](https://github.com/SecuritySi/CVE-2019-7304_DirtySock)

### CVE-2019-7482

<code>
Stack-based buffer overflow in SonicWall SMA100 allows an unauthenticated user to execute arbitrary code in function libSys.so. This vulnerability impacted SMA100 version 9.0.0.3 and earlier.
</code>

- [singletrackseeker/CVE-2019-7482](https://github.com/singletrackseeker/CVE-2019-7482)
- [b4bay/CVE-2019-7482](https://github.com/b4bay/CVE-2019-7482)

### CVE-2019-7609

<code>
Kibana versions before 5.6.15 and 6.6.1 contain an arbitrary code execution flaw in the Timelion visualizer. An attacker with access to the Timelion application could send a request that will attempt to execute javascript code. This could possibly lead to an attacker executing arbitrary commands with permissions of the Kibana process on the host system.
</code>

- [jas502n/kibana-RCE](https://github.com/jas502n/kibana-RCE)
- [mpgn/CVE-2019-7609](https://github.com/mpgn/CVE-2019-7609)
- [LandGrey/CVE-2019-7609](https://github.com/LandGrey/CVE-2019-7609)
- [hekadan/CVE-2019-7609](https://github.com/hekadan/CVE-2019-7609)
- [rhbb/CVE-2019-7609](https://github.com/rhbb/CVE-2019-7609)

### CVE-2019-7610

<code>
Kibana versions before 6.6.1 contain an arbitrary code execution flaw in the security audit logger. If a Kibana instance has the setting xpack.security.audit.enabled set to true, an attacker could send a request that will attempt to execute javascript code. This could possibly lead to an attacker executing arbitrary commands with permissions of the Kibana process on the host system.
</code>

- [whoami0622/CVE-2019-7610](https://github.com/whoami0622/CVE-2019-7610)

### CVE-2019-7642

<code>
D-Link routers with the mydlink feature have some web interfaces without authentication requirements. An attacker can remotely obtain users' DNS query logs and login logs. Vulnerable targets include but are not limited to the latest firmware versions of DIR-817LW (A1-1.04), DIR-816L (B1-2.06), DIR-816 (B1-2.06?), DIR-850L (A1-1.09), and DIR-868L (A1-1.10).
</code>

- [xw77cve/CVE-2019-7642](https://github.com/xw77cve/CVE-2019-7642)

### CVE-2019-7839

<code>
ColdFusion versions Update 3 and earlier, Update 10 and earlier, and Update 18 and earlier have a command injection vulnerability. Successful exploitation could lead to arbitrary code execution.
</code>

- [securifera/CVE-2019-7839](https://github.com/securifera/CVE-2019-7839)

### CVE-2019-8389

<code>
A file-read vulnerability was identified in the Wi-Fi transfer feature of Musicloud 1.6. By default, the application runs a transfer service on port 8080, accessible by everyone on the same Wi-Fi network. An attacker can send the POST parameters downfiles and cur-folder (with a crafted ../ payload) to the download.script endpoint. This will create a MusicPlayerArchive.zip archive that is publicly accessible and includes the content of any requested file (such as the /etc/passwd file).
</code>

- [shawarkhanethicalhacker/CVE-2019-8389](https://github.com/shawarkhanethicalhacker/CVE-2019-8389)

### CVE-2019-8446

<code>
The /rest/issueNav/1/issueTable resource in Jira before version 8.3.2 allows remote attackers to enumerate usernames via an incorrect authorisation check.
</code>

- [CyberTrashPanda/CVE-2019-8446](https://github.com/CyberTrashPanda/CVE-2019-8446)

### CVE-2019-8449

<code>
The /rest/api/latest/groupuserpicker resource in Jira before version 8.4.0 allows remote attackers to enumerate usernames via an information disclosure vulnerability.
</code>

- [mufeedvh/CVE-2019-8449](https://github.com/mufeedvh/CVE-2019-8449)
- [r0lh/CVE-2019-8449](https://github.com/r0lh/CVE-2019-8449)

### CVE-2019-8451

<code>
The /plugins/servlet/gadgets/makeRequest resource in Jira before version 8.4.0 allows remote attackers to access the content of internal network resources via a Server Side Request Forgery (SSRF) vulnerability due to a logic bug in the JiraWhitelist class.
</code>

- [0xbug/CVE-2019-8451](https://github.com/0xbug/CVE-2019-8451)
- [ianxtianxt/CVE-2019-8451](https://github.com/ianxtianxt/CVE-2019-8451)
- [jas502n/CVE-2019-8451](https://github.com/jas502n/CVE-2019-8451)
- [h0ffayyy/Jira-CVE-2019-8451](https://github.com/h0ffayyy/Jira-CVE-2019-8451)

### CVE-2019-8513

<code>
This issue was addressed with improved checks. This issue is fixed in macOS Mojave 10.14.4. A local user may be able to execute arbitrary shell commands.
</code>

- [genknife/cve-2019-8513](https://github.com/genknife/cve-2019-8513)

### CVE-2019-8540

<code>
A memory initialization issue was addressed with improved memory handling. This issue is fixed in iOS 12.2, macOS Mojave 10.14.4, tvOS 12.2, watchOS 5.2. A malicious application may be able to determine kernel memory layout.
</code>

- [maldiohead/CVE-2019-8540](https://github.com/maldiohead/CVE-2019-8540)

### CVE-2019-8565

<code>
A race condition was addressed with additional validation. This issue is fixed in iOS 12.2, macOS Mojave 10.14.4. A malicious application may be able to gain root privileges.
</code>

- [genknife/cve-2019-8565](https://github.com/genknife/cve-2019-8565)

### CVE-2019-8591

<code>
A type confusion issue was addressed with improved memory handling. This issue is fixed in iOS 12.3, macOS Mojave 10.14.5, tvOS 12.3, watchOS 5.2.1. An application may be able to cause unexpected system termination or write kernel memory.
</code>

- [jsherman212/used_sock](https://github.com/jsherman212/used_sock)

### CVE-2019-8601

<code>
Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in iOS 12.3, macOS Mojave 10.14.5, tvOS 12.3, watchOS 5.2.1, Safari 12.1.1, iTunes for Windows 12.9.5, iCloud for Windows 7.12. Processing maliciously crafted web content may lead to arbitrary code execution.
</code>

- [BadAccess11/CVE-2019-8601](https://github.com/BadAccess11/CVE-2019-8601)

### CVE-2019-8627
- [maldiohead/CVE-2019-8627](https://github.com/maldiohead/CVE-2019-8627)

### CVE-2019-8781

<code>
A memory corruption issue was addressed with improved state management. This issue is fixed in macOS Catalina 10.15. An application may be able to execute arbitrary code with kernel privileges.
</code>

- [A2nkF/macOS-Kernel-Exploit](https://github.com/A2nkF/macOS-Kernel-Exploit)
- [TrungNguyen1909/CVE-2019-8781-macOS](https://github.com/TrungNguyen1909/CVE-2019-8781-macOS)

### CVE-2019-8936

<code>
NTP through 4.2.8p12 has a NULL Pointer Dereference.
</code>

- [snappyJack/CVE-2019-8936](https://github.com/snappyJack/CVE-2019-8936)

### CVE-2019-8942

<code>
WordPress before 4.9.9 and 5.x before 5.0.1 allows remote code execution because an _wp_attached_file Post Meta entry can be changed to an arbitrary string, such as one ending with a .jpg?file.php substring. An attacker with author privileges can execute arbitrary code by uploading a crafted image containing PHP code in the Exif metadata. Exploitation can leverage CVE-2019-8943.
</code>

- [brianwrf/WordPress_4.9.8_RCE_POC](https://github.com/brianwrf/WordPress_4.9.8_RCE_POC)
- [synacktiv/CVE-2019-8942](https://github.com/synacktiv/CVE-2019-8942)

### CVE-2019-8956

<code>
In the Linux Kernel before versions 4.20.8 and 4.19.21 a use-after-free error in the &quot;sctp_sendmsg()&quot; function (net/sctp/socket.c) when handling SCTP_SENDALL flag can be exploited to corrupt memory.
</code>

- [butterflyhack/CVE-2019-8956](https://github.com/butterflyhack/CVE-2019-8956)

### CVE-2019-8978

<code>
An improper authentication vulnerability can be exploited through a race condition that occurs in Ellucian Banner Web Tailor 8.8.3, 8.8.4, and 8.9 and Banner Enterprise Identity Services 8.3, 8.3.1, 8.3.2, and 8.4, in conjunction with SSO Manager. This vulnerability allows remote attackers to steal a victim's session (and cause a denial of service) by repeatedly requesting the initial Banner Web Tailor main page with the IDMSESSID cookie set to the victim's UDCID, which in the case tested is the institutional ID. During a login attempt by a victim, the attacker can leverage the race condition and will be issued the SESSID that was meant for this victim.
</code>

- [JoshuaMulliken/CVE-2019-8978](https://github.com/JoshuaMulliken/CVE-2019-8978)

### CVE-2019-8997

<code>
An XML External Entity Injection (XXE) vulnerability in the Management System (console) of BlackBerry AtHoc versions earlier than 7.6 HF-567 could allow an attacker to potentially read arbitrary local files from the application server or make requests on the network by entering maliciously crafted XML in an existing field.
</code>

- [nxkennedy/CVE-2019-8997](https://github.com/nxkennedy/CVE-2019-8997)

### CVE-2019-9153

<code>
Improper Verification of a Cryptographic Signature in OpenPGP.js &lt;=4.1.2 allows an attacker to forge signed messages by replacing its signatures with a &quot;standalone&quot; or &quot;timestamp&quot; signature.
</code>

- [ZenyWay/opgp-service-cve-2019-9153](https://github.com/ZenyWay/opgp-service-cve-2019-9153)

### CVE-2019-9184

<code>
SQL injection vulnerability in the J2Store plugin 3.x before 3.3.7 for Joomla! allows remote attackers to execute arbitrary SQL commands via the product_option[] parameter.
</code>

- [cved-sources/cve-2019-9184](https://github.com/cved-sources/cve-2019-9184)

### CVE-2019-9193

<code>
** DISPUTED ** In PostgreSQL 9.3 through 11.2, the &quot;COPY TO/FROM PROGRAM&quot; function allows superusers and users in the 'pg_execute_server_program' group to execute arbitrary code in the context of the database's operating system user. This functionality is enabled by default and can be abused to run arbitrary operating system commands on Windows, Linux, and macOS. NOTE: Third parties claim/state this is not an issue because PostgreSQL functionality for ‘COPY TO/FROM PROGRAM’ is acting as intended. References state that in PostgreSQL, a superuser can execute commands as the server user without using the ‘COPY FROM PROGRAM’.
</code>

- [skyship36/CVE-2019-9193](https://github.com/skyship36/CVE-2019-9193)

### CVE-2019-9194

<code>
elFinder before 2.1.48 has a command injection vulnerability in the PHP connector.
</code>

- [cved-sources/cve-2019-9194](https://github.com/cved-sources/cve-2019-9194)

### CVE-2019-9202

<code>
Nagios IM (component of Nagios XI) before 2.2.7 allows authenticated users to execute arbitrary code via API key issues.
</code>

- [polict/CVE-2019-9202](https://github.com/polict/CVE-2019-9202)

### CVE-2019-9465

<code>
In the Titan M handling of cryptographic operations, there is a possible information disclosure due to an unusual root cause. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation. Product: Android Versions: Android-10 Android ID: A-133258003
</code>

- [alexbakker/CVE-2019-9465](https://github.com/alexbakker/CVE-2019-9465)

### CVE-2019-9506

<code>
The Bluetooth BR/EDR specification up to and including version 5.1 permits sufficiently low encryption key length and does not prevent an attacker from influencing the key length negotiation. This allows practical brute-force attacks (aka &quot;KNOB&quot;) that can decrypt traffic and inject arbitrary ciphertext without the victim noticing.
</code>

- [francozappa/knob](https://github.com/francozappa/knob)

### CVE-2019-9580

<code>
In st2web in StackStorm Web UI before 2.9.3 and 2.10.x before 2.10.3, it is possible to bypass the CORS protection mechanism via a &quot;null&quot; origin value, potentially leading to XSS.
</code>

- [mpgn/CVE-2019-9580](https://github.com/mpgn/CVE-2019-9580)

### CVE-2019-9596

<code>
Darktrace Enterprise Immune System before 3.1 allows CSRF via the /whitelisteddomains endpoint.
</code>

- [gerwout/CVE-2019-9596-and-CVE-2019-9597](https://github.com/gerwout/CVE-2019-9596-and-CVE-2019-9597)

### CVE-2019-9599

<code>
The AirDroid application through 4.2.1.6 for Android allows remote attackers to cause a denial of service (service crash) via many simultaneous sdctl/comm/lite_auth/ requests.
</code>

- [s4vitar/AirDroidPwner](https://github.com/s4vitar/AirDroidPwner)

### CVE-2019-9621

<code>
Zimbra Collaboration Suite before 8.6 patch 13, 8.7.x before 8.7.11 patch 10, and 8.8.x before 8.8.10 patch 7 or 8.8.x before 8.8.11 patch 3 allows SSRF via the ProxyServlet component.
</code>

- [k8gege/ZimbraExploit](https://github.com/k8gege/ZimbraExploit)

### CVE-2019-9653

<code>
NUUO Network Video Recorder Firmware 1.7.x through 3.3.x allows unauthenticated attackers to execute arbitrary commands via shell metacharacters to handle_load_config.php.
</code>

- [grayoneday/CVE-2019-9653](https://github.com/grayoneday/CVE-2019-9653)

### CVE-2019-9670

<code>
mailboxd component in Synacor Zimbra Collaboration Suite 8.7.x before 8.7.11p10 has an XML External Entity injection (XXE) vulnerability.
</code>

- [rek7/Zimbra-RCE](https://github.com/rek7/Zimbra-RCE)
- [attackgithub/Zimbra-RCE](https://github.com/attackgithub/Zimbra-RCE)

### CVE-2019-9673

<code>
Freenet 1483 has a MIME type bypass that allows arbitrary JavaScript execution via a crafted Freenet URI.
</code>

- [mgrube/CVE-2019-9673](https://github.com/mgrube/CVE-2019-9673)

### CVE-2019-9729

<code>
In Shanda MapleStory Online V160, the SdoKeyCrypt.sys driver allows privilege escalation to NT AUTHORITY\SYSTEM because of not validating the IOCtl 0x8000c01c input value, leading to an integer signedness error and a heap-based buffer underflow.
</code>

- [HyperSine/SdoKeyCrypt-sys-local-privilege-elevation](https://github.com/HyperSine/SdoKeyCrypt-sys-local-privilege-elevation)

### CVE-2019-9730

<code>
Incorrect access control in the CxUtilSvc component of the Synaptics Sound Device drivers prior to version 2.29 allows a local attacker to increase access privileges to the Windows Registry via an unpublished API.
</code>

- [jthuraisamy/CVE-2019-9730](https://github.com/jthuraisamy/CVE-2019-9730)

### CVE-2019-9745

<code>
CloudCTI HIP Integrator Recognition Configuration Tool allows privilege escalation via its EXQUISE integration. This tool communicates with a service (Recognition Update Client Service) via an insecure communication channel (Named Pipe). The data (JSON) sent via this channel is used to import data from CRM software using plugins (.dll files). The plugin to import data from the EXQUISE software (DatasourceExquiseExporter.dll) can be persuaded to start arbitrary programs (including batch files) that are executed using the same privileges as Recognition Update Client Service (NT AUTHORITY\SYSTEM), thus elevating privileges. This occurs because a higher-privileged process executes scripts from a directory writable by a lower-privileged user.
</code>

- [KPN-CISO/CVE-2019-9745](https://github.com/KPN-CISO/CVE-2019-9745)

### CVE-2019-9766

<code>
Stack-based buffer overflow in Free MP3 CD Ripper 2.6, when converting a file, allows user-assisted remote attackers to execute arbitrary code via a crafted .mp3 file.
</code>

- [moonheadobj/CVE-2019-9766](https://github.com/moonheadobj/CVE-2019-9766)

### CVE-2019-9787

<code>
WordPress before 5.1.1 does not properly filter comment content, leading to Remote Code Execution by unauthenticated users in a default configuration. This occurs because CSRF protection is mishandled, and because Search Engine Optimization of A elements is performed incorrectly, leading to XSS. The XSS results in administrative access, which allows arbitrary changes to .php files. This is related to wp-admin/includes/ajax-actions.php and wp-includes/comment.php.
</code>

- [rkatogit/cve-2019-9787_csrf_poc](https://github.com/rkatogit/cve-2019-9787_csrf_poc)
- [PalmTreeForest/CodePath_Week_7-8](https://github.com/PalmTreeForest/CodePath_Week_7-8)
- [sijiahi/Wordpress_cve-2019-9787_defense](https://github.com/sijiahi/Wordpress_cve-2019-9787_defense)

### CVE-2019-9810

<code>
Incorrect alias information in IonMonkey JIT compiler for Array.prototype.slice method may lead to missing bounds check and a buffer overflow. This vulnerability affects Firefox &lt; 66.0.1, Firefox ESR &lt; 60.6.1, and Thunderbird &lt; 60.6.1.
</code>

- [xuechiyaobai/CVE-2019-9810-PoC](https://github.com/xuechiyaobai/CVE-2019-9810-PoC)
- [0vercl0k/CVE-2019-9810](https://github.com/0vercl0k/CVE-2019-9810)

### CVE-2019-9896

<code>
In PuTTY versions before 0.71 on Windows, local attackers could hijack the application by putting a malicious help file in the same directory as the executable.
</code>

- [yasinyilmaz/vuln-chm-hijack](https://github.com/yasinyilmaz/vuln-chm-hijack)

### CVE-2019-9978

<code>
The social-warfare plugin before 3.5.3 for WordPress has stored XSS via the wp-admin/admin-post.php?swp_debug=load_options swp_url parameter, as exploited in the wild in March 2019. This affects Social Warfare and Social Warfare Pro.
</code>

- [mpgn/CVE-2019-9978](https://github.com/mpgn/CVE-2019-9978)
- [hash3liZer/CVE-2019-9978](https://github.com/hash3liZer/CVE-2019-9978)
- [KTN1990/CVE-2019-9978](https://github.com/KTN1990/CVE-2019-9978)
- [cved-sources/cve-2019-9978](https://github.com/cved-sources/cve-2019-9978)


## 2018
### CVE-2018-0101

<code>
A vulnerability in the Secure Sockets Layer (SSL) VPN functionality of the Cisco Adaptive Security Appliance (ASA) Software could allow an unauthenticated, remote attacker to cause a reload of the affected system or to remotely execute code. The vulnerability is due to an attempt to double free a region of memory when the webvpn feature is enabled on the Cisco ASA device. An attacker could exploit this vulnerability by sending multiple, crafted XML packets to a webvpn-configured interface on the affected system. An exploit could allow the attacker to execute arbitrary code and obtain full control of the system, or cause a reload of the affected device. This vulnerability affects Cisco ASA Software that is running on the following Cisco products: 3000 Series Industrial Security Appliance (ISA), ASA 5500 Series Adaptive Security Appliances, ASA 5500-X Series Next-Generation Firewalls, ASA Services Module for Cisco Catalyst 6500 Series Switches and Cisco 7600 Series Routers, ASA 1000V Cloud Firewall, Adaptive Security Virtual Appliance (ASAv), Firepower 2100 Series Security Appliance, Firepower 4110 Security Appliance, Firepower 9300 ASA Security Module, Firepower Threat Defense Software (FTD). Cisco Bug IDs: CSCvg35618.
</code>

- [1337g/CVE-2018-0101-DOS-POC](https://github.com/1337g/CVE-2018-0101-DOS-POC)
- [Cymmetria/ciscoasa_honeypot](https://github.com/Cymmetria/ciscoasa_honeypot)

### CVE-2018-0114

<code>
A vulnerability in the Cisco node-jose open source library before 0.11.0 could allow an unauthenticated, remote attacker to re-sign tokens using a key that is embedded within the token. The vulnerability is due to node-jose following the JSON Web Signature (JWS) standard for JSON Web Tokens (JWTs). This standard specifies that a JSON Web Key (JWK) representing a public key can be embedded within the header of a JWS. This public key is then trusted for verification. An attacker could exploit this by forging valid JWS objects by removing the original signature, adding a new public key to the header, and then signing the object using the (attacker-owned) private key associated with the public key embedded in that JWS header.
</code>

- [zi0Black/POC-CVE-2018-0114](https://github.com/zi0Black/POC-CVE-2018-0114)

### CVE-2018-0202

<code>
clamscan in ClamAV before 0.99.4 contains a vulnerability that could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected device. The vulnerability is due to improper input validation checking mechanisms when handling Portable Document Format (.pdf) files sent to an affected device. An unauthenticated, remote attacker could exploit this vulnerability by sending a crafted .pdf file to an affected device. This action could cause an out-of-bounds read when ClamAV scans the malicious file, allowing the attacker to cause a DoS condition. This concerns pdf_parse_array and pdf_parse_string in libclamav/pdfng.c. Cisco Bug IDs: CSCvh91380, CSCvh91400.
</code>

- [jaychowjingjie/CVE-2018-0202](https://github.com/jaychowjingjie/CVE-2018-0202)

### CVE-2018-0296

<code>
A vulnerability in the web interface of the Cisco Adaptive Security Appliance (ASA) could allow an unauthenticated, remote attacker to cause an affected device to reload unexpectedly, resulting in a denial of service (DoS) condition. It is also possible on certain software releases that the ASA will not reload, but an attacker could view sensitive system information without authentication by using directory traversal techniques. The vulnerability is due to lack of proper input validation of the HTTP URL. An attacker could exploit this vulnerability by sending a crafted HTTP request to an affected device. An exploit could allow the attacker to cause a DoS condition or unauthenticated disclosure of information. This vulnerability applies to IPv4 and IPv6 HTTP traffic. This vulnerability affects Cisco ASA Software and Cisco Firepower Threat Defense (FTD) Software that is running on the following Cisco products: 3000 Series Industrial Security Appliance (ISA), ASA 1000V Cloud Firewall, ASA 5500 Series Adaptive Security Appliances, ASA 5500-X Series Next-Generation Firewalls, ASA Services Module for Cisco Catalyst 6500 Series Switches and Cisco 7600 Series Routers, Adaptive Security Virtual Appliance (ASAv), Firepower 2100 Series Security Appliance, Firepower 4100 Series Security Appliance, Firepower 9300 ASA Security Module, FTD Virtual (FTDv). Cisco Bug IDs: CSCvi16029.
</code>

- [milo2012/CVE-2018-0296](https://github.com/milo2012/CVE-2018-0296)
- [yassineaboukir/CVE-2018-0296](https://github.com/yassineaboukir/CVE-2018-0296)
- [bhenner1/CVE-2018-0296](https://github.com/bhenner1/CVE-2018-0296)
- [irbishop/CVE-2018-0296](https://github.com/irbishop/CVE-2018-0296)
- [qiantu88/CVE-2018-0296](https://github.com/qiantu88/CVE-2018-0296)

### CVE-2018-0708

<code>
Command injection vulnerability in networking of QNAP Q'center Virtual Appliance version 1.7.1063 and earlier could allow authenticated users to run arbitrary commands.
</code>

- [ntkernel0/CVE-2019-0708](https://github.com/ntkernel0/CVE-2019-0708)

### CVE-2018-0802

<code>
Equation Editor in Microsoft Office 2007, Microsoft Office 2010, Microsoft Office 2013, and Microsoft Office 2016 allow a remote code execution vulnerability due to the way objects are handled in memory, aka &quot;Microsoft Office Memory Corruption Vulnerability&quot;. This CVE is unique from CVE-2018-0797 and CVE-2018-0812.
</code>

- [zldww2011/CVE-2018-0802_POC](https://github.com/zldww2011/CVE-2018-0802_POC)
- [rxwx/CVE-2018-0802](https://github.com/rxwx/CVE-2018-0802)
- [Ridter/RTF_11882_0802](https://github.com/Ridter/RTF_11882_0802)
- [denmilu/CVE-2018-0802_CVE-2017-11882](https://github.com/denmilu/CVE-2018-0802_CVE-2017-11882)

### CVE-2018-0824

<code>
A remote code execution vulnerability exists in &quot;Microsoft COM for Windows&quot; when it fails to properly handle serialized objects, aka &quot;Microsoft COM for Windows Remote Code Execution Vulnerability.&quot; This affects Windows 7, Windows Server 2012 R2, Windows RT 8.1, Windows Server 2008, Windows Server 2012, Windows 8.1, Windows Server 2016, Windows Server 2008 R2, Windows 10, Windows 10 Servers.
</code>

- [codewhitesec/UnmarshalPwn](https://github.com/codewhitesec/UnmarshalPwn)

### CVE-2018-0833

<code>
The Microsoft Server Message Block 2.0 and 3.0 (SMBv2/SMBv3) client in Windows 8.1 and RT 8.1 and Windows Server 2012 R2 allows a denial of service vulnerability due to how specially crafted requests are handled, aka &quot;SMBv2/SMBv3 Null Dereference Denial of Service Vulnerability&quot;.
</code>

- [RealBearcat/CVE-2018-0833](https://github.com/RealBearcat/CVE-2018-0833)

### CVE-2018-0886

<code>
The Credential Security Support Provider protocol (CredSSP) in Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1 and RT 8.1, Windows Server 2012 and R2, Windows 10 Gold, 1511, 1607, 1703, and 1709 Windows Server 2016 and Windows Server, version 1709 allows a remote code execution vulnerability due to how CredSSP validates request during the authentication process, aka &quot;CredSSP Remote Code Execution Vulnerability&quot;.
</code>

- [preempt/credssp](https://github.com/preempt/credssp)

### CVE-2018-0952

<code>
An Elevation of Privilege vulnerability exists when Diagnostics Hub Standard Collector allows file creation in arbitrary locations, aka &quot;Diagnostic Hub Standard Collector Elevation Of Privilege Vulnerability.&quot; This affects Windows Server 2016, Windows 10, Microsoft Visual Studio, Windows 10 Servers.
</code>

- [atredispartners/CVE-2018-0952-SystemCollector](https://github.com/atredispartners/CVE-2018-0952-SystemCollector)

### CVE-2018-1000001

<code>
In glibc 2.26 and earlier there is confusion in the usage of getcwd() by realpath() which can be used to write before the destination buffer leading to a buffer underflow and potential code execution.
</code>

- [0x00-0x00/CVE-2018-1000001](https://github.com/0x00-0x00/CVE-2018-1000001)

### CVE-2018-1000006

<code>
GitHub Electron versions 1.8.2-beta.3 and earlier, 1.7.10 and earlier, 1.6.15 and earlier has a vulnerability in the protocol handler, specifically Electron apps running on Windows 10, 7 or 2008 that register custom protocol handlers can be tricked in arbitrary command execution if the user clicks on a specially crafted URL. This has been fixed in versions 1.8.2-beta.4, 1.7.11, and 1.6.16.
</code>

- [CHYbeta/CVE-2018-1000006-DEMO](https://github.com/CHYbeta/CVE-2018-1000006-DEMO)

### CVE-2018-1000030

<code>
Python 2.7.14 is vulnerable to a Heap-Buffer-Overflow as well as a Heap-Use-After-Free. Python versions prior to 2.7.14 may also be vulnerable and it appears that Python 2.7.17 and prior may also be vulnerable however this has not been confirmed. The vulnerability lies when multiply threads are handling large amounts of data. In both cases there is essentially a race condition that occurs. For the Heap-Buffer-Overflow, Thread 2 is creating the size for a buffer, but Thread1 is already writing to the buffer without knowing how much to write. So when a large amount of data is being processed, it is very easy to cause memory corruption using a Heap-Buffer-Overflow. As for the Use-After-Free, Thread3-&gt;Malloc-&gt;Thread1-&gt;Free's-&gt;Thread2-Re-uses-Free'd Memory. The PSRT has stated that this is not a security vulnerability due to the fact that the attacker must be able to run code, however in some situations, such as function as a service, this vulnerability can potentially be used by an attacker to violate a trust boundary, as such the DWF feels this issue deserves a CVE.
</code>

- [tylepr96/CVE-2018-1000030](https://github.com/tylepr96/CVE-2018-1000030)

### CVE-2018-1000082

<code>
Ajenti version version 2 contains a Cross ite Request Forgery (CSRF) vulnerability in the command execution panel of the tool used to manage the server. that can result in Code execution on the server . This attack appear to be exploitable via Being a CSRF, victim interaction is needed, when the victim access the infected trigger of the CSRF any code that match the victim privledges on the server can be executed..
</code>

- [SECFORCE/CVE-2018-1000082-exploit](https://github.com/SECFORCE/CVE-2018-1000082-exploit)

### CVE-2018-1000117

<code>
Python Software Foundation CPython version From 3.2 until 3.6.4 on Windows contains a Buffer Overflow vulnerability in os.symlink() function on Windows that can result in Arbitrary code execution, likely escalation of privilege. This attack appears to be exploitable via a python script that creates a symlink with an attacker controlled name or location. This vulnerability appears to have been fixed in 3.7.0 and 3.6.5.
</code>

- [1337r00t/CVE-2018-1000117-Exploit](https://github.com/1337r00t/CVE-2018-1000117-Exploit)

### CVE-2018-1000134

<code>
UnboundID LDAP SDK version from commit 801111d8b5c732266a5dbd4b3bb0b6c7b94d7afb up to commit 8471904a02438c03965d21367890276bc25fa5a6, where the issue was reported and fixed contains an Incorrect Access Control vulnerability in process function in SimpleBindRequest class doesn't check for empty password when running in synchronous mode. commit with applied fix https://github.com/pingidentity/ldapsdk/commit/8471904a02438c03965d21367890276bc25fa5a6#diff-f6cb23b459be1ec17df1da33760087fd that can result in Ability to impersonate any valid user. This attack appear to be exploitable via Providing valid username and empty password against servers that do not do additional validation as per https://tools.ietf.org/html/rfc4513#section-5.1.1. This vulnerability appears to have been fixed in after commit 8471904a02438c03965d21367890276bc25fa5a6.
</code>

- [dragotime/cve-2018-1000134](https://github.com/dragotime/cve-2018-1000134)

### CVE-2018-1000140

<code>
rsyslog librelp version 1.2.14 and earlier contains a Buffer Overflow vulnerability in the checking of x509 certificates from a peer that can result in Remote code execution. This attack appear to be exploitable a remote attacker that can connect to rsyslog and trigger a stack buffer overflow by sending a specially crafted x509 certificate.
</code>

- [s0/rsyslog-librelp-CVE-2018-1000140](https://github.com/s0/rsyslog-librelp-CVE-2018-1000140)
- [s0/rsyslog-librelp-CVE-2018-1000140-fixed](https://github.com/s0/rsyslog-librelp-CVE-2018-1000140-fixed)

### CVE-2018-1000199

<code>
The Linux Kernel version 3.18 contains a dangerous feature vulnerability in modify_user_hw_breakpoint() that can result in crash and possibly memory corruption. This attack appear to be exploitable via local code execution and the ability to use ptrace. This vulnerability appears to have been fixed in git commit f67b15037a7a50c57f72e69a6d59941ad90a0f0f.
</code>

- [dsfau/CVE-2018-1000199](https://github.com/dsfau/CVE-2018-1000199)

### CVE-2018-1000224

<code>
Godot Engine version All versions prior to 2.1.5, all 3.0 versions prior to 3.0.6. contains a Signed/unsigned comparison, wrong buffer size chackes, integer overflow, missing padding initialization vulnerability in (De)Serialization functions (core/io/marshalls.cpp) that can result in DoS (packet of death), possible leak of uninitialized memory. This attack appear to be exploitable via A malformed packet is received over the network by a Godot application that uses built-in serialization (e.g. game server, or game client). Could be triggered by multiplayer opponent. This vulnerability appears to have been fixed in 2.1.5, 3.0.6, master branch after commit feaf03421dda0213382b51aff07bd5a96b29487b.
</code>

- [zann1x/ITS](https://github.com/zann1x/ITS)

### CVE-2018-1000529

<code>
Grails Fields plugin version 2.2.7 contains a Cross Site Scripting (XSS) vulnerability in Using the display tag that can result in XSS . This vulnerability appears to have been fixed in 2.2.8.
</code>

- [martinfrancois/CVE-2018-1000529](https://github.com/martinfrancois/CVE-2018-1000529)

### CVE-2018-1000802

<code>
Python Software Foundation Python (CPython) version 2.7 contains a CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection') vulnerability in shutil module (make_archive function) that can result in Denial of service, Information gain via injection of arbitrary files on the system or entire drive. This attack appear to be exploitable via Passage of unfiltered user input to the function. This vulnerability appears to have been fixed in after commit add531a1e55b0a739b0f42582f1c9747e5649ace.
</code>

- [tna0y/CVE-2018-1000802-PoC](https://github.com/tna0y/CVE-2018-1000802-PoC)

### CVE-2018-1000861

<code>
A code execution vulnerability exists in the Stapler web framework used by Jenkins 2.153 and earlier, LTS 2.138.3 and earlier in stapler/core/src/main/java/org/kohsuke/stapler/MetaClass.java that allows attackers to invoke some methods on Java objects by accessing crafted URLs that were not intended to be invoked this way.
</code>

- [1NTheKut/CVE-2019-1003000_RCE-DETECTION](https://github.com/1NTheKut/CVE-2019-1003000_RCE-DETECTION)

### CVE-2018-1002105

<code>
In all Kubernetes versions prior to v1.10.11, v1.11.5, and v1.12.3, incorrect handling of error responses to proxied upgrade requests in the kube-apiserver allowed specially crafted requests to establish a connection through the Kubernetes API server to backend servers, then send arbitrary requests over the same connection directly to the backend, authenticated with the Kubernetes API server's TLS credentials used to establish the backend connection.
</code>

- [gravitational/cve-2018-1002105](https://github.com/gravitational/cve-2018-1002105)
- [evict/poc_CVE-2018-1002105](https://github.com/evict/poc_CVE-2018-1002105)
- [imlzw/Kubernetes-1.12.3-all-auto-install](https://github.com/imlzw/Kubernetes-1.12.3-all-auto-install)
- [bgeesaman/cve-2018-1002105](https://github.com/bgeesaman/cve-2018-1002105)

### CVE-2018-1010

<code>
A remote code execution vulnerability exists when the Windows font library improperly handles specially crafted embedded fonts, aka &quot;Microsoft Graphics Remote Code Execution Vulnerability.&quot; This affects Windows 7, Windows Server 2012 R2, Windows RT 8.1, Windows Server 2008, Windows Server 2012, Windows 8.1, Windows Server 2016, Windows Server 2008 R2, Windows 10, Windows 10 Servers. This CVE ID is unique from CVE-2018-1012, CVE-2018-1013, CVE-2018-1015, CVE-2018-1016.
</code>

- [ymgh96/Detecting-the-patch-of-CVE-2018-1010](https://github.com/ymgh96/Detecting-the-patch-of-CVE-2018-1010)

### CVE-2018-10118

<code>
Monstra CMS 3.0.4 has Stored XSS via the Name field on the Create New Page screen under the admin/index.php?id=pages URI, related to plugins/box/pages/pages.admin.php.
</code>

- [GeunSam2/CVE-2018-10118](https://github.com/GeunSam2/CVE-2018-10118)

### CVE-2018-1026

<code>
A remote code execution vulnerability exists in Microsoft Office software when the software fails to properly handle objects in memory, aka &quot;Microsoft Office Remote Code Execution Vulnerability.&quot; This affects Microsoft Office. This CVE ID is unique from CVE-2018-1030.
</code>

- [ymgh96/Detecting-the-CVE-2018-1026-and-its-patch](https://github.com/ymgh96/Detecting-the-CVE-2018-1026-and-its-patch)

### CVE-2018-10299

<code>
An integer overflow in the batchTransfer function of a smart contract implementation for Beauty Ecosystem Coin (BEC), the Ethereum ERC20 token used in the Beauty Chain economic system, allows attackers to accomplish an unauthorized increase of digital assets by providing two _receivers arguments in conjunction with a large _value argument, as exploited in the wild in April 2018, aka the &quot;batchOverflow&quot; issue.
</code>

- [phzietsman/batchOverflow](https://github.com/phzietsman/batchOverflow)

### CVE-2018-10388

<code>
Format string vulnerability in the logMess function in TFTP Server SP 1.66 and earlier allows remote attackers to perform a denial of service or execute arbitrary code via format string sequences in a TFTP error packet.
</code>

- [0xddaa/CVE-2018-10388](https://github.com/0xddaa/CVE-2018-10388)

### CVE-2018-10467
- [alt3kx/CVE-2018-10467](https://github.com/alt3kx/CVE-2018-10467)

### CVE-2018-10517

<code>
In CMS Made Simple (CMSMS) through 2.2.7, the &quot;module import&quot; operation in the admin dashboard contains a remote code execution vulnerability, exploitable by an admin user, because an XML Package can contain base64-encoded PHP code in a data element.
</code>

- [0x00-0x00/CVE-2018-10517](https://github.com/0x00-0x00/CVE-2018-10517)

### CVE-2018-10546

<code>
An issue was discovered in PHP before 5.6.36, 7.0.x before 7.0.30, 7.1.x before 7.1.17, and 7.2.x before 7.2.5. An infinite loop exists in ext/iconv/iconv.c because the iconv stream filter does not reject invalid multibyte sequences.
</code>

- [dsfau/CVE-2018-10546](https://github.com/dsfau/CVE-2018-10546)

### CVE-2018-1056

<code>
An out-of-bounds heap buffer read flaw was found in the way advancecomp before 2.1-2018/02 handled processing of ZIP files. An attacker could potentially use this flaw to crash the advzip utility by tricking it into processing crafted ZIP files.
</code>

- [pollonegro/Gpon-Routers](https://github.com/pollonegro/Gpon-Routers)

### CVE-2018-10561

<code>
An issue was discovered on Dasan GPON home routers. It is possible to bypass authentication simply by appending &quot;?images&quot; to any URL of the device that requires authentication, as demonstrated by the /menu.html?images/ or /GponForm/diag_FORM?images/ URI. One can then manage the device.
</code>

- [vhackor/GPON-home-routers-Exploit](https://github.com/vhackor/GPON-home-routers-Exploit)

### CVE-2018-10562

<code>
An issue was discovered on Dasan GPON home routers. Command Injection can occur via the dest_host parameter in a diag_action=ping request to a GponForm/diag_Form URI. Because the router saves ping results in /tmp and transmits them to the user when the user revisits /diag.html, it's quite simple to execute commands and retrieve their output.
</code>

- [f3d0x0/GPON](https://github.com/f3d0x0/GPON)
- [649/Pingpon-Exploit](https://github.com/649/Pingpon-Exploit)
- [Choudai/GPON-LOADER](https://github.com/Choudai/GPON-LOADER)
- [c0ld1/GPON_RCE](https://github.com/c0ld1/GPON_RCE)
- [ATpiu/CVE-2018-10562](https://github.com/ATpiu/CVE-2018-10562)

### CVE-2018-10583

<code>
An information disclosure vulnerability occurs when LibreOffice 6.0.3 and Apache OpenOffice Writer 4.1.5 automatically process and initiate an SMB connection embedded in a malicious file, as demonstrated by xlink:href=file://192.168.0.2/test.jpg within an office:document-content element in a .odt XML document.
</code>

- [TaharAmine/CVE-2018-10583](https://github.com/TaharAmine/CVE-2018-10583)

### CVE-2018-10678

<code>
MyBB 1.8.15, when accessed with Microsoft Edge, mishandles 'target=&quot;_blank&quot; rel=&quot;noopener&quot;' in A elements, which makes it easier for remote attackers to conduct redirection attacks.
</code>

- [hbranco/CVE-2018-10678](https://github.com/hbranco/CVE-2018-10678)

### CVE-2018-10715
- [alt3kx/CVE-2018-10715](https://github.com/alt3kx/CVE-2018-10715)

### CVE-2018-10732

<code>
The REST API in Dataiku DSS before 4.2.3 allows remote attackers to obtain sensitive information (i.e., determine if a username is valid) because of profile pictures visibility.
</code>

- [alt3kx/CVE-2018-10732](https://github.com/alt3kx/CVE-2018-10732)

### CVE-2018-10821

<code>
Cross-site scripting (XSS) vulnerability in backend/pages/modify.php in BlackCatCMS 1.3 allows remote authenticated users with the Admin role to inject arbitrary web script or HTML via the search panel.
</code>

- [BalvinderSingh23/Cross-Site-Scripting-Reflected-XSS-Vulnerability-in-blackcatcms_v1.3](https://github.com/BalvinderSingh23/Cross-Site-Scripting-Reflected-XSS-Vulnerability-in-blackcatcms_v1.3)

### CVE-2018-1088

<code>
A privilege escalation flaw was found in gluster 3.x snapshot scheduler. Any gluster client allowed to mount gluster volumes could also mount shared gluster storage volume and escalate privileges by scheduling malicious cronjob via symlink.
</code>

- [MauroEldritch/GEVAUDAN](https://github.com/MauroEldritch/GEVAUDAN)

### CVE-2018-10920

<code>
Improper input validation bug in DNS resolver component of Knot Resolver before 2.4.1 allows remote attacker to poison cache.
</code>

- [shutingrz/CVE-2018-10920_PoC](https://github.com/shutingrz/CVE-2018-10920_PoC)

### CVE-2018-10933

<code>
A vulnerability was found in libssh's server-side state machine before versions 0.7.6 and 0.8.4. A malicious client could create channels without first performing authentication, resulting in unauthorized access.
</code>

- [SoledaD208/CVE-2018-10933](https://github.com/SoledaD208/CVE-2018-10933)
- [blacknbunny/CVE-2018-10933](https://github.com/blacknbunny/CVE-2018-10933)
- [hook-s3c/CVE-2018-10933](https://github.com/hook-s3c/CVE-2018-10933)
- [kn6869610/CVE-2018-10933](https://github.com/kn6869610/CVE-2018-10933)
- [leapsecurity/libssh-scanner](https://github.com/leapsecurity/libssh-scanner)
- [denmilu/CVE-2018-10933_ssh](https://github.com/denmilu/CVE-2018-10933_ssh)
- [trbpnd/bpnd-libssh](https://github.com/trbpnd/bpnd-libssh)
- [denmilu/CVE-2018-10933-libSSH-Authentication-Bypass](https://github.com/denmilu/CVE-2018-10933-libSSH-Authentication-Bypass)
- [marco-lancini/hunt-for-cve-2018-10933](https://github.com/marco-lancini/hunt-for-cve-2018-10933)
- [hackerhouse-opensource/cve-2018-10933](https://github.com/hackerhouse-opensource/cve-2018-10933)
- [cve-2018/cve-2018-10933](https://github.com/cve-2018/cve-2018-10933)
- [jas502n/CVE-2018-10933](https://github.com/jas502n/CVE-2018-10933)
- [ninp0/cve-2018-10933_poc](https://github.com/ninp0/cve-2018-10933_poc)
- [IDX4CKS/CVE-2018-10933_Scanner](https://github.com/IDX4CKS/CVE-2018-10933_Scanner)
- [Virgula0/POC-CVE-2018-10933](https://github.com/Virgula0/POC-CVE-2018-10933)
- [shifa123/pythonprojects-CVE-2018-10933](https://github.com/shifa123/pythonprojects-CVE-2018-10933)
- [xFreed0m/CVE-2018-10933](https://github.com/xFreed0m/CVE-2018-10933)
- [Bifrozt/CVE-2018-10933](https://github.com/Bifrozt/CVE-2018-10933)
- [r3dxpl0it/CVE-2018-10933](https://github.com/r3dxpl0it/CVE-2018-10933)
- [ivanacostarubio/libssh-scanner](https://github.com/ivanacostarubio/libssh-scanner)
- [throwawayaccount12312312/precompiled-CVE-2018-10933](https://github.com/throwawayaccount12312312/precompiled-CVE-2018-10933)
- [ensimag-security/CVE-2018-10933](https://github.com/ensimag-security/CVE-2018-10933)
- [Ad1bDaw/libSSH-bypass](https://github.com/Ad1bDaw/libSSH-bypass)
- [sambiyal/CVE-2018-10933-POC](https://github.com/sambiyal/CVE-2018-10933-POC)
- [nikhil1232/LibSSH-Authentication-Bypass](https://github.com/nikhil1232/LibSSH-Authentication-Bypass)
- [Kurlee/LibSSH-exploit](https://github.com/Kurlee/LibSSH-exploit)
- [crispy-peppers/Libssh-server-CVE-2018-10933](https://github.com/crispy-peppers/Libssh-server-CVE-2018-10933)
- [youkergav/CVE-2018-10933](https://github.com/youkergav/CVE-2018-10933)
- [kristyna-mlcakova/CVE-2018-10933](https://github.com/kristyna-mlcakova/CVE-2018-10933)
- [lalishasanduwara/CVE-2018-10933](https://github.com/lalishasanduwara/CVE-2018-10933)

### CVE-2018-10936

<code>
A weakness was found in postgresql-jdbc before version 42.2.5. It was possible to provide an SSL Factory and not check the host name if a host name verifier was not provided to the driver. This could lead to a condition where a man-in-the-middle attacker could masquerade as a trusted server by providing a certificate for the wrong host, as long as it was signed by a trusted CA.
</code>

- [tafamace/CVE-2018-10936](https://github.com/tafamace/CVE-2018-10936)

### CVE-2018-10949

<code>
mailboxd in Zimbra Collaboration Suite 8.8 before 8.8.8; 8.7 before 8.7.11.Patch3; and 8.6 allows Account Enumeration by leveraging a Discrepancy between the &quot;HTTP 404 - account is not active&quot; and &quot;HTTP 401 - must authenticate&quot; errors.
</code>

- [0x00-0x00/CVE-2018-10949](https://github.com/0x00-0x00/CVE-2018-10949)

### CVE-2018-1111

<code>
DHCP packages in Red Hat Enterprise Linux 6 and 7, Fedora 28, and earlier are vulnerable to a command injection flaw in the NetworkManager integration script included in the DHCP client. A malicious DHCP server, or an attacker on the local network able to spoof DHCP responses, could use this flaw to execute arbitrary commands with root privileges on systems using NetworkManager and configured to obtain network configuration using the DHCP protocol.
</code>

- [knqyf263/CVE-2018-1111](https://github.com/knqyf263/CVE-2018-1111)
- [kkirsche/CVE-2018-1111](https://github.com/kkirsche/CVE-2018-1111)

### CVE-2018-11235

<code>
In Git before 2.13.7, 2.14.x before 2.14.4, 2.15.x before 2.15.2, 2.16.x before 2.16.4, and 2.17.x before 2.17.1, remote code execution can occur. With a crafted .gitmodules file, a malicious project can execute an arbitrary script on a machine that runs &quot;git clone --recurse-submodules&quot; because submodule &quot;names&quot; are obtained from this file, and then appended to $GIT_DIR/modules, leading to directory traversal with &quot;../&quot; in a name. Finally, post-checkout hooks from a submodule are executed, bypassing the intended design in which hooks are not obtained from a remote server.
</code>

- [Rogdham/CVE-2018-11235](https://github.com/Rogdham/CVE-2018-11235)
- [vmotos/CVE-2018-11235](https://github.com/vmotos/CVE-2018-11235)
- [Choihosu/cve-2018-11235](https://github.com/Choihosu/cve-2018-11235)
- [CHYbeta/CVE-2018-11235-DEMO](https://github.com/CHYbeta/CVE-2018-11235-DEMO)
- [Kiss-sh0t/CVE-2018-11235-poc](https://github.com/Kiss-sh0t/CVE-2018-11235-poc)
- [H0K5/clone_and_pwn](https://github.com/H0K5/clone_and_pwn)
- [knqyf263/CVE-2018-11235](https://github.com/knqyf263/CVE-2018-11235)
- [ygouzerh/CVE-2018-11235](https://github.com/ygouzerh/CVE-2018-11235)
- [qweraqq/CVE-2018-11235-Git-Submodule-CE](https://github.com/qweraqq/CVE-2018-11235-Git-Submodule-CE)
- [jhswartz/CVE-2018-11235](https://github.com/jhswartz/CVE-2018-11235)
- [AnonymKing/CVE-2018-11235](https://github.com/AnonymKing/CVE-2018-11235)
- [morhax/CVE-2018-11235](https://github.com/morhax/CVE-2018-11235)
- [cchang27/CVE-2018-11235-test](https://github.com/cchang27/CVE-2018-11235-test)
- [nthuong95/CVE-2018-11235](https://github.com/nthuong95/CVE-2018-11235)

### CVE-2018-11236

<code>
stdlib/canonicalize.c in the GNU C Library (aka glibc or libc6) 2.27 and earlier, when processing very long pathname arguments to the realpath function, could encounter an integer overflow on 32-bit architectures, leading to a stack-based buffer overflow and, potentially, arbitrary code execution.
</code>

- [evilmiracle/CVE-2018-11236](https://github.com/evilmiracle/CVE-2018-11236)

### CVE-2018-11311

<code>
A hardcoded FTP username of myscada and password of Vikuk63 in 'myscadagate.exe' in mySCADA myPRO 7 allows remote attackers to access the FTP server on port 2121, and upload files or list directories, by entering these credentials.
</code>

- [EmreOvunc/mySCADA-myPRO-7-Hardcoded-FTP-Username-and-Password](https://github.com/EmreOvunc/mySCADA-myPRO-7-Hardcoded-FTP-Username-and-Password)

### CVE-2018-1133

<code>
An issue was discovered in Moodle 3.x. A Teacher creating a Calculated question can intentionally cause remote code execution on the server, aka eval injection.
</code>

- [darrynten/MoodleExploit](https://github.com/darrynten/MoodleExploit)
- [M4LV0/MOODLE-3.X-Remote-Code-Execution](https://github.com/M4LV0/MOODLE-3.X-Remote-Code-Execution)

### CVE-2018-11450

<code>
A reflected Cross-Site-Scripting (XSS) vulnerability has been identified in Siemens PLM Software TEAMCENTER (V9.1.2.5). If a user visits the login portal through the URL crafted by the attacker, the attacker can insert html/javascript and thus alter/rewrite the login portal page. Siemens PLM Software TEAMCENTER V9.1.3 and newer are not affected.
</code>

- [LucvanDonk/Siemens-Siemens-PLM-Software-TEAMCENTER-Reflected-Cross-Site-Scripting-XSS-vulnerability](https://github.com/LucvanDonk/Siemens-Siemens-PLM-Software-TEAMCENTER-Reflected-Cross-Site-Scripting-XSS-vulnerability)

### CVE-2018-11510

<code>
The ASUSTOR ADM 3.1.0.RFQ3 NAS portal suffers from an unauthenticated remote code execution vulnerability in the portal/apis/aggrecate_js.cgi file by embedding OS commands in the 'script' parameter.
</code>

- [mefulton/CVE-2018-11510](https://github.com/mefulton/CVE-2018-11510)

### CVE-2018-11517

<code>
mySCADA myPRO 7 allows remote attackers to discover all ProjectIDs in a project by sending all of the prj parameter values from 870000 to 875000 in t=0&amp;rq=0 requests to TCP port 11010.
</code>

- [EmreOvunc/mySCADA-myPRO-7-projectID-Disclosure](https://github.com/EmreOvunc/mySCADA-myPRO-7-projectID-Disclosure)

### CVE-2018-11564

<code>
Stored XSS in YOOtheme Pagekit 1.0.13 and earlier allows a user to upload malicious code via the picture upload feature. A user with elevated privileges could upload a photo to the system in an SVG format. This file will be uploaded to the system and it will not be stripped or filtered. The user can create a link on the website pointing to &quot;/storage/poc.svg&quot; that will point to http://localhost/pagekit/storage/poc.svg. When a user comes along to click that link, it will trigger a XSS attack.
</code>

- [GeunSam2/CVE-2018-11564](https://github.com/GeunSam2/CVE-2018-11564)

### CVE-2018-1160

<code>
Netatalk before 3.1.12 is vulnerable to an out of bounds write in dsi_opensess.c. This is due to lack of bounds checking on attacker controlled data. A remote unauthenticated attacker can leverage this vulnerability to achieve arbitrary code execution.
</code>

- [SachinThanushka/CVE-2018-1160](https://github.com/SachinThanushka/CVE-2018-1160)

### CVE-2018-11631

<code>
Rondaful M1 Wristband Smart Band 1 devices allow remote attackers to send an arbitrary number of call or SMS notifications via crafted Bluetooth Low Energy (BLE) traffic.
</code>

- [xMagass/bandexploit](https://github.com/xMagass/bandexploit)

### CVE-2018-11686

<code>
The Publish Service in FlexPaper (later renamed FlowPaper) 2.3.6 allows remote code execution via setup.php and change_config.php.
</code>

- [mpgn/CVE-2018-11686](https://github.com/mpgn/CVE-2018-11686)

### CVE-2018-11759

<code>
The Apache Web Server (httpd) specific code that normalised the requested path before matching it to the URI-worker map in Apache Tomcat JK (mod_jk) Connector 1.2.0 to 1.2.44 did not handle some edge cases correctly. If only a sub-set of the URLs supported by Tomcat were exposed via httpd, then it was possible for a specially constructed request to expose application functionality through the reverse proxy that was not intended for clients accessing the application via the reverse proxy. It was also possible in some configurations for a specially constructed request to bypass the access controls configured in httpd. While there is some overlap between this issue and CVE-2018-1323, they are not identical.
</code>

- [immunIT/CVE-2018-11759](https://github.com/immunIT/CVE-2018-11759)
- [Jul10l1r4/Identificador-CVE-2018-11759](https://github.com/Jul10l1r4/Identificador-CVE-2018-11759)

### CVE-2018-11761

<code>
In Apache Tika 0.1 to 1.18, the XML parsers were not configured to limit entity expansion. They were therefore vulnerable to an entity expansion vulnerability which can lead to a denial of service attack.
</code>

- [brianwrf/CVE-2018-11761](https://github.com/brianwrf/CVE-2018-11761)

### CVE-2018-11770

<code>
From version 1.3.0 onward, Apache Spark's standalone master exposes a REST API for job submission, in addition to the submission mechanism used by spark-submit. In standalone, the config property 'spark.authenticate.secret' establishes a shared secret for authenticating requests to submit jobs via spark-submit. However, the REST API does not use this or any other authentication mechanism, and this is not adequately documented. In this case, a user would be able to run a driver program without authenticating, but not launch executors, using the REST API. This REST API is also used by Mesos, when set up to run in cluster mode (i.e., when also running MesosClusterDispatcher), for job submission. Future versions of Spark will improve documentation on these points, and prohibit setting 'spark.authenticate.secret' when running the REST APIs, to make this clear. Future versions will also disable the REST API by default in the standalone master by changing the default value of 'spark.master.rest.enabled' to 'false'.
</code>

- [ivanitlearning/CVE-2018-11770](https://github.com/ivanitlearning/CVE-2018-11770)

### CVE-2018-11776

<code>
Apache Struts versions 2.3 to 2.3.34 and 2.5 to 2.5.16 suffer from possible Remote Code Execution when alwaysSelectFullNamespace is true (either by user or a plugin like Convention Plugin) and then: results are used with no namespace and in same time, its upper package have no or wildcard namespace and similar to results, same possibility when using url tag which doesn't have value and action set and in same time, its upper package have no or wildcard namespace.
</code>

- [trbpnd/CVE-2018-11776](https://github.com/trbpnd/CVE-2018-11776)
- [xfox64x/CVE-2018-11776](https://github.com/xfox64x/CVE-2018-11776)
- [jiguangin/CVE-2018-11776](https://github.com/jiguangin/CVE-2018-11776)
- [hook-s3c/CVE-2018-11776-Python-PoC](https://github.com/hook-s3c/CVE-2018-11776-Python-PoC)
- [mazen160/struts-pwn_CVE-2018-11776](https://github.com/mazen160/struts-pwn_CVE-2018-11776)
- [bhdresh/CVE-2018-11776](https://github.com/bhdresh/CVE-2018-11776)
- [knqyf263/CVE-2018-11776](https://github.com/knqyf263/CVE-2018-11776)
- [Ekultek/Strutter](https://github.com/Ekultek/Strutter)
- [tuxotron/cve-2018-11776-docker](https://github.com/tuxotron/cve-2018-11776-docker)
- [brianwrf/S2-057-CVE-2018-11776](https://github.com/brianwrf/S2-057-CVE-2018-11776)
- [649/Apache-Struts-Shodan-Exploit](https://github.com/649/Apache-Struts-Shodan-Exploit)
- [jezzus/CVE-2018-11776-Python-PoC](https://github.com/jezzus/CVE-2018-11776-Python-PoC)
- [cved-sources/cve-2018-11776](https://github.com/cved-sources/cve-2018-11776)
- [OzNetNerd/apche-struts-vuln-demo-cve-2018-11776](https://github.com/OzNetNerd/apche-struts-vuln-demo-cve-2018-11776)
- [cucadili/CVE-2018-11776](https://github.com/cucadili/CVE-2018-11776)
- [LightC0der/Apache-Struts-0Day-Exploit](https://github.com/LightC0der/Apache-Struts-0Day-Exploit)

### CVE-2018-11788

<code>
Apache Karaf provides a features deployer, which allows users to &quot;hot deploy&quot; a features XML by dropping the file directly in the deploy folder. The features XML is parsed by XMLInputFactory class. Apache Karaf XMLInputFactory class doesn't contain any mitigation codes against XXE. This is a potential security risk as an user can inject external XML entities in Apache Karaf version prior to 4.1.7 or 4.2.2. It has been fixed in Apache Karaf 4.1.7 and 4.2.2 releases.
</code>

- [brianwrf/CVE-2018-11788](https://github.com/brianwrf/CVE-2018-11788)

### CVE-2018-11882

<code>
Incorrect bound check can lead to potential buffer overwrite in WLAN controller in Snapdragon Mobile in version SD 835, SD 845, SD 850, SDA660.
</code>

- [jguard01/cve-2018-11882](https://github.com/jguard01/cve-2018-11882)

### CVE-2018-12018

<code>
The GetBlockHeadersMsg handler in the LES protocol implementation in Go Ethereum (aka geth) before 1.8.11 may lead to an access violation because of an integer signedness error for the array index, which allows attackers to launch a Denial of Service attack by sending a packet with a -1 query.Skip value. The vulnerable remote node would be crashed by such an attack immediately, aka the EPoD (Ethereum Packet of Death) issue.
</code>

- [k3v142/CVE-2018-12018](https://github.com/k3v142/CVE-2018-12018)

### CVE-2018-12031

<code>
Local file inclusion in Eaton Intelligent Power Manager v1.6 allows an attacker to include a file via server/node_upgrade_srv.js directory traversal with the firmware parameter in a downloadFirmware action.
</code>

- [EmreOvunc/Eaton-Intelligent-Power-Manager-Local-File-Inclusion](https://github.com/EmreOvunc/Eaton-Intelligent-Power-Manager-Local-File-Inclusion)

### CVE-2018-12038

<code>
An issue was discovered on Samsung 840 EVO devices. Vendor-specific commands may allow access to the disk-encryption key.
</code>

- [gdraperi/remote-bitlocker-encryption-report](https://github.com/gdraperi/remote-bitlocker-encryption-report)

### CVE-2018-12086

<code>
Buffer overflow in OPC UA applications allows remote attackers to trigger a stack overflow with carefully structured requests.
</code>

- [kevinherron/stack-overflow-poc](https://github.com/kevinherron/stack-overflow-poc)

### CVE-2018-1235

<code>
Dell EMC RecoverPoint versions prior to 5.1.2 and RecoverPoint for VMs versions prior to 5.1.1.3, contain a command injection vulnerability. An unauthenticated remote attacker may potentially exploit this vulnerability to execute arbitrary commands on the affected system with root privilege.
</code>

- [AbsoZed/CVE-2018-1235](https://github.com/AbsoZed/CVE-2018-1235)

### CVE-2018-12386

<code>
A vulnerability in register allocation in JavaScript can lead to type confusion, allowing for an arbitrary read and write. This leads to remote code execution inside the sandboxed content process when triggered. This vulnerability affects Firefox ESR &lt; 60.2.2 and Firefox &lt; 62.0.3.
</code>

- [Hydra3evil/cve-2018-12386](https://github.com/Hydra3evil/cve-2018-12386)
- [0xLyte/cve-2018-12386](https://github.com/0xLyte/cve-2018-12386)

### CVE-2018-12418

<code>
Archive.java in Junrar before 1.0.1, as used in Apache Tika and other products, is affected by a denial of service vulnerability due to an infinite loop when handling corrupt RAR files.
</code>

- [tafamace/CVE-2018-12418](https://github.com/tafamace/CVE-2018-12418)

### CVE-2018-12463

<code>
An XML external entity (XXE) vulnerability in Fortify Software Security Center (SSC), version 17.1, 17.2, 18.1 allows remote unauthenticated users to read arbitrary files or conduct server-side request forgery (SSRF) attacks via a crafted DTD in an XML request.
</code>

- [alt3kx/CVE-2018-12463](https://github.com/alt3kx/CVE-2018-12463)

### CVE-2018-12533

<code>
JBoss RichFaces 3.1.0 through 3.3.4 allows unauthenticated remote attackers to inject expression language (EL) expressions and execute arbitrary Java code via a /DATA/ substring in a path with an org.richfaces.renderkit.html.Paint2DResource$ImageData object, aka RF-14310.
</code>

- [TheKalin/CVE-2018-12533](https://github.com/TheKalin/CVE-2018-12533)

### CVE-2018-12537

<code>
In Eclipse Vert.x version 3.0 to 3.5.1, the HttpServer response headers and HttpClient request headers do not filter carriage return and line feed characters from the header value. This allow unfiltered values to inject a new header in the client request or server response.
</code>

- [tafamace/CVE-2018-12537](https://github.com/tafamace/CVE-2018-12537)

### CVE-2018-12540

<code>
In version from 3.0.0 to 3.5.2 of Eclipse Vert.x, the CSRFHandler do not assert that the XSRF Cookie matches the returned XSRF header/form parameter. This allows replay attacks with previously issued tokens which are not expired yet.
</code>

- [tafamace/CVE-2018-12540](https://github.com/tafamace/CVE-2018-12540)

### CVE-2018-1259

<code>
Spring Data Commons, versions 1.13 prior to 1.13.12 and 2.0 prior to 2.0.7, used in combination with XMLBeam 1.4.14 or earlier versions, contains a property binder vulnerability caused by improper restriction of XML external entity references as underlying library XMLBeam does not restrict external reference expansion. An unauthenticated remote malicious user can supply specially crafted request parameters against Spring Data's projection-based request payload binding to access arbitrary files on the system.
</code>

- [tafamace/CVE-2018-1259](https://github.com/tafamace/CVE-2018-1259)

### CVE-2018-12596

<code>
Episerver Ektron CMS before 9.0 SP3 Site CU 31, 9.1 before SP3 Site CU 45, or 9.2 before SP2 Site CU 22 allows remote attackers to call aspx pages via the &quot;activateuser.aspx&quot; page, even if a page is located under the /WorkArea/ path, which is forbidden (normally available exclusively for local admins).
</code>

- [alt3kx/CVE-2018-12596](https://github.com/alt3kx/CVE-2018-12596)

### CVE-2018-12597
- [alt3kx/CVE-2018-12597](https://github.com/alt3kx/CVE-2018-12597)

### CVE-2018-12598
- [alt3kx/CVE-2018-12598](https://github.com/alt3kx/CVE-2018-12598)

### CVE-2018-12613

<code>
An issue was discovered in phpMyAdmin 4.8.x before 4.8.2, in which an attacker can include (view and potentially execute) files on the server. The vulnerability comes from a portion of code where pages are redirected and loaded within phpMyAdmin, and an improper test for whitelisted pages. An attacker must be authenticated, except in the &quot;$cfg['AllowArbitraryServer'] = true&quot; case (where an attacker can specify any host he/she is already in control of, and execute arbitrary code on phpMyAdmin) and the &quot;$cfg['ServerDefault'] = 0&quot; case (which bypasses the login requirement and runs the vulnerable code without any authentication).
</code>

- [0x00-0x00/CVE-2018-12613](https://github.com/0x00-0x00/CVE-2018-12613)
- [ivanitlearning/CVE-2018-12613](https://github.com/ivanitlearning/CVE-2018-12613)
- [eastmountyxz/CVE-2018-12613-phpMyAdmin](https://github.com/eastmountyxz/CVE-2018-12613-phpMyAdmin)

### CVE-2018-1270

<code>
Spring Framework, versions 5.0 prior to 5.0.5 and versions 4.3 prior to 4.3.15 and older unsupported versions, allow applications to expose STOMP over WebSocket endpoints with a simple, in-memory STOMP broker through the spring-messaging module. A malicious user (or attacker) can craft a message to the broker that can lead to a remote code execution attack.
</code>

- [CaledoniaProject/CVE-2018-1270](https://github.com/CaledoniaProject/CVE-2018-1270)
- [genxor/CVE-2018-1270_EXP](https://github.com/genxor/CVE-2018-1270_EXP)
- [tafamace/CVE-2018-1270](https://github.com/tafamace/CVE-2018-1270)
- [Venscor/CVE-2018-1270](https://github.com/Venscor/CVE-2018-1270)

### CVE-2018-1273

<code>
Spring Data Commons, versions prior to 1.13 to 1.13.10, 2.0 to 2.0.5, and older unsupported versions, contain a property binder vulnerability caused by improper neutralization of special elements. An unauthenticated remote malicious user (or attacker) can supply specially crafted request parameters against Spring Data REST backed HTTP resources or using Spring Data's projection-based request payload binding hat can lead to a remote code execution attack.
</code>

- [knqyf263/CVE-2018-1273](https://github.com/knqyf263/CVE-2018-1273)
- [wearearima/poc-cve-2018-1273](https://github.com/wearearima/poc-cve-2018-1273)
- [webr0ck/poc-cve-2018-1273](https://github.com/webr0ck/poc-cve-2018-1273)
- [cved-sources/cve-2018-1273](https://github.com/cved-sources/cve-2018-1273)
- [jas502n/cve-2018-1273](https://github.com/jas502n/cve-2018-1273)

### CVE-2018-12798

<code>
Adobe Acrobat and Reader 2018.011.20040 and earlier, 2017.011.30080 and earlier, and 2015.006.30418 and earlier versions have a Heap Overflow vulnerability. Successful exploitation could lead to arbitrary code execution in the context of the current user.
</code>

- [sharmasandeepkr/cve-2018-12798](https://github.com/sharmasandeepkr/cve-2018-12798)

### CVE-2018-1288

<code>
In Apache Kafka 0.9.0.0 to 0.9.0.1, 0.10.0.0 to 0.10.2.1, 0.11.0.0 to 0.11.0.2, and 1.0.0, authenticated Kafka users may perform action reserved for the Broker via a manually created fetch request interfering with data replication, resulting in data loss.
</code>

- [joegallagher4/CVE-2018-1288-](https://github.com/joegallagher4/CVE-2018-1288-)

### CVE-2018-12895

<code>
WordPress through 4.9.6 allows Author users to execute arbitrary code by leveraging directory traversal in the wp-admin/post.php thumb parameter, which is passed to the PHP unlink function and can delete the wp-config.php file. This is related to missing filename validation in the wp-includes/post.php wp_delete_attachment function. The attacker must have capabilities for files and posts that are normally available only to the Author, Editor, and Administrator roles. The attack methodology is to delete wp-config.php and then launch a new installation process to increase the attacker's privileges.
</code>

- [bloom-ux/cve-2018-12895-hotfix](https://github.com/bloom-ux/cve-2018-12895-hotfix)

### CVE-2018-12914

<code>
A remote code execution issue was discovered in PublicCMS V4.0.20180210. An attacker can upload a ZIP archive that contains a .jsp file with a directory traversal pathname. After an unzip operation, the attacker can execute arbitrary code by visiting a .jsp URI.
</code>

- [RealBearcat/CVE-2018-12914](https://github.com/RealBearcat/CVE-2018-12914)

### CVE-2018-1304

<code>
The URL pattern of &quot;&quot; (the empty string) which exactly maps to the context root was not correctly handled in Apache Tomcat 9.0.0.M1 to 9.0.4, 8.5.0 to 8.5.27, 8.0.0.RC1 to 8.0.49 and 7.0.0 to 7.0.84 when used as part of a security constraint definition. This caused the constraint to be ignored. It was, therefore, possible for unauthorised users to gain access to web application resources that should have been protected. Only security constraints with a URL pattern of the empty string were affected.
</code>

- [knqyf263/CVE-2018-1304](https://github.com/knqyf263/CVE-2018-1304)
- [thariyarox/tomcat_CVE-2018-1304_testing](https://github.com/thariyarox/tomcat_CVE-2018-1304_testing)

### CVE-2018-1305

<code>
Security constraints defined by annotations of Servlets in Apache Tomcat 9.0.0.M1 to 9.0.4, 8.5.0 to 8.5.27, 8.0.0.RC1 to 8.0.49 and 7.0.0 to 7.0.84 were only applied once a Servlet had been loaded. Because security constraints defined in this way apply to the URL pattern and any URLs below that point, it was possible - depending on the order Servlets were loaded - for some security constraints not to be applied. This could have exposed resources to users who were not authorised to access them.
</code>

- [RealBearcat/CVE-2018-1305](https://github.com/RealBearcat/CVE-2018-1305)

### CVE-2018-1306

<code>
The PortletV3AnnotatedDemo Multipart Portlet war file code provided in Apache Pluto version 3.0.0 could allow a remote attacker to obtain sensitive information, caused by the failure to restrict path information provided during a file upload. An attacker could exploit this vulnerability to obtain configuration data and other sensitive information.
</code>

- [JJSO12/Apache-Pluto-3.0.0--CVE-2018-1306](https://github.com/JJSO12/Apache-Pluto-3.0.0--CVE-2018-1306)

### CVE-2018-1313

<code>
In Apache Derby 10.3.1.4 to 10.14.1.0, a specially-crafted network packet can be used to request the Derby Network Server to boot a database whose location and contents are under the user's control. If the Derby Network Server is not running with a Java Security Manager policy file, the attack is successful. If the server is using a policy file, the policy file must permit the database location to be read for the attack to work. The default Derby Network Server policy file distributed with the affected releases includes a permissive policy as the default Network Server policy, which allows the attack to work.
</code>

- [tafamace/CVE-2018-1313](https://github.com/tafamace/CVE-2018-1313)

### CVE-2018-1324

<code>
A specially crafted ZIP archive can be used to cause an infinite loop inside of Apache Commons Compress' extra field parser used by the ZipFile and ZipArchiveInputStream classes in versions 1.11 to 1.15. This can be used to mount a denial of service attack against services that use Compress' zip package.
</code>

- [tafamace/CVE-2018-1324](https://github.com/tafamace/CVE-2018-1324)

### CVE-2018-13257

<code>
The bb-auth-provider-cas authentication module within Blackboard Learn 2018-07-02 is susceptible to HTTP host header spoofing during Central Authentication Service (CAS) service ticket validation, enabling a phishing attack from the CAS server login page.
</code>

- [gluxon/CVE-2018-13257](https://github.com/gluxon/CVE-2018-13257)

### CVE-2018-1327

<code>
The Apache Struts REST Plugin is using XStream library which is vulnerable and allow perform a DoS attack when using a malicious request with specially crafted XML payload. Upgrade to the Apache Struts version 2.5.16 and switch to an optional Jackson XML handler as described here http://struts.apache.org/plugins/rest/#custom-contenttypehandlers. Another option is to implement a custom XML handler based on the Jackson XML handler from the Apache Struts 2.5.16.
</code>

- [RealBearcat/S2-056-XStream](https://github.com/RealBearcat/S2-056-XStream)

### CVE-2018-13341

<code>
Crestron TSW-X60 all versions prior to 2.001.0037.001 and MC3 all versions prior to 1.502.0047.00, The passwords for special sudo accounts may be calculated using information accessible to those with regular user privileges. Attackers could decipher these passwords, which may allow them to execute hidden API calls and escape the CTP console sandbox environment with elevated privileges.
</code>

- [axcheron/crestron_getsudopwd](https://github.com/axcheron/crestron_getsudopwd)

### CVE-2018-1335

<code>
From Apache Tika versions 1.7 to 1.17, clients could send carefully crafted headers to tika-server that could be used to inject commands into the command line of the server running tika-server. This vulnerability only affects those running tika-server on a server that is open to untrusted clients. The mitigation is to upgrade to Tika 1.18.
</code>

- [SkyBlueEternal/CVE-2018-1335-EXP-GUI](https://github.com/SkyBlueEternal/CVE-2018-1335-EXP-GUI)
- [GEIGEI123/CVE-2018-1335-Python3](https://github.com/GEIGEI123/CVE-2018-1335-Python3)

### CVE-2018-13379

<code>
An Improper Limitation of a Pathname to a Restricted Directory (&quot;Path Traversal&quot;) in Fortinet FortiOS 6.0.0 to 6.0.4, 5.6.3 to 5.6.7 and 5.4.6 to 5.4.12 under SSL VPN web portal allows an unauthenticated attacker to download system files via special crafted HTTP resource requests.
</code>

- [milo2012/CVE-2018-13379](https://github.com/milo2012/CVE-2018-13379)
- [jpiechowka/at-doom-fortigate](https://github.com/jpiechowka/at-doom-fortigate)
- [0xHunter/FortiOS-Credentials-Disclosure](https://github.com/0xHunter/FortiOS-Credentials-Disclosure)
- [Blazz3/cve2018-13379-nmap-script](https://github.com/Blazz3/cve2018-13379-nmap-script)

### CVE-2018-13382

<code>
An Improper Authorization vulnerability in Fortinet FortiOS 6.0.0 to 6.0.4, 5.6.0 to 5.6.8 and 5.4.1 to 5.4.10 under SSL VPN web portal allows an unauthenticated attacker to modify the password of an SSL VPN web portal user via specially crafted HTTP requests.
</code>

- [milo2012/CVE-2018-13382](https://github.com/milo2012/CVE-2018-13382)

### CVE-2018-13410

<code>
** DISPUTED ** Info-ZIP Zip 3.0, when the -T and -TT command-line options are used, allows attackers to cause a denial of service (invalid free and application crash) or possibly have unspecified other impact because of an off-by-one error. NOTE: it is unclear whether there are realistic scenarios in which an untrusted party controls the -TT value, given that the entire purpose of -TT is execution of arbitrary commands.
</code>

- [shinecome/zip](https://github.com/shinecome/zip)

### CVE-2018-13784

<code>
PrestaShop before 1.6.1.20 and 1.7.x before 1.7.3.4 mishandles cookie encryption in Cookie.php, Rinjdael.php, and Blowfish.php.
</code>

- [ambionics/prestashop-exploits](https://github.com/ambionics/prestashop-exploits)

### CVE-2018-13864

<code>
A directory traversal vulnerability has been found in the Assets controller in Play Framework 2.6.12 through 2.6.15 (fixed in 2.6.16) when running on Windows. It allows a remote attacker to download arbitrary files from the target server via specially crafted HTTP requests.
</code>

- [tafamace/CVE-2018-13864](https://github.com/tafamace/CVE-2018-13864)

### CVE-2018-14
- [lckJack/legacySymfony](https://github.com/lckJack/legacySymfony)

### CVE-2018-14083

<code>
LICA miniCMTS E8K(u/i/...) devices allow remote attackers to obtain sensitive information via a direct POST request for the inc/user.ini file, leading to discovery of a password hash.
</code>

- [pudding2/CVE-2018-14083](https://github.com/pudding2/CVE-2018-14083)

### CVE-2018-14442

<code>
Foxit Reader before 9.2 and PhantomPDF before 9.2 have a Use-After-Free that leads to Remote Code Execution, aka V-88f4smlocs.
</code>

- [payatu/CVE-2018-14442](https://github.com/payatu/CVE-2018-14442)
- [sharmasandeepkr/PS-2018-002---CVE-2018-14442](https://github.com/sharmasandeepkr/PS-2018-002---CVE-2018-14442)

### CVE-2018-14634

<code>
An integer overflow flaw was found in the Linux kernel's create_elf_tables() function. An unprivileged local user with access to SUID (or otherwise privileged) binary could use this flaw to escalate their privileges on the system. Kernel versions 2.6.x, 3.10.x and 4.14.x are believed to be vulnerable.
</code>

- [luan0ap/cve-2018-14634](https://github.com/luan0ap/cve-2018-14634)

### CVE-2018-14665

<code>
A flaw was found in xorg-x11-server before 1.20.3. An incorrect permission check for -modulepath and -logfile options when starting Xorg. X server allows unprivileged users with the ability to log in to the system via physical console to escalate their privileges and run arbitrary code under root privileges.
</code>

- [jas502n/CVE-2018-14665](https://github.com/jas502n/CVE-2018-14665)
- [bolonobolo/CVE-2018-14665](https://github.com/bolonobolo/CVE-2018-14665)
- [samueldustin/cve-2018-14665](https://github.com/samueldustin/cve-2018-14665)

### CVE-2018-14667

<code>
The RichFaces Framework 3.X through 3.3.4 is vulnerable to Expression Language (EL) injection via the UserResource resource. A remote, unauthenticated attacker could exploit this to execute arbitrary code using a chain of java serialized objects via org.ajax4jsf.resource.UserResource$UriData.
</code>

- [nareshmail/cve-2018-14667](https://github.com/nareshmail/cve-2018-14667)
- [zeroto01/CVE-2018-14667](https://github.com/zeroto01/CVE-2018-14667)
- [r00t4dm/CVE-2018-14667](https://github.com/r00t4dm/CVE-2018-14667)
- [syriusbughunt/CVE-2018-14667](https://github.com/syriusbughunt/CVE-2018-14667)
- [quandqn/cve-2018-14667](https://github.com/quandqn/cve-2018-14667)
- [Venscor/CVE-2018-14667-poc](https://github.com/Venscor/CVE-2018-14667-poc)

### CVE-2018-14714

<code>
System command injection in appGet.cgi on ASUS RT-AC3200 version 3.0.0.4.382.50010 allows attackers to execute system commands via the &quot;load_script&quot; URL parameter.
</code>

- [tin-z/CVE-2018-14714-POC](https://github.com/tin-z/CVE-2018-14714-POC)

### CVE-2018-14729

<code>
The database backup feature in upload/source/admincp/admincp_db.php in Discuz! 2.5 and 3.4 allows remote attackers to execute arbitrary PHP code.
</code>

- [FoolMitAh/CVE-2018-14729](https://github.com/FoolMitAh/CVE-2018-14729)

### CVE-2018-14772

<code>
Pydio 4.2.1 through 8.2.1 has an authenticated remote code execution vulnerability in which an attacker with administrator access to the web application can execute arbitrary code on the underlying system via Command Injection.
</code>

- [spencerdodd/CVE-2018-14772](https://github.com/spencerdodd/CVE-2018-14772)

### CVE-2018-14847

<code>
MikroTik RouterOS through 6.42 allows unauthenticated remote attackers to read arbitrary files and remote authenticated attackers to write arbitrary files due to a directory traversal vulnerability in the WinBox interface.
</code>

- [BasuCert/WinboxPoC](https://github.com/BasuCert/WinboxPoC)
- [msterusky/WinboxExploit](https://github.com/msterusky/WinboxExploit)
- [syrex1013/MikroRoot](https://github.com/syrex1013/MikroRoot)
- [jas502n/CVE-2018-14847](https://github.com/jas502n/CVE-2018-14847)
- [th3f3n1x87/winboxPOC](https://github.com/th3f3n1x87/winboxPOC)
- [krnull/mikrotik-beast](https://github.com/krnull/mikrotik-beast)
- [sinichi449/Python-MikrotikLoginExploit](https://github.com/sinichi449/Python-MikrotikLoginExploit)
- [yukar1z0e/CVE-2018-14847](https://github.com/yukar1z0e/CVE-2018-14847)

### CVE-2018-15131

<code>
An issue was discovered in Synacor Zimbra Collaboration Suite 8.6.x before 8.6.0 Patch 11, 8.7.x before 8.7.11 Patch 6, 8.8.x before 8.8.8 Patch 9, and 8.8.9 before 8.8.9 Patch 3. Account number enumeration is possible via inconsistent responses for specific types of authentication requests.
</code>

- [0x00-0x00/CVE-2018-15131](https://github.com/0x00-0x00/CVE-2018-15131)

### CVE-2018-15133

<code>
In Laravel Framework through 5.5.40 and 5.6.x through 5.6.29, remote code execution might occur as a result of an unserialize call on a potentially untrusted X-XSRF-TOKEN value. This involves the decrypt method in Illuminate/Encryption/Encrypter.php and PendingBroadcast in gadgetchains/Laravel/RCE/3/chain.php in phpggc. The attacker must know the application key, which normally would never occur, but could happen if the attacker previously had privileged access or successfully accomplished a previous attack.
</code>

- [kozmic/laravel-poc-CVE-2018-15133](https://github.com/kozmic/laravel-poc-CVE-2018-15133)
- [sKirua/Laravel-CVE-2018-15133](https://github.com/sKirua/Laravel-CVE-2018-15133)
- [Prabesh01/Laravel-PHP-Unit-RCE-Auto-shell-uploader](https://github.com/Prabesh01/Laravel-PHP-Unit-RCE-Auto-shell-uploader)
- [iansangaji/laravel-rce-cve-2018-15133](https://github.com/iansangaji/laravel-rce-cve-2018-15133)

### CVE-2018-15365

<code>
A Reflected Cross-Site Scripting (XSS) vulnerability in Trend Micro Deep Discovery Inspector 3.85 and below could allow an attacker to bypass CSRF protection and conduct an attack on vulnerable installations. An attacker must be an authenticated user in order to exploit the vulnerability.
</code>

- [nixwizard/CVE-2018-15365](https://github.com/nixwizard/CVE-2018-15365)

### CVE-2018-15473

<code>
OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid authenticating user until after the packet containing the request has been fully parsed, related to auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c.
</code>

- [trimstray/massh-enum](https://github.com/trimstray/massh-enum)
- [gbonacini/opensshenum](https://github.com/gbonacini/opensshenum)
- [Rhynorater/CVE-2018-15473-Exploit](https://github.com/Rhynorater/CVE-2018-15473-Exploit)
- [epi052/cve-2018-15473](https://github.com/epi052/cve-2018-15473)
- [pyperanger/CVE-2018-15473_exploit](https://github.com/pyperanger/CVE-2018-15473_exploit)
- [r3dxpl0it/CVE-2018-15473](https://github.com/r3dxpl0it/CVE-2018-15473)
- [JoeBlackSecurity/CrappyCode](https://github.com/JoeBlackSecurity/CrappyCode)
- [JoeBlackSecurity/SSHUsernameBruter-SSHUB](https://github.com/JoeBlackSecurity/SSHUsernameBruter-SSHUB)
- [cved-sources/cve-2018-15473](https://github.com/cved-sources/cve-2018-15473)
- [LINYIKAI/CVE-2018-15473-exp](https://github.com/LINYIKAI/CVE-2018-15473-exp)
- [securemode/enumpossible](https://github.com/securemode/enumpossible)
- [trickster1103/-](https://github.com/trickster1103/-)
- [NHPT/SSH-account-enumeration-verification-script](https://github.com/NHPT/SSH-account-enumeration-verification-script)
- [CaioCGH/EP4-redes](https://github.com/CaioCGH/EP4-redes)
- [Moon1705/easy_security](https://github.com/Moon1705/easy_security)

### CVE-2018-15499

<code>
GEAR Software products that include GEARAspiWDM.sys, 2.2.5.0, allow local users to cause a denial of service (Race Condition and BSoD on Windows) by not checking that user-mode memory is available right before writing to it. A check is only performed at the beginning of a long subroutine.
</code>

- [DownWithUp/CVE-2018-15499](https://github.com/DownWithUp/CVE-2018-15499)

### CVE-2018-15686

<code>
A vulnerability in unit_deserialize of systemd allows an attacker to supply arbitrary state across systemd re-execution via NotifyAccess. This can be used to improperly influence systemd execution and possibly lead to root privilege escalation. Affected releases are systemd versions up to and including 239.
</code>

- [hpcprofessional/remediate_cesa_2019_2091](https://github.com/hpcprofessional/remediate_cesa_2019_2091)

### CVE-2018-15727

<code>
Grafana 2.x, 3.x, and 4.x before 4.6.4 and 5.x before 5.2.3 allows authentication bypass because an attacker can generate a valid &quot;remember me&quot; cookie knowing only a username of an LDAP or OAuth user.
</code>

- [u238/grafana-CVE-2018-15727](https://github.com/u238/grafana-CVE-2018-15727)

### CVE-2018-15832

<code>
upc.exe in Ubisoft Uplay Desktop Client versions 63.0.5699.0 allows remote attackers to execute arbitrary code. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the processing of URI handlers. The issue results from the lack of proper validation of a user-supplied string before using it to execute a system call. An attacker can leverage this vulnerability to execute code under the context of the current process.
</code>

- [JacksonKuo/Ubisoft-Uplay-Desktop-Client-63.0.5699.0](https://github.com/JacksonKuo/Ubisoft-Uplay-Desktop-Client-63.0.5699.0)

### CVE-2018-15877

<code>
The Plainview Activity Monitor plugin before 20180826 for WordPress is vulnerable to OS command injection via shell metacharacters in the ip parameter of a wp-admin/admin.php?page=plainview_activity_monitor&amp;tab=activity_tools request.
</code>

- [cved-sources/cve-2018-15877](https://github.com/cved-sources/cve-2018-15877)

### CVE-2018-15912

<code>
An issue was discovered in manjaro-update-system.sh in manjaro-system 20180716-1 on Manjaro Linux. A local attacker can install or remove arbitrary packages and package repositories potentially containing hooks with arbitrary code, which will automatically be run as root, or remove packages vital to the system.
</code>

- [coderobe/CVE-2018-15912-PoC](https://github.com/coderobe/CVE-2018-15912-PoC)

### CVE-2018-15961

<code>
Adobe ColdFusion versions July 12 release (2018.0.0.310739), Update 6 and earlier, and Update 14 and earlier have an unrestricted file upload vulnerability. Successful exploitation could lead to arbitrary code execution.
</code>

- [vah13/CVE-2018-15961](https://github.com/vah13/CVE-2018-15961)
- [cved-sources/cve-2018-15961](https://github.com/cved-sources/cve-2018-15961)

### CVE-2018-15968

<code>
Adobe Acrobat and Reader versions 2018.011.20063 and earlier, 2017.011.30102 and earlier, and 2015.006.30452 and earlier have an out-of-bounds read vulnerability. Successful exploitation could lead to information disclosure.
</code>

- [sharmasandeepkr/cve-2018-15968](https://github.com/sharmasandeepkr/cve-2018-15968)

### CVE-2018-15982

<code>
Flash Player versions 31.0.0.153 and earlier, and 31.0.0.108 and earlier have a use after free vulnerability. Successful exploitation could lead to arbitrary code execution.
</code>

- [FlatL1neAPT/CVE-2018-15982](https://github.com/FlatL1neAPT/CVE-2018-15982)
- [AirEvan/CVE-2018-15982_PoC](https://github.com/AirEvan/CVE-2018-15982_PoC)
- [Ridter/CVE-2018-15982_EXP](https://github.com/Ridter/CVE-2018-15982_EXP)
- [kphongagsorn/adobe-flash-cve2018-15982](https://github.com/kphongagsorn/adobe-flash-cve2018-15982)
- [jas502n/CVE-2018-15982_EXP_IE](https://github.com/jas502n/CVE-2018-15982_EXP_IE)
- [scanfsec/CVE-2018-15982](https://github.com/scanfsec/CVE-2018-15982)
- [SyFi/CVE-2018-15982](https://github.com/SyFi/CVE-2018-15982)
- [create12138/CVE-2018-15982](https://github.com/create12138/CVE-2018-15982)

### CVE-2018-16119

<code>
Stack-based buffer overflow in the httpd server of TP-Link WR1043nd (Firmware Version 3) allows remote attackers to execute arbitrary code via a malicious MediaServer request to /userRpm/MediaServerFoldersCfgRpm.htm.
</code>

- [hdbreaker/CVE-2018-16119](https://github.com/hdbreaker/CVE-2018-16119)

### CVE-2018-16135
- [c0d3G33k/CVE-2018-16135](https://github.com/c0d3G33k/CVE-2018-16135)

### CVE-2018-16156

<code>
In PaperStream IP (TWAIN) 1.42.0.5685 (Service Update 7), the FJTWSVIC service running with SYSTEM privilege processes unauthenticated messages received over the FjtwMkic_Fjicube_32 named pipe. One of these message processing functions attempts to dynamically load the UninOldIS.dll library and executes an exported function named ChangeUninstallString. The default install does not contain this library and therefore if any DLL with that name exists in any directory listed in the PATH variable, it can be used to escalate to SYSTEM level privilege.
</code>

- [securifera/CVE-2018-16156-Exploit](https://github.com/securifera/CVE-2018-16156-Exploit)

### CVE-2018-16283

<code>
The Wechat Broadcast plugin 1.2.0 and earlier for WordPress allows Directory Traversal via the Image.php url parameter.
</code>

- [cved-sources/cve-2018-16283](https://github.com/cved-sources/cve-2018-16283)

### CVE-2018-16323

<code>
ReadXBMImage in coders/xbm.c in ImageMagick before 7.0.8-9 leaves data uninitialized when processing an XBM file that has a negative pixel value. If the affected code is used as a library loaded into a process that includes sensitive information, that information sometimes can be leaked via the image data.
</code>

- [ttffdd/XBadManners](https://github.com/ttffdd/XBadManners)

### CVE-2018-16341
- [mpgn/CVE-2018-16341](https://github.com/mpgn/CVE-2018-16341)

### CVE-2018-16370

<code>
In PESCMS Team 2.2.1, attackers may upload and execute arbitrary PHP code through /Public/?g=Team&amp;m=Setting&amp;a=upgrade by placing a .php file in a ZIP archive.
</code>

- [snappyJack/CVE-2018-16370](https://github.com/snappyJack/CVE-2018-16370)

### CVE-2018-16373

<code>
Frog CMS 0.9.5 has an Upload vulnerability that can create files via /admin/?/plugin/file_manager/save.
</code>

- [snappyJack/CVE-2018-16373](https://github.com/snappyJack/CVE-2018-16373)

### CVE-2018-16447

<code>
Frog CMS 0.9.5 has admin/?/user/edit/1 CSRF.
</code>

- [security-breachlock/CVE-2018-16447](https://github.com/security-breachlock/CVE-2018-16447)

### CVE-2018-16509

<code>
An issue was discovered in Artifex Ghostscript before 9.24. Incorrect &quot;restoration of privilege&quot; checking during handling of /invalidaccess exceptions could be used by attackers able to supply crafted PostScript to execute code using the &quot;pipe&quot; instruction.
</code>

- [farisv/PIL-RCE-Ghostscript-CVE-2018-16509](https://github.com/farisv/PIL-RCE-Ghostscript-CVE-2018-16509)
- [knqyf263/CVE-2018-16509](https://github.com/knqyf263/CVE-2018-16509)
- [cved-sources/cve-2018-16509](https://github.com/cved-sources/cve-2018-16509)
- [rhpco/CVE-2018-16509](https://github.com/rhpco/CVE-2018-16509)

### CVE-2018-16623

<code>
Kirby V2.5.12 is prone to a Persistent XSS attack via the Title of the &quot;Site options&quot; in the admin panel dashboard dropdown.
</code>

- [security-breachlock/CVE-2018-16623](https://github.com/security-breachlock/CVE-2018-16623)

### CVE-2018-16624

<code>
panel/pages/home/edit in Kirby v2.5.12 allows XSS via the title of a new page.
</code>

- [security-breachlock/CVE-2018-16624](https://github.com/security-breachlock/CVE-2018-16624)

### CVE-2018-16625

<code>
index.php/Admin/Uploaded in Typesetter 5.1 allows XSS via an SVG file with JavaScript in a SCRIPT element.
</code>

- [security-breachlock/CVE-2018-16625](https://github.com/security-breachlock/CVE-2018-16625)

### CVE-2018-16626

<code>
index.php/Admin/Classes in Typesetter 5.1 allows XSS via the description of a new class name.
</code>

- [security-breachlock/CVE-2018-16626](https://github.com/security-breachlock/CVE-2018-16626)

### CVE-2018-16627

<code>
panel/login in Kirby v2.5.12 allows Host header injection via the &quot;forget password&quot; feature.
</code>

- [security-breachlock/CVE-2018-16627](https://github.com/security-breachlock/CVE-2018-16627)

### CVE-2018-16628

<code>
panel/login in Kirby v2.5.12 allows XSS via a blog name.
</code>

- [security-breachlock/CVE-2018-16628](https://github.com/security-breachlock/CVE-2018-16628)

### CVE-2018-16629

<code>
panel/uploads/#elf_l1_XA in Subrion CMS v4.2.1 allows XSS via an SVG file with JavaScript in a SCRIPT element.
</code>

- [security-breachlock/CVE-2018-16629](https://github.com/security-breachlock/CVE-2018-16629)

### CVE-2018-16630

<code>
Kirby v2.5.12 allows XSS by using the &quot;site files&quot; Add option to upload an SVG file.
</code>

- [security-breachlock/CVE-2018-16630](https://github.com/security-breachlock/CVE-2018-16630)

### CVE-2018-16631

<code>
Subrion CMS v4.2.1 allows XSS via the panel/configuration/general/ SITE TITLE parameter.
</code>

- [security-breachlock/CVE-2018-16631](https://github.com/security-breachlock/CVE-2018-16631)

### CVE-2018-16632

<code>
Mezzanine CMS v4.3.1 allows XSS via the /admin/blog/blogcategory/add/?_to_field=id&amp;_popup=1 title parameter at admin/blog/blogpost/add/.
</code>

- [security-breachlock/CVE-2018-16632](https://github.com/security-breachlock/CVE-2018-16632)

### CVE-2018-16633

<code>
Pluck v4.7.7 allows XSS via the admin.php?action=editpage&amp;page= page title.
</code>

- [security-breachlock/CVE-2018-16633](https://github.com/security-breachlock/CVE-2018-16633)

### CVE-2018-16634

<code>
Pluck v4.7.7 allows CSRF via admin.php?action=settings.
</code>

- [security-breachlock/CVE-2018-16634](https://github.com/security-breachlock/CVE-2018-16634)

### CVE-2018-16635

<code>
Blackcat CMS 1.3.2 allows XSS via the willkommen.php?lang=DE page title at backend/pages/modify.php.
</code>

- [security-breachlock/CVE-2018-16635](https://github.com/security-breachlock/CVE-2018-16635)

### CVE-2018-16636

<code>
Nucleus CMS 3.70 allows HTML Injection via the index.php body parameter.
</code>

- [security-breachlock/CVE-2018-16636](https://github.com/security-breachlock/CVE-2018-16636)

### CVE-2018-16637

<code>
Evolution CMS 1.4.x allows XSS via the page weblink title parameter to the manager/ URI.
</code>

- [security-breachlock/CVE-2018-16637](https://github.com/security-breachlock/CVE-2018-16637)

### CVE-2018-16638

<code>
Evolution CMS 1.4.x allows XSS via the manager/ search parameter.
</code>

- [security-breachlock/CVE-2018-16638](https://github.com/security-breachlock/CVE-2018-16638)

### CVE-2018-16639

<code>
Typesetter 5.1 allows XSS via the index.php/Admin LABEL parameter during new page creation.
</code>

- [security-breachlock/CVE-2018-16639](https://github.com/security-breachlock/CVE-2018-16639)

### CVE-2018-16706

<code>
LG SuperSign CMS allows TVs to be rebooted remotely without authentication via a direct HTTP request to /qsr_server/device/reboot on port 9080.
</code>

- [Nurdilin/CVE-2018-16706](https://github.com/Nurdilin/CVE-2018-16706)

### CVE-2018-16711

<code>
IObit Advanced SystemCare, which includes Monitor_win10_x64.sys or Monitor_win7_x64.sys, 1.2.0.5 (and possibly earlier versions) allows a user to send an IOCTL (0x9C402088) with a buffer containing user defined content. The driver's subroutine will execute a wrmsr instruction with the user's buffer for input.
</code>

- [DownWithUp/CVE-2018-16711](https://github.com/DownWithUp/CVE-2018-16711)

### CVE-2018-16712

<code>
IObit Advanced SystemCare, which includes Monitor_win10_x64.sys or Monitor_win7_x64.sys, 1.2.0.5 (and possibly earlier versions) allows a user to send a specially crafted IOCTL 0x9C406104 to read physical memory.
</code>

- [DownWithUp/CVE-2018-16712](https://github.com/DownWithUp/CVE-2018-16712)

### CVE-2018-16713

<code>
IObit Advanced SystemCare, which includes Monitor_win10_x64.sys or Monitor_win7_x64.sys, 1.2.0.5 (and possibly earlier versions) allows a user to send an IOCTL (0x9C402084) with a buffer containing user defined content. The driver's subroutine will execute a rdmsr instruction with the user's buffer for input, and provide output from the instruction.
</code>

- [DownWithUp/CVE-2018-16713](https://github.com/DownWithUp/CVE-2018-16713)

### CVE-2018-16763

<code>
FUEL CMS 1.4.1 allows PHP Code Evaluation via the pages/select/ filter parameter or the preview/ data parameter. This can lead to Pre-Auth Remote Code Execution.
</code>

- [dinhbaouit/CVE-2018-16763](https://github.com/dinhbaouit/CVE-2018-16763)
- [SalimAlk/CVE-2018-16763-](https://github.com/SalimAlk/CVE-2018-16763-)

### CVE-2018-16854

<code>
A flaw was found in moodle versions 3.5 to 3.5.2, 3.4 to 3.4.5, 3.3 to 3.3.8, 3.1 to 3.1.14 and earlier. The login form is not protected by a token to prevent login cross-site request forgery. Fixed versions include 3.6, 3.5.3, 3.4.6, 3.3.9 and 3.1.15.
</code>

- [danielthatcher/moodle-login-csrf](https://github.com/danielthatcher/moodle-login-csrf)

### CVE-2018-16858

<code>
It was found that libreoffice before versions 6.0.7 and 6.1.3 was vulnerable to a directory traversal attack which could be used to execute arbitrary macros bundled with a document. An attacker could craft a document, which when opened by LibreOffice, would execute a Python method from a script in any arbitrary file system location, specified relative to the LibreOffice install location.
</code>

- [4nimanegra/libreofficeExploit1](https://github.com/4nimanegra/libreofficeExploit1)
- [k0o97/detect-cve-2018-16858](https://github.com/k0o97/detect-cve-2018-16858)

### CVE-2018-16875

<code>
The crypto/x509 package of Go before 1.10.6 and 1.11.x before 1.11.3 does not limit the amount of work performed for each chain verification, which might allow attackers to craft pathological inputs leading to a CPU denial of service. Go TLS servers accepting client certificates and TLS clients are affected.
</code>

- [alexzorin/poc-cve-2018-16875](https://github.com/alexzorin/poc-cve-2018-16875)

### CVE-2018-16890

<code>
libcurl versions from 7.36.0 to before 7.64.0 is vulnerable to a heap buffer out-of-bounds read. The function handling incoming NTLM type-2 messages (`lib/vauth/ntlm.c:ntlm_decode_type2_target`) does not validate incoming data correctly and is subject to an integer overflow vulnerability. Using that overflow, a malicious or broken NTLM server could trick libcurl to accept a bad length + offset combination that would lead to a buffer read out-of-bounds.
</code>

- [zjw88282740/CVE-2018-16890](https://github.com/zjw88282740/CVE-2018-16890)

### CVE-2018-16987

<code>
Squash TM through 1.18.0 presents the cleartext passwords of external services in the administration panel, as demonstrated by a ta-server-password field in the HTML source code.
</code>

- [gquere/CVE-2018-16987](https://github.com/gquere/CVE-2018-16987)

### CVE-2018-17024

<code>
admin/index.php in Monstra CMS 3.0.4 allows XSS via the page_meta_title parameter in an add_page action.
</code>

- [security-breachlock/CVE-2018-17024](https://github.com/security-breachlock/CVE-2018-17024)

### CVE-2018-17144

<code>
Bitcoin Core 0.14.x before 0.14.3, 0.15.x before 0.15.2, and 0.16.x before 0.16.3 and Bitcoin Knots 0.14.x through 0.16.x before 0.16.3 allow a remote denial of service (application crash) exploitable by miners via duplicate input. An attacker can make bitcoind or Bitcoin-Qt crash.
</code>

- [iioch/ban-exploitable-bitcoin-nodes](https://github.com/iioch/ban-exploitable-bitcoin-nodes)
- [hikame/CVE-2018-17144_POC](https://github.com/hikame/CVE-2018-17144_POC)

### CVE-2018-17182

<code>
An issue was discovered in the Linux kernel through 4.18.8. The vmacache_flush_all function in mm/vmacache.c mishandles sequence number overflows. An attacker can trigger a use-after-free (and possibly gain privileges) via certain thread creation, map, unmap, invalidation, and dereference operations.
</code>

- [jas502n/CVE-2018-17182](https://github.com/jas502n/CVE-2018-17182)
- [denmilu/CVE-2018-17182](https://github.com/denmilu/CVE-2018-17182)
- [denmilu/vmacache_CVE-2018-17182](https://github.com/denmilu/vmacache_CVE-2018-17182)

### CVE-2018-17207

<code>
An issue was discovered in Snap Creek Duplicator before 1.2.42. By accessing leftover installer files (installer.php and installer-backup.php), an attacker can inject PHP code into wp-config.php during the database setup step, achieving arbitrary code execution.
</code>

- [cved-sources/cve-2018-17207](https://github.com/cved-sources/cve-2018-17207)

### CVE-2018-17246

<code>
Kibana versions before 6.4.3 and 5.6.13 contain an arbitrary file inclusion flaw in the Console plugin. An attacker with access to the Kibana Console API could send a request that will attempt to execute javascript code. This could possibly lead to an attacker executing arbitrary commands with permissions of the Kibana process on the host system.
</code>

- [mpgn/CVE-2018-17246](https://github.com/mpgn/CVE-2018-17246)

### CVE-2018-17300

<code>
Stored XSS exists in CuppaCMS through 2018-09-03 via an administrator/#/component/table_manager/view/cu_menus section name.
</code>

- [security-breachlock/CVE-2018-17300](https://github.com/security-breachlock/CVE-2018-17300)

### CVE-2018-17301

<code>
Reflected XSS exists in client/res/templates/global-search/name-field.tpl in EspoCRM 5.3.6 via /#Account in the search panel.
</code>

- [security-breachlock/CVE-2018-17301](https://github.com/security-breachlock/CVE-2018-17301)

### CVE-2018-17302

<code>
Stored XSS exists in views/fields/wysiwyg.js in EspoCRM 5.3.6 via a /#Email/view saved draft message.
</code>

- [security-breachlock/CVE-2018-17302](https://github.com/security-breachlock/CVE-2018-17302)

### CVE-2018-17418

<code>
Monstra CMS 3.0.4 allows remote attackers to execute arbitrary PHP code via a mixed-case file extension, as demonstrated by the 123.PhP filename, because plugins\box\filesmanager\filesmanager.admin.php mishandles the forbidden_types variable.
</code>

- [AlwaysHereFight/monstra_cms-3.0.4--getshell](https://github.com/AlwaysHereFight/monstra_cms-3.0.4--getshell)

### CVE-2018-17431

<code>
Web Console in Comodo UTM Firewall before 2.7.0 allows remote attackers to execute arbitrary code without authentication via a crafted URL.
</code>

- [Fadavvi/CVE-2018-17431-PoC](https://github.com/Fadavvi/CVE-2018-17431-PoC)

### CVE-2018-17456

<code>
Git before 2.14.5, 2.15.x before 2.15.3, 2.16.x before 2.16.5, 2.17.x before 2.17.2, 2.18.x before 2.18.1, and 2.19.x before 2.19.1 allows remote code execution during processing of a recursive &quot;git clone&quot; of a superproject if a .gitmodules file has a URL field beginning with a '-' character.
</code>

- [SeahunOh/CVE-2018-17456](https://github.com/SeahunOh/CVE-2018-17456)
- [matlink/CVE-2018-17456](https://github.com/matlink/CVE-2018-17456)
- [799600966/CVE-2018-17456](https://github.com/799600966/CVE-2018-17456)
- [AnonymKing/CVE-2018-17456](https://github.com/AnonymKing/CVE-2018-17456)

### CVE-2018-17873

<code>
An incorrect access control vulnerability in the FTP configuration of WiFiRanger devices with firmware version 7.0.8rc3 and earlier allows an attacker with adjacent network access to read the SSH Private Key and log in to the root account.
</code>

- [Luct0r/CVE-2018-17873](https://github.com/Luct0r/CVE-2018-17873)

### CVE-2018-17961

<code>
Artifex Ghostscript 9.25 and earlier allows attackers to bypass a sandbox protection mechanism via vectors involving errorhandler setup. NOTE: this issue exists because of an incomplete fix for CVE-2018-17183.
</code>

- [matlink/CVE-2018-17961](https://github.com/matlink/CVE-2018-17961)

### CVE-2018-18026

<code>
IMFCameraProtect.sys in IObit Malware Fighter 6.2 (and possibly lower versions) is vulnerable to a stack-based buffer overflow. The attacker can use DeviceIoControl to pass a user specified size which can be used to overwrite return addresses. This can lead to a denial of service or code execution attack.
</code>

- [DownWithUp/CVE-2018-18026](https://github.com/DownWithUp/CVE-2018-18026)

### CVE-2018-18368

<code>
Symantec Endpoint Protection Manager (SEPM), prior to 14.2 RU1, may be susceptible to a privilege escalation vulnerability, which is a type of issue whereby an attacker may attempt to compromise the software application to gain elevated access to resources that are normally protected from an application or user.
</code>

- [DimopoulosElias/SEPM-EoP](https://github.com/DimopoulosElias/SEPM-EoP)

### CVE-2018-18387

<code>
playSMS through 1.4.2 allows Privilege Escalation through Daemon abuse.
</code>

- [TheeBlind/CVE-2018-18387](https://github.com/TheeBlind/CVE-2018-18387)

### CVE-2018-18500

<code>
A use-after-free vulnerability can occur while parsing an HTML5 stream in concert with custom HTML elements. This results in the stream parser object being freed while still in use, leading to a potentially exploitable crash. This vulnerability affects Thunderbird &lt; 60.5, Firefox ESR &lt; 60.5, and Firefox &lt; 65.
</code>

- [sophoslabs/CVE-2018-18500](https://github.com/sophoslabs/CVE-2018-18500)

### CVE-2018-18649

<code>
An issue was discovered in the wiki API in GitLab Community and Enterprise Edition before 11.2.7, 11.3.x before 11.3.8, and 11.4.x before 11.4.3. It allows for remote code execution.
</code>

- [Snowming04/CVE-2018-18649](https://github.com/Snowming04/CVE-2018-18649)

### CVE-2018-18714

<code>
RegFilter.sys in IOBit Malware Fighter 6.2 and earlier is susceptible to a stack-based buffer overflow when an attacker uses IOCTL 0x8006E010. This can lead to denial of service (DoS) or code execution with root privileges.
</code>

- [DownWithUp/CVE-2018-18714](https://github.com/DownWithUp/CVE-2018-18714)

### CVE-2018-18852

<code>
Cerio DT-300N 1.1.6 through 1.1.12 devices allow OS command injection because of improper input validation of the web-interface PING feature's use of Save.cgi to execute a ping command, as exploited in the wild in October 2018.
</code>

- [hook-s3c/CVE-2018-18852](https://github.com/hook-s3c/CVE-2018-18852)
- [andripwn/CVE-2018-18852](https://github.com/andripwn/CVE-2018-18852)

### CVE-2018-19126

<code>
PrestaShop 1.6.x before 1.6.1.23 and 1.7.x before 1.7.4.4 allows remote attackers to execute arbitrary code via a file upload.
</code>

- [farisv/PrestaShop-CVE-2018-19126](https://github.com/farisv/PrestaShop-CVE-2018-19126)

### CVE-2018-19127

<code>
A code injection vulnerability in /type.php in PHPCMS 2008 allows attackers to write arbitrary content to a website cache file with a controllable filename, leading to arbitrary code execution. The PHP code is sent via the template parameter, and is written to a data/cache_template/*.tpl.php file along with a &quot;&lt;?php function &quot; substring.
</code>

- [ab1gale/phpcms-2008-CVE-2018-19127](https://github.com/ab1gale/phpcms-2008-CVE-2018-19127)

### CVE-2018-19131

<code>
Squid before 4.4 has XSS via a crafted X.509 certificate during HTTP(S) error page generation for certificate errors.
</code>

- [JonathanWilbur/CVE-2018-19131](https://github.com/JonathanWilbur/CVE-2018-19131)

### CVE-2018-19207

<code>
The Van Ons WP GDPR Compliance (aka wp-gdpr-compliance) plugin before 1.4.3 for WordPress allows remote attackers to execute arbitrary code because $wpdb-&gt;prepare() input is mishandled, as exploited in the wild in November 2018.
</code>

- [aeroot/WP-GDPR-Compliance-Plugin-Exploit](https://github.com/aeroot/WP-GDPR-Compliance-Plugin-Exploit)
- [cved-sources/cve-2018-19207](https://github.com/cved-sources/cve-2018-19207)

### CVE-2018-19276

<code>
OpenMRS before 2.24.0 is affected by an Insecure Object Deserialization vulnerability that allows an unauthenticated user to execute arbitrary commands on the targeted system via crafted XML data in a request body.
</code>

- [mpgn/CVE-2018-19276](https://github.com/mpgn/CVE-2018-19276)

### CVE-2018-19320

<code>
The GDrv low-level driver in GIGABYTE APP Center v1.05.21 and earlier, AORUS GRAPHICS ENGINE before 1.57, XTREME GAMING ENGINE before 1.26, and OC GURU II v2.08 exposes ring0 memcpy-like functionality that could allow a local attacker to take complete control of the affected system.
</code>

- [fdiskyou/CVE-2018-19320](https://github.com/fdiskyou/CVE-2018-19320)

### CVE-2018-19466

<code>
A vulnerability was found in Portainer before 1.20.0. Portainer stores LDAP credentials, corresponding to a master password, in cleartext and allows their retrieval via API calls.
</code>

- [MauroEldritch/lempo](https://github.com/MauroEldritch/lempo)

### CVE-2018-19487

<code>
The WP-jobhunt plugin before version 2.4 for WordPress does not control AJAX requests sent to the cs_employer_ajax_profile() function through the admin-ajax.php file, which allows remote unauthenticated attackers to enumerate information about users.
</code>

- [Antho59/wp-jobhunt-exploit](https://github.com/Antho59/wp-jobhunt-exploit)

### CVE-2018-19506

<code>
Zurmo 3.2.4 has XSS via an admin's use of the name parameter in the reports section, aka the app/index.php/reports/default/details?id=1 URI.
</code>

- [security-breachlock/CVE-2018-19506](https://github.com/security-breachlock/CVE-2018-19506)

### CVE-2018-19507

<code>
CMSimple 4.7.5 has XSS via an admin's use of a ?file=config&amp;action=array URI.
</code>

- [security-breachlock/CVE-2018-19507](https://github.com/security-breachlock/CVE-2018-19507)

### CVE-2018-19508

<code>
CMSimple 4.7.5 has XSS via an admin's upload of an SVG file at a ?userfiles&amp;subdir=userfiles/images/flags/ URI.
</code>

- [security-breachlock/CVE-2018-19508](https://github.com/security-breachlock/CVE-2018-19508)

### CVE-2018-19518

<code>
University of Washington IMAP Toolkit 2007f on UNIX, as used in imap_open() in PHP and other products, launches an rsh command (by means of the imap_rimap function in c-client/imap4r1.c and the tcp_aopen function in osdep/unix/tcp_unix.c) without preventing argument injection, which might allow remote attackers to execute arbitrary OS commands if the IMAP server name is untrusted input (e.g., entered by a user of a web application) and if rsh has been replaced by a program with different argument semantics. For example, if rsh is a link to ssh (as seen on Debian and Ubuntu systems), then the attack can use an IMAP server name containing a &quot;-oProxyCommand&quot; argument.
</code>

- [ensimag-security/CVE-2018-19518](https://github.com/ensimag-security/CVE-2018-19518)

### CVE-2018-19537

<code>
TP-Link Archer C5 devices through V2_160201_US allow remote command execution via shell metacharacters on the wan_dyn_hostname line of a configuration file that is encrypted with the 478DA50BF9E3D2CF key and uploaded through the web GUI by using the web admin account. The default password of admin may be used in some cases.
</code>

- [JackDoan/TP-Link-ArcherC5-RCE](https://github.com/JackDoan/TP-Link-ArcherC5-RCE)

### CVE-2018-19592

<code>
The &quot;CLink4Service&quot; service is installed with Corsair Link 4.9.7.35 with insecure permissions by default. This allows unprivileged users to take control of the service and execute commands in the context of NT AUTHORITY\SYSTEM, leading to total system takeover, a similar issue to CVE-2018-12441.
</code>

- [BradyDonovan/CVE-2018-19592](https://github.com/BradyDonovan/CVE-2018-19592)

### CVE-2018-19596

<code>
Zurmo 3.2.4 allows HTML Injection via an admin's use of HTML in the report section, a related issue to CVE-2018-19506.
</code>

- [security-breachlock/CVE-2018-19596](https://github.com/security-breachlock/CVE-2018-19596)

### CVE-2018-19597

<code>
CMS Made Simple 2.2.8 allows XSS via an uploaded SVG document, a related issue to CVE-2017-16798.
</code>

- [security-breachlock/CVE-2018-19597](https://github.com/security-breachlock/CVE-2018-19597)

### CVE-2018-19598

<code>
Statamic 2.10.3 allows XSS via First Name or Last Name to the /users URI in an 'Add new user' request.
</code>

- [security-breachlock/CVE-2018-19598](https://github.com/security-breachlock/CVE-2018-19598)

### CVE-2018-19599

<code>
Monstra CMS 1.6 allows XSS via an uploaded SVG document to the admin/index.php?id=filesmanager&amp;path=uploads/ URI. NOTE: this is a discontinued product.
</code>

- [security-breachlock/CVE-2018-19599](https://github.com/security-breachlock/CVE-2018-19599)

### CVE-2018-19600

<code>
Rhymix CMS 1.9.8.1 allows XSS via an index.php?module=admin&amp;act=dispModuleAdminFileBox SVG upload.
</code>

- [security-breachlock/CVE-2018-19600](https://github.com/security-breachlock/CVE-2018-19600)

### CVE-2018-19601

<code>
Rhymix CMS 1.9.8.1 allows SSRF via an index.php?module=admin&amp;act=dispModuleAdminFileBox SVG upload.
</code>

- [security-breachlock/CVE-2018-19601](https://github.com/security-breachlock/CVE-2018-19601)

### CVE-2018-19788

<code>
A flaw was found in PolicyKit (aka polkit) 0.115 that allows a user with a uid greater than INT_MAX to successfully execute any systemctl command.
</code>

- [AbsoZed/CVE-2018-19788](https://github.com/AbsoZed/CVE-2018-19788)
- [d4gh0s7/CVE-2018-19788](https://github.com/d4gh0s7/CVE-2018-19788)
- [Ekultek/PoC](https://github.com/Ekultek/PoC)
- [jhlongjr/CVE-2018-19788](https://github.com/jhlongjr/CVE-2018-19788)

### CVE-2018-19844

<code>
FROG CMS 0.9.5 has XSS via the admin/?/snippet/add name parameter, which is mishandled during an edit action, a related issue to CVE-2018-10319.
</code>

- [security-breachlock/CVE-2018-19844](https://github.com/security-breachlock/CVE-2018-19844)

### CVE-2018-19845

<code>
There is Stored XSS in GetSimple CMS 3.3.12 via the admin/edit.php &quot;post-menu&quot; parameter, a related issue to CVE-2018-16325.
</code>

- [security-breachlock/CVE-2018-19845](https://github.com/security-breachlock/CVE-2018-19845)

### CVE-2018-19864

<code>
NUUO NVRmini2 Network Video Recorder firmware through 3.9.1 allows remote attackers to execute arbitrary code or cause a denial of service (buffer overflow), resulting in ability to read camera feeds or reconfigure the device.
</code>

- [pwnhacker0x18/CVE-2018-19864](https://github.com/pwnhacker0x18/CVE-2018-19864)

### CVE-2018-19901

<code>
No-CMS 1.1.3 is prone to Persistent XSS via the blog/manage_article/index/ &quot;article_title&quot; parameter.
</code>

- [security-breachlock/CVE-2018-19901](https://github.com/security-breachlock/CVE-2018-19901)

### CVE-2018-19902

<code>
No-CMS 1.1.3 is prone to Persistent XSS via the blog/manage_article &quot;keyword&quot; parameter.
</code>

- [security-breachlock/CVE-2018-19902](https://github.com/security-breachlock/CVE-2018-19902)

### CVE-2018-19903

<code>
Persistent XSS exists in XSLT CMS via the create/?action=items.edit&amp;type=Page title field.
</code>

- [security-breachlock/CVE-2018-19903](https://github.com/security-breachlock/CVE-2018-19903)

### CVE-2018-19904

<code>
Persistent XSS exists in XSLT CMS via the create/?action=items.edit&amp;type=Page &quot;body&quot; field.
</code>

- [security-breachlock/CVE-2018-19904](https://github.com/security-breachlock/CVE-2018-19904)

### CVE-2018-19905

<code>
HTML injection exists in razorCMS 3.4.8 via the /#/page keywords parameter.
</code>

- [security-breachlock/CVE-2018-19905](https://github.com/security-breachlock/CVE-2018-19905)

### CVE-2018-19906

<code>
Stored XSS exists in razorCMS 3.4.8 via the /#/page description parameter.
</code>

- [security-breachlock/CVE-2018-19906](https://github.com/security-breachlock/CVE-2018-19906)

### CVE-2018-19911

<code>
FreeSWITCH through 1.8.2, when mod_xml_rpc is enabled, allows remote attackers to execute arbitrary commands via the api/system or txtapi/system (or api/bg_system or txtapi/bg_system) query string on TCP port 8080, as demonstrated by an api/system?calc URI. This can also be exploited via CSRF. Alternatively, the default password of works for the freeswitch account can sometimes be used.
</code>

- [iSafeBlue/freeswitch_rce](https://github.com/iSafeBlue/freeswitch_rce)

### CVE-2018-19918

<code>
CuppaCMS has XSS via an SVG document uploaded to the administrator/#/component/table_manager/view/cu_views URI.
</code>

- [security-breachlock/CVE-2018-19918](https://github.com/security-breachlock/CVE-2018-19918)

### CVE-2018-19919

<code>
Pixelimity 1.0 has Persistent XSS via the admin/portfolio.php data[title] parameter, as demonstrated by a crafted onload attribute of an SVG element.
</code>

- [security-breachlock/CVE-2018-19919](https://github.com/security-breachlock/CVE-2018-19919)

### CVE-2018-1999002

<code>
A arbitrary file read vulnerability exists in Jenkins 2.132 and earlier, 2.121.1 and earlier in the Stapler web framework's org/kohsuke/stapler/Stapler.java that allows attackers to send crafted HTTP requests returning the contents of any file on the Jenkins master file system that the Jenkins master has access to.
</code>

- [wetw0rk/Exploit-Development](https://github.com/wetw0rk/Exploit-Development)
- [0xtavian/CVE-2019-1003000-and-CVE-2018-1999002-Pre-Auth-RCE-Jenkins](https://github.com/0xtavian/CVE-2019-1003000-and-CVE-2018-1999002-Pre-Auth-RCE-Jenkins)
- [0x6b7966/CVE-2018-1999002](https://github.com/0x6b7966/CVE-2018-1999002)

### CVE-2018-20062

<code>
An issue was discovered in NoneCms V1.3. thinkphp/library/think/App.php allows remote attackers to execute arbitrary PHP code via crafted use of the filter parameter, as demonstrated by the s=index/\think\Request/input&amp;filter=phpinfo&amp;data=1 query string.
</code>

- [NS-Sp4ce/thinkphp5.XRce](https://github.com/NS-Sp4ce/thinkphp5.XRce)

### CVE-2018-20162

<code>
Digi TransPort LR54 4.4.0.26 and possible earlier devices have Improper Input Validation that allows users with 'super' CLI access privileges to bypass a restricted shell and execute arbitrary commands as root.
</code>

- [stigtsp/CVE-2018-20162-digi-lr54-restricted-shell-escape](https://github.com/stigtsp/CVE-2018-20162-digi-lr54-restricted-shell-escape)

### CVE-2018-20165

<code>
Cross-site scripting (XSS) vulnerability in OpenText Portal 7.4.4 allows remote attackers to inject arbitrary web script or HTML via the vgnextoid parameter to a menuitem URI.
</code>

- [hect0rS/Reflected-XSS-on-Opentext-Portal-v7.4.4](https://github.com/hect0rS/Reflected-XSS-on-Opentext-Portal-v7.4.4)

### CVE-2018-2019

<code>
IBM Security Identity Manager 6.0.0 Virtual Appliance is vulnerable to a XML External Entity Injection (XXE) attack when processing XML data. A remote attacker could exploit this vulnerability to expose sensitive information or consume memory resources. IBM X-Force ID: 155265.
</code>

- [attakercyebr/hack4lx_CVE-2018-2019](https://github.com/attakercyebr/hack4lx_CVE-2018-2019)

### CVE-2018-20250

<code>
In WinRAR versions prior to and including 5.61, There is path traversal vulnerability when crafting the filename field of the ACE format (in UNACEV2.dll). When the filename field is manipulated with specific patterns, the destination (extraction) folder is ignored, thus treating the filename as an absolute path.
</code>

- [WyAtu/CVE-2018-20250](https://github.com/WyAtu/CVE-2018-20250)
- [QAX-A-Team/CVE-2018-20250](https://github.com/QAX-A-Team/CVE-2018-20250)
- [nmweizi/CVE-2018-20250-poc-winrar](https://github.com/nmweizi/CVE-2018-20250-poc-winrar)
- [blunden/UNACEV2.DLL-CVE-2018-20250](https://github.com/blunden/UNACEV2.DLL-CVE-2018-20250)
- [easis/CVE-2018-20250-WinRAR-ACE](https://github.com/easis/CVE-2018-20250-WinRAR-ACE)
- [STP5940/CVE-2018-20250](https://github.com/STP5940/CVE-2018-20250)
- [n4r1b/WinAce-POC](https://github.com/n4r1b/WinAce-POC)
- [technicaldada/hack-winrar](https://github.com/technicaldada/hack-winrar)
- [Ektoplasma/ezwinrar](https://github.com/Ektoplasma/ezwinrar)
- [arkangel-dev/CVE-2018-20250-WINRAR-ACE-GUI](https://github.com/arkangel-dev/CVE-2018-20250-WINRAR-ACE-GUI)
- [AeolusTF/CVE-2018-20250](https://github.com/AeolusTF/CVE-2018-20250)
- [joydragon/Detect-CVE-2018-20250](https://github.com/joydragon/Detect-CVE-2018-20250)
- [DANIELVISPOBLOG/WinRar_ACE_exploit_CVE-2018-20250](https://github.com/DANIELVISPOBLOG/WinRar_ACE_exploit_CVE-2018-20250)
- [denmilu/CVE-2018-20250](https://github.com/denmilu/CVE-2018-20250)
- [930201676/CVE-2018-20250](https://github.com/930201676/CVE-2018-20250)
- [eastmountyxz/CVE-2018-20250-WinRAR](https://github.com/eastmountyxz/CVE-2018-20250-WinRAR)
- [lxg5763/cve-2018-20250](https://github.com/lxg5763/cve-2018-20250)

### CVE-2018-20343

<code>
Multiple buffer overflow vulnerabilities have been found in Ken Silverman Build Engine 1. An attacker could craft a special map file to execute arbitrary code when the map file is loaded.
</code>

- [Alexandre-Bartel/CVE-2018-20343](https://github.com/Alexandre-Bartel/CVE-2018-20343)

### CVE-2018-20434

<code>
LibreNMS 1.46 allows remote attackers to execute arbitrary OS commands by using the $_POST['community'] parameter to html/pages/addhost.inc.php during creation of a new device, and then making a /ajax_output.php?id=capture&amp;format=text&amp;type=snmpwalk&amp;hostname=localhost request that triggers html/includes/output/capture.inc.php command mishandling.
</code>

- [mhaskar/CVE-2018-20434](https://github.com/mhaskar/CVE-2018-20434)

### CVE-2018-20555

<code>
The Design Chemical Social Network Tabs plugin 1.7.1 for WordPress allows remote attackers to discover Twitter access_token, access_token_secret, consumer_key, and consumer_secret values by reading the dcwp_twitter.php source code. This leads to Twitter account takeover.
</code>

- [fs0c131y/CVE-2018-20555](https://github.com/fs0c131y/CVE-2018-20555)

### CVE-2018-20580

<code>
The WSDL import functionality in SmartBear ReadyAPI 2.5.0 and 2.6.0 allows remote attackers to execute arbitrary Java code via a crafted request parameter in a WSDL file.
</code>

- [gscamelo/CVE-2018-20580](https://github.com/gscamelo/CVE-2018-20580)

### CVE-2018-20718

<code>
In Pydio before 8.2.2, an attack is possible via PHP Object Injection because a user is allowed to use the $phpserial$a:0:{} syntax to store a preference. An attacker either needs a &quot;public link&quot; of a file, or access to any unprivileged user account for creation of such a link.
</code>

- [us3r777/CVE-2018-20718](https://github.com/us3r777/CVE-2018-20718)

### CVE-2018-2380

<code>
SAP CRM, 7.01, 7.02,7.30, 7.31, 7.33, 7.54, allows an attacker to exploit insufficient validation of path information provided by users, thus characters representing &quot;traverse to parent directory&quot; are passed through to the file APIs.
</code>

- [erpscanteam/CVE-2018-2380](https://github.com/erpscanteam/CVE-2018-2380)

### CVE-2018-2628

<code>
Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.2 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
</code>

- [forlin/CVE-2018-2628](https://github.com/forlin/CVE-2018-2628)
- [shengqi158/CVE-2018-2628](https://github.com/shengqi158/CVE-2018-2628)
- [skydarker/CVE-2018-2628](https://github.com/skydarker/CVE-2018-2628)
- [jiansiting/weblogic-cve-2018-2628](https://github.com/jiansiting/weblogic-cve-2018-2628)
- [zjxzjx/CVE-2018-2628-detect](https://github.com/zjxzjx/CVE-2018-2628-detect)
- [aedoo/CVE-2018-2628-MultiThreading](https://github.com/aedoo/CVE-2018-2628-MultiThreading)
- [hawk-tiger/CVE-2018-2628](https://github.com/hawk-tiger/CVE-2018-2628)
- [9uest/CVE-2018-2628](https://github.com/9uest/CVE-2018-2628)
- [Shadowshusky/CVE-2018-2628all](https://github.com/Shadowshusky/CVE-2018-2628all)
- [shaoshore/CVE-2018-2628](https://github.com/shaoshore/CVE-2018-2628)
- [tdy218/ysoserial-cve-2018-2628](https://github.com/tdy218/ysoserial-cve-2018-2628)
- [s0wr0b1ndef/CVE-2018-2628](https://github.com/s0wr0b1ndef/CVE-2018-2628)
- [wrysunny/cve-2018-2628](https://github.com/wrysunny/cve-2018-2628)
- [jas502n/CVE-2018-2628](https://github.com/jas502n/CVE-2018-2628)
- [stevenlinfeng/CVE-2018-2628](https://github.com/stevenlinfeng/CVE-2018-2628)
- [denmilu/CVE-2018-2628](https://github.com/denmilu/CVE-2018-2628)
- [Nervous/WebLogic-RCE-exploit](https://github.com/Nervous/WebLogic-RCE-exploit)
- [Lighird/CVE-2018-2628](https://github.com/Lighird/CVE-2018-2628)
- [0xMJ/CVE-2018-2628](https://github.com/0xMJ/CVE-2018-2628)
- [0xn0ne/weblogicScanner](https://github.com/0xn0ne/weblogicScanner)

### CVE-2018-2636

<code>
Vulnerability in the Oracle Hospitality Simphony component of Oracle Hospitality Applications (subcomponent: Security). Supported versions that are affected are 2.7, 2.8 and 2.9. Difficult to exploit vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Hospitality Simphony. Successful attacks of this vulnerability can result in takeover of Oracle Hospitality Simphony. CVSS 3.0 Base Score 8.1 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H).
</code>

- [erpscanteam/CVE-2018-2636](https://github.com/erpscanteam/CVE-2018-2636)
- [Cymmetria/micros_honeypot](https://github.com/Cymmetria/micros_honeypot)

### CVE-2018-2844

<code>
Vulnerability in the Oracle VM VirtualBox component of Oracle Virtualization (subcomponent: Core). Supported versions that are affected are Prior to 5.1.36 and Prior to 5.2.10. Easily exploitable vulnerability allows low privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in takeover of Oracle VM VirtualBox. CVSS 3.0 Base Score 8.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H).
</code>

- [renorobert/virtualbox-cve-2018-2844](https://github.com/renorobert/virtualbox-cve-2018-2844)

### CVE-2018-2879

<code>
Vulnerability in the Oracle Access Manager component of Oracle Fusion Middleware (subcomponent: Authentication Engine). Supported versions that are affected are 11.1.2.3.0 and 12.2.1.3.0. Difficult to exploit vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Access Manager. While the vulnerability is in Oracle Access Manager, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in takeover of Oracle Access Manager. Note: Please refer to Doc ID &lt;a href=&quot;http://support.oracle.com/CSP/main/article?cmd=show&amp;type=NOT&amp;id=2386496.1&quot;&gt;My Oracle Support Note 2386496.1 for instructions on how to address this issue. CVSS 3.0 Base Score 9.0 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H).
</code>

- [MostafaSoliman/Oracle-OAM-Padding-Oracle-CVE-2018-2879-Exploit](https://github.com/MostafaSoliman/Oracle-OAM-Padding-Oracle-CVE-2018-2879-Exploit)
- [AymanElSherif/oracle-oam-authentication-bypas-exploit](https://github.com/AymanElSherif/oracle-oam-authentication-bypas-exploit)
- [redtimmy/OAMBuster](https://github.com/redtimmy/OAMBuster)

### CVE-2018-2893

<code>
Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.2 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
</code>

- [anbai-inc/CVE-2018-2893](https://github.com/anbai-inc/CVE-2018-2893)
- [ryanInf/CVE-2018-2893](https://github.com/ryanInf/CVE-2018-2893)
- [bigsizeme/CVE-2018-2893](https://github.com/bigsizeme/CVE-2018-2893)
- [pyn3rd/CVE-2018-2893](https://github.com/pyn3rd/CVE-2018-2893)
- [qianl0ng/CVE-2018-2893](https://github.com/qianl0ng/CVE-2018-2893)
- [jas502n/CVE-2018-2893](https://github.com/jas502n/CVE-2018-2893)
- [ianxtianxt/CVE-2018-2893](https://github.com/ianxtianxt/CVE-2018-2893)

### CVE-2018-2894

<code>
Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS - Web Services). Supported versions that are affected are 12.1.3.0, 12.2.1.2 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
</code>

- [111ddea/cve-2018-2894](https://github.com/111ddea/cve-2018-2894)
- [LandGrey/CVE-2018-2894](https://github.com/LandGrey/CVE-2018-2894)
- [jas502n/CVE-2018-2894](https://github.com/jas502n/CVE-2018-2894)

### CVE-2018-3191

<code>
Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
</code>

- [arongmh/CVE-2018-3191](https://github.com/arongmh/CVE-2018-3191)
- [pyn3rd/CVE-2018-3191](https://github.com/pyn3rd/CVE-2018-3191)
- [Libraggbond/CVE-2018-3191](https://github.com/Libraggbond/CVE-2018-3191)
- [jas502n/CVE-2018-3191](https://github.com/jas502n/CVE-2018-3191)
- [mackleadmire/CVE-2018-3191-Rce-Exploit](https://github.com/mackleadmire/CVE-2018-3191-Rce-Exploit)

### CVE-2018-3245

<code>
Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
</code>

- [pyn3rd/CVE-2018-3245](https://github.com/pyn3rd/CVE-2018-3245)
- [jas502n/CVE-2018-3245](https://github.com/jas502n/CVE-2018-3245)
- [ianxtianxt/CVE-2018-3245](https://github.com/ianxtianxt/CVE-2018-3245)

### CVE-2018-3252

<code>
Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
</code>

- [jas502n/CVE-2018-3252](https://github.com/jas502n/CVE-2018-3252)
- [b1ueb0y/CVE-2018-3252](https://github.com/b1ueb0y/CVE-2018-3252)
- [pyn3rd/CVE-2018-3252](https://github.com/pyn3rd/CVE-2018-3252)

### CVE-2018-3260
- [ionescu007/SpecuCheck](https://github.com/ionescu007/SpecuCheck)

### CVE-2018-3295

<code>
Vulnerability in the Oracle VM VirtualBox component of Oracle Virtualization (subcomponent: Core). The supported version that is affected is Prior to 5.2.20. Easily exploitable vulnerability allows unauthenticated attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in takeover of Oracle VM VirtualBox. CVSS 3.0 Base Score 8.6 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H).
</code>

- [ndureiss/e1000_vulnerability_exploit](https://github.com/ndureiss/e1000_vulnerability_exploit)

### CVE-2018-3608

<code>
A vulnerability in Trend Micro Maximum Security's (Consumer) 2018 (versions 12.0.1191 and below) User-Mode Hooking (UMH) driver could allow an attacker to create a specially crafted packet that could alter a vulnerable system in such a way that malicious code could be injected into other processes.
</code>

- [ZhiyuanWang-Chengdu-Qihoo360/Trend_Micro_POC](https://github.com/ZhiyuanWang-Chengdu-Qihoo360/Trend_Micro_POC)

### CVE-2018-3639

<code>
Systems with microprocessors utilizing speculative execution and speculative execution of memory reads before the addresses of all prior memory writes are known may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis, aka Speculative Store Bypass (SSB), Variant 4.
</code>

- [tyhicks/ssbd-tools](https://github.com/tyhicks/ssbd-tools)
- [malindarathnayake/Intel-CVE-2018-3639-Mitigation_RegistryUpdate](https://github.com/malindarathnayake/Intel-CVE-2018-3639-Mitigation_RegistryUpdate)
- [mmxsrup/CVE-2018-3639](https://github.com/mmxsrup/CVE-2018-3639)
- [Shuiliusheng/CVE-2018-3639-specter-v4-](https://github.com/Shuiliusheng/CVE-2018-3639-specter-v4-)

### CVE-2018-3760

<code>
There is an information leak vulnerability in Sprockets. Versions Affected: 4.0.0.beta7 and lower, 3.7.1 and lower, 2.12.4 and lower. Specially crafted requests can be used to access files that exists on the filesystem that is outside an application's root directory, when the Sprockets server is used in production. All users running an affected release should either upgrade or use one of the work arounds immediately.
</code>

- [mpgn/CVE-2018-3760](https://github.com/mpgn/CVE-2018-3760)

### CVE-2018-3783

<code>
A privilege escalation detected in flintcms versions &lt;= 1.1.9 allows account takeover due to blind MongoDB injection in password reset.
</code>

- [nisaruj/nosqli-flintcms](https://github.com/nisaruj/nosqli-flintcms)

### CVE-2018-3810

<code>
Authentication Bypass vulnerability in the Oturia Smart Google Code Inserter plugin before 3.5 for WordPress allows unauthenticated attackers to insert arbitrary JavaScript or HTML code (via the sgcgoogleanalytic parameter) that runs on all pages served by WordPress. The saveGoogleCode() function in smartgooglecode.php does not check if the current request is made by an authorized user, thus allowing any unauthenticated user to successfully update the inserted code.
</code>

- [lucad93/CVE-2018-3810](https://github.com/lucad93/CVE-2018-3810)
- [cved-sources/cve-2018-3810](https://github.com/cved-sources/cve-2018-3810)

### CVE-2018-3811

<code>
SQL Injection vulnerability in the Oturia Smart Google Code Inserter plugin before 3.5 for WordPress allows unauthenticated attackers to execute SQL queries in the context of the web server. The saveGoogleAdWords() function in smartgooglecode.php did not use prepared statements and did not sanitize the $_POST[&quot;oId&quot;] variable before passing it as input into the SQL query.
</code>

- [cved-sources/cve-2018-3811](https://github.com/cved-sources/cve-2018-3811)

### CVE-2018-4013

<code>
An exploitable code execution vulnerability exists in the HTTP packet-parsing functionality of the LIVE555 RTSP server library version 0.92. A specially crafted packet can cause a stack-based buffer overflow, resulting in code execution. An attacker can send a packet to trigger this vulnerability.
</code>

- [DoubleMice/cve-2018-4013](https://github.com/DoubleMice/cve-2018-4013)
- [r3dxpl0it/RTSPServer-Code-Execution-Vulnerability](https://github.com/r3dxpl0it/RTSPServer-Code-Execution-Vulnerability)

### CVE-2018-4087

<code>
An issue was discovered in certain Apple products. iOS before 11.2.5 is affected. tvOS before 11.2.5 is affected. watchOS before 4.2.2 is affected. The issue involves the &quot;Core Bluetooth&quot; component. It allows attackers to execute arbitrary code in a privileged context or cause a denial of service (memory corruption) via a crafted app.
</code>

- [rani-i/bluetoothdPoC](https://github.com/rani-i/bluetoothdPoC)
- [MTJailed/UnjailMe](https://github.com/MTJailed/UnjailMe)
- [joedaguy/Exploit11.2](https://github.com/joedaguy/Exploit11.2)

### CVE-2018-4110

<code>
An issue was discovered in certain Apple products. iOS before 11.3 is affected. The issue involves the &quot;Web App&quot; component. It allows remote attackers to bypass intended restrictions on cookie persistence.
</code>

- [bencompton/ios11-cookie-set-expire-issue](https://github.com/bencompton/ios11-cookie-set-expire-issue)

### CVE-2018-4121

<code>
An issue was discovered in certain Apple products. iOS before 11.3 is affected. Safari before 11.1 is affected. iCloud before 7.4 on Windows is affected. iTunes before 12.7.4 on Windows is affected. tvOS before 11.3 is affected. watchOS before 4.3 is affected. The issue involves the &quot;WebKit&quot; component. It allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption and application crash) via a crafted web site.
</code>

- [FSecureLABS/CVE-2018-4121](https://github.com/FSecureLABS/CVE-2018-4121)
- [denmilu/CVE-2018-4121](https://github.com/denmilu/CVE-2018-4121)
- [jezzus/CVE-2018-4121](https://github.com/jezzus/CVE-2018-4121)

### CVE-2018-4124

<code>
An issue was discovered in certain Apple products. iOS before 11.2.6 is affected. macOS before 10.13.3 Supplemental Update is affected. tvOS before 11.2.6 is affected. watchOS before 4.2.3 is affected. The issue involves the &quot;CoreText&quot; component. It allows remote attackers to cause a denial of service (memory corruption and system crash) or possibly have unspecified other impact via a crafted string containing a certain Telugu character.
</code>

- [ZecOps/TELUGU_CVE-2018-4124_POC](https://github.com/ZecOps/TELUGU_CVE-2018-4124_POC)

### CVE-2018-4150

<code>
An issue was discovered in certain Apple products. iOS before 11.3 is affected. macOS before 10.13.4 is affected. tvOS before 11.3 is affected. watchOS before 4.3 is affected. The issue involves the &quot;Kernel&quot; component. It allows attackers to execute arbitrary code in a privileged context or cause a denial of service (memory corruption) via a crafted app.
</code>

- [Jailbreaks/CVE-2018-4150](https://github.com/Jailbreaks/CVE-2018-4150)
- [RPwnage/LovelySn0w](https://github.com/RPwnage/LovelySn0w)
- [littlelailo/incomplete-exploit-for-CVE-2018-4150-bpf-filter-poc-](https://github.com/littlelailo/incomplete-exploit-for-CVE-2018-4150-bpf-filter-poc-)

### CVE-2018-4185

<code>
In iOS before 11.3, tvOS before 11.3, watchOS before 4.3, and macOS before High Sierra 10.13.4, an information disclosure issue existed in the transition of program state. This issue was addressed with improved state handling.
</code>

- [bazad/x18-leak](https://github.com/bazad/x18-leak)

### CVE-2018-4193

<code>
An issue was discovered in certain Apple products. macOS before 10.13.5 is affected. The issue involves the &quot;Windows Server&quot; component. It allows attackers to execute arbitrary code in a privileged context or cause a denial of service (memory corruption) via a crafted app.
</code>

- [Synacktiv-contrib/CVE-2018-4193](https://github.com/Synacktiv-contrib/CVE-2018-4193)

### CVE-2018-4233

<code>
An issue was discovered in certain Apple products. iOS before 11.4 is affected. Safari before 11.1.1 is affected. iCloud before 7.5 on Windows is affected. iTunes before 12.7.5 on Windows is affected. tvOS before 11.4 is affected. watchOS before 4.3.1 is affected. The issue involves the &quot;WebKit&quot; component. It allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption and application crash) via a crafted web site.
</code>

- [saelo/cve-2018-4233](https://github.com/saelo/cve-2018-4233)

### CVE-2018-4241

<code>
An issue was discovered in certain Apple products. iOS before 11.4 is affected. macOS before 10.13.5 is affected. tvOS before 11.4 is affected. watchOS before 4.3.1 is affected. The issue involves the &quot;Kernel&quot; component. A buffer overflow in mptcp_usr_connectx allows attackers to execute arbitrary code in a privileged context via a crafted app.
</code>

- [0neday/multi_path](https://github.com/0neday/multi_path)

### CVE-2018-4242

<code>
An issue was discovered in certain Apple products. macOS before 10.13.5 is affected. The issue involves the &quot;Hypervisor&quot; component. It allows attackers to execute arbitrary code in a privileged context or cause a denial of service (memory corruption) via a crafted app.
</code>

- [yeonnic/Look-at-The-XNU-Through-A-Tube-CVE-2018-4242-Write-up-Translation-](https://github.com/yeonnic/Look-at-The-XNU-Through-A-Tube-CVE-2018-4242-Write-up-Translation-)

### CVE-2018-4243

<code>
An issue was discovered in certain Apple products. iOS before 11.4 is affected. macOS before 10.13.5 is affected. tvOS before 11.4 is affected. watchOS before 4.3.1 is affected. The issue involves the &quot;Kernel&quot; component. A buffer overflow in getvolattrlist allows attackers to execute arbitrary code in a privileged context via a crafted app.
</code>

- [Jailbreaks/empty_list](https://github.com/Jailbreaks/empty_list)

### CVE-2018-4248

<code>
An out-of-bounds read was addressed with improved input validation. This issue affected versions prior to iOS 11.4.1, macOS High Sierra 10.13.6, tvOS 11.4.1, watchOS 4.3.2.
</code>

- [bazad/xpc-string-leak](https://github.com/bazad/xpc-string-leak)

### CVE-2018-4280

<code>
A memory corruption issue was addressed with improved memory handling. This issue affected versions prior to iOS 11.4.1, macOS High Sierra 10.13.6, tvOS 11.4.1, watchOS 4.3.2.
</code>

- [bazad/launchd-portrep](https://github.com/bazad/launchd-portrep)
- [bazad/blanket](https://github.com/bazad/blanket)

### CVE-2018-4327

<code>
A memory corruption issue was addressed with improved memory handling. This issue affected versions prior to iOS 11.4.1.
</code>

- [omerporze/brokentooth](https://github.com/omerporze/brokentooth)
- [harryanon/POC-CVE-2018-4327-and-CVE-2018-4330](https://github.com/harryanon/POC-CVE-2018-4327-and-CVE-2018-4330)

### CVE-2018-4330

<code>
In iOS before 11.4, a memory corruption issue exists and was addressed with improved memory handling.
</code>

- [omerporze/toothfairy](https://github.com/omerporze/toothfairy)

### CVE-2018-4331

<code>
A memory corruption issue was addressed with improved memory handling. This issue affected versions prior to iOS 12, macOS Mojave 10.14, tvOS 12, watchOS 5.
</code>

- [bazad/gsscred-race](https://github.com/bazad/gsscred-race)

### CVE-2018-4343

<code>
A memory corruption issue was addressed with improved memory handling. This issue affected versions prior to iOS 12, macOS Mojave 10.14, tvOS 12, watchOS 5.
</code>

- [bazad/gsscred-move-uaf](https://github.com/bazad/gsscred-move-uaf)

### CVE-2018-4407

<code>
A memory corruption issue was addressed with improved validation. This issue affected versions prior to iOS 12, macOS Mojave 10.14, tvOS 12, watchOS 5.
</code>

- [Pa55w0rd/check_icmp_dos](https://github.com/Pa55w0rd/check_icmp_dos)
- [unixpickle/cve-2018-4407](https://github.com/unixpickle/cve-2018-4407)
- [s2339956/check_icmp_dos-CVE-2018-4407-](https://github.com/s2339956/check_icmp_dos-CVE-2018-4407-)
- [farisv/AppleDOS](https://github.com/farisv/AppleDOS)
- [WyAtu/CVE-2018-4407](https://github.com/WyAtu/CVE-2018-4407)
- [zteeed/CVE-2018-4407-IOS](https://github.com/zteeed/CVE-2018-4407-IOS)
- [SamDecrock/node-cve-2018-4407](https://github.com/SamDecrock/node-cve-2018-4407)
- [r3dxpl0it/CVE-2018-4407](https://github.com/r3dxpl0it/CVE-2018-4407)
- [lucagiovagnoli/CVE-2018-4407](https://github.com/lucagiovagnoli/CVE-2018-4407)
- [anonymouz4/Apple-Remote-Crash-Tool-CVE-2018-4407](https://github.com/anonymouz4/Apple-Remote-Crash-Tool-CVE-2018-4407)
- [soccercab/wifi](https://github.com/soccercab/wifi)
- [zeng9t/CVE-2018-4407-iOS-exploit](https://github.com/zeng9t/CVE-2018-4407-iOS-exploit)
- [5431/CVE-2018-4407](https://github.com/5431/CVE-2018-4407)
- [pwnhacker0x18/iOS-Kernel-Crash](https://github.com/pwnhacker0x18/iOS-Kernel-Crash)

### CVE-2018-4411

<code>
A memory corruption issue was addressed with improved input validation. This issue affected versions prior to macOS Mojave 10.14.
</code>

- [lilang-wu/POC-CVE-2018-4411](https://github.com/lilang-wu/POC-CVE-2018-4411)

### CVE-2018-4415

<code>
A memory corruption issue was addressed with improved memory handling. This issue affected versions prior to macOS Mojave 10.14.1.
</code>

- [T1V0h/CVE-2018-4415](https://github.com/T1V0h/CVE-2018-4415)

### CVE-2018-4431

<code>
A memory initialization issue was addressed with improved memory handling. This issue affected versions prior to iOS 12.1.1, macOS Mojave 10.14.2, tvOS 12.1.1, watchOS 5.1.2.
</code>

- [ktiOSz/PoC_iOS12](https://github.com/ktiOSz/PoC_iOS12)

### CVE-2018-4441

<code>
A memory corruption issue was addressed with improved memory handling. This issue affected versions prior to iOS 12.1.1, tvOS 12.1.1, watchOS 5.1.2, Safari 12.0.2, iTunes 12.9.2 for Windows, iCloud for Windows 7.9.
</code>

- [Cryptogenic/PS4-6.20-WebKit-Code-Execution-Exploit](https://github.com/Cryptogenic/PS4-6.20-WebKit-Code-Execution-Exploit)

### CVE-2018-4878

<code>
A use-after-free vulnerability was discovered in Adobe Flash Player before 28.0.0.161. This vulnerability occurs due to a dangling pointer in the Primetime SDK related to media player handling of listener objects. A successful attack can lead to arbitrary code execution. This was exploited in the wild in January and February 2018.
</code>

- [ydl555/CVE-2018-4878-](https://github.com/ydl555/CVE-2018-4878-)
- [mdsecactivebreach/CVE-2018-4878](https://github.com/mdsecactivebreach/CVE-2018-4878)
- [hybridious/CVE-2018-4878](https://github.com/hybridious/CVE-2018-4878)
- [vysecurity/CVE-2018-4878](https://github.com/vysecurity/CVE-2018-4878)
- [anbai-inc/CVE-2018-4878](https://github.com/anbai-inc/CVE-2018-4878)
- [Sch01ar/CVE-2018-4878](https://github.com/Sch01ar/CVE-2018-4878)
- [SyFi/CVE-2018-4878](https://github.com/SyFi/CVE-2018-4878)
- [ydl555/CVE-2018-4878](https://github.com/ydl555/CVE-2018-4878)
- [B0fH/CVE-2018-4878](https://github.com/B0fH/CVE-2018-4878)
- [Yable/CVE-2018-4878](https://github.com/Yable/CVE-2018-4878)
- [HuanWoWeiLan/SoftwareSystemSecurity-2019](https://github.com/HuanWoWeiLan/SoftwareSystemSecurity-2019)

### CVE-2018-4901

<code>
An issue was discovered in Adobe Acrobat Reader 2018.009.20050 and earlier versions, 2017.011.30070 and earlier versions, 2015.006.30394 and earlier versions. The vulnerability is caused by the computation that writes data past the end of the intended buffer; the computation is part of the document identity representation. An attacker can potentially leverage the vulnerability to corrupt sensitive data or execute arbitrary code.
</code>

- [bigric3/CVE-2018-4901](https://github.com/bigric3/CVE-2018-4901)

### CVE-2018-5234

<code>
The Norton Core router prior to v237 may be susceptible to a command injection exploit. This is a type of attack in which the goal is execution of arbitrary commands on the host system via vulnerable software.
</code>

- [embedi/ble_norton_core](https://github.com/embedi/ble_norton_core)

### CVE-2018-5711

<code>
gd_gif_in.c in the GD Graphics Library (aka libgd), as used in PHP before 5.6.33, 7.0.x before 7.0.27, 7.1.x before 7.1.13, and 7.2.x before 7.2.1, has an integer signedness error that leads to an infinite loop via a crafted GIF file, as demonstrated by a call to the imagecreatefromgif or imagecreatefromstring PHP function. This is related to GetCode_ and gdImageCreateFromGifCtx.
</code>

- [huzhenghui/Test-7-2-0-PHP-CVE-2018-5711](https://github.com/huzhenghui/Test-7-2-0-PHP-CVE-2018-5711)
- [huzhenghui/Test-7-2-1-PHP-CVE-2018-5711](https://github.com/huzhenghui/Test-7-2-1-PHP-CVE-2018-5711)

### CVE-2018-5724

<code>
MASTER IPCAMERA01 3.3.4.2103 devices allow Unauthenticated Configuration Download and Upload, as demonstrated by restore.cgi.
</code>

- [gusrmsdlrh/Python-CVE-Code](https://github.com/gusrmsdlrh/Python-CVE-Code)

### CVE-2018-5728

<code>
Cobham Sea Tel 121 build 222701 devices allow remote attackers to obtain potentially sensitive information via a /cgi-bin/getSysStatus request, as demonstrated by the Latitude/Longitude of the ship, or satellite details.
</code>

- [ezelf/seatel_terminals](https://github.com/ezelf/seatel_terminals)

### CVE-2018-5740

<code>
&quot;deny-answer-aliases&quot; is a little-used feature intended to help recursive server operators protect end users against DNS rebinding attacks, a potential method of circumventing the security model used by client browsers. However, a defect in this feature makes it easy, when the feature is in use, to experience an assertion failure in name.c. Affects BIND 9.7.0-&gt;9.8.8, 9.9.0-&gt;9.9.13, 9.10.0-&gt;9.10.8, 9.11.0-&gt;9.11.4, 9.12.0-&gt;9.12.2, 9.13.0-&gt;9.13.2.
</code>

- [sischkg/cve-2018-5740](https://github.com/sischkg/cve-2018-5740)

### CVE-2018-5951

<code>
An issue was discovered in Mikrotik RouterOS. Crafting a packet that has a size of 1 byte and sending it to an IPv6 address of a RouterOS box with IP Protocol 97 will cause RouterOS to reboot imminently. All versions of RouterOS that supports EoIPv6 are vulnerable to this attack.
</code>

- [Nat-Lab/CVE-2018-5951](https://github.com/Nat-Lab/CVE-2018-5951)

### CVE-2018-5955

<code>
An issue was discovered in GitStack through 2.3.10. User controlled input is not sufficiently filtered, allowing an unauthenticated attacker to add a user to the server via the username and password fields to the rest/user/ URI.
</code>

- [cisp/GitStackRCE](https://github.com/cisp/GitStackRCE)
- [YagamiiLight/Cerberus](https://github.com/YagamiiLight/Cerberus)

### CVE-2018-6242

<code>
Some NVIDIA Tegra mobile processors released prior to 2016 contain a buffer overflow vulnerability in BootROM Recovery Mode (RCM). An attacker with physical access to the device's USB and the ability to force the device to reboot into RCM could exploit the vulnerability to execute unverified code.
</code>

- [DavidBuchanan314/NXLoader](https://github.com/DavidBuchanan314/NXLoader)
- [reswitched/rcm-modchips](https://github.com/reswitched/rcm-modchips)
- [switchjs/fusho](https://github.com/switchjs/fusho)

### CVE-2018-6376

<code>
In Joomla! before 3.8.4, the lack of type casting of a variable in a SQL statement leads to a SQL injection vulnerability in the Hathor postinstall message.
</code>

- [knqyf263/CVE-2018-6376](https://github.com/knqyf263/CVE-2018-6376)

### CVE-2018-6389

<code>
In WordPress through 4.9.2, unauthenticated attackers can cause a denial of service (resource consumption) by using the large list of registered .js files (from wp-includes/script-loader.php) to construct a series of requests to load every file many times.
</code>

- [yolabingo/wordpress-fix-cve-2018-6389](https://github.com/yolabingo/wordpress-fix-cve-2018-6389)
- [WazeHell/CVE-2018-6389](https://github.com/WazeHell/CVE-2018-6389)
- [rastating/modsecurity-cve-2018-6389](https://github.com/rastating/modsecurity-cve-2018-6389)
- [knqyf263/CVE-2018-6389](https://github.com/knqyf263/CVE-2018-6389)
- [JulienGadanho/cve-2018-6389-php-patcher](https://github.com/JulienGadanho/cve-2018-6389-php-patcher)
- [dsfau/wordpress-CVE-2018-6389](https://github.com/dsfau/wordpress-CVE-2018-6389)
- [Jetserver/CVE-2018-6389-FIX](https://github.com/Jetserver/CVE-2018-6389-FIX)
- [thechrono13/PoC---CVE-2018-6389](https://github.com/thechrono13/PoC---CVE-2018-6389)
- [BlackRouter/cve-2018-6389](https://github.com/BlackRouter/cve-2018-6389)
- [alessiogilardi/PoC---CVE-2018-6389](https://github.com/alessiogilardi/PoC---CVE-2018-6389)
- [JavierOlmedo/wordpress-cve-2018-6389](https://github.com/JavierOlmedo/wordpress-cve-2018-6389)
- [m3ssap0/wordpress_cve-2018-6389](https://github.com/m3ssap0/wordpress_cve-2018-6389)
- [s0md3v/Shiva](https://github.com/s0md3v/Shiva)
- [mudhappy/Wordpress-Hack-CVE-2018-6389](https://github.com/mudhappy/Wordpress-Hack-CVE-2018-6389)
- [armaanpathan12345/WP-DOS-Exploit-CVE-2018-6389](https://github.com/armaanpathan12345/WP-DOS-Exploit-CVE-2018-6389)
- [ItinerisLtd/trellis-cve-2018-6389](https://github.com/ItinerisLtd/trellis-cve-2018-6389)
- [Zazzzles/Wordpress-DOS](https://github.com/Zazzzles/Wordpress-DOS)
- [fakedob/tvsz](https://github.com/fakedob/tvsz)
- [heisenberg-official/Wordpress-DOS-Attack-CVE-2018-6389](https://github.com/heisenberg-official/Wordpress-DOS-Attack-CVE-2018-6389)
- [ianxtianxt/CVE-2018-6389](https://github.com/ianxtianxt/CVE-2018-6389)

### CVE-2018-6396

<code>
SQL Injection exists in the Google Map Landkarten through 4.2.3 component for Joomla! via the cid or id parameter in a layout=form_markers action, or the map parameter in a layout=default action.
</code>

- [JavierOlmedo/joomla-cve-2018-6396](https://github.com/JavierOlmedo/joomla-cve-2018-6396)

### CVE-2018-6407

<code>
An issue was discovered on Conceptronic CIPCAMPTIWL V3 0.61.30.21 devices. An unauthenticated attacker can crash a device by sending a POST request with a huge body size to /hy-cgi/devices.cgi?cmd=searchlandevice. The crash completely freezes the device.
</code>

- [dreadlocked/ConceptronicIPCam_MultipleVulnerabilities](https://github.com/dreadlocked/ConceptronicIPCam_MultipleVulnerabilities)

### CVE-2018-6479

<code>
An issue was discovered on Netwave IP Camera devices. An unauthenticated attacker can crash a device by sending a POST request with a huge body size to the / URI.
</code>

- [dreadlocked/netwave-dosvulnerability](https://github.com/dreadlocked/netwave-dosvulnerability)

### CVE-2018-6518

<code>
Composr CMS 10.0.13 has XSS via the site_name parameter in a page=admin-setupwizard&amp;type=step3 request to /adminzone/index.php.
</code>

- [faizzaidi/Composr-CMS-10.0.13-Cross-Site-Scripting-XSS](https://github.com/faizzaidi/Composr-CMS-10.0.13-Cross-Site-Scripting-XSS)

### CVE-2018-6546

<code>
plays_service.exe in the plays.tv service before 1.27.7.0, as distributed in AMD driver-installation packages and Gaming Evolved products, executes code at a user-defined (local or SMB) path as SYSTEM when the execute_installer parameter is used in an HTTP message. This occurs without properly authenticating the user.
</code>

- [securifera/CVE-2018-6546-Exploit](https://github.com/securifera/CVE-2018-6546-Exploit)
- [YanZiShuang/CVE-2018-6546](https://github.com/YanZiShuang/CVE-2018-6546)

### CVE-2018-6574

<code>
Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow &quot;go get&quot; remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.
</code>

- [acole76/cve-2018-6574](https://github.com/acole76/cve-2018-6574)
- [neargle/CVE-2018-6574-POC](https://github.com/neargle/CVE-2018-6574-POC)
- [willbo4r/go-get-rce](https://github.com/willbo4r/go-get-rce)
- [ahmetmanga/go-get-rce](https://github.com/ahmetmanga/go-get-rce)
- [ahmetmanga/cve-2018-6574](https://github.com/ahmetmanga/cve-2018-6574)
- [michiiii/go-get-exploit](https://github.com/michiiii/go-get-exploit)
- [kenprice/cve-2018-6574](https://github.com/kenprice/cve-2018-6574)
- [redirected/cve-2018-6574](https://github.com/redirected/cve-2018-6574)
- [20matan/CVE-2018-6574-POC](https://github.com/20matan/CVE-2018-6574-POC)
- [zur250/Zur-Go-GET-RCE-Solution](https://github.com/zur250/Zur-Go-GET-RCE-Solution)
- [mekhalleh/cve-2018-6574](https://github.com/mekhalleh/cve-2018-6574)
- [veter069/go-get-rce](https://github.com/veter069/go-get-rce)
- [duckzsc2/CVE-2018-6574-POC](https://github.com/duckzsc2/CVE-2018-6574-POC)
- [ivnnn1/CVE-2018-6574](https://github.com/ivnnn1/CVE-2018-6574)
- [dollyptm/cve-2018-6574](https://github.com/dollyptm/cve-2018-6574)
- [qweraqq/CVE-2018-6574](https://github.com/qweraqq/CVE-2018-6574)
- [d4rkshell/go-get-rce](https://github.com/d4rkshell/go-get-rce)
- [chaosura/CVE-2018-6574](https://github.com/chaosura/CVE-2018-6574)
- [french560/ptl6574](https://github.com/french560/ptl6574)
- [InfoSecJack/CVE-2018-6574](https://github.com/InfoSecJack/CVE-2018-6574)
- [asavior2/CVE-2018-6574](https://github.com/asavior2/CVE-2018-6574)
- [drset/golang](https://github.com/drset/golang)
- [frozenkp/CVE-2018-6574](https://github.com/frozenkp/CVE-2018-6574)
- [kev-ho/cve-2018-6574-payload](https://github.com/kev-ho/cve-2018-6574-payload)
- [sdosis/cve-2018-6574](https://github.com/sdosis/cve-2018-6574)
- [No1zy/CVE-2018-6574-PoC](https://github.com/No1zy/CVE-2018-6574-PoC)
- [nthuong95/CVE-2018-6574](https://github.com/nthuong95/CVE-2018-6574)
- [AdriVillaB/CVE-2018-6574](https://github.com/AdriVillaB/CVE-2018-6574)
- [yitingfan/CVE-2018-6574_demo](https://github.com/yitingfan/CVE-2018-6574_demo)
- [mhamed366/CVE-2018-6574](https://github.com/mhamed366/CVE-2018-6574)
- [Eugene24/CVE-2018-6574](https://github.com/Eugene24/CVE-2018-6574)
- [coblax/CVE-2018-6574](https://github.com/coblax/CVE-2018-6574)

### CVE-2018-6622

<code>
An issue was discovered that affects all producers of BIOS firmware who make a certain realistic interpretation of an obscure portion of the Trusted Computing Group (TCG) Trusted Platform Module (TPM) 2.0 specification. An abnormal case is not handled properly by this firmware while S3 sleep and can clear TPM 2.0. It allows local users to overwrite static PCRs of TPM and neutralize the security features of it, such as seal/unseal and remote attestation.
</code>

- [kkamagui/napper-for-tpm](https://github.com/kkamagui/napper-for-tpm)

### CVE-2018-6643

<code>
Infoblox NetMRI 7.1.1 has Reflected Cross-Site Scripting via the /api/docs/index.php query parameter.
</code>

- [undefinedmode/CVE-2018-6643](https://github.com/undefinedmode/CVE-2018-6643)

### CVE-2018-6789

<code>
An issue was discovered in the base64d function in the SMTP listener in Exim before 4.90.1. By sending a handcrafted message, a buffer overflow may happen. This can be used to execute code remotely.
</code>

- [c0llision/exim-vuln-poc](https://github.com/c0llision/exim-vuln-poc)
- [beraphin/CVE-2018-6789](https://github.com/beraphin/CVE-2018-6789)
- [synacktiv/Exim-CVE-2018-6789](https://github.com/synacktiv/Exim-CVE-2018-6789)
- [martinclauss/exim-rce-cve-2018-6789](https://github.com/martinclauss/exim-rce-cve-2018-6789)

### CVE-2018-6791

<code>
An issue was discovered in soliduiserver/deviceserviceaction.cpp in KDE Plasma Workspace before 5.12.0. When a vfat thumbdrive that contains `` or $() in its volume label is plugged in and mounted through the device notifier, it's interpreted as a shell command, leading to a possibility of arbitrary command execution. An example of an offending volume label is &quot;$(touch b)&quot; -- this will create a file called b in the home folder.
</code>

- [rarar0/KDE_Vuln](https://github.com/rarar0/KDE_Vuln)

### CVE-2018-6890

<code>
Cross-site scripting (XSS) vulnerability in Wolf CMS 0.8.3.1 via the page editing feature, as demonstrated by /?/admin/page/edit/3.
</code>

- [pradeepjairamani/WolfCMS-XSS-POC](https://github.com/pradeepjairamani/WolfCMS-XSS-POC)

### CVE-2018-6892

<code>
An issue was discovered in CloudMe before 1.11.0. An unauthenticated remote attacker that can connect to the &quot;CloudMe Sync&quot; client application listening on port 8888 can send a malicious payload causing a buffer overflow condition. This will result in an attacker controlling the program's execution flow and allowing arbitrary code execution.
</code>

- [manojcode/CloudMe-Sync-1.10.9---Buffer-Overflow-SEH-DEP-Bypass](https://github.com/manojcode/CloudMe-Sync-1.10.9---Buffer-Overflow-SEH-DEP-Bypass)
- [manojcode/-Win10-x64-CloudMe-Sync-1.10.9-Buffer-Overflow-SEH-DEP-Bypass](https://github.com/manojcode/-Win10-x64-CloudMe-Sync-1.10.9-Buffer-Overflow-SEH-DEP-Bypass)

### CVE-2018-6905

<code>
The page module in TYPO3 before 8.7.11, and 9.1.0, has XSS via $GLOBALS['TYPO3_CONF_VARS']['SYS']['sitename'], as demonstrated by an admin entering a crafted site name during the installation process.
</code>

- [pradeepjairamani/TYPO3-XSS-POC](https://github.com/pradeepjairamani/TYPO3-XSS-POC)

### CVE-2018-6961

<code>
VMware NSX SD-WAN Edge by VeloCloud prior to version 3.1.0 contains a command injection vulnerability in the local web UI component. This component is disabled by default and should not be enabled on untrusted networks. VeloCloud by VMware will be removing this service from the product in future releases. Successful exploitation of this issue could result in remote code execution.
</code>

- [bokanrb/CVE-2018-6961](https://github.com/bokanrb/CVE-2018-6961)
- [r3dxpl0it/CVE-2018-6961](https://github.com/r3dxpl0it/CVE-2018-6961)

### CVE-2018-6981

<code>
VMware ESXi 6.7 without ESXi670-201811401-BG and VMware ESXi 6.5 without ESXi650-201811301-BG, VMware ESXi 6.0 without ESXi600-201811401-BG, VMware Workstation 15, VMware Workstation 14.1.3 or below, VMware Fusion 11, VMware Fusion 10.1.3 or below contain uninitialized stack memory usage in the vmxnet3 virtual network adapter which may allow a guest to execute code on the host.
</code>

- [heaphopopotamus/vmxnet3Hunter](https://github.com/heaphopopotamus/vmxnet3Hunter)

### CVE-2018-7171

<code>
Directory traversal vulnerability in Twonky Server 7.0.11 through 8.5 allows remote attackers to share the contents of arbitrary directories via a .. (dot dot) in the contentbase parameter to rpc/set_all.
</code>

- [mechanico/sharingIsCaring](https://github.com/mechanico/sharingIsCaring)

### CVE-2018-7197

<code>
An issue was discovered in Pluck through 4.7.4. A stored cross-site scripting (XSS) vulnerability allows remote unauthenticated users to inject arbitrary web script or HTML into admin/blog Reaction Comments via a crafted URL.
</code>

- [Alyssa-o-Herrera/CVE-2018-7197](https://github.com/Alyssa-o-Herrera/CVE-2018-7197)

### CVE-2018-7211

<code>
An issue was discovered in iDashboards 9.6b. The SSO implementation is affected by a weak obfuscation library, allowing man-in-the-middle attackers to discover credentials.
</code>

- [c3r34lk1ll3r/CVE-2018-7211-PoC](https://github.com/c3r34lk1ll3r/CVE-2018-7211-PoC)

### CVE-2018-7249

<code>
An issue was discovered in secdrv.sys as shipped in Microsoft Windows Vista, Windows 7, Windows 8, and Windows 8.1 before KB3086255, and as shipped in Macrovision SafeDisc. Two carefully timed calls to IOCTL 0xCA002813 can cause a race condition that leads to a use-after-free. When exploited, an unprivileged attacker can run arbitrary code in the kernel.
</code>

- [Elvin9/NotSecDrv](https://github.com/Elvin9/NotSecDrv)

### CVE-2018-7250

<code>
An issue was discovered in secdrv.sys as shipped in Microsoft Windows Vista, Windows 7, Windows 8, and Windows 8.1 before KB3086255, and as shipped in Macrovision SafeDisc. An uninitialized kernel pool allocation in IOCTL 0xCA002813 allows a local unprivileged attacker to leak 16 bits of uninitialized kernel PagedPool data.
</code>

- [Elvin9/SecDrvPoolLeak](https://github.com/Elvin9/SecDrvPoolLeak)

### CVE-2018-7284

<code>
A Buffer Overflow issue was discovered in Asterisk through 13.19.1, 14.x through 14.7.5, and 15.x through 15.2.1, and Certified Asterisk through 13.18-cert2. When processing a SUBSCRIBE request, the res_pjsip_pubsub module stores the accepted formats present in the Accept headers of the request. This code did not limit the number of headers it processed, despite having a fixed limit of 32. If more than 32 Accept headers were present, the code would write outside of its memory and cause a crash.
</code>

- [Rodrigo-D/astDoS](https://github.com/Rodrigo-D/astDoS)

### CVE-2018-7422

<code>
A Local File Inclusion vulnerability in the Site Editor plugin through 1.1.1 for WordPress allows remote attackers to retrieve arbitrary files via the ajax_path parameter to editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php, aka absolute path traversal.
</code>

- [0x00-0x00/CVE-2018-7422](https://github.com/0x00-0x00/CVE-2018-7422)

### CVE-2018-7489

<code>
FasterXML jackson-databind before 2.7.9.3, 2.8.x before 2.8.11.1 and 2.9.x before 2.9.5 allows unauthenticated remote code execution because of an incomplete fix for the CVE-2017-7525 deserialization flaw. This is exploitable by sending maliciously crafted JSON input to the readValue method of the ObjectMapper, bypassing a blacklist that is ineffective if the c3p0 libraries are available in the classpath.
</code>

- [tafamace/CVE-2018-7489](https://github.com/tafamace/CVE-2018-7489)

### CVE-2018-7600

<code>
Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations.
</code>

- [g0rx/CVE-2018-7600-Drupal-RCE](https://github.com/g0rx/CVE-2018-7600-Drupal-RCE)
- [a2u/CVE-2018-7600](https://github.com/a2u/CVE-2018-7600)
- [dreadlocked/Drupalgeddon2](https://github.com/dreadlocked/Drupalgeddon2)
- [knqyf263/CVE-2018-7600](https://github.com/knqyf263/CVE-2018-7600)
- [dr-iman/CVE-2018-7600-Drupal-0day-RCE](https://github.com/dr-iman/CVE-2018-7600-Drupal-0day-RCE)
- [jirojo2/drupalgeddon2](https://github.com/jirojo2/drupalgeddon2)
- [dwisiswant0/CVE-2018-7600](https://github.com/dwisiswant0/CVE-2018-7600)
- [thehappydinoa/CVE-2018-7600](https://github.com/thehappydinoa/CVE-2018-7600)
- [sl4cky/CVE-2018-7600](https://github.com/sl4cky/CVE-2018-7600)
- [sl4cky/CVE-2018-7600-Masschecker](https://github.com/sl4cky/CVE-2018-7600-Masschecker)
- [FireFart/CVE-2018-7600](https://github.com/FireFart/CVE-2018-7600)
- [pimps/CVE-2018-7600](https://github.com/pimps/CVE-2018-7600)
- [lorddemon/drupalgeddon2](https://github.com/lorddemon/drupalgeddon2)
- [Sch01ar/CVE-2018-7600](https://github.com/Sch01ar/CVE-2018-7600)
- [Hestat/drupal-check](https://github.com/Hestat/drupal-check)
- [fyraiga/CVE-2018-7600-drupalgeddon2-scanner](https://github.com/fyraiga/CVE-2018-7600-drupalgeddon2-scanner)
- [Damian972/drupalgeddon-2](https://github.com/Damian972/drupalgeddon-2)
- [Jyozi/CVE-2018-7600](https://github.com/Jyozi/CVE-2018-7600)
- [happynote3966/CVE-2018-7600](https://github.com/happynote3966/CVE-2018-7600)
- [shellord/CVE-2018-7600-Drupal-RCE](https://github.com/shellord/CVE-2018-7600-Drupal-RCE)
- [r3dxpl0it/CVE-2018-7600](https://github.com/r3dxpl0it/CVE-2018-7600)
- [cved-sources/cve-2018-7600](https://github.com/cved-sources/cve-2018-7600)
- [neal1991/drupalgeddon2](https://github.com/neal1991/drupalgeddon2)
- [drugeddon/drupal-exploit](https://github.com/drugeddon/drupal-exploit)
- [shellord/Drupalgeddon-Mass-Exploiter](https://github.com/shellord/Drupalgeddon-Mass-Exploiter)
- [zhzyker/CVE-2018-7600-Drupal-POC-EXP](https://github.com/zhzyker/CVE-2018-7600-Drupal-POC-EXP)
- [rabbitmask/CVE-2018-7600-Drupal7](https://github.com/rabbitmask/CVE-2018-7600-Drupal7)

### CVE-2018-7602

<code>
A remote code execution vulnerability exists within multiple subsystems of Drupal 7.x and 8.x. This potentially allows attackers to exploit multiple attack vectors on a Drupal site, which could result in the site being compromised. This vulnerability is related to Drupal core - Highly critical - Remote Code Execution - SA-CORE-2018-002. Both SA-CORE-2018-002 and this vulnerability are being exploited in the wild.
</code>

- [1337g/Drupalgedon3](https://github.com/1337g/Drupalgedon3)
- [happynote3966/CVE-2018-7602](https://github.com/happynote3966/CVE-2018-7602)
- [kastellanos/CVE-2018-7602](https://github.com/kastellanos/CVE-2018-7602)

### CVE-2018-7690

<code>
A potential Remote Unauthorized Access in Micro Focus Fortify Software Security Center (SSC), versions 17.10, 17.20, 18.10 this exploitation could allow Remote Unauthorized Access
</code>

- [alt3kx/CVE-2018-7690](https://github.com/alt3kx/CVE-2018-7690)

### CVE-2018-7691

<code>
A potential Remote Unauthorized Access in Micro Focus Fortify Software Security Center (SSC), versions 17.10, 17.20, 18.10 this exploitation could allow Remote Unauthorized Access
</code>

- [alt3kx/CVE-2018-7691](https://github.com/alt3kx/CVE-2018-7691)

### CVE-2018-7747

<code>
Multiple cross-site scripting (XSS) vulnerabilities in the Caldera Forms plugin before 1.6.0-rc.1 for WordPress allow remote attackers to inject arbitrary web script or HTML via vectors involving (1) a greeting message, (2) the email transaction log, or (3) an imported form.
</code>

- [mindpr00f/CVE-2018-7747](https://github.com/mindpr00f/CVE-2018-7747)

### CVE-2018-7750

<code>
transport.py in the SSH server implementation of Paramiko before 1.17.6, 1.18.x before 1.18.5, 2.0.x before 2.0.8, 2.1.x before 2.1.5, 2.2.x before 2.2.3, 2.3.x before 2.3.2, and 2.4.x before 2.4.1 does not properly check whether authentication is completed before processing other requests, as demonstrated by channel-open. A customized SSH client can simply skip the authentication step.
</code>

- [jm33-m0/CVE-2018-7750](https://github.com/jm33-m0/CVE-2018-7750)

### CVE-2018-7935
- [lawrenceamer/CVE-2018-7935](https://github.com/lawrenceamer/CVE-2018-7935)

### CVE-2018-8021

<code>
Versions of Superset prior to 0.23 used an unsafe load method from the pickle library to deserialize data leading to possible remote code execution. Note Superset 0.23 was released prior to any Superset release under the Apache Software Foundation.
</code>

- [r3dxpl0it/Apache-Superset-Remote-Code-Execution-PoC-CVE-2018-8021](https://github.com/r3dxpl0it/Apache-Superset-Remote-Code-Execution-PoC-CVE-2018-8021)

### CVE-2018-8032

<code>
Apache Axis 1.x up to and including 1.4 is vulnerable to a cross-site scripting (XSS) attack in the default servlet/services.
</code>

- [cairuojin/CVE-2018-8032](https://github.com/cairuojin/CVE-2018-8032)

### CVE-2018-8038

<code>
Versions of Apache CXF Fediz prior to 1.4.4 do not fully disable Document Type Declarations (DTDs) when either parsing the Identity Provider response in the application plugins, or in the Identity Provider itself when parsing certain XML-based parameters.
</code>

- [tafamace/CVE-2018-8038](https://github.com/tafamace/CVE-2018-8038)

### CVE-2018-8039

<code>
It is possible to configure Apache CXF to use the com.sun.net.ssl implementation via 'System.setProperty(&quot;java.protocol.handler.pkgs&quot;, &quot;com.sun.net.ssl.internal.www.protocol&quot;);'. When this system property is set, CXF uses some reflection to try to make the HostnameVerifier work with the old com.sun.net.ssl.HostnameVerifier interface. However, the default HostnameVerifier implementation in CXF does not implement the method in this interface, and an exception is thrown. However, in Apache CXF prior to 3.2.5 and 3.1.16 the exception is caught in the reflection code and not properly propagated. What this means is that if you are using the com.sun.net.ssl stack with CXF, an error with TLS hostname verification will not be thrown, leaving a CXF client subject to man-in-the-middle attacks.
</code>

- [tafamace/CVE-2018-8039](https://github.com/tafamace/CVE-2018-8039)

### CVE-2018-8045

<code>
In Joomla! 3.5.0 through 3.8.5, the lack of type casting of a variable in a SQL statement leads to a SQL injection vulnerability in the User Notes list view.
</code>

- [luckybool1020/CVE-2018-8045](https://github.com/luckybool1020/CVE-2018-8045)

### CVE-2018-8060

<code>
HWiNFO AMD64 Kernel driver version 8.98 and lower allows an unprivileged user to send an IOCTL to the device driver. If input and/or output buffer pointers are NULL or if these buffers' data are invalid, a NULL/invalid pointer access occurs, resulting in a Windows kernel panic aka Blue Screen. This affects IOCTLs higher than 0x85FE2600 with the HWiNFO32 symbolic device name.
</code>

- [otavioarj/SIOCtl](https://github.com/otavioarj/SIOCtl)

### CVE-2018-8065

<code>
An issue was discovered in the web server in Flexense SyncBreeze Enterprise 10.6.24. There is a user mode write access violation on the syncbrs.exe memory region that can be triggered by rapidly sending a variety of HTTP requests with long HTTP header values or long URIs.
</code>

- [EgeBalci/CVE-2018-8065](https://github.com/EgeBalci/CVE-2018-8065)

### CVE-2018-8078

<code>
YzmCMS 3.7 has Stored XSS via the title parameter to advertisement/adver/edit.html.
</code>

- [AlwaysHereFight/YZMCMSxss](https://github.com/AlwaysHereFight/YZMCMSxss)

### CVE-2018-8090

<code>
Quick Heal Total Security 64 bit 17.00 (QHTS64.exe), (QHTSFT64.exe) - Version 10.0.1.38; Quick Heal Total Security 32 bit 17.00 (QHTS32.exe), (QHTSFT32.exe) - Version 10.0.1.38; Quick Heal Internet Security 64 bit 17.00 (QHIS64.exe), (QHISFT64.exe) - Version 10.0.0.37; Quick Heal Internet Security 32 bit 17.00 (QHIS32.exe), (QHISFT32.exe) - Version 10.0.0.37; Quick Heal AntiVirus Pro 64 bit 17.00 (QHAV64.exe), (QHAVFT64.exe) - Version 10.0.0.37; and Quick Heal AntiVirus Pro 32 bit 17.00 (QHAV32.exe), (QHAVFT32.exe) - Version 10.0.0.37 allow DLL Hijacking because of Insecure Library Loading.
</code>

- [kernelm0de/CVE-2018-8090](https://github.com/kernelm0de/CVE-2018-8090)

### CVE-2018-8108

<code>
The select component in bui through 2018-03-13 has XSS because it performs an escape operation on already-escaped text, as demonstrated by workGroupList text.
</code>

- [zlgxzswjy/BUI-select-xss](https://github.com/zlgxzswjy/BUI-select-xss)

### CVE-2018-8115

<code>
A remote code execution vulnerability exists when the Windows Host Compute Service Shim (hcsshim) library fails to properly validate input while importing a container image, aka &quot;Windows Host Compute Service Shim Remote Code Execution Vulnerability.&quot; This affects Windows Host Compute.
</code>

- [aquasecurity/scan-cve-2018-8115](https://github.com/aquasecurity/scan-cve-2018-8115)

### CVE-2018-8120

<code>
An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka &quot;Win32k Elevation of Privilege Vulnerability.&quot; This affects Windows Server 2008, Windows 7, Windows Server 2008 R2. This CVE ID is unique from CVE-2018-8124, CVE-2018-8164, CVE-2018-8166.
</code>

- [bigric3/cve-2018-8120](https://github.com/bigric3/cve-2018-8120)
- [unamer/CVE-2018-8120](https://github.com/unamer/CVE-2018-8120)
- [ne1llee/cve-2018-8120](https://github.com/ne1llee/cve-2018-8120)
- [alpha1ab/CVE-2018-8120](https://github.com/alpha1ab/CVE-2018-8120)
- [areuu/CVE-2018-8120](https://github.com/areuu/CVE-2018-8120)
- [EVOL4/CVE-2018-8120](https://github.com/EVOL4/CVE-2018-8120)
- [ozkanbilge/CVE-2018-8120](https://github.com/ozkanbilge/CVE-2018-8120)
- [qiantu88/CVE-2018-8120](https://github.com/qiantu88/CVE-2018-8120)
- [Y0n0Y/cve-2018-8120-exp](https://github.com/Y0n0Y/cve-2018-8120-exp)

### CVE-2018-8172

<code>
A remote code execution vulnerability exists in Visual Studio software when the software does not check the source markup of a file for an unbuilt project, aka &quot;Visual Studio Remote Code Execution Vulnerability.&quot; This affects Microsoft Visual Studio, Expression Blend 4.
</code>

- [SyFi/CVE-2018-8172](https://github.com/SyFi/CVE-2018-8172)

### CVE-2018-8174

<code>
A remote code execution vulnerability exists in the way that the VBScript engine handles objects in memory, aka &quot;Windows VBScript Engine Remote Code Execution Vulnerability.&quot; This affects Windows 7, Windows Server 2012 R2, Windows RT 8.1, Windows Server 2008, Windows Server 2012, Windows 8.1, Windows Server 2016, Windows Server 2008 R2, Windows 10, Windows 10 Servers.
</code>

- [0x09AL/CVE-2018-8174-msf](https://github.com/0x09AL/CVE-2018-8174-msf)
- [Yt1g3r/CVE-2018-8174_EXP](https://github.com/Yt1g3r/CVE-2018-8174_EXP)
- [SyFi/CVE-2018-8174](https://github.com/SyFi/CVE-2018-8174)
- [orf53975/Rig-Exploit-for-CVE-2018-8174](https://github.com/orf53975/Rig-Exploit-for-CVE-2018-8174)
- [piotrflorczyk/cve-2018-8174_analysis](https://github.com/piotrflorczyk/cve-2018-8174_analysis)
- [denmilu/CVE-2018-8174-msf](https://github.com/denmilu/CVE-2018-8174-msf)
- [ruthlezs/ie11_vbscript_exploit](https://github.com/ruthlezs/ie11_vbscript_exploit)

### CVE-2018-8208

<code>
An elevation of privilege vulnerability exists in Windows when Desktop Bridge does not properly manage the virtual registry, aka &quot;Windows Desktop Bridge Elevation of Privilege Vulnerability.&quot; This affects Windows Server 2016, Windows 10, Windows 10 Servers. This CVE ID is unique from CVE-2018-8214.
</code>

- [kaisaryousuf/CVE-2018-8208](https://github.com/kaisaryousuf/CVE-2018-8208)

### CVE-2018-8214

<code>
An elevation of privilege vulnerability exists in Windows when Desktop Bridge does not properly manage the virtual registry, aka &quot;Windows Desktop Bridge Elevation of Privilege Vulnerability.&quot; This affects Windows Server 2016, Windows 10, Windows 10 Servers. This CVE ID is unique from CVE-2018-8208.
</code>

- [guwudoor/CVE-2018-8214](https://github.com/guwudoor/CVE-2018-8214)

### CVE-2018-8284

<code>
A remote code execution vulnerability exists when the Microsoft .NET Framework fails to validate input properly, aka &quot;.NET Framework Remote Code Injection Vulnerability.&quot; This affects Microsoft .NET Framework 2.0, Microsoft .NET Framework 3.0, Microsoft .NET Framework 4.6.2/4.7/4.7.1/4.7.2, Microsoft .NET Framework 4.5.2, Microsoft .NET Framework 4.6, Microsoft .NET Framework 4.7/4.7.1/4.7.2, Microsoft .NET Framework 4.7.1/4.7.2, Microsoft .NET Framework 3.5, Microsoft .NET Framework 3.5.1, Microsoft .NET Framework 4.6/4.6.1/4.6.2, Microsoft .NET Framework 4.6/4.6.1/4.6.2/4.7/4.7.1/4.7.1/4.7.2, Microsoft .NET Framework 4.7.2.
</code>

- [quantiti/CVE-2018-8284-Sharepoint-RCE](https://github.com/quantiti/CVE-2018-8284-Sharepoint-RCE)

### CVE-2018-8353

<code>
A remote code execution vulnerability exists in the way that the scripting engine handles objects in memory in Internet Explorer, aka &quot;Scripting Engine Memory Corruption Vulnerability.&quot; This affects Internet Explorer 9, Internet Explorer 11, Internet Explorer 10. This CVE ID is unique from CVE-2018-8355, CVE-2018-8359, CVE-2018-8371, CVE-2018-8372, CVE-2018-8373, CVE-2018-8385, CVE-2018-8389, CVE-2018-8390.
</code>

- [whereisr0da/CVE-2018-8353-POC](https://github.com/whereisr0da/CVE-2018-8353-POC)

### CVE-2018-8389

<code>
A remote code execution vulnerability exists in the way that the scripting engine handles objects in memory in Internet Explorer, aka &quot;Scripting Engine Memory Corruption Vulnerability.&quot; This affects Internet Explorer 9, Internet Explorer 11, Internet Explorer 10. This CVE ID is unique from CVE-2018-8353, CVE-2018-8355, CVE-2018-8359, CVE-2018-8371, CVE-2018-8372, CVE-2018-8373, CVE-2018-8385, CVE-2018-8390.
</code>

- [sharmasandeepkr/cve-2018-8389](https://github.com/sharmasandeepkr/cve-2018-8389)

### CVE-2018-8414

<code>
A remote code execution vulnerability exists when the Windows Shell does not properly validate file paths, aka &quot;Windows Shell Remote Code Execution Vulnerability.&quot; This affects Windows 10 Servers, Windows 10.
</code>

- [whereisr0da/CVE-2018-8414-POC](https://github.com/whereisr0da/CVE-2018-8414-POC)

### CVE-2018-8420

<code>
A remote code execution vulnerability exists when the Microsoft XML Core Services MSXML parser processes user input, aka &quot;MS XML Remote Code Execution Vulnerability.&quot; This affects Windows 7, Windows Server 2012 R2, Windows RT 8.1, Windows Server 2008, Windows Server 2012, Windows 8.1, Windows Server 2016, Windows Server 2008 R2, Windows 10, Windows 10 Servers.
</code>

- [idkwim/CVE-2018-8420](https://github.com/idkwim/CVE-2018-8420)

### CVE-2018-8440

<code>
An elevation of privilege vulnerability exists when Windows improperly handles calls to Advanced Local Procedure Call (ALPC), aka &quot;Windows ALPC Elevation of Privilege Vulnerability.&quot; This affects Windows 7, Windows Server 2012 R2, Windows RT 8.1, Windows Server 2008, Windows Server 2012, Windows 8.1, Windows Server 2016, Windows Server 2008 R2, Windows 10, Windows 10 Servers.
</code>

- [sourceincite/CVE-2018-8440](https://github.com/sourceincite/CVE-2018-8440)

### CVE-2018-8453

<code>
An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka &quot;Win32k Elevation of Privilege Vulnerability.&quot; This affects Windows 7, Windows Server 2012 R2, Windows RT 8.1, Windows Server 2008, Windows Server 2019, Windows Server 2012, Windows 8.1, Windows Server 2016, Windows Server 2008 R2, Windows 10, Windows 10 Servers.
</code>

- [Mkv4/cve-2018-8453-exp](https://github.com/Mkv4/cve-2018-8453-exp)
- [ze0r/cve-2018-8453-exp](https://github.com/ze0r/cve-2018-8453-exp)
- [thepwnrip/leHACK-Analysis-of-CVE-2018-8453](https://github.com/thepwnrip/leHACK-Analysis-of-CVE-2018-8453)

### CVE-2018-8495

<code>
A remote code execution vulnerability exists when Windows Shell improperly handles URIs, aka &quot;Windows Shell Remote Code Execution Vulnerability.&quot; This affects Windows Server 2016, Windows 10, Windows 10 Servers.
</code>

- [whereisr0da/CVE-2018-8495-POC](https://github.com/whereisr0da/CVE-2018-8495-POC)

### CVE-2018-8581

<code>
An elevation of privilege vulnerability exists in Microsoft Exchange Server, aka &quot;Microsoft Exchange Server Elevation of Privilege Vulnerability.&quot; This affects Microsoft Exchange Server.
</code>

- [WyAtu/CVE-2018-8581](https://github.com/WyAtu/CVE-2018-8581)
- [qiantu88/CVE-2018-8581](https://github.com/qiantu88/CVE-2018-8581)
- [Ridter/Exchange2domain](https://github.com/Ridter/Exchange2domain)

### CVE-2018-8639

<code>
An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka &quot;Win32k Elevation of Privilege Vulnerability.&quot; This affects Windows 7, Windows Server 2012 R2, Windows RT 8.1, Windows Server 2008, Windows Server 2019, Windows Server 2012, Windows 8.1, Windows Server 2016, Windows Server 2008 R2, Windows 10, Windows 10 Servers. This CVE ID is unique from CVE-2018-8641.
</code>

- [ze0r/CVE-2018-8639-exp](https://github.com/ze0r/CVE-2018-8639-exp)
- [timwhitez/CVE-2018-8639-EXP](https://github.com/timwhitez/CVE-2018-8639-EXP)

### CVE-2018-8718

<code>
Cross-site request forgery (CSRF) vulnerability in the Mailer Plugin 1.20 for Jenkins 2.111 allows remote authenticated users to send unauthorized mail as an arbitrary user via a /descriptorByName/hudson.tasks.Mailer/sendTestMail request.
</code>

- [GeunSam2/CVE-2018-8718](https://github.com/GeunSam2/CVE-2018-8718)

### CVE-2018-8733

<code>
Authentication bypass vulnerability in the core config manager in Nagios XI 5.2.x through 5.4.x before 5.4.13 allows an unauthenticated attacker to make configuration changes and leverage an authenticated SQL injection vulnerability.
</code>

- [xfer0/Nagios-XI-5.2.6-9-5.3-5.4-Chained-Remote-Root-Exploit-Fixed](https://github.com/xfer0/Nagios-XI-5.2.6-9-5.3-5.4-Chained-Remote-Root-Exploit-Fixed)

### CVE-2018-8820

<code>
An issue was discovered in Square 9 GlobalForms 6.2.x. A Time Based SQL injection vulnerability in the &quot;match&quot; parameter allows remote authenticated attackers to execute arbitrary SQL commands. It is possible to upgrade access to full server compromise via xp_cmdshell. In some cases, the authentication requirement for the attack can be met by sending the default admin credentials.
</code>

- [hateshape/frevvomapexec](https://github.com/hateshape/frevvomapexec)

### CVE-2018-8897

<code>
A statement in the System Programming Guide of the Intel 64 and IA-32 Architectures Software Developer's Manual (SDM) was mishandled in the development of some or all operating-system kernels, resulting in unexpected behavior for #DB exceptions that are deferred by MOV SS or POP SS, as demonstrated by (for example) privilege escalation in Windows, macOS, some Xen configurations, or FreeBSD, or a Linux kernel crash. The MOV to SS and POP SS instructions inhibit interrupts (including NMIs), data breakpoints, and single step trap exceptions until the instruction boundary following the next instruction (SDM Vol. 3A; section 6.8.3). (The inhibited data breakpoints are those on memory accessed by the MOV to SS or POP to SS instruction itself.) Note that debug exceptions are not inhibited by the interrupt enable (EFLAGS.IF) system flag (SDM Vol. 3A; section 2.3). If the instruction following the MOV to SS or POP to SS instruction is an instruction like SYSCALL, SYSENTER, INT 3, etc. that transfers control to the operating system at CPL &lt; 3, the debug exception is delivered after the transfer to CPL &lt; 3 is complete. OS kernels may not expect this order of events and may therefore experience unexpected behavior when it occurs.
</code>

- [nmulasmajic/CVE-2018-8897](https://github.com/nmulasmajic/CVE-2018-8897)
- [jiazhang0/pop-mov-ss-exploit](https://github.com/jiazhang0/pop-mov-ss-exploit)
- [can1357/CVE-2018-8897](https://github.com/can1357/CVE-2018-8897)
- [nmulasmajic/syscall_exploit_CVE-2018-8897](https://github.com/nmulasmajic/syscall_exploit_CVE-2018-8897)

### CVE-2018-8941

<code>
Diagnostics functionality on D-Link DSL-3782 devices with firmware EU v. 1.01 has a buffer overflow, allowing authenticated remote attackers to execute arbitrary code via a long Addr value to the 'set Diagnostics_Entry' function in an HTTP request, related to /userfs/bin/tcapi.
</code>

- [SECFORCE/CVE-2018-8941](https://github.com/SECFORCE/CVE-2018-8941)

### CVE-2018-8943

<code>
There is a SQL injection in the PHPSHE 1.6 userbank parameter.
</code>

- [coolboy0816/CVE-2018-8943](https://github.com/coolboy0816/CVE-2018-8943)

### CVE-2018-8970

<code>
The int_x509_param_set_hosts function in lib/libcrypto/x509/x509_vpm.c in LibreSSL 2.7.0 before 2.7.1 does not support a certain special case of a zero name length, which causes silent omission of hostname verification, and consequently allows man-in-the-middle attackers to spoof servers and obtain sensitive information via a crafted certificate. NOTE: the LibreSSL documentation indicates that this special case is supported, but the BoringSSL documentation does not.
</code>

- [tiran/CVE-2018-8970](https://github.com/tiran/CVE-2018-8970)

### CVE-2018-9059

<code>
Stack-based buffer overflow in Easy File Sharing (EFS) Web Server 7.2 allows remote attackers to execute arbitrary code via a malicious login request to forum.ghp.  NOTE: this may overlap CVE-2014-3791.
</code>

- [manojcode/easy-file-share-7.2-exploit-CVE-2018-9059](https://github.com/manojcode/easy-file-share-7.2-exploit-CVE-2018-9059)

### CVE-2018-9075

<code>
For some Iomega, Lenovo, LenovoEMC NAS devices versions 4.1.402.34662 and earlier, when joining a PersonalCloud setup, an attacker can craft a command injection payload using backtick &quot;``&quot; characters in the client:password parameter. As a result, arbitrary commands may be executed as the root user. The attack requires a value __c and iomega parameter.
</code>

- [beverlymiller818/cve-2018-9075](https://github.com/beverlymiller818/cve-2018-9075)

### CVE-2018-9160

<code>
SickRage before v2018.03.09-1 includes cleartext credentials in HTTP responses.
</code>

- [mechanico/sickrageWTF](https://github.com/mechanico/sickrageWTF)

### CVE-2018-9206

<code>
Unauthenticated arbitrary file upload vulnerability in Blueimp jQuery-File-Upload &lt;= v9.22.0
</code>

- [Den1al/CVE-2018-9206](https://github.com/Den1al/CVE-2018-9206)
- [Stahlz/JQShell](https://github.com/Stahlz/JQShell)
- [cved-sources/cve-2018-9206](https://github.com/cved-sources/cve-2018-9206)

### CVE-2018-9207

<code>
Arbitrary file upload in jQuery Upload File &lt;= 4.0.2
</code>

- [cved-sources/cve-2018-9207](https://github.com/cved-sources/cve-2018-9207)

### CVE-2018-9208

<code>
Unauthenticated arbitrary file upload vulnerability in jQuery Picture Cut &lt;= v1.1Beta
</code>

- [cved-sources/cve-2018-9208](https://github.com/cved-sources/cve-2018-9208)

### CVE-2018-9276

<code>
An issue was discovered in PRTG Network Monitor before 18.2.39. An attacker who has access to the PRTG System Administrator web console with administrative privileges can exploit an OS command injection vulnerability (both on the server and on devices) by sending malformed parameters in sensor or notification management scenarios.
</code>

- [wildkindcc/CVE-2018-9276](https://github.com/wildkindcc/CVE-2018-9276)

### CVE-2018-9375
- [IOActive/AOSP-ExploitUserDictionary](https://github.com/IOActive/AOSP-ExploitUserDictionary)

### CVE-2018-9411
- [tamirzb/CVE-2018-9411](https://github.com/tamirzb/CVE-2018-9411)

### CVE-2018-9468
- [IOActive/AOSP-DownloadProviderHijacker](https://github.com/IOActive/AOSP-DownloadProviderHijacker)

### CVE-2018-9493

<code>
In the content provider of the download manager, there is a possible SQL injection due to improper input validation. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation. Product: Android Versions: Android-7.0 Android-7.1.1 Android-7.1.2 Android-8.0 Android-8.1 Android-9.0 Android ID: A-111085900
</code>

- [IOActive/AOSP-DownloadProviderDbDumper](https://github.com/IOActive/AOSP-DownloadProviderDbDumper)

### CVE-2018-9539

<code>
In the ClearKey CAS descrambler, there is a possible use after free due to a race condition. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. Product: Android. Versions: Android-8.0 Android-8.1 Android-9. Android ID: A-113027383
</code>

- [tamirzb/CVE-2018-9539](https://github.com/tamirzb/CVE-2018-9539)

### CVE-2018-9546
- [IOActive/AOSP-DownloadProviderHeadersDumper](https://github.com/IOActive/AOSP-DownloadProviderHeadersDumper)

### CVE-2018-9948

<code>
This vulnerability allows remote attackers to disclose sensitive information on vulnerable installations of Foxit Reader 9.0.0.29935. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the handling of typed arrays. The issue results from the lack of proper initialization of a pointer prior to accessing it. An attacker can leverage this in conjunction with other vulnerabilities to execute code in the context of the current process. Was ZDI-CAN-5380.
</code>

- [manojcode/Foxit-Reader-RCE-with-virualalloc-and-shellcode-for-CVE-2018-9948-and-CVE-2018-9958](https://github.com/manojcode/Foxit-Reader-RCE-with-virualalloc-and-shellcode-for-CVE-2018-9948-and-CVE-2018-9958)
- [orangepirate/cve-2018-9948-9958-exp](https://github.com/orangepirate/cve-2018-9948-9958-exp)

### CVE-2018-9950

<code>
This vulnerability allows remote attackers to disclose sensitive information on vulnerable installations of Foxit Reader 9.0.0.29935. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of PDF documents. The issue results from the lack of proper validation of user-supplied data, which can result in a read past the end of an allocated object. An attacker can leverage this in conjunction with other vulnerabilities to execute code in the context of the current process. Was ZDI-CAN-5413.
</code>

- [sharmasandeepkr/PS-2017-13---CVE-2018-9950](https://github.com/sharmasandeepkr/PS-2017-13---CVE-2018-9950)

### CVE-2018-9951

<code>
This vulnerability allows remote attackers to execute arbitrary code on vulnerable installations of Foxit Reader 9.0.0.29935. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the handling of CPDF_Object objects. The issue results from the lack of validating the existence of an object prior to performing operations on the object. An attacker can leverage this vulnerability to execute code under the context of the current process. Was ZDI-CAN-5414.
</code>

- [sharmasandeepkr/cve-2018-9951](https://github.com/sharmasandeepkr/cve-2018-9951)

### CVE-2018-9958

<code>
This vulnerability allows remote attackers to execute arbitrary code on vulnerable installations of Foxit Reader 9.0.1.1049. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the handling of Text Annotations. When setting the point attribute, the process does not properly validate the existence of an object prior to performing operations on the object. An attacker can leverage this vulnerability to execute code under the context of the current process. Was ZDI-CAN-5620.
</code>

- [t3rabyt3/CVE-2018-9958--Exploit](https://github.com/t3rabyt3/CVE-2018-9958--Exploit)

### CVE-2018-9995

<code>
TBK DVR4104 and DVR4216 devices, as well as Novo, CeNova, QSee, Pulnix, XVR 5 in 1, Securus, Night OWL, DVR Login, HVR Login, and MDVR Login, which run re-branded versions of the original TBK DVR4104 and DVR4216 series, allow remote attackers to bypass authentication via a &quot;Cookie: uid=admin&quot; header, as demonstrated by a device.rsp?opt=user&amp;cmd=list request that provides credentials within JSON data in a response.
</code>

- [ezelf/CVE-2018-9995_dvr_credentials](https://github.com/ezelf/CVE-2018-9995_dvr_credentials)
- [zzh217/CVE-2018-9995_Batch_scanning_exp](https://github.com/zzh217/CVE-2018-9995_Batch_scanning_exp)
- [Huangkey/CVE-2018-9995_check](https://github.com/Huangkey/CVE-2018-9995_check)
- [gwolfs/CVE-2018-9995-ModifiedByGwolfs](https://github.com/gwolfs/CVE-2018-9995-ModifiedByGwolfs)
- [shacojx/cve-2018-9995](https://github.com/shacojx/cve-2018-9995)
- [Cyb0r9/DVR-Exploiter](https://github.com/Cyb0r9/DVR-Exploiter)
- [codeholic2k18/CVE-2018-9995](https://github.com/codeholic2k18/CVE-2018-9995)
- [TateYdq/CVE-2018-9995-ModifiedByGwolfs](https://github.com/TateYdq/CVE-2018-9995-ModifiedByGwolfs)
- [ABIZCHI/CVE-2018-9995_dvr_credentials](https://github.com/ABIZCHI/CVE-2018-9995_dvr_credentials)
- [IHA114/CVE-2018-9995_dvr_credentials](https://github.com/IHA114/CVE-2018-9995_dvr_credentials)
- [likaifeng0/CVE-2018-9995_dvr_credentials-dev_tool](https://github.com/likaifeng0/CVE-2018-9995_dvr_credentials-dev_tool)
- [b510/CVE-2018-9995-POC](https://github.com/b510/CVE-2018-9995-POC)
- [keyw0rds/HTC](https://github.com/keyw0rds/HTC)
- [g5q2/cve-2018-9995](https://github.com/g5q2/cve-2018-9995)


## 2017
### CVE-2017-0038

<code>
gdi32.dll in Graphics Device Interface (GDI) in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, and Windows 10 Gold, 1511, and 1607 allows remote attackers to obtain sensitive information from process heap memory via a crafted EMF file, as demonstrated by an EMR_SETDIBITSTODEVICE record with modified Device Independent Bitmap (DIB) dimensions. NOTE: this vulnerability exists because of an incomplete fix for CVE-2016-3216, CVE-2016-3219, and/or CVE-2016-3220.
</code>

- [k0keoyo/CVE-2017-0038-EXP-C-JS](https://github.com/k0keoyo/CVE-2017-0038-EXP-C-JS)

### CVE-2017-0065

<code>
Microsoft Edge allows remote attackers to obtain sensitive information from process memory via a crafted web site, aka &quot;Microsoft Browser Information Disclosure Vulnerability.&quot; This vulnerability is different from those described in CVE-2017-0009, CVE-2017-0011, CVE-2017-0017, and CVE-2017-0068.
</code>

- [Dankirk/cve-2017-0065](https://github.com/Dankirk/cve-2017-0065)

### CVE-2017-0075

<code>
Hyper-V in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows guest OS users to execute arbitrary code on the host OS via a crafted application, aka &quot;Hyper-V Remote Code Execution Vulnerability.&quot; This vulnerability is different from that described in CVE-2017-0109.
</code>

- [4B5F5F4B/HyperV](https://github.com/4B5F5F4B/HyperV)

### CVE-2017-0106

<code>
Microsoft Excel 2007 SP3, Microsoft Outlook 2010 SP2, Microsoft Outlook 2013 SP1, and Microsoft Outlook 2016 allow remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted document, aka &quot;Microsoft Office Memory Corruption Vulnerability.&quot;
</code>

- [ryhanson/CVE-2017-0106](https://github.com/ryhanson/CVE-2017-0106)

### CVE-2017-0108

<code>
The Windows Graphics Component in Microsoft Office 2007 SP3; 2010 SP2; and Word Viewer; Skype for Business 2016; Lync 2013 SP1; Lync 2010; Live Meeting 2007; Silverlight 5; Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; and Windows 7 SP1 allows remote attackers to execute arbitrary code via a crafted web site, aka &quot;Graphics Component Remote Code Execution Vulnerability.&quot; This vulnerability is different from that described in CVE-2017-0014.
</code>

- [homjxi0e/CVE-2017-0108](https://github.com/homjxi0e/CVE-2017-0108)

### CVE-2017-0143

<code>
The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka &quot;Windows SMB Remote Code Execution Vulnerability.&quot; This vulnerability is different from those described in CVE-2017-0144, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.
</code>

- [valarauco/wannafind](https://github.com/valarauco/wannafind)

### CVE-2017-0144

<code>
The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka &quot;Windows SMB Remote Code Execution Vulnerability.&quot; This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.
</code>

- [peterpt/eternal_scanner](https://github.com/peterpt/eternal_scanner)
- [kimocoder/eternalblue](https://github.com/kimocoder/eternalblue)

### CVE-2017-0145

<code>
The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka &quot;Windows SMB Remote Code Execution Vulnerability.&quot; This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0144, CVE-2017-0146, and CVE-2017-0148.
</code>

- [MelonSmasher/chef_tissues](https://github.com/MelonSmasher/chef_tissues)

### CVE-2017-0199

<code>
Microsoft Office 2007 SP3, Microsoft Office 2010 SP2, Microsoft Office 2013 SP1, Microsoft Office 2016, Microsoft Windows Vista SP2, Windows Server 2008 SP2, Windows 7 SP1, Windows 8.1 allow remote attackers to execute arbitrary code via a crafted document, aka &quot;Microsoft Office/WordPad Remote Code Execution Vulnerability w/Windows API.&quot;
</code>

- [ryhanson/CVE-2017-0199](https://github.com/ryhanson/CVE-2017-0199)
- [SyFi/cve-2017-0199](https://github.com/SyFi/cve-2017-0199)
- [bhdresh/CVE-2017-0199](https://github.com/bhdresh/CVE-2017-0199)
- [NotAwful/CVE-2017-0199-Fix](https://github.com/NotAwful/CVE-2017-0199-Fix)
- [haibara3839/CVE-2017-0199-master](https://github.com/haibara3839/CVE-2017-0199-master)
- [Exploit-install/CVE-2017-0199](https://github.com/Exploit-install/CVE-2017-0199)
- [zakybstrd21215/PoC-CVE-2017-0199](https://github.com/zakybstrd21215/PoC-CVE-2017-0199)
- [n1shant-sinha/CVE-2017-0199](https://github.com/n1shant-sinha/CVE-2017-0199)
- [kn0wm4d/htattack](https://github.com/kn0wm4d/htattack)
- [joke998/Cve-2017-0199](https://github.com/joke998/Cve-2017-0199)
- [joke998/Cve-2017-0199-](https://github.com/joke998/Cve-2017-0199-)
- [r0otshell/Microsoft-Word-CVE-2017-0199-](https://github.com/r0otshell/Microsoft-Word-CVE-2017-0199-)
- [viethdgit/CVE-2017-0199](https://github.com/viethdgit/CVE-2017-0199)
- [nicpenning/RTF-Cleaner](https://github.com/nicpenning/RTF-Cleaner)
- [bloomer1016/2017-11-17-Maldoc-Using-CVE-2017-0199](https://github.com/bloomer1016/2017-11-17-Maldoc-Using-CVE-2017-0199)
- [jacobsoo/RTF-Cleaner](https://github.com/jacobsoo/RTF-Cleaner)
- [denmilu/CVE-2017-0199](https://github.com/denmilu/CVE-2017-0199)

### CVE-2017-0204

<code>
Microsoft Outlook 2007 SP3, Microsoft Outlook 2010 SP2, Microsoft Outlook 2013 SP1, and Microsoft Outlook 2016 allow remote attackers to bypass the Office Protected View via a specially crafted document, aka &quot;Microsoft Office Security Feature Bypass Vulnerability.&quot;
</code>

- [ryhanson/CVE-2017-0204](https://github.com/ryhanson/CVE-2017-0204)

### CVE-2017-0213

<code>
Windows COM Aggregate Marshaler in Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, and 1703, and Windows Server 2016 allows an elevation privilege vulnerability when an attacker runs a specially crafted application, aka &quot;Windows COM Elevation of Privilege Vulnerability&quot;. This CVE ID is unique from CVE-2017-0214.
</code>

- [shaheemirza/CVE-2017-0213-](https://github.com/shaheemirza/CVE-2017-0213-)
- [zcgonvh/CVE-2017-0213](https://github.com/zcgonvh/CVE-2017-0213)
- [billa3283/CVE-2017-0213](https://github.com/billa3283/CVE-2017-0213)
- [denmilu/CVE-2017-0213](https://github.com/denmilu/CVE-2017-0213)
- [jbooz1/CVE-2017-0213](https://github.com/jbooz1/CVE-2017-0213)
- [eonrickity/CVE-2017-0213](https://github.com/eonrickity/CVE-2017-0213)
- [Jos675/CVE-2017-0213-Exploit](https://github.com/Jos675/CVE-2017-0213-Exploit)

### CVE-2017-0248

<code>
Microsoft .NET Framework 2.0, 3.5, 3.5.1, 4.5.2, 4.6, 4.6.1, 4.6.2 and 4.7 allow an attacker to bypass Enhanced Security Usage taggings when they present a certificate that is invalid for a specific use, aka &quot;.NET Security Feature Bypass Vulnerability.&quot;
</code>

- [rubenmamo/CVE-2017-0248-Test](https://github.com/rubenmamo/CVE-2017-0248-Test)

### CVE-2017-0261

<code>
Microsoft Office 2010 SP2, Office 2013 SP1, and Office 2016 allow a remote code execution vulnerability when the software fails to properly handle objects in memory, aka &quot;Office Remote Code Execution Vulnerability&quot;. This CVE ID is unique from CVE-2017-0262 and CVE-2017-0281.
</code>

- [kcufId/eps-CVE-2017-0261](https://github.com/kcufId/eps-CVE-2017-0261)

### CVE-2017-0263

<code>
The kernel-mode drivers in Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, 1703, and Windows Server 2016 allow local users to gain privileges via a crafted application, aka &quot;Win32k Elevation of Privilege Vulnerability.&quot;
</code>

- [R06otMD5/cve-2017-0263-poc](https://github.com/R06otMD5/cve-2017-0263-poc)

### CVE-2017-0290

<code>
The Microsoft Malware Protection Engine running on Microsoft Forefront and Microsoft Defender on Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, and 1703, and Windows Server 2016 does not properly scan a specially crafted file leading to memory corruption, aka &quot;Microsoft Malware Protection Engine Remote Code Execution Vulnerability.&quot;
</code>

- [homjxi0e/CVE-2017-0290-](https://github.com/homjxi0e/CVE-2017-0290-)

### CVE-2017-0411

<code>
An elevation of privilege vulnerability in the Framework APIs could enable a local malicious application to execute arbitrary code within the context of a privileged process. This issue is rated as High because it could be used to gain local access to elevated capabilities, which are not normally accessible to a third-party application. Product: Android. Versions: 7.0, 7.1.1. Android ID: A-33042690.
</code>

- [lulusudoku/PoC](https://github.com/lulusudoku/PoC)

### CVE-2017-0478

<code>
A remote code execution vulnerability in the Framesequence library could enable an attacker using a specially crafted file to execute arbitrary code in the context of an unprivileged process. This issue is rated as High due to the possibility of remote code execution in an application that uses the Framesequence library. Product: Android. Versions: 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1. Android ID: A-33718716.
</code>

- [JiounDai/CVE-2017-0478](https://github.com/JiounDai/CVE-2017-0478)
- [denmilu/CVE-2017-0478](https://github.com/denmilu/CVE-2017-0478)

### CVE-2017-0541

<code>
A remote code execution vulnerability in sonivox in Mediaserver could enable an attacker using a specially crafted file to cause memory corruption during media file and data processing. This issue is rated as Critical due to the possibility of remote code execution within the context of the Mediaserver process. Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1. Android ID: A-34031018.
</code>

- [JiounDai/CVE-2017-0541](https://github.com/JiounDai/CVE-2017-0541)
- [denmilu/CVE-2017-0541](https://github.com/denmilu/CVE-2017-0541)

### CVE-2017-0554

<code>
An elevation of privilege vulnerability in the Telephony component could enable a local malicious application to access capabilities outside of its permission levels. This issue is rated as Moderate because it could be used to gain access to elevated capabilities, which are not normally accessible to a third-party application. Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1. Android ID: A-33815946.
</code>

- [lanrat/tethr](https://github.com/lanrat/tethr)

### CVE-2017-0564

<code>
An elevation of privilege vulnerability in the kernel ION subsystem could enable a local malicious application to execute arbitrary code within the context of the kernel. This issue is rated as Critical due to the possibility of a local permanent device compromise, which may require reflashing the operating system to repair the device. Product: Android. Versions: Kernel-3.10, Kernel-3.18. Android ID: A-34276203.
</code>

- [guoygang/CVE-2017-0564-ION-PoC](https://github.com/guoygang/CVE-2017-0564-ION-PoC)

### CVE-2017-0781

<code>
A remote code execution vulnerability in the Android system (bluetooth). Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-63146105.
</code>

- [ojasookert/CVE-2017-0781](https://github.com/ojasookert/CVE-2017-0781)
- [marcinguy/android712-blueborne](https://github.com/marcinguy/android712-blueborne)

### CVE-2017-0785

<code>
A information disclosure vulnerability in the Android system (bluetooth). Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-63146698.
</code>

- [ojasookert/CVE-2017-0785](https://github.com/ojasookert/CVE-2017-0785)
- [aymankhalfatni/CVE-2017-0785](https://github.com/aymankhalfatni/CVE-2017-0785)
- [Alfa100001/-CVE-2017-0785-BlueBorne-PoC](https://github.com/Alfa100001/-CVE-2017-0785-BlueBorne-PoC)
- [Android013/CVE-2017-0785](https://github.com/Android013/CVE-2017-0785)
- [Hackerscript/BlueBorne-CVE-2017-0785](https://github.com/Hackerscript/BlueBorne-CVE-2017-0785)
- [pieterbork/blueborne](https://github.com/pieterbork/blueborne)
- [sigbitsadmin/diff](https://github.com/sigbitsadmin/diff)
- [SigBitsLabs/diff](https://github.com/SigBitsLabs/diff)
- [RavSS/Bluetooth-Crash-CVE-2017-0785](https://github.com/RavSS/Bluetooth-Crash-CVE-2017-0785)

### CVE-2017-0806

<code>
An elevation of privilege vulnerability in the Android framework (gatekeeperresponse). Product: Android. Versions: 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-62998805.
</code>

- [michalbednarski/ReparcelBug](https://github.com/michalbednarski/ReparcelBug)

### CVE-2017-0807

<code>
An elevation of privilege vulnerability in the Android framework (ui framework). Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2. Android ID: A-35056974.
</code>

- [kpatsakis/PoC_CVE-2017-0807](https://github.com/kpatsakis/PoC_CVE-2017-0807)

### CVE-2017-1000000
- [smythtech/DWF-CVE-2017-1000000](https://github.com/smythtech/DWF-CVE-2017-1000000)

### CVE-2017-1000083

<code>
backend/comics/comics-document.c (aka the comic book backend) in GNOME Evince before 3.24.1 allows remote attackers to execute arbitrary commands via a .cbt file that is a TAR archive containing a filename beginning with a &quot;--&quot; command-line option substring, as demonstrated by a --checkpoint-action=exec=bash at the beginning of the filename.
</code>

- [matlink/evince-cve-2017-1000083](https://github.com/matlink/evince-cve-2017-1000083)
- [matlink/cve-2017-1000083-atril-nautilus](https://github.com/matlink/cve-2017-1000083-atril-nautilus)

### CVE-2017-1000112

<code>
Linux kernel: Exploitable memory corruption due to UFO to non-UFO path switch. When building a UFO packet with MSG_MORE __ip_append_data() calls ip_ufo_append_data() to append. However in between two send() calls, the append path can be switched from UFO to non-UFO one, which leads to a memory corruption. In case UFO packet lengths exceeds MTU, copy = maxfraglen - skb-&gt;len becomes negative on the non-UFO path and the branch to allocate new skb is taken. This triggers fragmentation and computation of fraggap = skb_prev-&gt;len - maxfraglen. Fraggap can exceed MTU, causing copy = datalen - transhdrlen - fraggap to become negative. Subsequently skb_copy_and_csum_bits() writes out-of-bounds. A similar issue is present in IPv6 code. The bug was introduced in e89e9cf539a2 (&quot;[IPv4/IPv6]: UFO Scatter-gather approach&quot;) on Oct 18 2005.
</code>

- [hikame/docker_escape_pwn](https://github.com/hikame/docker_escape_pwn)
- [ol0273st-s/CVE-2017-1000112-Adpated](https://github.com/ol0273st-s/CVE-2017-1000112-Adpated)
- [IT19083124/SNP-Assignment](https://github.com/IT19083124/SNP-Assignment)

### CVE-2017-1000117

<code>
A malicious third-party can give a crafted &quot;ssh://...&quot; URL to an unsuspecting victim, and an attempt to visit the URL can result in any program that exists on the victim's machine being executed. Such a URL could be placed in the .gitmodules file of a malicious project, and an unsuspecting victim could be tricked into running &quot;git clone --recurse-submodules&quot; to trigger the vulnerability.
</code>

- [timwr/CVE-2017-1000117](https://github.com/timwr/CVE-2017-1000117)
- [GrahamMThomas/test-git-vuln_CVE-2017-1000117](https://github.com/GrahamMThomas/test-git-vuln_CVE-2017-1000117)
- [Manouchehri/CVE-2017-1000117](https://github.com/Manouchehri/CVE-2017-1000117)
- [thelastbyte/CVE-2017-1000117](https://github.com/thelastbyte/CVE-2017-1000117)
- [alilangtest/CVE-2017-1000117](https://github.com/alilangtest/CVE-2017-1000117)
- [VulApps/CVE-2017-1000117](https://github.com/VulApps/CVE-2017-1000117)
- [greymd/CVE-2017-1000117](https://github.com/greymd/CVE-2017-1000117)
- [shogo82148/Fix-CVE-2017-1000117](https://github.com/shogo82148/Fix-CVE-2017-1000117)
- [sasairc/CVE-2017-1000117_wasawasa](https://github.com/sasairc/CVE-2017-1000117_wasawasa)
- [Shadow5523/CVE-2017-1000117-test](https://github.com/Shadow5523/CVE-2017-1000117-test)
- [bells17/CVE-2017-1000117](https://github.com/bells17/CVE-2017-1000117)
- [ieee0824/CVE-2017-1000117](https://github.com/ieee0824/CVE-2017-1000117)
- [rootclay/CVE-2017-1000117](https://github.com/rootclay/CVE-2017-1000117)
- [ieee0824/CVE-2017-1000117-sl](https://github.com/ieee0824/CVE-2017-1000117-sl)
- [takehaya/CVE-2017-1000117](https://github.com/takehaya/CVE-2017-1000117)
- [ikmski/CVE-2017-1000117](https://github.com/ikmski/CVE-2017-1000117)
- [nkoneko/CVE-2017-1000117](https://github.com/nkoneko/CVE-2017-1000117)
- [chenzhuo0618/test](https://github.com/chenzhuo0618/test)
- [siling2017/CVE-2017-1000117](https://github.com/siling2017/CVE-2017-1000117)
- [Q2h1Cg/CVE-2017-1000117](https://github.com/Q2h1Cg/CVE-2017-1000117)
- [cved-sources/cve-2017-1000117](https://github.com/cved-sources/cve-2017-1000117)
- [leezp/CVE-2017-1000117](https://github.com/leezp/CVE-2017-1000117)
- [AnonymKing/CVE-2017-1000117](https://github.com/AnonymKing/CVE-2017-1000117)

### CVE-2017-1000250

<code>
All versions of the SDP server in BlueZ 5.46 and earlier are vulnerable to an information disclosure vulnerability which allows remote attackers to obtain sensitive information from the bluetoothd process memory. This vulnerability lies in the processing of SDP search attribute requests.
</code>

- [olav-st/CVE-2017-1000250-PoC](https://github.com/olav-st/CVE-2017-1000250-PoC)

### CVE-2017-1000251

<code>
The native Bluetooth stack in the Linux Kernel (BlueZ), starting at the Linux kernel version 2.6.32 and up to and including 4.13.1, are vulnerable to a stack overflow vulnerability in the processing of L2CAP configuration responses resulting in Remote code execution in kernel space.
</code>

- [hayzamjs/Blueborne-CVE-2017-1000251](https://github.com/hayzamjs/Blueborne-CVE-2017-1000251)
- [tlatkdgus1/blueborne-CVE-2017-1000251](https://github.com/tlatkdgus1/blueborne-CVE-2017-1000251)
- [own2pwn/blueborne-CVE-2017-1000251-POC](https://github.com/own2pwn/blueborne-CVE-2017-1000251-POC)
- [marcinguy/blueborne-CVE-2017-1000251](https://github.com/marcinguy/blueborne-CVE-2017-1000251)

### CVE-2017-1000253

<code>
Linux distributions that have not patched their long-term kernels with https://git.kernel.org/linus/a87938b2e246b81b4fb713edb371a9fa3c5c3c86 (committed on April 14, 2015). This kernel vulnerability was fixed in April 2015 by commit a87938b2e246b81b4fb713edb371a9fa3c5c3c86 (backported to Linux 3.10.77 in May 2015), but it was not recognized as a security threat. With CONFIG_ARCH_BINFMT_ELF_RANDOMIZE_PIE enabled, and a normal top-down address allocation strategy, load_elf_binary() will attempt to map a PIE binary into an address range immediately below mm-&gt;mmap_base. Unfortunately, load_elf_ binary() does not take account of the need to allocate sufficient space for the entire binary which means that, while the first PT_LOAD segment is mapped below mm-&gt;mmap_base, the subsequent PT_LOAD segment(s) end up being mapped above mm-&gt;mmap_base into the are that is supposed to be the &quot;gap&quot; between the stack and the binary.
</code>

- [sagiesec/PIE-Stack-Clash-CVE-2017-1000253](https://github.com/sagiesec/PIE-Stack-Clash-CVE-2017-1000253)

### CVE-2017-1000353

<code>
Jenkins versions 2.56 and earlier as well as 2.46.1 LTS and earlier are vulnerable to an unauthenticated remote code execution. An unauthenticated remote code execution vulnerability allowed attackers to transfer a serialized Java `SignedObject` object to the Jenkins CLI, that would be deserialized using a new `ObjectInputStream`, bypassing the existing blacklist-based protection mechanism. We're fixing this issue by adding `SignedObject` to the blacklist. We're also backporting the new HTTP CLI protocol from Jenkins 2.54 to LTS 2.46.2, and deprecating the remoting-based (i.e. Java serialization) CLI protocol, disabling it by default.
</code>

- [vulhub/CVE-2017-1000353](https://github.com/vulhub/CVE-2017-1000353)

### CVE-2017-1000367

<code>
Todd Miller's sudo version 1.8.20 and earlier is vulnerable to an input validation (embedded spaces) in the get_process_ttyname() function resulting in information disclosure and command execution.
</code>

- [c0d3z3r0/sudo-CVE-2017-1000367](https://github.com/c0d3z3r0/sudo-CVE-2017-1000367)
- [homjxi0e/CVE-2017-1000367](https://github.com/homjxi0e/CVE-2017-1000367)
- [pucerpocok/sudo_exploit](https://github.com/pucerpocok/sudo_exploit)

### CVE-2017-1000405

<code>
The Linux Kernel versions 2.6.38 through 4.14 have a problematic use of pmd_mkdirty() in the touch_pmd() function inside the THP implementation. touch_pmd() can be reached by get_user_pages(). In such case, the pmd will become dirty. This scenario breaks the new can_follow_write_pmd()'s logic - pmd can become dirty without going through a COW cycle. This bug is not as severe as the original &quot;Dirty cow&quot; because an ext4 file (or any other regular file) cannot be mapped using THP. Nevertheless, it does allow us to overwrite read-only huge pages. For example, the zero huge page and sealed shmem files can be overwritten (since their mapping can be populated using THP). Note that after the first write page-fault to the zero page, it will be replaced with a new fresh (and zeroed) thp.
</code>

- [bindecy/HugeDirtyCowPOC](https://github.com/bindecy/HugeDirtyCowPOC)

### CVE-2017-1000475

<code>
FreeSSHd 1.3.1 version is vulnerable to an Unquoted Path Service allowing local users to launch processes with elevated privileges.
</code>

- [lajarajorge/CVE-2017-1000475](https://github.com/lajarajorge/CVE-2017-1000475)

### CVE-2017-1000486

<code>
Primetek Primefaces 5.x is vulnerable to a weak encryption flaw resulting in remote code execution
</code>

- [pimps/CVE-2017-1000486](https://github.com/pimps/CVE-2017-1000486)
- [mogwailabs/CVE-2017-1000486](https://github.com/mogwailabs/CVE-2017-1000486)
- [cved-sources/cve-2017-1000486](https://github.com/cved-sources/cve-2017-1000486)

### CVE-2017-1000499

<code>
phpMyAdmin versions 4.7.x (prior to 4.7.6.1/4.7.7) are vulnerable to a CSRF weakness. By deceiving a user to click on a crafted URL, it is possible to perform harmful database operations such as deleting records, dropping/truncating tables etc.
</code>

- [Villaquiranm/5MMISSI-CVE-2017-1000499](https://github.com/Villaquiranm/5MMISSI-CVE-2017-1000499)

### CVE-2017-1002101

<code>
In Kubernetes versions 1.3.x, 1.4.x, 1.5.x, 1.6.x and prior to versions 1.7.14, 1.8.9 and 1.9.4 containers using subpath volume mounts with any volume type (including non-privileged pods, subject to file permissions) can access files/directories outside of the volume, including the host's filesystem.
</code>

- [bgeesaman/subpath-exploit](https://github.com/bgeesaman/subpath-exploit)

### CVE-2017-10235

<code>
Vulnerability in the Oracle VM VirtualBox component of Oracle Virtualization (subcomponent: Core). The supported version that is affected is Prior to 5.1.24. Easily exploitable vulnerability allows high privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle VM VirtualBox as well as unauthorized update, insert or delete access to some of Oracle VM VirtualBox accessible data. CVSS 3.0 Base Score 6.7 (Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:L/A:H).
</code>

- [fundacion-sadosky/vbox_cve_2017_10235](https://github.com/fundacion-sadosky/vbox_cve_2017_10235)

### CVE-2017-10271

<code>
Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Security). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.1.0 and 12.2.1.2.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 7.5 (Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H).
</code>

- [1337g/CVE-2017-10271](https://github.com/1337g/CVE-2017-10271)
- [s3xy/CVE-2017-10271](https://github.com/s3xy/CVE-2017-10271)
- [ZH3FENG/PoCs-Weblogic_2017_10271](https://github.com/ZH3FENG/PoCs-Weblogic_2017_10271)
- [c0mmand3rOpSec/CVE-2017-10271](https://github.com/c0mmand3rOpSec/CVE-2017-10271)
- [Luffin/CVE-2017-10271](https://github.com/Luffin/CVE-2017-10271)
- [cjjduck/weblogic_wls_wsat_rce](https://github.com/cjjduck/weblogic_wls_wsat_rce)
- [kkirsche/CVE-2017-10271](https://github.com/kkirsche/CVE-2017-10271)
- [pssss/CVE-2017-10271](https://github.com/pssss/CVE-2017-10271)
- [SuperHacker-liuan/cve-2017-10271-poc](https://github.com/SuperHacker-liuan/cve-2017-10271-poc)
- [bmcculley/CVE-2017-10271](https://github.com/bmcculley/CVE-2017-10271)
- [RealBearcat/Oracle-WebLogic-CVE-2017-10271](https://github.com/RealBearcat/Oracle-WebLogic-CVE-2017-10271)
- [Sch01ar/CVE-2017-10271](https://github.com/Sch01ar/CVE-2017-10271)
- [Cymmetria/weblogic_honeypot](https://github.com/Cymmetria/weblogic_honeypot)
- [JackyTsuuuy/weblogic_wls_rce_poc-exp](https://github.com/JackyTsuuuy/weblogic_wls_rce_poc-exp)
- [s0wr0b1ndef/Oracle-WebLogic-WLS-WSAT](https://github.com/s0wr0b1ndef/Oracle-WebLogic-WLS-WSAT)
- [lonehand/Oracle-WebLogic-CVE-2017-10271-master](https://github.com/lonehand/Oracle-WebLogic-CVE-2017-10271-master)
- [shack2/javaserializetools](https://github.com/shack2/javaserializetools)
- [nhwuxiaojun/CVE-2017-10271](https://github.com/nhwuxiaojun/CVE-2017-10271)
- [ETOCheney/JavaDeserialization](https://github.com/ETOCheney/JavaDeserialization)
- [cved-sources/cve-2017-10271](https://github.com/cved-sources/cve-2017-10271)
- [XHSecurity/Oracle-WebLogic-CVE-2017-10271](https://github.com/XHSecurity/Oracle-WebLogic-CVE-2017-10271)
- [kbsec/Weblogic_Wsat_RCE](https://github.com/kbsec/Weblogic_Wsat_RCE)
- [SkyBlueEternal/CNVD-C-2019-48814-CNNVD-201904-961](https://github.com/SkyBlueEternal/CNVD-C-2019-48814-CNNVD-201904-961)
- [Yuusuke4/WebLogic_CNVD_C_2019_48814](https://github.com/Yuusuke4/WebLogic_CNVD_C_2019_48814)
- [7kbstorm/WebLogic_CNVD_C2019_48814](https://github.com/7kbstorm/WebLogic_CNVD_C2019_48814)
- [ianxtianxt/-CVE-2017-10271-](https://github.com/ianxtianxt/-CVE-2017-10271-)
- [testwc/CVE-2017-10271](https://github.com/testwc/CVE-2017-10271)

### CVE-2017-10352

<code>
Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS - Web Services). The supported version that is affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.1.0, 12.2.1.2.0 and 12.2.1.3.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. While the vulnerability is in Oracle WebLogic Server, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle WebLogic Server as well as unauthorized update, insert or delete access to some of Oracle WebLogic Server accessible data and unauthorized read access to a subset of Oracle WebLogic Server accessible data. CVSS 3.0 Base Score 9.9 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:H).
</code>

- [bigsizeme/weblogic-XMLDecoder](https://github.com/bigsizeme/weblogic-XMLDecoder)

### CVE-2017-10366

<code>
Vulnerability in the PeopleSoft Enterprise PT PeopleTools component of Oracle PeopleSoft Products (subcomponent: Performance Monitor). Supported versions that are affected are 8.54, 8.55 and 8.56. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise PeopleSoft Enterprise PT PeopleTools. Successful attacks of this vulnerability can result in takeover of PeopleSoft Enterprise PT PeopleTools. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
</code>

- [blazeinfosec/CVE-2017-10366_peoplesoft](https://github.com/blazeinfosec/CVE-2017-10366_peoplesoft)

### CVE-2017-10617

<code>
The ifmap service that comes bundled with Contrail has an XML External Entity (XXE) vulnerability that may allow an attacker to retrieve sensitive system files. Affected releases are Juniper Networks Contrail 2.2 prior to 2.21.4; 3.0 prior to 3.0.3.4; 3.1 prior to 3.1.4.0; 3.2 prior to 3.2.5.0. CVE-2017-10616 and CVE-2017-10617 can be chained together and have a combined CVSSv3 score of 5.8 (AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N).
</code>

- [gteissier/CVE-2017-10617](https://github.com/gteissier/CVE-2017-10617)

### CVE-2017-10661

<code>
Race condition in fs/timerfd.c in the Linux kernel before 4.10.15 allows local users to gain privileges or cause a denial of service (list corruption or use-after-free) via simultaneous file-descriptor operations that leverage improper might_cancel queueing.
</code>

- [GeneBlue/CVE-2017-10661_POC](https://github.com/GeneBlue/CVE-2017-10661_POC)

### CVE-2017-10797
- [n4xh4ck5/CVE-2017-10797](https://github.com/n4xh4ck5/CVE-2017-10797)

### CVE-2017-10952

<code>
This vulnerability allows remote attackers to execute arbitrary code on vulnerable installations of Foxit Reader 8.2.0.2051. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the saveAs JavaScript function. The issue results from the lack of proper validation of user-supplied data, which can lead to writing arbitrary files into attacker controlled locations. An attacker can leverage this vulnerability to execute code under the context of the current process. Was ZDI-CAN-4518.
</code>

- [afbase/CVE-2017-10952](https://github.com/afbase/CVE-2017-10952)

### CVE-2017-11176

<code>
The mq_notify function in the Linux kernel through 4.11.9 does not set the sock pointer to NULL upon entry into the retry logic. During a user-space close of a Netlink socket, it allows attackers to cause a denial of service (use-after-free) or possibly have unspecified other impact.
</code>

- [DoubleMice/cve-2017-11176](https://github.com/DoubleMice/cve-2017-11176)
- [HckEX/CVE-2017-11176](https://github.com/HckEX/CVE-2017-11176)
- [leonardo1101/cve-2017-11176](https://github.com/leonardo1101/cve-2017-11176)
- [c3r34lk1ll3r/CVE-2017-11176](https://github.com/c3r34lk1ll3r/CVE-2017-11176)

### CVE-2017-11317

<code>
Telerik.Web.UI in Progress Telerik UI for ASP.NET AJAX before R1 2017 and R2 before R2 2017 SP2 uses weak RadAsyncUpload encryption, which allows remote attackers to perform arbitrary file uploads or execute arbitrary code.
</code>

- [bao7uo/RAU_crypto](https://github.com/bao7uo/RAU_crypto)

### CVE-2017-11427

<code>
OneLogin PythonSAML 2.3.0 and earlier may incorrectly utilize the results of XML DOM traversal and canonicalization APIs in such a way that an attacker may be able to manipulate the SAML data without invalidating the cryptographic signature, allowing the attack to potentially bypass authentication to SAML service providers.
</code>

- [CHYbeta/CVE-2017-11427-DEMO](https://github.com/CHYbeta/CVE-2017-11427-DEMO)

### CVE-2017-11503

<code>
PHPMailer 5.2.23 has XSS in the &quot;From Email Address&quot; and &quot;To Email Address&quot; fields of code_generator.php.
</code>

- [wizardafric/download](https://github.com/wizardafric/download)

### CVE-2017-11519

<code>
passwd_recovery.lua on the TP-Link Archer C9(UN)_V2_160517 allows an attacker to reset the admin password by leveraging a predictable random number generator seed. This is fixed in C9(UN)_V2_170511.
</code>

- [vakzz/tplink-CVE-2017-11519](https://github.com/vakzz/tplink-CVE-2017-11519)

### CVE-2017-11610

<code>
The XML-RPC server in supervisor before 3.0.1, 3.1.x before 3.1.4, 3.2.x before 3.2.4, and 3.3.x before 3.3.3 allows remote authenticated users to execute arbitrary commands via a crafted XML-RPC request, related to nested supervisord namespace lookups.
</code>

- [ivanitlearning/CVE-2017-11610](https://github.com/ivanitlearning/CVE-2017-11610)

### CVE-2017-11611

<code>
Wolf CMS 0.8.3.1 allows Cross-Site Scripting (XSS) attacks. The vulnerability exists due to insufficient sanitization of the file name in a &quot;create-file-popup&quot; action, and the directory name in a &quot;create-directory-popup&quot; action, in the HTTP POST method to the &quot;/plugin/file_manager/&quot; script (aka an /admin/plugin/file_manager/browse// URI).
</code>

- [faizzaidi/Wolfcms-v0.8.3.1-xss-POC-by-Provensec-llc](https://github.com/faizzaidi/Wolfcms-v0.8.3.1-xss-POC-by-Provensec-llc)

### CVE-2017-11774

<code>
Microsoft Outlook 2010 SP2, Outlook 2013 SP1 and RT SP1, and Outlook 2016 allow an attacker to execute arbitrary commands, due to how Microsoft Office handles objects in memory, aka &quot;Microsoft Outlook Security Feature Bypass Vulnerability.&quot;
</code>

- [devcoinfet/SniperRoost](https://github.com/devcoinfet/SniperRoost)

### CVE-2017-11783

<code>
Microsoft Windows 8.1, Windows Server 2012 R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, and 1703, and Windows Server 2016 allows an elevation of privilege vulnerability in the way it handles calls to Advanced Local Procedure Call (ALPC), aka &quot;Windows Elevation of Privilege Vulnerability&quot;.
</code>

- [Sheisback/CVE-2017-11783](https://github.com/Sheisback/CVE-2017-11783)

### CVE-2017-11816

<code>
The Microsoft Windows Graphics Device Interface (GDI) on Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, and 1703, and Windows Server 2016 allows an information disclosure vulnerability in the way it handles objects in memory, aka &quot;Windows GDI Information Disclosure Vulnerability&quot;.
</code>

- [lr3800/CVE-2017-11816](https://github.com/lr3800/CVE-2017-11816)

### CVE-2017-11826

<code>
Microsoft Office 2010, SharePoint Enterprise Server 2010, SharePoint Server 2010, Web Applications, Office Web Apps Server 2010 and 2013, Word Viewer, Word 2007, 2010, 2013 and 2016, Word Automation Services, and Office Online Server allow remote code execution when the software fails to properly handle objects in memory.
</code>

- [thatskriptkid/CVE-2017-11826](https://github.com/thatskriptkid/CVE-2017-11826)

### CVE-2017-11882

<code>
Microsoft Office 2007 Service Pack 3, Microsoft Office 2010 Service Pack 2, Microsoft Office 2013 Service Pack 1, and Microsoft Office 2016 allow an attacker to run arbitrary code in the context of the current user by failing to properly handle objects in memory, aka &quot;Microsoft Office Memory Corruption Vulnerability&quot;. This CVE ID is unique from CVE-2017-11884.
</code>

- [starnightcyber/exploits](https://github.com/starnightcyber/exploits)
- [zhouat/cve-2017-11882](https://github.com/zhouat/cve-2017-11882)
- [embedi/CVE-2017-11882](https://github.com/embedi/CVE-2017-11882)
- [Ridter/CVE-2017-11882](https://github.com/Ridter/CVE-2017-11882)
- [BlackMathIT/2017-11882_Generator](https://github.com/BlackMathIT/2017-11882_Generator)
- [unamer/CVE-2017-11882](https://github.com/unamer/CVE-2017-11882)
- [0x09AL/CVE-2017-11882-metasploit](https://github.com/0x09AL/CVE-2017-11882-metasploit)
- [HZachev/ABC](https://github.com/HZachev/ABC)
- [starnightcyber/CVE-2017-11882](https://github.com/starnightcyber/CVE-2017-11882)
- [Grey-Li/CVE-2017-11882](https://github.com/Grey-Li/CVE-2017-11882)
- [legendsec/CVE-2017-11882-for-Kali](https://github.com/legendsec/CVE-2017-11882-for-Kali)
- [CSC-pentest/cve-2017-11882](https://github.com/CSC-pentest/cve-2017-11882)
- [Shadowshusky/CVE-2017-11882-](https://github.com/Shadowshusky/CVE-2017-11882-)
- [rxwx/CVE-2018-0802](https://github.com/rxwx/CVE-2018-0802)
- [Ridter/RTF_11882_0802](https://github.com/Ridter/RTF_11882_0802)
- [denmilu/CVE-2017-11882](https://github.com/denmilu/CVE-2017-11882)
- [denmilu/CVE-2018-0802_CVE-2017-11882](https://github.com/denmilu/CVE-2018-0802_CVE-2017-11882)
- [bloomer1016/CVE-2017-11882-Possible-Remcos-Malspam](https://github.com/bloomer1016/CVE-2017-11882-Possible-Remcos-Malspam)
- [ChaitanyaHaritash/CVE-2017-11882](https://github.com/ChaitanyaHaritash/CVE-2017-11882)
- [qy1202/https-github.com-Ridter-CVE-2017-11882-](https://github.com/qy1202/https-github.com-Ridter-CVE-2017-11882-)
- [j0lama/CVE-2017-11882](https://github.com/j0lama/CVE-2017-11882)
- [R0fM1a/IDB_Share](https://github.com/R0fM1a/IDB_Share)
- [chanbin/CVE-2017-11882](https://github.com/chanbin/CVE-2017-11882)
- [littlebin404/CVE-2017-11882](https://github.com/littlebin404/CVE-2017-11882)
- [ekgg/Overflow-Demo-CVE-2017-11882](https://github.com/ekgg/Overflow-Demo-CVE-2017-11882)

### CVE-2017-11907

<code>
Internet Explorer in Microsoft Windows 7 SP1, Windows Server 2008 and R2 SP1, Windows 8.1 and Windows RT 8.1, Windows Server 2012 and R2, Windows 10 Gold, 1511, 1607, 1703, 1709, and Windows Server 2016 allows an attacker to gain the same user rights as the current user, due to how Internet Explorer handles objects in memory, aka &quot;Scripting Engine Memory Corruption Vulnerability&quot;. This CVE ID is unique from CVE-2017-11886, CVE-2017-11889, CVE-2017-11890, CVE-2017-11893, CVE-2017-11894, CVE-2017-11895, CVE-2017-11901, CVE-2017-11903, CVE-2017-11905, CVE-2017-11905, CVE-2017-11908, CVE-2017-11909, CVE-2017-11910, CVE-2017-11911, CVE-2017-11912, CVE-2017-11913, CVE-2017-11914, CVE-2017-11916, CVE-2017-11918, and CVE-2017-11930.
</code>

- [re4lity/CVE-2017-11907](https://github.com/re4lity/CVE-2017-11907)

### CVE-2017-12149

<code>
In Jboss Application Server as shipped with Red Hat Enterprise Application Platform 5.2, it was found that the doFilter method in the ReadOnlyAccessFilter of the HTTP Invoker does not restrict classes for which it performs deserialization and thus allowing an attacker to execute arbitrary code via crafted serialized data.
</code>

- [sevck/CVE-2017-12149](https://github.com/sevck/CVE-2017-12149)
- [yunxu1/jboss-_CVE-2017-12149](https://github.com/yunxu1/jboss-_CVE-2017-12149)
- [1337g/CVE-2017-12149](https://github.com/1337g/CVE-2017-12149)
- [jreppiks/CVE-2017-12149](https://github.com/jreppiks/CVE-2017-12149)

### CVE-2017-12426

<code>
GitLab Community Edition (CE) and Enterprise Edition (EE) before 8.17.8, 9.0.x before 9.0.13, 9.1.x before 9.1.10, 9.2.x before 9.2.10, 9.3.x before 9.3.10, and 9.4.x before 9.4.4 might allow remote attackers to execute arbitrary code via a crafted SSH URL in a project import.
</code>

- [sm-paul-schuette/CVE-2017-12426](https://github.com/sm-paul-schuette/CVE-2017-12426)

### CVE-2017-12542

<code>
A authentication bypass and execution of code vulnerability in HPE Integrated Lights-out 4 (iLO 4) version prior to 2.53 was found.
</code>

- [skelsec/CVE-2017-12542](https://github.com/skelsec/CVE-2017-12542)
- [sk1dish/ilo4-rce-vuln-scanner](https://github.com/sk1dish/ilo4-rce-vuln-scanner)

### CVE-2017-12611

<code>
In Apache Struts 2.0.0 through 2.3.33 and 2.5 through 2.5.10.1, using an unintentional expression in a Freemarker tag instead of string literals can lead to a RCE attack.
</code>

- [brianwrf/S2-053-CVE-2017-12611](https://github.com/brianwrf/S2-053-CVE-2017-12611)

### CVE-2017-12615

<code>
When running Apache Tomcat 7.0.0 to 7.0.79 on Windows with HTTP PUTs enabled (e.g. via setting the readonly initialisation parameter of the Default to false) it was possible to upload a JSP file to the server via a specially crafted request. This JSP could then be requested and any code it contained would be executed by the server.
</code>

- [breaktoprotect/CVE-2017-12615](https://github.com/breaktoprotect/CVE-2017-12615)
- [mefulton/cve-2017-12615](https://github.com/mefulton/cve-2017-12615)
- [zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717](https://github.com/zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717)
- [RealBearcat/CVE-2017-12615](https://github.com/RealBearcat/CVE-2017-12615)
- [wsg00d/cve-2017-12615](https://github.com/wsg00d/cve-2017-12615)
- [1337g/CVE-2017-12615](https://github.com/1337g/CVE-2017-12615)
- [Shellkeys/CVE-2017-12615](https://github.com/Shellkeys/CVE-2017-12615)
- [cved-sources/cve-2017-12615](https://github.com/cved-sources/cve-2017-12615)
- [ianxtianxt/CVE-2017-12615](https://github.com/ianxtianxt/CVE-2017-12615)

### CVE-2017-12617

<code>
When running Apache Tomcat versions 9.0.0.M1 to 9.0.0, 8.5.0 to 8.5.22, 8.0.0.RC1 to 8.0.46 and 7.0.0 to 7.0.81 with HTTP PUTs enabled (e.g. via setting the readonly initialisation parameter of the Default servlet to false) it was possible to upload a JSP file to the server via a specially crafted request. This JSP could then be requested and any code it contained would be executed by the server.
</code>

- [cyberheartmi9/CVE-2017-12617](https://github.com/cyberheartmi9/CVE-2017-12617)
- [devcoinfet/CVE-2017-12617](https://github.com/devcoinfet/CVE-2017-12617)
- [qiantu88/CVE-2017-12617](https://github.com/qiantu88/CVE-2017-12617)
- [ygouzerh/CVE-2017-12617](https://github.com/ygouzerh/CVE-2017-12617)

### CVE-2017-12624

<code>
Apache CXF supports sending and receiving attachments via either the JAX-WS or JAX-RS specifications. It is possible to craft a message attachment header that could lead to a Denial of Service (DoS) attack on a CXF web service provider. Both JAX-WS and JAX-RS services are vulnerable to this attack. From Apache CXF 3.2.1 and 3.1.14, message attachment headers that are greater than 300 characters will be rejected by default. This value is configurable via the property &quot;attachment-max-header-size&quot;.
</code>

- [tafamace/CVE-2017-12624](https://github.com/tafamace/CVE-2017-12624)

### CVE-2017-12635

<code>
Due to differences in the Erlang-based JSON parser and JavaScript-based JSON parser, it is possible in Apache CouchDB before 1.7.0 and 2.x before 2.1.1 to submit _users documents with duplicate keys for 'roles' used for access control within the database, including the special case '_admin' role, that denotes administrative users. In combination with CVE-2017-12636 (Remote Code Execution), this can be used to give non-admin users access to arbitrary shell commands on the server as the database system user. The JSON parser differences result in behaviour that if two 'roles' keys are available in the JSON, the second one will be used for authorising the document write, but the first 'roles' key is used for subsequent authorization for the newly created user. By design, users can not assign themselves roles. The vulnerability allows non-admin users to give themselves admin privileges.
</code>

- [assalielmehdi/CVE-2017-12635](https://github.com/assalielmehdi/CVE-2017-12635)

### CVE-2017-12636

<code>
CouchDB administrative users can configure the database server via HTTP(S). Some of the configuration options include paths for operating system-level binaries that are subsequently launched by CouchDB. This allows an admin user in Apache CouchDB before 1.7.0 and 2.x before 2.1.1 to execute arbitrary shell commands as the CouchDB user, including downloading and executing scripts from the public internet.
</code>

- [moayadalmalat/CVE-2017-12636](https://github.com/moayadalmalat/CVE-2017-12636)
- [F1uffyGoat/F1uffyCouchDB](https://github.com/F1uffyGoat/F1uffyCouchDB)
- [RedTeamWing/CVE-2017-12636](https://github.com/RedTeamWing/CVE-2017-12636)

### CVE-2017-12792

<code>
Multiple cross-site request forgery (CSRF) vulnerabilities in NexusPHP 1.5 allow remote attackers to hijack the authentication of administrators for requests that conduct cross-site scripting (XSS) attacks via the (1) linkname, (2) url, or (3) title parameter in an add action to linksmanage.php.
</code>

- [ZZS2017/cve-2017-12792](https://github.com/ZZS2017/cve-2017-12792)

### CVE-2017-12852

<code>
The numpy.pad function in Numpy 1.13.1 and older versions is missing input validation. An empty list or ndarray will stick into an infinite loop, which can allow attackers to cause a DoS attack.
</code>

- [BT123/numpy-1.13.1](https://github.com/BT123/numpy-1.13.1)

### CVE-2017-12943

<code>
D-Link DIR-600 Rev Bx devices with v2.x firmware allow remote attackers to read passwords via a model/__show_info.php?REQUIRE_FILE= absolute path traversal attack, as demonstrated by discovering the admin password.
</code>

- [aymankhalfatni/D-Link](https://github.com/aymankhalfatni/D-Link)

### CVE-2017-12945

<code>
Insufficient validation of user-supplied input for the Solstice Pod before 2.8.4 networking configuration enables authenticated attackers to execute arbitrary commands as root.
</code>

- [aress31/cve-2017-12945](https://github.com/aress31/cve-2017-12945)

### CVE-2017-13089

<code>
The http.c:skip_short_body() function is called in some circumstances, such as when processing redirects. When the response is sent chunked in wget before 1.19.2, the chunk parser uses strtol() to read each chunk's length, but doesn't check that the chunk length is a non-negative number. The code then tries to skip the chunk in pieces of 512 bytes by using the MIN() macro, but ends up passing the negative chunk length to connect.c:fd_read(). As fd_read() takes an int argument, the high 32 bits of the chunk length are discarded, leaving fd_read() with a completely attacker controlled length argument.
</code>

- [r1b/CVE-2017-13089](https://github.com/r1b/CVE-2017-13089)
- [mzeyong/CVE-2017-13089](https://github.com/mzeyong/CVE-2017-13089)

### CVE-2017-13156

<code>
An elevation of privilege vulnerability in the Android system (art). Product: Android. Versions: 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID A-64211847.
</code>

- [xyzAsian/Janus-CVE-2017-13156](https://github.com/xyzAsian/Janus-CVE-2017-13156)
- [caxmd/CVE-2017-13156](https://github.com/caxmd/CVE-2017-13156)
- [giacomoferretti/janus-toolkit](https://github.com/giacomoferretti/janus-toolkit)

### CVE-2017-13253

<code>
In CryptoPlugin::decrypt of CryptoPlugin.cpp, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation. Product: Android. Versions: 8.0, 8.1. Android ID: A-71389378.
</code>

- [tamirzb/CVE-2017-13253](https://github.com/tamirzb/CVE-2017-13253)

### CVE-2017-13672

<code>
QEMU (aka Quick Emulator), when built with the VGA display emulator support, allows local guest OS privileged users to cause a denial of service (out-of-bounds read and QEMU process crash) via vectors involving display update.
</code>

- [DavidBuchanan314/CVE-2017-13672](https://github.com/DavidBuchanan314/CVE-2017-13672)

### CVE-2017-13868

<code>
An issue was discovered in certain Apple products. iOS before 11.2 is affected. macOS before 10.13.2 is affected. tvOS before 11.2 is affected. watchOS before 4.2 is affected. The issue involves the &quot;Kernel&quot; component. It allows attackers to bypass intended memory-read restrictions via a crafted app.
</code>

- [bazad/ctl_ctloutput-leak](https://github.com/bazad/ctl_ctloutput-leak)

### CVE-2017-13872

<code>
An issue was discovered in certain Apple products. macOS High Sierra before Security Update 2017-001 is affected. The issue involves the &quot;Directory Utility&quot; component. It allows attackers to obtain administrator access without a password via certain interactions involving entry of the root user name.
</code>

- [giovannidispoto/CVE-2017-13872-Patch](https://github.com/giovannidispoto/CVE-2017-13872-Patch)

### CVE-2017-14105

<code>
HiveManager Classic through 8.1r1 allows arbitrary JSP code execution by modifying a backup archive before a restore, because the restore feature does not validate pathnames within the archive. An authenticated, local attacker - even restricted as a tenant - can add a jsp at HiveManager/tomcat/webapps/hm/domains/$yourtenant/maps (it will be exposed at the web interface).
</code>

- [theguly/CVE-2017-14105](https://github.com/theguly/CVE-2017-14105)

### CVE-2017-14262

<code>
On Samsung NVR devices, remote attackers can read the MD5 password hash of the 'admin' account via certain szUserName JSON data to cgi-bin/main-cgi, and login to the device with that hash in the szUserPasswd parameter.
</code>

- [zzz66686/CVE-2017-14262](https://github.com/zzz66686/CVE-2017-14262)

### CVE-2017-14263

<code>
Honeywell NVR devices allow remote attackers to create a user account in the admin group by leveraging access to a guest account to obtain a session ID, and then sending that session ID in a userManager.addUser request to the /RPC2 URI. The attacker can login to the device with that new user account to fully control the device.
</code>

- [zzz66686/CVE-2017-14263](https://github.com/zzz66686/CVE-2017-14263)

### CVE-2017-14322

<code>
The function in charge to check whether the user is already logged in init.php in Interspire Email Marketer (IEM) prior to 6.1.6 allows remote attackers to bypass authentication and obtain administrative access by using the IEM_CookieLogin cookie with a specially crafted value.
</code>

- [joesmithjaffa/CVE-2017-14322](https://github.com/joesmithjaffa/CVE-2017-14322)

### CVE-2017-14491

<code>
Heap-based buffer overflow in dnsmasq before 2.78 allows remote attackers to cause a denial of service (crash) or execute arbitrary code via a crafted DNS response.
</code>

- [YIHSUEHTsai/dnsmasq-2.4.1-fix-CVE-2017-14491](https://github.com/YIHSUEHTsai/dnsmasq-2.4.1-fix-CVE-2017-14491)

### CVE-2017-14493

<code>
Stack-based buffer overflow in dnsmasq before 2.78 allows remote attackers to cause a denial of service (crash) or execute arbitrary code via a crafted DHCPv6 request.
</code>

- [pupiles/bof-dnsmasq-cve-2017-14493](https://github.com/pupiles/bof-dnsmasq-cve-2017-14493)

### CVE-2017-14719

<code>
Before version 4.8.2, WordPress was vulnerable to a directory traversal attack during unzip operations in the ZipArchive and PclZip components.
</code>

- [PalmTreeForest/CodePath_Week_7-8](https://github.com/PalmTreeForest/CodePath_Week_7-8)

### CVE-2017-14948

<code>
Certain D-Link products are affected by: Buffer Overflow. This affects DIR-880L 1.08B04 and DIR-895 L/R 1.13b03. The impact is: execute arbitrary code (remote). The component is: htdocs/fileaccess.cgi. The attack vector is: A crafted HTTP request handled by fileacces.cgi could allow an attacker to mount a ROP attack: if the HTTP header field CONTENT_TYPE starts with ''boundary=' followed by more than 256 characters, a buffer overflow would be triggered, potentially causing code execution.
</code>

- [badnack/d_link_880_bug](https://github.com/badnack/d_link_880_bug)

### CVE-2017-15120

<code>
An issue has been found in the parsing of authoritative answers in PowerDNS Recursor before 4.0.8, leading to a NULL pointer dereference when parsing a specially crafted answer containing a CNAME of a different class than IN. An unauthenticated remote attacker could cause a denial of service.
</code>

- [shutingrz/CVE-2017-15120_PoC](https://github.com/shutingrz/CVE-2017-15120_PoC)

### CVE-2017-15277

<code>
ReadGIFImage in coders/gif.c in ImageMagick 7.0.6-1 and GraphicsMagick 1.3.26 leaves the palette uninitialized when processing a GIF file that has neither a global nor local palette. If the affected product is used as a library loaded into a process that operates on interesting data, this data sometimes can be leaked via the uninitialized palette.
</code>

- [tacticthreat/ImageMagick-CVE-2017-15277](https://github.com/tacticthreat/ImageMagick-CVE-2017-15277)

### CVE-2017-15303

<code>
In CPUID CPU-Z before 1.43, there is an arbitrary memory write that results directly in elevation of privileges, because any program running on the local machine (while CPU-Z is running) can issue an ioctl 0x9C402430 call to the kernel-mode driver (e.g., cpuz141_x64.sys for version 1.41).
</code>

- [hfiref0x/Stryker](https://github.com/hfiref0x/Stryker)

### CVE-2017-15361

<code>
The Infineon RSA library 1.02.013 in Infineon Trusted Platform Module (TPM) firmware, such as versions before 0000000000000422 - 4.34, before 000000000000062b - 6.43, and before 0000000000008521 - 133.33, mishandles RSA key generation, which makes it easier for attackers to defeat various cryptographic protection mechanisms via targeted attacks, aka ROCA. Examples of affected technologies include BitLocker with TPM 1.2, YubiKey 4 (before 4.3.5) PGP key generation, and the Cached User Data encryption feature in Chrome OS.
</code>

- [lva/Infineon-CVE-2017-15361](https://github.com/lva/Infineon-CVE-2017-15361)
- [titanous/rocacheck](https://github.com/titanous/rocacheck)
- [jnpuskar/RocaCmTest](https://github.com/jnpuskar/RocaCmTest)
- [nsacyber/Detect-CVE-2017-15361-TPM](https://github.com/nsacyber/Detect-CVE-2017-15361-TPM)
- [0xxon/zeek-plugin-roca](https://github.com/0xxon/zeek-plugin-roca)
- [0xxon/roca](https://github.com/0xxon/roca)

### CVE-2017-15394

<code>
Insufficient Policy Enforcement in Extensions in Google Chrome prior to 62.0.3202.62 allowed a remote attacker to perform domain spoofing in permission dialogs via IDN homographs in a crafted Chrome Extension.
</code>

- [sudosammy/CVE-2017-15394](https://github.com/sudosammy/CVE-2017-15394)

### CVE-2017-15708

<code>
In Apache Synapse, by default no authentication is required for Java Remote Method Invocation (RMI). So Apache Synapse 3.0.1 or all previous releases (3.0.0, 2.1.0, 2.0.0, 1.2, 1.1.2, 1.1.1) allows remote code execution attacks that can be performed by injecting specially crafted serialized objects. And the presence of Apache Commons Collections 3.2.1 (commons-collections-3.2.1.jar) or previous versions in Synapse distribution makes this exploitable. To mitigate the issue, we need to limit RMI access to trusted users only. Further upgrading to 3.0.1 version will eliminate the risk of having said Commons Collection version. In Synapse 3.0.1, Commons Collection has been updated to 3.2.2 version.
</code>

- [RealBearcat/CVE-2017-15708](https://github.com/RealBearcat/CVE-2017-15708)

### CVE-2017-15715

<code>
In Apache httpd 2.4.0 to 2.4.29, the expression specified in &lt;FilesMatch&gt; could match '$' to a newline character in a malicious filename, rather than matching only the end of the filename. This could be exploited in environments where uploads of some files are are externally blocked, but only by matching the trailing portion of the filename.
</code>

- [whisp1830/CVE-2017-15715](https://github.com/whisp1830/CVE-2017-15715)

### CVE-2017-15944

<code>
Palo Alto Networks PAN-OS before 6.1.19, 7.0.x before 7.0.19, 7.1.x before 7.1.14, and 8.0.x before 8.0.6 allows remote attackers to execute arbitrary code via vectors involving the management interface.
</code>

- [xxnbyy/CVE-2017-15944-POC](https://github.com/xxnbyy/CVE-2017-15944-POC)
- [surajraghuvanshi/PaloAltoRceDetectionAndExploit](https://github.com/surajraghuvanshi/PaloAltoRceDetectionAndExploit)

### CVE-2017-16082

<code>
A remote code execution vulnerability was found within the pg module when the remote database or query specifies a specially crafted column name. There are 2 likely scenarios in which one would likely be vulnerable. 1) Executing unsafe, user-supplied sql which contains a malicious column name. 2) Connecting to an untrusted database and executing a query which returns results where any of the column names are malicious.
</code>

- [nulldreams/CVE-2017-16082](https://github.com/nulldreams/CVE-2017-16082)

### CVE-2017-16088

<code>
The safe-eval module describes itself as a safer version of eval. By accessing the object constructors, un-sanitized user input can access the entire standard library and effectively break out of the sandbox.
</code>

- [Flyy-yu/CVE-2017-16088](https://github.com/Flyy-yu/CVE-2017-16088)

### CVE-2017-16245
- [AOCorsaire/CVE-2017-16245](https://github.com/AOCorsaire/CVE-2017-16245)

### CVE-2017-1635

<code>
IBM Tivoli Monitoring V6 6.2.2.x could allow a remote attacker to execute arbitrary code on the system, caused by a use-after-free error. A remote attacker could exploit this vulnerability to execute arbitrary code on the system or cause the application to crash. IBM X-Force ID: 133243.
</code>

- [emcalv/tivoli-poc](https://github.com/emcalv/tivoli-poc)

### CVE-2017-16524

<code>
Web Viewer 1.0.0.193 on Samsung SRN-1670D devices suffers from an Unrestricted file upload vulnerability: 'network_ssl_upload.php' allows remote authenticated attackers to upload and execute arbitrary PHP code via a filename with a .php extension, which is then accessed via a direct request to the file in the upload/ directory. To authenticate for this attack, one can obtain web-interface credentials in cleartext by leveraging the existing Local File Read Vulnerability referenced as CVE-2015-8279, which allows remote attackers to read the web-interface credentials via a request for the cslog_export.php?path=/root/php_modules/lighttpd/sbin/userpw URI.
</code>

- [realistic-security/CVE-2017-16524](https://github.com/realistic-security/CVE-2017-16524)

### CVE-2017-16567

<code>
Cross-site scripting (XSS) vulnerability in Logitech Media Server 7.9.0 allows remote attackers to inject arbitrary web script or HTML via a &quot;favorite.&quot;
</code>

- [dewankpant/CVE-2017-16567](https://github.com/dewankpant/CVE-2017-16567)

### CVE-2017-16568

<code>
Cross-site scripting (XSS) vulnerability in Logitech Media Server 7.9.0 allows remote attackers to inject arbitrary web script or HTML via a radio URL.
</code>

- [dewankpant/CVE-2017-16568](https://github.com/dewankpant/CVE-2017-16568)

### CVE-2017-16744

<code>
A path traversal vulnerability in Tridium Niagara AX Versions 3.8 and prior and Niagara 4 systems Versions 4.4 and prior installed on Microsoft Windows Systems can be exploited by leveraging valid platform (administrator) credentials.
</code>

- [GainSec/CVE-2017-16744-and-CVE-2017-16748-Tridium-Niagara](https://github.com/GainSec/CVE-2017-16744-and-CVE-2017-16748-Tridium-Niagara)

### CVE-2017-16778

<code>
An access control weakness in the DTMF tone receiver of Fermax Outdoor Panel allows physical attackers to inject a Dual-Tone-Multi-Frequency (DTMF) tone to invoke an access grant that would allow physical access to a restricted floor/level. By design, only a residential unit owner may allow such an access grant. However, due to incorrect access control, an attacker could inject it via the speaker unit to perform an access grant to gain unauthorized access, as demonstrated by a loud DTMF tone representing '1' and a long '#' (697 Hz and 1209 Hz, followed by 941 Hz and 1477 Hz).
</code>

- [breaktoprotect/CVE-2017-16778-Intercom-DTMF-Injection](https://github.com/breaktoprotect/CVE-2017-16778-Intercom-DTMF-Injection)

### CVE-2017-16806

<code>
The Process function in RemoteTaskServer/WebServer/HttpServer.cs in Ulterius before 1.9.5.0 allows HTTP server directory traversal.
</code>

- [rickoooooo/ulteriusExploit](https://github.com/rickoooooo/ulteriusExploit)

### CVE-2017-16943

<code>
The receive_msg function in receive.c in the SMTP daemon in Exim 4.88 and 4.89 allows remote attackers to execute arbitrary code or cause a denial of service (use-after-free) via vectors involving BDAT commands.
</code>

- [beraphin/CVE-2017-16943](https://github.com/beraphin/CVE-2017-16943)

### CVE-2017-16995

<code>
The check_alu_op function in kernel/bpf/verifier.c in the Linux kernel through 4.14.8 allows local users to cause a denial of service (memory corruption) or possibly have unspecified other impact by leveraging incorrect sign extension.
</code>

- [RealBearcat/CVE-2017-16995](https://github.com/RealBearcat/CVE-2017-16995)
- [Al1ex/CVE-2017-16995](https://github.com/Al1ex/CVE-2017-16995)
- [gugronnier/CVE-2017-16995](https://github.com/gugronnier/CVE-2017-16995)
- [senyuuri/cve-2017-16995](https://github.com/senyuuri/cve-2017-16995)
- [vnik5287/CVE-2017-16995](https://github.com/vnik5287/CVE-2017-16995)
- [littlebin404/CVE-2017-16995](https://github.com/littlebin404/CVE-2017-16995)
- [Lumindu/CVE-2017-16995-Linux-Kernel---BPF-Sign-Extension-Local-Privilege-Escalation-](https://github.com/Lumindu/CVE-2017-16995-Linux-Kernel---BPF-Sign-Extension-Local-Privilege-Escalation-)

### CVE-2017-16997

<code>
elf/dl-load.c in the GNU C Library (aka glibc or libc6) 2.19 through 2.26 mishandles RPATH and RUNPATH containing $ORIGIN for a privileged (setuid or AT_SECURE) program, which allows local users to gain privileges via a Trojan horse library in the current working directory, related to the fillin_rpath and decompose_rpath functions. This is associated with misinterpretion of an empty RPATH/RUNPATH token as the &quot;./&quot; directory. NOTE: this configuration of RPATH/RUNPATH for a privileged program is apparently very uncommon; most likely, no such program is shipped with any common Linux distribution.
</code>

- [Xiami2012/CVE-2017-16997-poc](https://github.com/Xiami2012/CVE-2017-16997-poc)

### CVE-2017-17099

<code>
There exists an unauthenticated SEH based Buffer Overflow vulnerability in the HTTP server of Flexense SyncBreeze Enterprise v10.1.16. When sending a GET request with an excessive length, it is possible for a malicious user to overwrite the SEH record and execute a payload that would run under the Windows SYSTEM account.
</code>

- [wetw0rk/Exploit-Development](https://github.com/wetw0rk/Exploit-Development)

### CVE-2017-17215

<code>
Huawei HG532 with some customized versions has a remote code execution vulnerability. An authenticated attacker could send malicious packets to port 37215 to launch attacks. Successful exploit could lead to the remote execution of arbitrary code.
</code>

- [1337g/CVE-2017-17215](https://github.com/1337g/CVE-2017-17215)

### CVE-2017-17309

<code>
Huawei HG255s-10 V100R001C163B025SP02 has a path traversal vulnerability due to insufficient validation of the received HTTP requests, a remote attacker may access the local files on the device without authentication.
</code>

- [exploit-labs/huawei_hg255s_exploit](https://github.com/exploit-labs/huawei_hg255s_exploit)

### CVE-2017-17485

<code>
FasterXML jackson-databind through 2.8.10 and 2.9.x through 2.9.3 allows unauthenticated remote code execution because of an incomplete fix for the CVE-2017-7525 deserialization flaw. This is exploitable by sending maliciously crafted JSON input to the readValue method of the ObjectMapper, bypassing a blacklist that is ineffective if the Spring libraries are available in the classpath.
</code>

- [RealBearcat/Jackson-CVE-2017-17485](https://github.com/RealBearcat/Jackson-CVE-2017-17485)
- [tafamace/CVE-2017-17485](https://github.com/tafamace/CVE-2017-17485)
- [x7iaob/cve-2017-17485](https://github.com/x7iaob/cve-2017-17485)

### CVE-2017-17562

<code>
Embedthis GoAhead before 3.6.5 allows remote code execution if CGI is enabled and a CGI program is dynamically linked. This is a result of initializing the environment of forked CGI scripts using untrusted HTTP request parameters in the cgiHandler function in cgi.c. When combined with the glibc dynamic linker, this behaviour can be abused for remote code execution using special parameter names such as LD_PRELOAD. An attacker can POST their shared object payload in the body of the request, and reference it using /proc/self/fd/0.
</code>

- [1337g/CVE-2017-17562](https://github.com/1337g/CVE-2017-17562)
- [ivanitlearning/CVE-2017-17562](https://github.com/ivanitlearning/CVE-2017-17562)
- [crispy-peppers/Goahead-CVE-2017-17562](https://github.com/crispy-peppers/Goahead-CVE-2017-17562)

### CVE-2017-17692

<code>
Samsung Internet Browser 5.4.02.3 allows remote attackers to bypass the Same Origin Policy and obtain sensitive information via crafted JavaScript code that redirects to a child tab and rewrites the innerHTML property.
</code>

- [lr3800/CVE-2017-17692](https://github.com/lr3800/CVE-2017-17692)

### CVE-2017-18044

<code>
A Command Injection issue was discovered in ContentStore/Base/CVDataPipe.dll in Commvault before v11 SP6. A certain message parsing function inside the Commvault service does not properly validate the input of an incoming string before passing it to CreateProcess. As a result, a specially crafted message can inject commands that will be executed on the target operating system. Exploitation of this vulnerability does not require authentication and can lead to SYSTEM level privilege on any system running the cvd daemon. This is a different vulnerability than CVE-2017-3195.
</code>

- [securifera/CVE-2017-18044-Exploit](https://github.com/securifera/CVE-2017-18044-Exploit)

### CVE-2017-18345

<code>
The Joomanager component through 2.0.0 for Joomla! has an arbitrary file download issue, resulting in exposing the credentials of the database via an index.php?option=com_joomanager&amp;controller=details&amp;task=download&amp;path=configuration.php request.
</code>

- [Luth1er/CVE-2017-18345-COM_JOOMANAGER-ARBITRARY-FILE-DOWNLOAD](https://github.com/Luth1er/CVE-2017-18345-COM_JOOMANAGER-ARBITRARY-FILE-DOWNLOAD)

### CVE-2017-18486

<code>
Jitbit Helpdesk before 9.0.3 allows remote attackers to escalate privileges because of mishandling of the User/AutoLogin userHash parameter. By inspecting the token value provided in a password reset link, a user can leverage a weak PRNG to recover the shared secret used by the server for remote authentication. The shared secret can be used to escalate privileges by forging new tokens for any user. These tokens can be used to automatically log in as the affected user.
</code>

- [Kc57/JitBit_Helpdesk_Auth_Bypass](https://github.com/Kc57/JitBit_Helpdesk_Auth_Bypass)

### CVE-2017-18635

<code>
An XSS vulnerability was discovered in noVNC before 0.6.2 in which the remote VNC server could inject arbitrary HTML into the noVNC web page via the messages propagated to the status field, such as the VNC server name.
</code>

- [ShielderSec/CVE-2017-18635](https://github.com/ShielderSec/CVE-2017-18635)

### CVE-2017-2368

<code>
An issue was discovered in certain Apple products. iOS before 10.2.1 is affected. The issue involves the &quot;Contacts&quot; component. It allows remote attackers to cause a denial of service (application crash) via a crafted contact card.
</code>

- [vincedes3/CVE-2017-2368](https://github.com/vincedes3/CVE-2017-2368)

### CVE-2017-2370

<code>
An issue was discovered in certain Apple products. iOS before 10.2.1 is affected. macOS before 10.12.3 is affected. tvOS before 10.1.1 is affected. watchOS before 3.1.3 is affected. The issue involves the &quot;Kernel&quot; component. It allows attackers to execute arbitrary code in a privileged context or cause a denial of service (buffer overflow) via a crafted app.
</code>

- [maximehip/extra_recipe](https://github.com/maximehip/extra_recipe)
- [JackBro/extra_recipe](https://github.com/JackBro/extra_recipe)
- [Rootkitsmm/extra_recipe-iOS-10.2](https://github.com/Rootkitsmm/extra_recipe-iOS-10.2)
- [Peterpan0927/CVE-2017-2370](https://github.com/Peterpan0927/CVE-2017-2370)

### CVE-2017-2388

<code>
An issue was discovered in certain Apple products. macOS before 10.12.4 is affected. The issue involves the &quot;IOFireWireFamily&quot; component. It allows attackers to cause a denial of service (NULL pointer dereference) via a crafted app.
</code>

- [bazad/IOFireWireFamily-null-deref](https://github.com/bazad/IOFireWireFamily-null-deref)

### CVE-2017-2636

<code>
Race condition in drivers/tty/n_hdlc.c in the Linux kernel through 4.10.1 allows local users to gain privileges or cause a denial of service (double free) by setting the HDLC line discipline.
</code>

- [alexzorin/cve-2017-2636-el](https://github.com/alexzorin/cve-2017-2636-el)

### CVE-2017-2666

<code>
It was discovered in Undertow that the code that parsed the HTTP request line permitted invalid characters. This could be exploited, in conjunction with a proxy that also permitted the invalid characters but with a different interpretation, to inject data into the HTTP response. By manipulating the HTTP response the attacker could poison a web-cache, perform an XSS attack, or obtain sensitive information from requests other than their own.
</code>

- [tafamace/CVE-2017-2666](https://github.com/tafamace/CVE-2017-2666)

### CVE-2017-2671

<code>
The ping_unhash function in net/ipv4/ping.c in the Linux kernel through 4.10.8 is too late in obtaining a certain lock and consequently cannot ensure that disconnect function calls are safe, which allows local users to cause a denial of service (panic) by leveraging access to the protocol value of IPPROTO_ICMP in a socket system call.
</code>

- [homjxi0e/CVE-2017-2671](https://github.com/homjxi0e/CVE-2017-2671)

### CVE-2017-2751

<code>
A BIOS password extraction vulnerability has been reported on certain consumer notebooks with firmware F.22 and others. The BIOS password was stored in CMOS in a way that allowed it to be extracted. This applies to consumer notebooks launched in early 2014.
</code>

- [BaderSZ/CVE-2017-2751](https://github.com/BaderSZ/CVE-2017-2751)

### CVE-2017-2793

<code>
An exploitable heap corruption vulnerability exists in the UnCompressUnicode functionality of Antenna House DMC HTMLFilter used by MarkLogic 8.0-6. A specially crafted xls file can cause a heap corruption resulting in arbitrary code execution. An attacker can send/provide malicious XLS file to trigger this vulnerability.
</code>

- [r0otshell/Detection-for-CVE-2017-2793](https://github.com/r0otshell/Detection-for-CVE-2017-2793)

### CVE-2017-3000

<code>
Adobe Flash Player versions 24.0.0.221 and earlier have a vulnerability in the random number generator used for constant blinding. Successful exploitation could lead to information disclosure.
</code>

- [dangokyo/CVE-2017-3000](https://github.com/dangokyo/CVE-2017-3000)

### CVE-2017-3066

<code>
Adobe ColdFusion 2016 Update 3 and earlier, ColdFusion 11 update 11 and earlier, ColdFusion 10 Update 22 and earlier have a Java deserialization vulnerability in the Apache BlazeDS library. Successful exploitation could lead to arbitrary code execution.
</code>

- [codewhitesec/ColdFusionPwn](https://github.com/codewhitesec/ColdFusionPwn)
- [cucadili/CVE-2017-3066](https://github.com/cucadili/CVE-2017-3066)

### CVE-2017-3078

<code>
Adobe Flash Player versions 25.0.0.171 and earlier have an exploitable memory corruption vulnerability in the Adobe Texture Format (ATF) module. Successful exploitation could lead to arbitrary code execution.
</code>

- [homjxi0e/CVE-2017-3078](https://github.com/homjxi0e/CVE-2017-3078)

### CVE-2017-3143

<code>
An attacker who is able to send and receive messages to an authoritative DNS server and who has knowledge of a valid TSIG key name for the zone and service being targeted may be able to manipulate BIND into accepting an unauthorized dynamic update. Affects BIND 9.4.0-&gt;9.8.8, 9.9.0-&gt;9.9.10-P1, 9.10.0-&gt;9.10.5-P1, 9.11.0-&gt;9.11.1-P1, 9.9.3-S1-&gt;9.9.10-S2, 9.10.5-S1-&gt;9.10.5-S2.
</code>

- [saaph/CVE-2017-3143](https://github.com/saaph/CVE-2017-3143)

### CVE-2017-3241

<code>
Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent: RMI). Supported versions that are affected are Java SE: 6u131, 7u121 and 8u112; Java SE Embedded: 8u111; JRockit: R28.3.12. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Java SE, Java SE Embedded, JRockit. While the vulnerability is in Java SE, Java SE Embedded, JRockit, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in takeover of Java SE, Java SE Embedded, JRockit. Note: This vulnerability can only be exploited by supplying data to APIs in the specified Component without using Untrusted Java Web Start applications or Untrusted Java applets, such as through a web service. CVSS v3.0 Base Score 9.0 (Confidentiality, Integrity and Availability impacts).
</code>

- [xfei3/CVE-2017-3241-POC](https://github.com/xfei3/CVE-2017-3241-POC)

### CVE-2017-3248

<code>
Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.0 and 12.2.1.1. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS v3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).
</code>

- [ianxtianxt/CVE-2017-3248](https://github.com/ianxtianxt/CVE-2017-3248)
- [0xn0ne/weblogicScanner](https://github.com/0xn0ne/weblogicScanner)

### CVE-2017-3506

<code>
Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Web Services). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.0, 12.2.1.1 and 12.2.1.2. Difficult to exploit vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification access to critical data or all Oracle WebLogic Server accessible data as well as unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.0 Base Score 7.4 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N).
</code>

- [ianxtianxt/CVE-2017-3506](https://github.com/ianxtianxt/CVE-2017-3506)

### CVE-2017-3599

<code>
Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server: Pluggable Auth). Supported versions that are affected are 5.6.35 and earlier and 5.7.17 and earlier. Easily &quot;exploitable&quot; vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.0 Base Score 7.5 (Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H). NOTE: the previous information is from the April 2017 CPU. Oracle has not commented on third-party claims that this issue is an integer overflow in sql/auth/sql_authentication.cc which allows remote attackers to cause a denial of service via a crafted authentication packet.
</code>

- [SECFORCE/CVE-2017-3599](https://github.com/SECFORCE/CVE-2017-3599)

### CVE-2017-3730

<code>
In OpenSSL 1.1.0 before 1.1.0d, if a malicious server supplies bad parameters for a DHE or ECDHE key exchange then this can result in the client attempting to dereference a NULL pointer leading to a client crash. This could be exploited in a Denial of Service attack.
</code>

- [guidovranken/CVE-2017-3730](https://github.com/guidovranken/CVE-2017-3730)
- [ymmah/OpenSSL-CVE-2017-3730](https://github.com/ymmah/OpenSSL-CVE-2017-3730)

### CVE-2017-3881

<code>
A vulnerability in the Cisco Cluster Management Protocol (CMP) processing code in Cisco IOS and Cisco IOS XE Software could allow an unauthenticated, remote attacker to cause a reload of an affected device or remotely execute code with elevated privileges. The Cluster Management Protocol utilizes Telnet internally as a signaling and command protocol between cluster members. The vulnerability is due to the combination of two factors: (1) the failure to restrict the use of CMP-specific Telnet options only to internal, local communications between cluster members and instead accept and process such options over any Telnet connection to an affected device; and (2) the incorrect processing of malformed CMP-specific Telnet options. An attacker could exploit this vulnerability by sending malformed CMP-specific Telnet options while establishing a Telnet session with an affected Cisco device configured to accept Telnet connections. An exploit could allow an attacker to execute arbitrary code and obtain full control of the device or cause a reload of the affected device. This affects Catalyst switches, Embedded Service 2020 switches, Enhanced Layer 2 EtherSwitch Service Module, Enhanced Layer 2/3 EtherSwitch Service Module, Gigabit Ethernet Switch Module (CGESM) for HP, IE Industrial Ethernet switches, ME 4924-10GE switch, RF Gateway 10, and SM-X Layer 2/3 EtherSwitch Service Module. Cisco Bug IDs: CSCvd48893.
</code>

- [artkond/cisco-rce](https://github.com/artkond/cisco-rce)
- [homjxi0e/CVE-2017-3881-exploit-cisco-](https://github.com/homjxi0e/CVE-2017-3881-exploit-cisco-)
- [homjxi0e/CVE-2017-3881-Cisco](https://github.com/homjxi0e/CVE-2017-3881-Cisco)
- [zakybstrd21215/PoC-CVE-2017-3881](https://github.com/zakybstrd21215/PoC-CVE-2017-3881)
- [1337g/CVE-2017-3881](https://github.com/1337g/CVE-2017-3881)

### CVE-2017-4490
- [homjxi0e/CVE-2017-4490-](https://github.com/homjxi0e/CVE-2017-4490-)
- [homjxi0e/CVE-2017-4490-install-Script-Python-in-Terminal-](https://github.com/homjxi0e/CVE-2017-4490-install-Script-Python-in-Terminal-)

### CVE-2017-4878
- [brianwrf/CVE-2017-4878-Samples](https://github.com/brianwrf/CVE-2017-4878-Samples)

### CVE-2017-4971

<code>
An issue was discovered in Pivotal Spring Web Flow through 2.4.4. Applications that do not change the value of the MvcViewFactoryCreator useSpringBinding property which is disabled by default (i.e., set to 'false') can be vulnerable to malicious EL expressions in view states that process form submissions but do not have a sub-element to declare explicit data binding property mappings.
</code>

- [cved-sources/cve-2017-4971](https://github.com/cved-sources/cve-2017-4971)

### CVE-2017-5005

<code>
Stack-based buffer overflow in Quick Heal Internet Security 10.1.0.316 and earlier, Total Security 10.1.0.316 and earlier, and AntiVirus Pro 10.1.0.316 and earlier on OS X allows remote attackers to execute arbitrary code via a crafted LC_UNIXTHREAD.cmdsize field in a Mach-O file that is mishandled during a Security Scan (aka Custom Scan) operation.
</code>

- [payatu/QuickHeal](https://github.com/payatu/QuickHeal)

### CVE-2017-5007

<code>
Blink in Google Chrome prior to 56.0.2924.76 for Linux, Windows and Mac, and 56.0.2924.87 for Android, incorrectly handled the sequence of events when closing a page, which allowed a remote attacker to inject arbitrary scripts or HTML (UXSS) via a crafted HTML page.
</code>

- [Ang-YC/CVE-2017-5007](https://github.com/Ang-YC/CVE-2017-5007)

### CVE-2017-5123
- [FloatingGuy/CVE-2017-5123](https://github.com/FloatingGuy/CVE-2017-5123)
- [0x5068656e6f6c/CVE-2017-5123](https://github.com/0x5068656e6f6c/CVE-2017-5123)
- [Synacktiv-contrib/exploiting-cve-2017-5123](https://github.com/Synacktiv-contrib/exploiting-cve-2017-5123)
- [teawater/CVE-2017-5123](https://github.com/teawater/CVE-2017-5123)

### CVE-2017-5124

<code>
Incorrect application of sandboxing in Blink in Google Chrome prior to 62.0.3202.62 allowed a remote attacker to inject arbitrary scripts or HTML (UXSS) via a crafted MHTML page.
</code>

- [Bo0oM/CVE-2017-5124](https://github.com/Bo0oM/CVE-2017-5124)

### CVE-2017-5223

<code>
An issue was discovered in PHPMailer before 5.2.22. PHPMailer's msgHTML method applies transformations to an HTML document to make it usable as an email message body. One of the transformations is to convert relative image URLs into attachments using a script-provided base directory. If no base directory is provided, it resolves to /, meaning that relative image URLs get treated as absolute local file paths and added as attachments. To form a remote vulnerability, the msgHTML method must be called, passed an unfiltered, user-supplied HTML document, and must not set a base directory.
</code>

- [cscli/CVE-2017-5223](https://github.com/cscli/CVE-2017-5223)

### CVE-2017-5415

<code>
An attack can use a blob URL and script to spoof an arbitrary addressbar URL prefaced by &quot;blob:&quot; as the protocol, leading to user confusion and further spoofing attacks. This vulnerability affects Firefox &lt; 52.
</code>

- [649/CVE-2017-5415](https://github.com/649/CVE-2017-5415)

### CVE-2017-5487

<code>
wp-includes/rest-api/endpoints/class-wp-rest-users-controller.php in the REST API implementation in WordPress 4.7 before 4.7.1 does not properly restrict listings of post authors, which allows remote attackers to obtain sensitive information via a wp-json/wp/v2/users request.
</code>

- [teambugsbunny/wpUsersScan](https://github.com/teambugsbunny/wpUsersScan)
- [R3K1NG/wpUsersScan](https://github.com/R3K1NG/wpUsersScan)
- [GeunSam2/CVE-2017-5487](https://github.com/GeunSam2/CVE-2017-5487)
- [patilkr/wp-CVE-2017-5487-exploit](https://github.com/patilkr/wp-CVE-2017-5487-exploit)

### CVE-2017-5633

<code>
Multiple cross-site request forgery (CSRF) vulnerabilities on the D-Link DI-524 Wireless Router with firmware 9.01 allow remote attackers to (1) change the admin password, (2) reboot the device, or (3) possibly have unspecified other impact via crafted requests to CGI programs.
</code>

- [cardangi/Exploit-CVE-2017-5633](https://github.com/cardangi/Exploit-CVE-2017-5633)

### CVE-2017-5638

<code>
The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.
</code>

- [PolarisLab/S2-045](https://github.com/PolarisLab/S2-045)
- [Flyteas/Struts2-045-Exp](https://github.com/Flyteas/Struts2-045-Exp)
- [bongbongco/cve-2017-5638](https://github.com/bongbongco/cve-2017-5638)
- [jas502n/S2-045-EXP-POC-TOOLS](https://github.com/jas502n/S2-045-EXP-POC-TOOLS)
- [mthbernardes/strutszeiro](https://github.com/mthbernardes/strutszeiro)
- [xsscx/cve-2017-5638](https://github.com/xsscx/cve-2017-5638)
- [immunio/apache-struts2-CVE-2017-5638](https://github.com/immunio/apache-struts2-CVE-2017-5638)
- [Masahiro-Yamada/OgnlContentTypeRejectorValve](https://github.com/Masahiro-Yamada/OgnlContentTypeRejectorValve)
- [aljazceru/CVE-2017-5638-Apache-Struts2](https://github.com/aljazceru/CVE-2017-5638-Apache-Struts2)
- [sjitech/test_struts2_vulnerability_CVE-2017-5638](https://github.com/sjitech/test_struts2_vulnerability_CVE-2017-5638)
- [jrrombaldo/CVE-2017-5638](https://github.com/jrrombaldo/CVE-2017-5638)
- [random-robbie/CVE-2017-5638](https://github.com/random-robbie/CVE-2017-5638)
- [initconf/CVE-2017-5638_struts](https://github.com/initconf/CVE-2017-5638_struts)
- [mazen160/struts-pwn](https://github.com/mazen160/struts-pwn)
- [ret2jazzy/Struts-Apache-ExploitPack](https://github.com/ret2jazzy/Struts-Apache-ExploitPack)
- [lolwaleet/ExpStruts](https://github.com/lolwaleet/ExpStruts)
- [oktavianto/CVE-2017-5638-Apache-Struts2](https://github.com/oktavianto/CVE-2017-5638-Apache-Struts2)
- [jrrdev/cve-2017-5638](https://github.com/jrrdev/cve-2017-5638)
- [opt9/Strutshock](https://github.com/opt9/Strutshock)
- [falcon-lnhg/StrutsShell](https://github.com/falcon-lnhg/StrutsShell)
- [bhagdave/CVE-2017-5638](https://github.com/bhagdave/CVE-2017-5638)
- [jas502n/st2-046-poc](https://github.com/jas502n/st2-046-poc)
- [KarzsGHR/S2-046_S2-045_POC](https://github.com/KarzsGHR/S2-046_S2-045_POC)
- [gsfish/S2-Reaper](https://github.com/gsfish/S2-Reaper)
- [mcassano/cve-2017-5638](https://github.com/mcassano/cve-2017-5638)
- [opt9/Strutscli](https://github.com/opt9/Strutscli)
- [tahmed11/strutsy](https://github.com/tahmed11/strutsy)
- [payatu/CVE-2017-5638](https://github.com/payatu/CVE-2017-5638)
- [Aasron/Struts2-045-Exp](https://github.com/Aasron/Struts2-045-Exp)
- [SpiderMate/Stutsfi](https://github.com/SpiderMate/Stutsfi)
- [jpacora/Struts2Shell](https://github.com/jpacora/Struts2Shell)
- [NyaMeeEain/Apache-Struts](https://github.com/NyaMeeEain/Apache-Struts)
- [AndreasKl/CVE-2017-5638](https://github.com/AndreasKl/CVE-2017-5638)
- [riyazwalikar/struts-rce-cve-2017-5638](https://github.com/riyazwalikar/struts-rce-cve-2017-5638)
- [homjxi0e/CVE-2017-5638](https://github.com/homjxi0e/CVE-2017-5638)
- [eeehit/CVE-2017-5638](https://github.com/eeehit/CVE-2017-5638)
- [r0otshell/Apache-Struts-CVE-2017-5638-RCE-Mass-Scanner](https://github.com/r0otshell/Apache-Struts-CVE-2017-5638-RCE-Mass-Scanner)
- [r0otshell/Apache-Struts2-RCE-Exploit-v2-CVE-2017-5638](https://github.com/r0otshell/Apache-Struts2-RCE-Exploit-v2-CVE-2017-5638)
- [R4v3nBl4ck/Apache-Struts-2-CVE-2017-5638-Exploit-](https://github.com/R4v3nBl4ck/Apache-Struts-2-CVE-2017-5638-Exploit-)
- [Xhendos/CVE-2017-5638](https://github.com/Xhendos/CVE-2017-5638)
- [TamiiLambrado/Apache-Struts-CVE-2017-5638-RCE-Mass-Scanner](https://github.com/TamiiLambrado/Apache-Struts-CVE-2017-5638-RCE-Mass-Scanner)
- [RealBearcat/S2-045](https://github.com/RealBearcat/S2-045)
- [invisiblethreat/strutser](https://github.com/invisiblethreat/strutser)
- [lizhi16/CVE-2017-5638](https://github.com/lizhi16/CVE-2017-5638)
- [donaldashdown/Common-Vulnerability-and-Exploit](https://github.com/donaldashdown/Common-Vulnerability-and-Exploit)
- [grant100/cybersecurity-struts2](https://github.com/grant100/cybersecurity-struts2)
- [cafnet/apache-struts-v2-CVE-2017-5638](https://github.com/cafnet/apache-struts-v2-CVE-2017-5638)
- [0x00-0x00/CVE-2017-5638](https://github.com/0x00-0x00/CVE-2017-5638)
- [m3ssap0/struts2_cve-2017-5638](https://github.com/m3ssap0/struts2_cve-2017-5638)
- [Greynad/struts2-jakarta-inject](https://github.com/Greynad/struts2-jakarta-inject)
- [ggolawski/struts-rce](https://github.com/ggolawski/struts-rce)
- [win3zz/CVE-2017-5638](https://github.com/win3zz/CVE-2017-5638)
- [leandrocamposcardoso/CVE-2017-5638-Mass-Exploit](https://github.com/leandrocamposcardoso/CVE-2017-5638-Mass-Exploit)
- [Iletee/struts2-rce](https://github.com/Iletee/struts2-rce)
- [andypitcher/check_struts](https://github.com/andypitcher/check_struts)
- [un4ckn0wl3z/CVE-2017-5638](https://github.com/un4ckn0wl3z/CVE-2017-5638)
- [colorblindpentester/CVE-2017-5638](https://github.com/colorblindpentester/CVE-2017-5638)
- [injcristianrojas/cve-2017-5638](https://github.com/injcristianrojas/cve-2017-5638)
- [pasannirmana/Aspire](https://github.com/pasannirmana/Aspire)

### CVE-2017-5645

<code>
In Apache Log4j 2.x before 2.8.2, when using the TCP socket server or UDP socket server to receive serialized log events from another application, a specially crafted binary payload can be sent that, when deserialized, can execute arbitrary code.
</code>

- [pimps/CVE-2017-5645](https://github.com/pimps/CVE-2017-5645)

### CVE-2017-5689

<code>
An unprivileged network attacker could gain system privileges to provisioned Intel manageability SKUs: Intel Active Management Technology (AMT) and Intel Standard Manageability (ISM). An unprivileged local attacker could provision manageability features gaining unprivileged network or local system privileges on Intel manageability SKUs: Intel Active Management Technology (AMT), Intel Standard Manageability (ISM), and Intel Small Business Technology (SBT).
</code>

- [CerberusSecurity/CVE-2017-5689](https://github.com/CerberusSecurity/CVE-2017-5689)
- [x1sec/amthoneypot](https://github.com/x1sec/amthoneypot)
- [Bijaye/intel_amt_bypass](https://github.com/Bijaye/intel_amt_bypass)
- [embedi/amt_auth_bypass_poc](https://github.com/embedi/amt_auth_bypass_poc)

### CVE-2017-5693

<code>
Firmware in the Intel Puma 5, 6, and 7 Series might experience resource depletion or timeout, which allows a network attacker to create a denial of service via crafted network traffic.
</code>

- [nallar/Puma6Fail](https://github.com/nallar/Puma6Fail)

### CVE-2017-5715

<code>
Systems with microprocessors utilizing speculative execution and indirect branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis.
</code>

- [opsxcq/exploit-cve-2017-5715](https://github.com/opsxcq/exploit-cve-2017-5715)
- [mathse/meltdown-spectre-bios-list](https://github.com/mathse/meltdown-spectre-bios-list)
- [GregAskew/SpeculativeExecutionAssessment](https://github.com/GregAskew/SpeculativeExecutionAssessment)
- [dmo2118/retpoline-audit](https://github.com/dmo2118/retpoline-audit)

### CVE-2017-5721

<code>
Insufficient input validation in system firmware for Intel NUC7i3BNK, NUC7i3BNH, NUC7i5BNK, NUC7i5BNH, NUC7i7BNH versions BN0049 and below allows local attackers to execute arbitrary code via manipulation of memory.
</code>

- [embedi/smm_usbrt_poc](https://github.com/embedi/smm_usbrt_poc)

### CVE-2017-5753

<code>
Systems with microprocessors utilizing speculative execution and branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis.
</code>

- [Eugnis/spectre-attack](https://github.com/Eugnis/spectre-attack)
- [EdwardOwusuAdjei/Spectre-PoC](https://github.com/EdwardOwusuAdjei/Spectre-PoC)
- [poilynx/spectre-attack-example](https://github.com/poilynx/spectre-attack-example)
- [xsscx/cve-2017-5753](https://github.com/xsscx/cve-2017-5753)
- [pedrolucasoliva/spectre-attack-demo](https://github.com/pedrolucasoliva/spectre-attack-demo)
- [ixtal23/spectreScope](https://github.com/ixtal23/spectreScope)
- [sachinthaBS/Spectre-Vulnerability-CVE-2017-5753-](https://github.com/sachinthaBS/Spectre-Vulnerability-CVE-2017-5753-)

### CVE-2017-5754

<code>
Systems with microprocessors utilizing speculative execution and indirect branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis of the data cache.
</code>

- [ionescu007/SpecuCheck](https://github.com/ionescu007/SpecuCheck)
- [raphaelsc/Am-I-affected-by-Meltdown](https://github.com/raphaelsc/Am-I-affected-by-Meltdown)
- [Viralmaniar/In-Spectre-Meltdown](https://github.com/Viralmaniar/In-Spectre-Meltdown)
- [speecyy/Am-I-affected-by-Meltdown](https://github.com/speecyy/Am-I-affected-by-Meltdown)
- [zzado/Meltdown](https://github.com/zzado/Meltdown)
- [jdmulloy/meltdown-aws-scanner](https://github.com/jdmulloy/meltdown-aws-scanner)

### CVE-2017-5792

<code>
A Remote Code Execution vulnerability in HPE Intelligent Management Center (iMC) PLAT version 7.3 E0504P2 was found.
</code>

- [RealBearcat/HPE-iMC-7.3-RMI-Java-Deserialization](https://github.com/RealBearcat/HPE-iMC-7.3-RMI-Java-Deserialization)

### CVE-2017-5941

<code>
An issue was discovered in the node-serialize package 0.0.4 for Node.js. Untrusted data passed into the unserialize() function can be exploited to achieve arbitrary code execution by passing a JavaScript Object with an Immediately Invoked Function Expression (IIFE).
</code>

- [p1gz/CVE-2017-5941-NodeJS-RCE](https://github.com/p1gz/CVE-2017-5941-NodeJS-RCE)

### CVE-2017-6008

<code>
A kernel pool overflow in the driver hitmanpro37.sys in Sophos SurfRight HitmanPro before 3.7.20 Build 286 (included in the HitmanPro.Alert solution and Sophos Clean) allows local users to escalate privileges via a malformed IOCTL call.
</code>

- [cbayet/Exploit-CVE-2017-6008](https://github.com/cbayet/Exploit-CVE-2017-6008)

### CVE-2017-6074

<code>
The dccp_rcv_state_process function in net/dccp/input.c in the Linux kernel through 4.9.11 mishandles DCCP_PKT_REQUEST packet data structures in the LISTEN state, which allows local users to obtain root privileges or cause a denial of service (double free) via an application that makes an IPV6_RECVPKTINFO setsockopt system call.
</code>

- [node1392/Linux-Kernel-Vulnerability](https://github.com/node1392/Linux-Kernel-Vulnerability)
- [BimsaraMalinda/Linux-Kernel-4.4.0-Ubuntu---DCCP-Double-Free-Privilege-Escalation-CVE-2017-6074](https://github.com/BimsaraMalinda/Linux-Kernel-4.4.0-Ubuntu---DCCP-Double-Free-Privilege-Escalation-CVE-2017-6074)

### CVE-2017-6079

<code>
The HTTP web-management application on Edgewater Networks Edgemarc appliances has a hidden page that allows for user-defined commands such as specific iptables routes, etc., to be set. You can use this page as a web shell essentially to execute commands, though you get no feedback client-side from the web application: if the command is valid, it executes. An example is the wget command. The page that allows this has been confirmed in firmware as old as 2006.
</code>

- [MostafaSoliman/CVE-2017-6079-Blind-Command-Injection-In-Edgewater-Edgemarc-Devices-Exploit](https://github.com/MostafaSoliman/CVE-2017-6079-Blind-Command-Injection-In-Edgewater-Edgemarc-Devices-Exploit)

### CVE-2017-6090

<code>
Unrestricted file upload vulnerability in clients/editclient.php in PhpCollab 2.5.1 and earlier allows remote authenticated users to execute arbitrary code by uploading a file with an executable extension, then accessing it via a direct request to the file in logos_clients/.
</code>

- [jlk/exploit-CVE-2017-6090](https://github.com/jlk/exploit-CVE-2017-6090)

### CVE-2017-6206

<code>
D-Link DGS-1510-28XMP, DGS-1510-28X, DGS-1510-52X, DGS-1510-52, DGS-1510-28P, DGS-1510-28, and DGS-1510-20 Websmart devices with firmware before 1.31.B003 allow attackers to conduct Unauthenticated Information Disclosure attacks via unspecified vectors.
</code>

- [varangamin/CVE-2017-6206](https://github.com/varangamin/CVE-2017-6206)

### CVE-2017-6370

<code>
TYPO3 7.6.15 sends an http request to an index.php?loginProvider URI in cases with an https Referer, which allows remote attackers to obtain sensitive cleartext information by sniffing the network and reading the userident and username fields.
</code>

- [faizzaidi/TYPO3-v7.6.15-Unencrypted-Login-Request](https://github.com/faizzaidi/TYPO3-v7.6.15-Unencrypted-Login-Request)

### CVE-2017-6558

<code>
iball Baton 150M iB-WRA150N v1 00000001 1.2.6 build 110401 Rel.47776n devices are prone to an authentication bypass vulnerability that allows remote attackers to view and modify administrative router settings by reading the HTML source code of the password.cgi file.
</code>

- [GemGeorge/iBall-UTStar-CVEChecker](https://github.com/GemGeorge/iBall-UTStar-CVEChecker)

### CVE-2017-6640

<code>
A vulnerability in Cisco Prime Data Center Network Manager (DCNM) Software could allow an unauthenticated, remote attacker to log in to the administrative console of a DCNM server by using an account that has a default, static password. The account could be granted root- or system-level privileges. The vulnerability exists because the affected software has a default user account that has a default, static password. The user account is created automatically when the software is installed. An attacker could exploit this vulnerability by connecting remotely to an affected system and logging in to the affected software by using the credentials for this default user account. A successful exploit could allow the attacker to use this default user account to log in to the affected software and gain access to the administrative console of a DCNM server. This vulnerability affects Cisco Prime Data Center Network Manager (DCNM) Software releases prior to Release 10.2(1) for Microsoft Windows, Linux, and Virtual Appliance platforms. Cisco Bug IDs: CSCvd95346.
</code>

- [hemp3l/CVE-2017-6640-POC](https://github.com/hemp3l/CVE-2017-6640-POC)

### CVE-2017-6736

<code>
The Simple Network Management Protocol (SNMP) subsystem of Cisco IOS 12.0 through 12.4 and 15.0 through 15.6 and IOS XE 2.2 through 3.17 contains multiple vulnerabilities that could allow an authenticated, remote attacker to remotely execute code on an affected system or cause an affected system to reload. An attacker could exploit these vulnerabilities by sending a crafted SNMP packet to an affected system via IPv4 or IPv6. Only traffic directed to an affected system can be used to exploit these vulnerabilities. The vulnerabilities are due to a buffer overflow condition in the SNMP subsystem of the affected software. The vulnerabilities affect all versions of SNMP: Versions 1, 2c, and 3. To exploit these vulnerabilities via SNMP Version 2c or earlier, the attacker must know the SNMP read-only community string for the affected system. To exploit these vulnerabilities via SNMP Version 3, the attacker must have user credentials for the affected system. All devices that have enabled SNMP and have not explicitly excluded the affected MIBs or OIDs should be considered vulnerable. Cisco Bug IDs: CSCve57697.
</code>

- [GarnetSunset/CiscoSpectreTakeover](https://github.com/GarnetSunset/CiscoSpectreTakeover)
- [GarnetSunset/CiscoIOSSNMPToolkit](https://github.com/GarnetSunset/CiscoIOSSNMPToolkit)

### CVE-2017-6913

<code>
Cross-site scripting (XSS) vulnerability in the Open-Xchange webmail before 7.6.3-rev28 allows remote attackers to inject arbitrary web script or HTML via the event attribute in a time tag.
</code>

- [gquere/CVE-2017-6913](https://github.com/gquere/CVE-2017-6913)

### CVE-2017-6971

<code>
AlienVault USM and OSSIM before 5.3.7 and NfSen before 1.3.8 allow remote authenticated users to execute arbitrary commands in a privileged context, or launch a reverse shell, via vectors involving the PHP session ID and the NfSen PHP code, aka AlienVault ID ENG-104862.
</code>

- [patrickfreed/nfsen-exploit](https://github.com/patrickfreed/nfsen-exploit)
- [KeyStrOke95/nfsen_1.3.7_CVE-2017-6971](https://github.com/KeyStrOke95/nfsen_1.3.7_CVE-2017-6971)

### CVE-2017-7038

<code>
A DOMParser XSS issue was discovered in certain Apple products. iOS before 10.3.3 is affected. Safari before 10.1.2 is affected. tvOS before 10.2.2 is affected. The issue involves the &quot;WebKit&quot; component.
</code>

- [ansjdnakjdnajkd/CVE-2017-7038](https://github.com/ansjdnakjdnajkd/CVE-2017-7038)

### CVE-2017-7047

<code>
An issue was discovered in certain Apple products. iOS before 10.3.3 is affected. macOS before 10.12.6 is affected. tvOS before 10.2.2 is affected. watchOS before 3.2.3 is affected. The issue involves the &quot;libxpc&quot; component. It allows attackers to execute arbitrary code in a privileged context or cause a denial of service (memory corruption) via a crafted app.
</code>

- [JosephShenton/Triple_Fetch-Kernel-Creds](https://github.com/JosephShenton/Triple_Fetch-Kernel-Creds)
- [q1f3/Triple_fetch](https://github.com/q1f3/Triple_fetch)

### CVE-2017-7061

<code>
An issue was discovered in certain Apple products. iOS before 10.3.3 is affected. Safari before 10.1.2 is affected. iCloud before 6.2.2 on Windows is affected. iTunes before 12.6.2 on Windows is affected. tvOS before 10.2.2 is affected. The issue involves the &quot;WebKit&quot; component. It allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption and application crash) via a crafted web site.
</code>

- [TheLoneHaxor/jailbreakme103](https://github.com/TheLoneHaxor/jailbreakme103)

### CVE-2017-7089

<code>
An issue was discovered in certain Apple products. iOS before 11 is affected. Safari before 11 is affected. iCloud before 7.0 on Windows is affected. The issue involves the &quot;WebKit&quot; component. It allows remote attackers to conduct Universal XSS (UXSS) attacks via a crafted web site that is mishandled during parent-tab processing.
</code>

- [Bo0oM/CVE-2017-7089](https://github.com/Bo0oM/CVE-2017-7089)
- [aymankhalfatni/Safari_Mac](https://github.com/aymankhalfatni/Safari_Mac)

### CVE-2017-7092

<code>
An issue was discovered in certain Apple products. iOS before 11 is affected. Safari before 11 is affected. iCloud before 7.0 on Windows is affected. iTunes before 12.7 on Windows is affected. tvOS before 11 is affected. The issue involves the &quot;WebKit&quot; component. It allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption and application crash) via a crafted web site.
</code>

- [xuechiyaobai/CVE-2017-7092-PoC](https://github.com/xuechiyaobai/CVE-2017-7092-PoC)

### CVE-2017-7173

<code>
An issue was discovered in certain Apple products. macOS before 10.13.2 is affected. The issue involves the &quot;Kernel&quot; component. It allows attackers to bypass intended memory-read restrictions via a crafted app.
</code>

- [bazad/sysctl_coalition_get_pid_list-dos](https://github.com/bazad/sysctl_coalition_get_pid_list-dos)

### CVE-2017-7184

<code>
The xfrm_replay_verify_len function in net/xfrm/xfrm_user.c in the Linux kernel through 4.10.6 does not validate certain size data after an XFRM_MSG_NEWAE update, which allows local users to obtain root privileges or cause a denial of service (heap-based out-of-bounds access) by leveraging the CAP_NET_ADMIN capability, as demonstrated during a Pwn2Own competition at CanSecWest 2017 for the Ubuntu 16.10 linux-image-* package 4.8.0.41.52.
</code>

- [rockl/cve-2017-7184](https://github.com/rockl/cve-2017-7184)
- [rockl/cve-2017-7184-bak](https://github.com/rockl/cve-2017-7184-bak)

### CVE-2017-7188

<code>
Zurmo 3.1.1 Stable allows a Cross-Site Scripting (XSS) attack with a base64-encoded SCRIPT element within a data: URL in the returnUrl parameter to default/toggleCollapse.
</code>

- [faizzaidi/Zurmo-Stable-3.1.1-XSS-By-Provensec-LLC](https://github.com/faizzaidi/Zurmo-Stable-3.1.1-XSS-By-Provensec-LLC)

### CVE-2017-7269

<code>
Buffer overflow in the ScStoragePathFromUrl function in the WebDAV service in Internet Information Services (IIS) 6.0 in Microsoft Windows Server 2003 R2 allows remote attackers to execute arbitrary code via a long header beginning with &quot;If: &lt;http://&quot; in a PROPFIND request, as exploited in the wild in July or August 2016.
</code>

- [eliuha/webdav_exploit](https://github.com/eliuha/webdav_exploit)
- [lcatro/CVE-2017-7269-Echo-PoC](https://github.com/lcatro/CVE-2017-7269-Echo-PoC)
- [caicai1355/CVE-2017-7269-exploit](https://github.com/caicai1355/CVE-2017-7269-exploit)
- [M1a0rz/CVE-2017-7269](https://github.com/M1a0rz/CVE-2017-7269)
- [whiteHat001/cve-2017-7269picture](https://github.com/whiteHat001/cve-2017-7269picture)
- [zcgonvh/cve-2017-7269](https://github.com/zcgonvh/cve-2017-7269)
- [jrrombaldo/CVE-2017-7269](https://github.com/jrrombaldo/CVE-2017-7269)
- [g0rx/iis6-exploit-2017-CVE-2017-7269](https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269)
- [slimpagey/IIS_6.0_WebDAV_Ruby](https://github.com/slimpagey/IIS_6.0_WebDAV_Ruby)
- [homjxi0e/cve-2017-7269](https://github.com/homjxi0e/cve-2017-7269)
- [xiaovpn/CVE-2017-7269](https://github.com/xiaovpn/CVE-2017-7269)
- [zcgonvh/cve-2017-7269-tool](https://github.com/zcgonvh/cve-2017-7269-tool)
- [mirrorblack/CVE-2017-7269](https://github.com/mirrorblack/CVE-2017-7269)
- [Al1ex/CVE-2017-7269](https://github.com/Al1ex/CVE-2017-7269)

### CVE-2017-7374

<code>
Use-after-free vulnerability in fs/crypto/ in the Linux kernel before 4.10.7 allows local users to cause a denial of service (NULL pointer dereference) or possibly gain privileges by revoking keyring keys being used for ext4, f2fs, or ubifs encryption, causing cryptographic transform objects to be freed prematurely.
</code>

- [ww9210/cve-2017-7374](https://github.com/ww9210/cve-2017-7374)

### CVE-2017-7472

<code>
The KEYS subsystem in the Linux kernel before 4.10.13 allows local users to cause a denial of service (memory consumption) via a series of KEY_REQKEY_DEFL_THREAD_KEYRING keyctl_set_reqkey_keyring calls.
</code>

- [homjxi0e/CVE-2017-7472](https://github.com/homjxi0e/CVE-2017-7472)

### CVE-2017-7494

<code>
Samba since version 3.5.0 and before 4.6.4, 4.5.10 and 4.4.14 is vulnerable to remote code execution vulnerability, allowing a malicious client to upload a shared library to a writable share, and then cause the server to load and execute it.
</code>

- [betab0t/cve-2017-7494](https://github.com/betab0t/cve-2017-7494)
- [homjxi0e/CVE-2017-7494](https://github.com/homjxi0e/CVE-2017-7494)
- [opsxcq/exploit-CVE-2017-7494](https://github.com/opsxcq/exploit-CVE-2017-7494)
- [Waffles-2/SambaCry](https://github.com/Waffles-2/SambaCry)
- [brianwrf/SambaHunter](https://github.com/brianwrf/SambaHunter)
- [joxeankoret/CVE-2017-7494](https://github.com/joxeankoret/CVE-2017-7494)
- [Zer0d0y/Samba-CVE-2017-7494](https://github.com/Zer0d0y/Samba-CVE-2017-7494)
- [incredible1yu/CVE-2017-7494](https://github.com/incredible1yu/CVE-2017-7494)
- [cved-sources/cve-2017-7494](https://github.com/cved-sources/cve-2017-7494)
- [john-80/cve-2017-7494](https://github.com/john-80/cve-2017-7494)
- [Optimus-hash/CVE-2017-7494_IT19115344](https://github.com/Optimus-hash/CVE-2017-7494_IT19115344)

### CVE-2017-7525

<code>
A deserialization flaw was discovered in the jackson-databind, versions before 2.6.7.1, 2.7.9.1 and 2.8.9, which could allow an unauthenticated user to perform code execution by sending the maliciously crafted input to the readValue method of the ObjectMapper.
</code>

- [SecureSkyTechnology/study-struts2-s2-054_055-jackson-cve-2017-7525_cve-2017-15095](https://github.com/SecureSkyTechnology/study-struts2-s2-054_055-jackson-cve-2017-7525_cve-2017-15095)
- [RealBearcat/S2-055](https://github.com/RealBearcat/S2-055)
- [JavanXD/Demo-Exploit-Jackson-RCE](https://github.com/JavanXD/Demo-Exploit-Jackson-RCE)
- [47bwy/CVE-2017-7525](https://github.com/47bwy/CVE-2017-7525)
- [BassinD/jackson-RCE](https://github.com/BassinD/jackson-RCE)
- [Dannners/jackson-deserialization-2017-7525](https://github.com/Dannners/jackson-deserialization-2017-7525)
- [Ingenuity-Fainting-Goats/CVE-2017-7525-Jackson-Deserialization-Lab](https://github.com/Ingenuity-Fainting-Goats/CVE-2017-7525-Jackson-Deserialization-Lab)

### CVE-2017-7529

<code>
Nginx versions since 0.5.6 up to and including 1.13.2 are vulnerable to integer overflow vulnerability in nginx range filter module resulting into leak of potentially sensitive information triggered by specially crafted request.
</code>

- [liusec/CVE-2017-7529](https://github.com/liusec/CVE-2017-7529)
- [en0f/CVE-2017-7529_PoC](https://github.com/en0f/CVE-2017-7529_PoC)
- [cved-sources/cve-2017-7529](https://github.com/cved-sources/cve-2017-7529)
- [mpalonso/ferni](https://github.com/mpalonso/ferni)
- [MaxSecurity/CVE-2017-7529-POC](https://github.com/MaxSecurity/CVE-2017-7529-POC)

### CVE-2017-7648

<code>
Foscam networked devices use the same hardcoded SSL private key across different customers' installations, which allows remote attackers to defeat cryptographic protection mechanisms by leveraging knowledge of this key from another installation.
</code>

- [notmot/CVE-2017-7648.](https://github.com/notmot/CVE-2017-7648.)

### CVE-2017-7679

<code>
In Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26, mod_mime can read one byte past the end of a buffer when sending a malicious Content-Type response header.
</code>

- [snknritr/CVE-2017-7679-in-python](https://github.com/snknritr/CVE-2017-7679-in-python)

### CVE-2017-7912

<code>
Hanwha Techwin SRN-4000, SRN-4000 firmware versions prior to SRN4000_v2.16_170401, A specially crafted http request and response could allow an attacker to gain access to the device management page with admin privileges without proper authentication.
</code>

- [homjxi0e/CVE-2017-7912_Sneak](https://github.com/homjxi0e/CVE-2017-7912_Sneak)

### CVE-2017-7921

<code>
An Improper Authentication issue was discovered in Hikvision DS-2CD2xx2F-I Series V5.2.0 build 140721 to V5.4.0 build 160530, DS-2CD2xx0F-I Series V5.2.0 build 140721 to V5.4.0 Build 160401, DS-2CD2xx2FWD Series V5.3.1 build 150410 to V5.4.4 Build 161125, DS-2CD4x2xFWD Series V5.2.0 build 140721 to V5.4.0 Build 160414, DS-2CD4xx5 Series V5.2.0 build 140721 to V5.4.0 Build 160421, DS-2DFx Series V5.2.0 build 140805 to V5.4.5 Build 160928, and DS-2CD63xx Series V5.0.9 build 140305 to V5.3.5 Build 160106 devices. The improper authentication vulnerability occurs when an application does not adequately or correctly authenticate users. This may allow a malicious user to escalate his or her privileges on the system and gain access to sensitive information.
</code>

- [JrDw0/CVE-2017-7921-EXP](https://github.com/JrDw0/CVE-2017-7921-EXP)

### CVE-2017-7998

<code>
Multiple cross-site scripting (XSS) vulnerabilities in Gespage before 7.4.9 allow remote attackers to inject arbitrary web script or HTML via the (1) printer name when adding a printer in the admin panel or (2) username parameter to webapp/users/user_reg.jsp.
</code>

- [homjxi0e/CVE-2017-7998](https://github.com/homjxi0e/CVE-2017-7998)

### CVE-2017-8046

<code>
Malicious PATCH requests submitted to servers using Spring Data REST versions prior to 2.6.9 (Ingalls SR9), versions prior to 3.0.1 (Kay SR1) and Spring Boot versions prior to 1.5.9, 2.0 M6 can use specially crafted JSON data to run arbitrary Java code.
</code>

- [Soontao/CVE-2017-8046-DEMO](https://github.com/Soontao/CVE-2017-8046-DEMO)
- [sj/spring-data-rest-CVE-2017-8046](https://github.com/sj/spring-data-rest-CVE-2017-8046)
- [m3ssap0/SpringBreakVulnerableApp](https://github.com/m3ssap0/SpringBreakVulnerableApp)
- [m3ssap0/spring-break_cve-2017-8046](https://github.com/m3ssap0/spring-break_cve-2017-8046)
- [FixYourFace/SpringBreakPoC](https://github.com/FixYourFace/SpringBreakPoC)
- [jkutner/spring-break-cve-2017-8046](https://github.com/jkutner/spring-break-cve-2017-8046)
- [bkhablenko/CVE-2017-8046](https://github.com/bkhablenko/CVE-2017-8046)
- [cved-sources/cve-2017-8046](https://github.com/cved-sources/cve-2017-8046)
- [jsotiro/VulnerableSpringDataRest](https://github.com/jsotiro/VulnerableSpringDataRest)

### CVE-2017-8295

<code>
WordPress through 4.7.4 relies on the Host HTTP header for a password-reset e-mail message, which makes it easier for remote attackers to reset arbitrary passwords by making a crafted wp-login.php?action=lostpassword request and then arranging for this message to bounce or be resent, leading to transmission of the reset key to a mailbox on an attacker-controlled SMTP server. This is related to problematic use of the SERVER_NAME variable in wp-includes/pluggable.php in conjunction with the PHP mail function. Exploitation is not achievable in all cases because it requires at least one of the following: (1) the attacker can prevent the victim from receiving any e-mail messages for an extended period of time (such as 5 days), (2) the victim's e-mail system sends an autoresponse containing the original message, or (3) the victim manually composes a reply containing the original message.
</code>

- [homjxi0e/CVE-2017-8295-WordPress-4.7.4---Unauthorized-Password-Reset](https://github.com/homjxi0e/CVE-2017-8295-WordPress-4.7.4---Unauthorized-Password-Reset)
- [alash3al/wp-allowed-hosts](https://github.com/alash3al/wp-allowed-hosts)
- [cyberheartmi9/CVE-2017-8295](https://github.com/cyberheartmi9/CVE-2017-8295)

### CVE-2017-8382

<code>
admidio 3.2.8 has CSRF in adm_program/modules/members/members_function.php with an impact of deleting arbitrary user accounts.
</code>

- [faizzaidi/Admidio-3.2.8-CSRF-POC-by-Provensec-llc](https://github.com/faizzaidi/Admidio-3.2.8-CSRF-POC-by-Provensec-llc)

### CVE-2017-8464

<code>
Windows Shell in Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, 1703, and Windows Server 2016 allows local users or remote attackers to execute arbitrary code via a crafted .LNK file, which is not properly handled during icon display in Windows Explorer or any other application that parses the icon of the shortcut. aka &quot;LNK Remote Code Execution Vulnerability.&quot;
</code>

- [Elm0D/CVE-2017-8464](https://github.com/Elm0D/CVE-2017-8464)
- [3gstudent/CVE-2017-8464-EXP](https://github.com/3gstudent/CVE-2017-8464-EXP)
- [Securitykid/CVE-2017-8464-exp-generator](https://github.com/Securitykid/CVE-2017-8464-exp-generator)
- [X-Vector/usbhijacking](https://github.com/X-Vector/usbhijacking)
- [xssfile/CVE-2017-8464-EXP](https://github.com/xssfile/CVE-2017-8464-EXP)

### CVE-2017-8465

<code>
Microsoft Windows 8.1 and Windows RT 8.1, Windows Server 2012 R2, Windows 10 Gold, 1511, 1607, and 1703, and Windows Server 2016 allow an attacker to run processes in an elevated context when the Windows kernel improperly handles objects in memory, aka &quot;Win32k Elevation of Privilege Vulnerability.&quot; This CVE ID is unique from CVE-2017-8468.
</code>

- [nghiadt1098/CVE-2017-8465](https://github.com/nghiadt1098/CVE-2017-8465)

### CVE-2017-8529

<code>
Internet Explorer in Microsoft Windows 7 SP1, Windows Server 2008 R2 SP1, Windows 8.1 and Windows RT 8.1, and Windows Server 2012 and R2 allow an attacker to detect specific files on the user's computer when affected Microsoft scripting engines do not properly handle objects in memory, aka &quot;Microsoft Browser Information Disclosure Vulnerability&quot;.
</code>

- [Lynggaard91/windows2016fixCVE-2017-8529](https://github.com/Lynggaard91/windows2016fixCVE-2017-8529)
- [sfitpro/cve-2017-8529](https://github.com/sfitpro/cve-2017-8529)

### CVE-2017-8543

<code>
Microsoft Windows XP SP3, Windows XP x64 XP2, Windows Server 2003 SP2, Windows Vista, Windows 7 SP1, Windows Server 2008 SP2 and R2 SP1, Windows 8, Windows 8.1 and Windows RT 8.1, Windows Server 2012 and R2, Windows 10 Gold, 1511, 1607, and 1703, and Windows Server 2016 allow an attacker to take control of the affected system when Windows Search fails to handle objects in memory, aka &quot;Windows Search Remote Code Execution Vulnerability&quot;.
</code>

- [americanhanko/windows-security-cve-2017-8543](https://github.com/americanhanko/windows-security-cve-2017-8543)

### CVE-2017-8570

<code>
Microsoft Office allows a remote code execution vulnerability due to the way that it handles objects in memory, aka &quot;Microsoft Office Remote Code Execution Vulnerability&quot;. This CVE ID is unique from CVE-2017-0243.
</code>

- [temesgeny/ppsx-file-generator](https://github.com/temesgeny/ppsx-file-generator)
- [rxwx/CVE-2017-8570](https://github.com/rxwx/CVE-2017-8570)
- [MaxSecurity/Office-CVE-2017-8570](https://github.com/MaxSecurity/Office-CVE-2017-8570)
- [SwordSheath/CVE-2017-8570](https://github.com/SwordSheath/CVE-2017-8570)
- [Drac0nids/CVE-2017-8570](https://github.com/Drac0nids/CVE-2017-8570)
- [930201676/CVE-2017-8570](https://github.com/930201676/CVE-2017-8570)

### CVE-2017-8625

<code>
Internet Explorer in Windows 10 Gold, 1511, 1607, 1703, and Windows Server 2016 allows an attacker to bypass Device Guard User Mode Code Integrity (UMCI) policies due to Internet Explorer failing to validate UMCI policies, aka &quot;Internet Explorer Security Feature Bypass Vulnerability&quot;.
</code>

- [homjxi0e/CVE-2017-8625_Bypass_UMCI](https://github.com/homjxi0e/CVE-2017-8625_Bypass_UMCI)

### CVE-2017-8641

<code>
Microsoft browsers in Microsoft Windows 7 SP1, Windows Server 2008 R2 SP1, Windows 8.1 and Windows RT 8.1, Windows Server 2012 and R2, Windows 10 Gold, 1511, 1607, 1703, and Windows Server 2016 allow an attacker to execute arbitrary code in the context of the current user due to the way that Microsoft browser JavaScript engines render when handling objects in memory, aka &quot;Scripting Engine Memory Corruption Vulnerability&quot;. This CVE ID is unique from CVE-2017-8634, CVE-2017-8635, CVE-2017-8636, CVE-2017-8638, CVE-2017-8639, CVE-2017-8640, CVE-2017-8645, CVE-2017-8646, CVE-2017-8647, CVE-2017-8655, CVE-2017-8656, CVE-2017-8657, CVE-2017-8670, CVE-2017-8671, CVE-2017-8672, and CVE-2017-8674.
</code>

- [homjxi0e/CVE-2017-8641_chakra_Js_GlobalObject](https://github.com/homjxi0e/CVE-2017-8641_chakra_Js_GlobalObject)

### CVE-2017-8759

<code>
Microsoft .NET Framework 2.0, 3.5, 3.5.1, 4.5.2, 4.6, 4.6.1, 4.6.2 and 4.7 allow an attacker to execute code remotely via a malicious document or application, aka &quot;.NET Framework Remote Code Execution Vulnerability.&quot;
</code>

- [Voulnet/CVE-2017-8759-Exploit-sample](https://github.com/Voulnet/CVE-2017-8759-Exploit-sample)
- [nccgroup/CVE-2017-8759](https://github.com/nccgroup/CVE-2017-8759)
- [vysecurity/CVE-2017-8759](https://github.com/vysecurity/CVE-2017-8759)
- [BasuCert/CVE-2017-8759](https://github.com/BasuCert/CVE-2017-8759)
- [tahisaad6/CVE-2017-8759-Exploit-sample2](https://github.com/tahisaad6/CVE-2017-8759-Exploit-sample2)
- [homjxi0e/CVE-2017-8759_-SOAP_WSDL](https://github.com/homjxi0e/CVE-2017-8759_-SOAP_WSDL)
- [bhdresh/CVE-2017-8759](https://github.com/bhdresh/CVE-2017-8759)
- [Lz1y/CVE-2017-8759](https://github.com/Lz1y/CVE-2017-8759)
- [JonasUliana/CVE-2017-8759](https://github.com/JonasUliana/CVE-2017-8759)
- [Securitykid/CVE-2017-8759](https://github.com/Securitykid/CVE-2017-8759)
- [ashr/CVE-2017-8759-exploits](https://github.com/ashr/CVE-2017-8759-exploits)
- [l0n3rs/CVE-2017-8759](https://github.com/l0n3rs/CVE-2017-8759)
- [ChaitanyaHaritash/CVE-2017-8759](https://github.com/ChaitanyaHaritash/CVE-2017-8759)
- [smashinu/CVE-2017-8759Expoit](https://github.com/smashinu/CVE-2017-8759Expoit)
- [adeljck/CVE-2017-8759](https://github.com/adeljck/CVE-2017-8759)
- [zhengkook/CVE-2017-8759](https://github.com/zhengkook/CVE-2017-8759)
- [varunsaru/SNP](https://github.com/varunsaru/SNP)
- [GayashanM/OHTS](https://github.com/GayashanM/OHTS)

### CVE-2017-8760

<code>
An issue was discovered on Accellion FTA devices before FTA_9_12_180. There is XSS in courier/1000@/index.html with the auth_params parameter. The device tries to use internal WAF filters to stop specific XSS Vulnerabilities. However, these can be bypassed by using some modifications to the payloads, e.g., URL encoding.
</code>

- [Voraka/cve-2017-8760](https://github.com/Voraka/cve-2017-8760)

### CVE-2017-8779

<code>
rpcbind through 0.2.4, LIBTIRPC through 1.0.1 and 1.0.2-rc through 1.0.2-rc3, and NTIRPC through 1.4.3 do not consider the maximum RPC data size during memory allocation for XDR strings, which allows remote attackers to cause a denial of service (memory consumption with no subsequent free) via a crafted UDP packet to port 111, aka rpcbomb.
</code>

- [drbothen/GO-RPCBOMB](https://github.com/drbothen/GO-RPCBOMB)

### CVE-2017-8802

<code>
Cross-site scripting (XSS) vulnerability in Zimbra Collaboration Suite (aka ZCS) before 8.8.0 Beta2 might allow remote attackers to inject arbitrary web script or HTML via vectors related to the &quot;Show Snippet&quot; functionality.
</code>

- [ozzi-/Zimbra-CVE-2017-8802-Hotifx](https://github.com/ozzi-/Zimbra-CVE-2017-8802-Hotifx)

### CVE-2017-8809

<code>
api.php in MediaWiki before 1.27.4, 1.28.x before 1.28.3, and 1.29.x before 1.29.2 has a Reflected File Download vulnerability.
</code>

- [motikan2010/CVE-2017-8809_MediaWiki_RFD](https://github.com/motikan2010/CVE-2017-8809_MediaWiki_RFD)

### CVE-2017-8890

<code>
The inet_csk_clone_lock function in net/ipv4/inet_connection_sock.c in the Linux kernel through 4.10.15 allows attackers to cause a denial of service (double free) or possibly have unspecified other impact by leveraging use of the accept system call.
</code>

- [beraphin/CVE-2017-8890](https://github.com/beraphin/CVE-2017-8890)
- [thinkycx/CVE-2017-8890](https://github.com/thinkycx/CVE-2017-8890)
- [7043mcgeep/cve-2017-8890-msf](https://github.com/7043mcgeep/cve-2017-8890-msf)

### CVE-2017-8917

<code>
SQL injection vulnerability in Joomla! 3.7.x before 3.7.1 allows attackers to execute arbitrary SQL commands via unspecified vectors.
</code>

- [brianwrf/Joomla3.7-SQLi-CVE-2017-8917](https://github.com/brianwrf/Joomla3.7-SQLi-CVE-2017-8917)
- [stefanlucas/Exploit-Joomla](https://github.com/stefanlucas/Exploit-Joomla)
- [cved-sources/cve-2017-8917](https://github.com/cved-sources/cve-2017-8917)

### CVE-2017-9097

<code>
In Anti-Web through 3.8.7, as used on NetBiter FGW200 devices through 3.21.2, WS100 devices through 3.30.5, EC150 devices through 1.40.0, WS200 devices through 3.30.4, EC250 devices through 1.40.0, and other products, an LFI vulnerability allows a remote attacker to read or modify files through a path traversal technique, as demonstrated by reading the password file, or using the template parameter to cgi-bin/write.cgi to write to an arbitrary file.
</code>

- [ezelf/AntiWeb_testing-Suite](https://github.com/ezelf/AntiWeb_testing-Suite)

### CVE-2017-9101

<code>
import.php (aka the Phonebook import feature) in PlaySMS 1.4 allows remote code execution via vectors involving the User-Agent HTTP header and PHP code in the name of a file.
</code>

- [jasperla/CVE-2017-9101](https://github.com/jasperla/CVE-2017-9101)

### CVE-2017-9248

<code>
Telerik.Web.UI.dll in Progress Telerik UI for ASP.NET AJAX before R2 2017 SP1 and Sitefinity before 10.0.6412.0 does not properly protect Telerik.Web.UI.DialogParametersEncryptionKey or the MachineKey, which makes it easier for remote attackers to defeat cryptographic protection mechanisms, leading to a MachineKey leak, arbitrary file uploads or downloads, XSS, or ASP.NET ViewState compromise.
</code>

- [bao7uo/dp_crypto](https://github.com/bao7uo/dp_crypto)
- [capt-meelo/Telewreck](https://github.com/capt-meelo/Telewreck)
- [ictnamanh/CVE-2017-9248](https://github.com/ictnamanh/CVE-2017-9248)
- [shacojx/dp](https://github.com/shacojx/dp)

### CVE-2017-9417

<code>
Broadcom BCM43xx Wi-Fi chips allow remote attackers to execute arbitrary code via unspecified vectors, aka the &quot;Broadpwn&quot; issue.
</code>

- [mailinneberg/Broadpwn](https://github.com/mailinneberg/Broadpwn)

### CVE-2017-9430

<code>
Stack-based buffer overflow in dnstracer through 1.9 allows attackers to cause a denial of service (application crash) or possibly have unspecified other impact via a command line with a long name argument that is mishandled in a strcpy call for argv[0]. An example threat model is a web application that launches dnstracer with an untrusted name string.
</code>

- [homjxi0e/CVE-2017-9430](https://github.com/homjxi0e/CVE-2017-9430)
- [j0lama/Dnstracer-1.9-Fix](https://github.com/j0lama/Dnstracer-1.9-Fix)

### CVE-2017-9476

<code>
The Comcast firmware on Cisco DPC3939 (firmware version dpc3939-P20-18-v303r20421733-160420a-CMCST); Cisco DPC3939 (firmware version dpc3939-P20-18-v303r20421746-170221a-CMCST); and Arris TG1682G (eMTA&amp;DOCSIS version 10.0.132.SIP.PC20.CT, software version TG1682_2.2p7s2_PROD_sey) devices makes it easy for remote attackers to determine the hidden SSID and passphrase for a Home Security Wi-Fi network.
</code>

- [wiire-a/CVE-2017-9476](https://github.com/wiire-a/CVE-2017-9476)

### CVE-2017-9506

<code>
The IconUriServlet of the Atlassian OAuth Plugin from version 1.3.0 before version 1.9.12 and from version 2.0.0 before version 2.0.4 allows remote attackers to access the content of internal network resources and/or perform an XSS attack via Server Side Request Forgery (SSRF).
</code>

- [random-robbie/Jira-Scan](https://github.com/random-robbie/Jira-Scan)
- [pwn1sher/jira-ssrf](https://github.com/pwn1sher/jira-ssrf)

### CVE-2017-9544

<code>
There is a remote stack-based buffer overflow (SEH) in register.ghp in EFS Software Easy Chat Server versions 2.0 to 3.1. By sending an overly long username string to registresult.htm for registering the user, an attacker may be able to execute arbitrary code.
</code>

- [adenkiewicz/CVE-2017-9544](https://github.com/adenkiewicz/CVE-2017-9544)

### CVE-2017-9554

<code>
An information exposure vulnerability in forget_passwd.cgi in Synology DiskStation Manager (DSM) before 6.1.3-15152 allows remote attackers to enumerate valid usernames via unspecified vectors.
</code>

- [rfcl/Synology-DiskStation-User-Enumeration-CVE-2017-9554-](https://github.com/rfcl/Synology-DiskStation-User-Enumeration-CVE-2017-9554-)

### CVE-2017-9606

<code>
Infotecs ViPNet Client and Coordinator before 4.3.2-42442 allow local users to gain privileges by placing a Trojan horse ViPNet update file in the update folder. The attack succeeds because of incorrect folder permissions in conjunction with a lack of integrity and authenticity checks.
</code>

- [Houl777/CVE-2017-9606](https://github.com/Houl777/CVE-2017-9606)

### CVE-2017-9609

<code>
Cross-site scripting (XSS) vulnerability in Blackcat CMS 1.2 allows remote authenticated users to inject arbitrary web script or HTML via the map_language parameter to backend/pages/lang_settings.php.
</code>

- [faizzaidi/Blackcat-cms-v1.2-xss-POC-by-Provensec-llc](https://github.com/faizzaidi/Blackcat-cms-v1.2-xss-POC-by-Provensec-llc)

### CVE-2017-9779

<code>
OCaml compiler allows attackers to have unspecified impact via unknown vectors, a similar issue to CVE-2017-9772 &quot;but with much less impact.&quot;
</code>

- [homjxi0e/CVE-2017-9779](https://github.com/homjxi0e/CVE-2017-9779)

### CVE-2017-9791

<code>
The Struts 1 plugin in Apache Struts 2.1.x and 2.3.x might allow remote code execution via a malicious field value passed in a raw message to the ActionMessage.
</code>

- [IanSmith123/s2-048](https://github.com/IanSmith123/s2-048)
- [dragoneeg/Struts2-048](https://github.com/dragoneeg/Struts2-048)
- [xfer0/CVE-2017-9791](https://github.com/xfer0/CVE-2017-9791)

### CVE-2017-9798

<code>
Apache httpd allows remote attackers to read secret data from process memory if the Limit directive can be set in a user's .htaccess file, or if httpd.conf has certain misconfigurations, aka Optionsbleed. This affects the Apache HTTP Server through 2.2.34 and 2.4.x through 2.4.27. The attacker sends an unauthenticated OPTIONS HTTP request when attempting to read secret data. This is a use-after-free issue and thus secret data is not always sent, and the specific data depends on many factors including configuration. Exploitation with .htaccess can be blocked with a patch to the ap_limit_section function in server/core.c.
</code>

- [nitrado/CVE-2017-9798](https://github.com/nitrado/CVE-2017-9798)
- [pabloec20/optionsbleed](https://github.com/pabloec20/optionsbleed)
- [l0n3rs/CVE-2017-9798](https://github.com/l0n3rs/CVE-2017-9798)
- [brokensound77/OptionsBleed-POC-Scanner](https://github.com/brokensound77/OptionsBleed-POC-Scanner)

### CVE-2017-9805

<code>
The REST Plugin in Apache Struts 2.1.1 through 2.3.x before 2.3.34 and 2.5.x before 2.5.13 uses an XStreamHandler with an instance of XStream for deserialization without any type filtering, which can lead to Remote Code Execution when deserializing XML payloads.
</code>

- [luc10/struts-rce-cve-2017-9805](https://github.com/luc10/struts-rce-cve-2017-9805)
- [hahwul/struts2-rce-cve-2017-9805-ruby](https://github.com/hahwul/struts2-rce-cve-2017-9805-ruby)
- [mazen160/struts-pwn_CVE-2017-9805](https://github.com/mazen160/struts-pwn_CVE-2017-9805)
- [Lone-Ranger/apache-struts-pwn_CVE-2017-9805](https://github.com/Lone-Ranger/apache-struts-pwn_CVE-2017-9805)
- [RealBearcat/S2-052](https://github.com/RealBearcat/S2-052)
- [0x00-0x00/-CVE-2017-9805](https://github.com/0x00-0x00/-CVE-2017-9805)
- [chrisjd20/cve-2017-9805.py](https://github.com/chrisjd20/cve-2017-9805.py)
- [UbuntuStrike/struts_rest_rce_fuzz-CVE-2017-9805-](https://github.com/UbuntuStrike/struts_rest_rce_fuzz-CVE-2017-9805-)
- [UbuntuStrike/CVE-2017-9805_Struts_Fuzz_N_Sploit](https://github.com/UbuntuStrike/CVE-2017-9805_Struts_Fuzz_N_Sploit)
- [thevivekkryadav/CVE-2017-9805-Exploit](https://github.com/thevivekkryadav/CVE-2017-9805-Exploit)
- [AvishkaSenadheera20/CVE-2017-9805---Documentation---IT19143378](https://github.com/AvishkaSenadheera20/CVE-2017-9805---Documentation---IT19143378)

### CVE-2017-9830

<code>
Remote Code Execution is possible in Code42 CrashPlan 5.4.x via the org.apache.commons.ssl.rmi.DateRMI Java class, because (upon instantiation) it creates an RMI server that listens on a TCP port and deserializes objects sent by TCP clients.
</code>

- [securifera/CVE-2017-9830](https://github.com/securifera/CVE-2017-9830)

### CVE-2017-9841

<code>
Util/PHP/eval-stdin.php in PHPUnit before 4.8.28 and 5.x before 5.6.3 allows remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a &quot;&lt;?php &quot; substring, as demonstrated by an attack on a site with an exposed /vendor folder, i.e., external access to the /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php URI.
</code>

- [mbrasile/CVE-2017-9841](https://github.com/mbrasile/CVE-2017-9841)

### CVE-2017-98505
- [mike-williams/Struts2Vuln](https://github.com/mike-williams/Struts2Vuln)

### CVE-2017-9934

<code>
Missing CSRF token checks and improper input validation in Joomla! CMS 1.7.3 through 3.7.2 lead to an XSS vulnerability.
</code>

- [xyringe/CVE-2017-9934](https://github.com/xyringe/CVE-2017-9934)

### CVE-2017-9999
- [homjxi0e/CVE-2017-9999_bypassing_General_Firefox](https://github.com/homjxi0e/CVE-2017-9999_bypassing_General_Firefox)


## 2016
### CVE-2016-0034

<code>
Microsoft Silverlight 5 before 5.1.41212.0 mishandles negative offsets during decoding, which allows remote attackers to execute arbitrary code or cause a denial of service (object-header corruption) via a crafted web site, aka &quot;Silverlight Runtime Remote Code Execution Vulnerability.&quot;
</code>

- [DiamondHunters/CVE-2016-0034-Decompile](https://github.com/DiamondHunters/CVE-2016-0034-Decompile)

### CVE-2016-0040

<code>
The kernel in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, and Windows 7 SP1 allows local users to gain privileges via a crafted application, aka &quot;Windows Elevation of Privilege Vulnerability.&quot;
</code>

- [Rootkitsmm/cve-2016-0040](https://github.com/Rootkitsmm/cve-2016-0040)
- [de7ec7ed/CVE-2016-0040](https://github.com/de7ec7ed/CVE-2016-0040)

### CVE-2016-0049

<code>
Kerberos in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, and Windows 10 Gold and 1511 does not properly validate password changes, which allows remote attackers to bypass authentication by deploying a crafted Key Distribution Center (KDC) and then performing a sign-in action, aka &quot;Windows Kerberos Security Feature Bypass.&quot;
</code>

- [JackOfMostTrades/bluebox](https://github.com/JackOfMostTrades/bluebox)

### CVE-2016-0051

<code>
The WebDAV client in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, and Windows 10 Gold and 1511 allows local users to gain privileges via a crafted application, aka &quot;WebDAV Elevation of Privilege Vulnerability.&quot;
</code>

- [koczkatamas/CVE-2016-0051](https://github.com/koczkatamas/CVE-2016-0051)
- [hexx0r/CVE-2016-0051](https://github.com/hexx0r/CVE-2016-0051)
- [ganrann/CVE-2016-0051](https://github.com/ganrann/CVE-2016-0051)

### CVE-2016-0095

<code>
The kernel-mode driver in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, and Windows 10 Gold and 1511 allows local users to gain privileges via a crafted application, aka &quot;Win32k Elevation of Privilege Vulnerability,&quot; a different vulnerability than CVE-2016-0093, CVE-2016-0094, and CVE-2016-0096.
</code>

- [4M4Z4/cve-2016-0095-x64](https://github.com/4M4Z4/cve-2016-0095-x64)

### CVE-2016-0099

<code>
The Secondary Logon Service in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, and Windows 10 Gold and 1511 does not properly process request handles, which allows local users to gain privileges via a crafted application, aka &quot;Secondary Logon Elevation of Privilege Vulnerability.&quot;
</code>

- [zcgonvh/MS16-032](https://github.com/zcgonvh/MS16-032)

### CVE-2016-010033
- [zi0Black/CVE-2016-010033-010045](https://github.com/zi0Black/CVE-2016-010033-010045)

### CVE-2016-0189

<code>
The Microsoft (1) JScript 5.8 and (2) VBScript 5.7 and 5.8 engines, as used in Internet Explorer 9 through 11 and other products, allow remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted web site, aka &quot;Scripting Engine Memory Corruption Vulnerability,&quot; a different vulnerability than CVE-2016-0187.
</code>

- [theori-io/cve-2016-0189](https://github.com/theori-io/cve-2016-0189)
- [deamwork/MS16-051-poc](https://github.com/deamwork/MS16-051-poc)

### CVE-2016-0199

<code>
Microsoft Internet Explorer 9 through 11 allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted web site, aka &quot;Internet Explorer Memory Corruption Vulnerability,&quot; a different vulnerability than CVE-2016-0200 and CVE-2016-3211.
</code>

- [LeoonZHANG/CVE-2016-0199](https://github.com/LeoonZHANG/CVE-2016-0199)

### CVE-2016-0638

<code>
Unspecified vulnerability in the Oracle WebLogic Server component in Oracle Fusion Middleware 10.3.6, 12.1.2, 12.1.3, and 12.2.1 allows remote attackers to affect confidentiality, integrity, and availability via vectors related to Java Messaging Service.
</code>

- [0xn0ne/weblogicScanner](https://github.com/0xn0ne/weblogicScanner)

### CVE-2016-0701

<code>
The DH_check_pub_key function in crypto/dh/dh_check.c in OpenSSL 1.0.2 before 1.0.2f does not ensure that prime numbers are appropriate for Diffie-Hellman (DH) key exchange, which makes it easier for remote attackers to discover a private DH exponent by making multiple handshakes with a peer that chose an inappropriate number, as demonstrated by a number in an X9.42 file.
</code>

- [luanjampa/cve-2016-0701](https://github.com/luanjampa/cve-2016-0701)

### CVE-2016-0728

<code>
The join_session_keyring function in security/keys/process_keys.c in the Linux kernel before 4.4.1 mishandles object references in a certain error case, which allows local users to gain privileges or cause a denial of service (integer overflow and use-after-free) via crafted keyctl commands.
</code>

- [idl3r/cve-2016-0728](https://github.com/idl3r/cve-2016-0728)
- [kennetham/cve_2016_0728](https://github.com/kennetham/cve_2016_0728)
- [nardholio/cve-2016-0728](https://github.com/nardholio/cve-2016-0728)
- [googleweb/CVE-2016-0728](https://github.com/googleweb/CVE-2016-0728)
- [MagicPwn/CVE-2016-0728-Check](https://github.com/MagicPwn/CVE-2016-0728-Check)
- [neuschaefer/cve-2016-0728-testbed](https://github.com/neuschaefer/cve-2016-0728-testbed)
- [bittorrent3389/cve-2016-0728](https://github.com/bittorrent3389/cve-2016-0728)
- [sibilleg/exploit_cve-2016-0728](https://github.com/sibilleg/exploit_cve-2016-0728)
- [hal0taso/CVE-2016-0728](https://github.com/hal0taso/CVE-2016-0728)
- [sugarvillela/CVE](https://github.com/sugarvillela/CVE)
- [th30d00r/Linux-Vulnerability-CVE-2016-0728-and-Exploit](https://github.com/th30d00r/Linux-Vulnerability-CVE-2016-0728-and-Exploit)

### CVE-2016-0752

<code>
Directory traversal vulnerability in Action View in Ruby on Rails before 3.2.22.1, 4.0.x and 4.1.x before 4.1.14.1, 4.2.x before 4.2.5.1, and 5.x before 5.0.0.beta1.1 allows remote attackers to read arbitrary files by leveraging an application's unrestricted use of the render method and providing a .. (dot dot) in a pathname.
</code>

- [forced-request/rails-rce-cve-2016-0752](https://github.com/forced-request/rails-rce-cve-2016-0752)
- [dachidahu/CVE-2016-0752](https://github.com/dachidahu/CVE-2016-0752)

### CVE-2016-0792

<code>
Multiple unspecified API endpoints in Jenkins before 1.650 and LTS before 1.642.2 allow remote authenticated users to execute arbitrary code via serialized data in an XML file, related to XStream and groovy.util.Expando.
</code>

- [jpiechowka/jenkins-cve-2016-0792](https://github.com/jpiechowka/jenkins-cve-2016-0792)
- [s0wr0b1ndef/java-deserialization-exploits](https://github.com/s0wr0b1ndef/java-deserialization-exploits)

### CVE-2016-0793

<code>
Incomplete blacklist vulnerability in the servlet filter restriction mechanism in WildFly (formerly JBoss Application Server) before 10.0.0.Final on Windows allows remote attackers to read the sensitive files in the (1) WEB-INF or (2) META-INF directory via a request that contains (a) lowercase or (b) &quot;meaningless&quot; characters.
</code>

- [tafamace/CVE-2016-0793](https://github.com/tafamace/CVE-2016-0793)

### CVE-2016-0801

<code>
The Broadcom Wi-Fi driver in the kernel in Android 4.x before 4.4.4, 5.x before 5.1.1 LMY49G, and 6.x before 2016-02-01 allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via crafted wireless control message packets, aka internal bug 25662029.
</code>

- [abdsec/CVE-2016-0801](https://github.com/abdsec/CVE-2016-0801)
- [zsaurus/CVE-2016-0801-test](https://github.com/zsaurus/CVE-2016-0801-test)

### CVE-2016-0805

<code>
The performance event manager for Qualcomm ARM processors in Android 4.x before 4.4.4, 5.x before 5.1.1 LMY49G, and 6.x before 2016-02-01 allows attackers to gain privileges via a crafted application, aka internal bug 25773204.
</code>

- [hulovebin/cve-2016-0805](https://github.com/hulovebin/cve-2016-0805)

### CVE-2016-0846

<code>
libs/binder/IMemory.cpp in the IMemory Native Interface in Android 4.x before 4.4.4, 5.0.x before 5.0.2, 5.1.x before 5.1.1, and 6.x before 2016-04-01 does not properly consider the heap size, which allows attackers to gain privileges via a crafted application, as demonstrated by obtaining Signature or SignatureOrSystem access, aka internal bug 26877992.
</code>

- [secmob/CVE-2016-0846](https://github.com/secmob/CVE-2016-0846)
- [b0b0505/CVE-2016-0846-PoC](https://github.com/b0b0505/CVE-2016-0846-PoC)

### CVE-2016-0974

<code>
Use-after-free vulnerability in Adobe Flash Player before 18.0.0.329 and 19.x and 20.x before 20.0.0.306 on Windows and OS X and before 11.2.202.569 on Linux, Adobe AIR before 20.0.0.260, Adobe AIR SDK before 20.0.0.260, and Adobe AIR SDK &amp; Compiler before 20.0.0.260 allows attackers to execute arbitrary code via unspecified vectors, a different vulnerability than CVE-2016-0973, CVE-2016-0975, CVE-2016-0982, CVE-2016-0983, and CVE-2016-0984.
</code>

- [Fullmetal5/FlashHax](https://github.com/Fullmetal5/FlashHax)

### CVE-2016-10033

<code>
The mailSend function in the isMail transport in PHPMailer before 5.2.18 might allow remote attackers to pass extra parameters to the mail command and consequently execute arbitrary code via a \&quot; (backslash double quote) in a crafted Sender property.
</code>

- [opsxcq/exploit-CVE-2016-10033](https://github.com/opsxcq/exploit-CVE-2016-10033)
- [Zenexer/safeshell](https://github.com/Zenexer/safeshell)
- [GeneralTesler/CVE-2016-10033](https://github.com/GeneralTesler/CVE-2016-10033)
- [chipironcin/CVE-2016-10033](https://github.com/chipironcin/CVE-2016-10033)
- [Bajunan/CVE-2016-10033](https://github.com/Bajunan/CVE-2016-10033)
- [qwertyuiop12138/CVE-2016-10033](https://github.com/qwertyuiop12138/CVE-2016-10033)
- [liusec/WP-CVE-2016-10033](https://github.com/liusec/WP-CVE-2016-10033)
- [pedro823/cve-2016-10033-45](https://github.com/pedro823/cve-2016-10033-45)
- [awidardi/opsxcq-cve-2016-10033](https://github.com/awidardi/opsxcq-cve-2016-10033)
- [0x00-0x00/CVE-2016-10033](https://github.com/0x00-0x00/CVE-2016-10033)
- [cved-sources/cve-2016-10033](https://github.com/cved-sources/cve-2016-10033)

### CVE-2016-10034

<code>
The setFrom function in the Sendmail adapter in the zend-mail component before 2.4.11, 2.5.x, 2.6.x, and 2.7.x before 2.7.2, and Zend Framework before 2.4.11 might allow remote attackers to pass extra parameters to the mail command and consequently execute arbitrary code via a \&quot; (backslash double quote) in a crafted e-mail address.
</code>

- [heikipikker/exploit-CVE-2016-10034](https://github.com/heikipikker/exploit-CVE-2016-10034)

### CVE-2016-10277

<code>
An elevation of privilege vulnerability in the Motorola bootloader could enable a local malicious application to execute arbitrary code within the context of the bootloader. This issue is rated as Critical due to the possibility of a local permanent device compromise, which may require reflashing the operating system to repair the device. Product: Android. Versions: Kernel-3.10, Kernel-3.18. Android ID: A-33840490.
</code>

- [alephsecurity/initroot](https://github.com/alephsecurity/initroot)
- [leosol/initroot](https://github.com/leosol/initroot)

### CVE-2016-10709

<code>
pfSense before 2.3 allows remote authenticated users to execute arbitrary OS commands via a '|' character in the status_rrd_graph_img.php graph parameter, related to _rrd_graph_img.php.
</code>

- [wetw0rk/Exploit-Development](https://github.com/wetw0rk/Exploit-Development)

### CVE-2016-10761

<code>
Logitech Unifying devices before 2016-02-26 allow keystroke injection, bypassing encryption, aka MouseJack.
</code>

- [ISSAPolska/CVE-2016-10761](https://github.com/ISSAPolska/CVE-2016-10761)

### CVE-2016-1240

<code>
The Tomcat init script in the tomcat7 package before 7.0.56-3+deb8u4 and tomcat8 package before 8.0.14-1+deb8u3 on Debian jessie and the tomcat6 and libtomcat6-java packages before 6.0.35-1ubuntu3.8 on Ubuntu 12.04 LTS, the tomcat7 and libtomcat7-java packages before 7.0.52-1ubuntu0.7 on Ubuntu 14.04 LTS, and tomcat8 and libtomcat8-java packages before 8.0.32-1ubuntu1.2 on Ubuntu 16.04 LTS allows local users with access to the tomcat account to gain root privileges via a symlink attack on the Catalina log file, as demonstrated by /var/log/tomcat7/catalina.out.
</code>

- [Naramsim/Offensive](https://github.com/Naramsim/Offensive)
- [mhe18/CVE_Project](https://github.com/mhe18/CVE_Project)

### CVE-2016-1287

<code>
Buffer overflow in the IKEv1 and IKEv2 implementations in Cisco ASA Software before 8.4(7.30), 8.7 before 8.7(1.18), 9.0 before 9.0(4.38), 9.1 before 9.1(7), 9.2 before 9.2(4.5), 9.3 before 9.3(3.7), 9.4 before 9.4(2.4), and 9.5 before 9.5(2.2) on ASA 5500 devices, ASA 5500-X devices, ASA Services Module for Cisco Catalyst 6500 and Cisco 7600 devices, ASA 1000V devices, Adaptive Security Virtual Appliance (aka ASAv), Firepower 9300 ASA Security Module, and ISA 3000 devices allows remote attackers to execute arbitrary code or cause a denial of service (device reload) via crafted UDP packets, aka Bug IDs CSCux29978 and CSCux42019.
</code>

- [jgajek/killasa](https://github.com/jgajek/killasa)
- [NetSPI/asa_tools](https://github.com/NetSPI/asa_tools)

### CVE-2016-1494

<code>
The verify function in the RSA package for Python (Python-RSA) before 3.3 allows attackers to spoof signatures with a small public exponent via crafted signature padding, aka a BERserk attack.
</code>

- [matthiasbe/secuimag3a](https://github.com/matthiasbe/secuimag3a)

### CVE-2016-1542

<code>
The RPC API in RSCD agent in BMC BladeLogic Server Automation (BSA) 8.2.x, 8.3.x, 8.5.x, 8.6.x, and 8.7.x on Linux and UNIX allows remote attackers to bypass authorization and enumerate users by sending an action packet to xmlrpc after an authorization failure.
</code>

- [patriknordlen/bladelogic_bmc-cve-2016-1542](https://github.com/patriknordlen/bladelogic_bmc-cve-2016-1542)
- [bao7uo/bmc_bladelogic](https://github.com/bao7uo/bmc_bladelogic)

### CVE-2016-1555

<code>
(1) boardData102.php, (2) boardData103.php, (3) boardDataJP.php, (4) boardDataNA.php, and (5) boardDataWW.php in Netgear WN604 before 3.3.3 and WN802Tv2, WNAP210v2, WNAP320, WNDAP350, WNDAP360, and WNDAP660 before 3.5.5.0 allow remote attackers to execute arbitrary commands.
</code>

- [ide0x90/cve-2016-1555](https://github.com/ide0x90/cve-2016-1555)

### CVE-2016-1734

<code>
AppleUSBNetworking in Apple iOS before 9.3 and OS X before 10.11.4 allows physically proximate attackers to execute arbitrary code in a privileged context or cause a denial of service (memory corruption) via a crafted USB device.
</code>

- [Manouchehri/CVE-2016-1734](https://github.com/Manouchehri/CVE-2016-1734)

### CVE-2016-1757

<code>
Race condition in the kernel in Apple iOS before 9.3 and OS X before 10.11.4 allows attackers to execute arbitrary code in a privileged context via a crafted app.
</code>

- [gdbinit/mach_race](https://github.com/gdbinit/mach_race)

### CVE-2016-1764

<code>
The Content Security Policy (CSP) implementation in Messages in Apple OS X before 10.11.4 allows remote attackers to obtain sensitive information via a javascript: URL.
</code>

- [moloch--/cve-2016-1764](https://github.com/moloch--/cve-2016-1764)

### CVE-2016-1825

<code>
IOHIDFamily in Apple OS X before 10.11.5 allows attackers to execute arbitrary code in a privileged context or cause a denial of service (memory corruption) via a crafted app.
</code>

- [bazad/physmem](https://github.com/bazad/physmem)

### CVE-2016-1827

<code>
The kernel in Apple iOS before 9.3.2, OS X before 10.11.5, tvOS before 9.2.1, and watchOS before 2.2.1 allows attackers to execute arbitrary code in a privileged context or cause a denial of service (memory corruption) via a crafted app, a different vulnerability than CVE-2016-1828, CVE-2016-1829, and CVE-2016-1830.
</code>

- [bazad/flow_divert-heap-overflow](https://github.com/bazad/flow_divert-heap-overflow)

### CVE-2016-1828

<code>
The kernel in Apple iOS before 9.3.2, OS X before 10.11.5, tvOS before 9.2.1, and watchOS before 2.2.1 allows attackers to execute arbitrary code in a privileged context or cause a denial of service (memory corruption) via a crafted app, a different vulnerability than CVE-2016-1827, CVE-2016-1829, and CVE-2016-1830.
</code>

- [bazad/rootsh](https://github.com/bazad/rootsh)

### CVE-2016-2098

<code>
Action Pack in Ruby on Rails before 3.2.22.2, 4.x before 4.1.14.2, and 4.2.x before 4.2.5.2 allows remote attackers to execute arbitrary Ruby code by leveraging an application's unrestricted use of the render method.
</code>

- [hderms/dh-CVE_2016_2098](https://github.com/hderms/dh-CVE_2016_2098)
- [CyberDefenseInstitute/PoC_CVE-2016-2098_Rails42](https://github.com/CyberDefenseInstitute/PoC_CVE-2016-2098_Rails42)
- [Alejandro-MartinG/rails-PoC-CVE-2016-2098](https://github.com/Alejandro-MartinG/rails-PoC-CVE-2016-2098)
- [0x00-0x00/CVE-2016-2098](https://github.com/0x00-0x00/CVE-2016-2098)
- [its-arun/CVE-2016-2098](https://github.com/its-arun/CVE-2016-2098)
- [3rg1s/CVE-2016-2098](https://github.com/3rg1s/CVE-2016-2098)

### CVE-2016-2107

<code>
The AES-NI implementation in OpenSSL before 1.0.1t and 1.0.2 before 1.0.2h does not consider memory allocation during a certain padding check, which allows remote attackers to obtain sensitive cleartext information via a padding-oracle attack against an AES CBC session. NOTE: this vulnerability exists because of an incorrect fix for CVE-2013-0169.
</code>

- [FiloSottile/CVE-2016-2107](https://github.com/FiloSottile/CVE-2016-2107)
- [tmiklas/docker-cve-2016-2107](https://github.com/tmiklas/docker-cve-2016-2107)

### CVE-2016-2118

<code>
The MS-SAMR and MS-LSAD protocol implementations in Samba 3.x and 4.x before 4.2.11, 4.3.x before 4.3.8, and 4.4.x before 4.4.2 mishandle DCERPC connections, which allows man-in-the-middle attackers to perform protocol-downgrade attacks and impersonate users by modifying the client-server data stream, aka &quot;BADLOCK.&quot;
</code>

- [nickanderson/cfengine-CVE-2016-2118](https://github.com/nickanderson/cfengine-CVE-2016-2118)

### CVE-2016-2173

<code>
org.springframework.core.serializer.DefaultDeserializer in Spring AMQP before 1.5.5 allows remote attackers to execute arbitrary code.
</code>

- [HaToan/CVE-2016-2173](https://github.com/HaToan/CVE-2016-2173)

### CVE-2016-2233

<code>
Stack-based buffer overflow in the inbound_cap_ls function in common/inbound.c in HexChat 2.10.2 allows remote IRC servers to cause a denial of service (crash) via a large number of options in a CAP LS message.
</code>

- [fath0218/CVE-2016-2233](https://github.com/fath0218/CVE-2016-2233)

### CVE-2016-2334

<code>
Heap-based buffer overflow in the NArchive::NHfs::CHandler::ExtractZlibFile method in 7zip before 16.00 and p7zip allows remote attackers to execute arbitrary code via a crafted HFS+ image.
</code>

- [icewall/CVE-2016-2334](https://github.com/icewall/CVE-2016-2334)

### CVE-2016-2402

<code>
OkHttp before 2.7.4 and 3.x before 3.1.2 allows man-in-the-middle attackers to bypass certificate pinning by sending a certificate chain with a certificate from a non-pinned trusted CA and the pinned certificate.
</code>

- [ikoz/cert-pinning-flaw-poc](https://github.com/ikoz/cert-pinning-flaw-poc)
- [ikoz/certPinningVulnerableOkHttp](https://github.com/ikoz/certPinningVulnerableOkHttp)

### CVE-2016-2431

<code>
The Qualcomm TrustZone component in Android before 2016-05-01 on Nexus 5, Nexus 6, Nexus 7 (2013), and Android One devices allows attackers to gain privileges via a crafted application, aka internal bug 24968809.
</code>

- [laginimaineb/cve-2016-2431](https://github.com/laginimaineb/cve-2016-2431)
- [laginimaineb/ExtractKeyMaster](https://github.com/laginimaineb/ExtractKeyMaster)

### CVE-2016-2434

<code>
The NVIDIA video driver in Android before 2016-05-01 on Nexus 9 devices allows attackers to gain privileges via a crafted application, aka internal bug 27251090.
</code>

- [jianqiangzhao/CVE-2016-2434](https://github.com/jianqiangzhao/CVE-2016-2434)

### CVE-2016-2468

<code>
The Qualcomm GPU driver in Android before 2016-06-01 on Nexus 5, 5X, 6, 6P, and 7 devices allows attackers to gain privileges via a crafted application, aka internal bug 27475454.
</code>

- [gitcollect/CVE-2016-2468](https://github.com/gitcollect/CVE-2016-2468)

### CVE-2016-2569

<code>
Squid 3.x before 3.5.15 and 4.x before 4.0.7 does not properly append data to String objects, which allows remote servers to cause a denial of service (assertion failure and daemon exit) via a long string, as demonstrated by a crafted HTTP Vary header.
</code>

- [amit-raut/CVE-2016-2569](https://github.com/amit-raut/CVE-2016-2569)

### CVE-2016-2776

<code>
buffer.c in named in ISC BIND 9 before 9.9.9-P3, 9.10.x before 9.10.4-P3, and 9.11.x before 9.11.0rc3 does not properly construct responses, which allows remote attackers to cause a denial of service (assertion failure and daemon exit) via a crafted query.
</code>

- [KosukeShimofuji/CVE-2016-2776](https://github.com/KosukeShimofuji/CVE-2016-2776)
- [infobyte/CVE-2016-2776](https://github.com/infobyte/CVE-2016-2776)

### CVE-2016-2783

<code>
Avaya Fabric Connect Virtual Services Platform (VSP) Operating System Software (VOSS) before 4.2.3.0 and 5.x before 5.0.1.0 does not properly handle VLAN and I-SIS indexes, which allows remote attackers to obtain unauthorized access via crafted Ethernet frames.
</code>

- [iknowjason/spb](https://github.com/iknowjason/spb)

### CVE-2016-3088

<code>
The Fileserver web application in Apache ActiveMQ 5.x before 5.14.0 allows remote attackers to upload and execute arbitrary files via an HTTP PUT followed by an HTTP MOVE request.
</code>

- [VVzv/CVE-2016-3088](https://github.com/VVzv/CVE-2016-3088)

### CVE-2016-3113

<code>
Cross-site scripting (XSS) vulnerability in ovirt-engine allows remote attackers to inject arbitrary web script or HTML.
</code>

- [0xEmanuel/CVE-2016-3113](https://github.com/0xEmanuel/CVE-2016-3113)

### CVE-2016-3141

<code>
Use-after-free vulnerability in wddx.c in the WDDX extension in PHP before 5.5.33 and 5.6.x before 5.6.19 allows remote attackers to cause a denial of service (memory corruption and application crash) or possibly have unspecified other impact by triggering a wddx_deserialize call on XML data containing a crafted var element.
</code>

- [peternguyen93/CVE-2016-3141](https://github.com/peternguyen93/CVE-2016-3141)

### CVE-2016-3308

<code>
The kernel-mode drivers in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607 allow local users to gain privileges via a crafted application, aka &quot;Win32k Elevation of Privilege Vulnerability,&quot; a different vulnerability than CVE-2016-3309, CVE-2016-3310, and CVE-2016-3311.
</code>

- [55-AA/CVE-2016-3308](https://github.com/55-AA/CVE-2016-3308)

### CVE-2016-3309

<code>
The kernel-mode drivers in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607 allow local users to gain privileges via a crafted application, aka &quot;Win32k Elevation of Privilege Vulnerability,&quot; a different vulnerability than CVE-2016-3308, CVE-2016-3310, and CVE-2016-3311.
</code>

- [siberas/CVE-2016-3309_Reloaded](https://github.com/siberas/CVE-2016-3309_Reloaded)

### CVE-2016-3714

<code>
The (1) EPHEMERAL, (2) HTTPS, (3) MVG, (4) MSL, (5) TEXT, (6) SHOW, (7) WIN, and (8) PLT coders in ImageMagick before 6.9.3-10 and 7.x before 7.0.1-1 allow remote attackers to execute arbitrary code via shell metacharacters in a crafted image, aka &quot;ImageTragick.&quot;
</code>

- [jackdpeterson/imagick_secure_puppet](https://github.com/jackdpeterson/imagick_secure_puppet)
- [tommiionfire/CVE-2016-3714](https://github.com/tommiionfire/CVE-2016-3714)
- [chusiang/CVE-2016-3714.ansible.role](https://github.com/chusiang/CVE-2016-3714.ansible.role)
- [jpeanut/ImageTragick-CVE-2016-3714-RShell](https://github.com/jpeanut/ImageTragick-CVE-2016-3714-RShell)
- [Hood3dRob1n/CVE-2016-3714](https://github.com/Hood3dRob1n/CVE-2016-3714)
- [HRSkraps/CVE-2016-3714](https://github.com/HRSkraps/CVE-2016-3714)

### CVE-2016-3749

<code>
server/LockSettingsService.java in LockSettingsService in Android 6.x before 2016-07-01 allows attackers to modify the screen-lock password or pattern via a crafted application, aka internal bug 28163930.
</code>

- [nirdev/CVE-2016-3749-PoC](https://github.com/nirdev/CVE-2016-3749-PoC)

### CVE-2016-3955

<code>
The usbip_recv_xbuff function in drivers/usb/usbip/usbip_common.c in the Linux kernel before 4.5.3 allows remote attackers to cause a denial of service (out-of-bounds write) or possibly have unspecified other impact via a crafted length value in a USB/IP packet.
</code>

- [pqsec/uboatdemo](https://github.com/pqsec/uboatdemo)

### CVE-2016-3957

<code>
The secure_load function in gluon/utils.py in web2py before 2.14.2 uses pickle.loads to deserialize session information stored in cookies, which might allow remote attackers to execute arbitrary code by leveraging knowledge of encryption_key.
</code>

- [sj/web2py-e94946d-CVE-2016-3957](https://github.com/sj/web2py-e94946d-CVE-2016-3957)

### CVE-2016-3959

<code>
The Verify function in crypto/dsa/dsa.go in Go before 1.5.4 and 1.6.x before 1.6.1 does not properly check parameters passed to the big integer library, which might allow remote attackers to cause a denial of service (infinite loop) via a crafted public key to a program that uses HTTPS client certificates or SSH server libraries.
</code>

- [alexmullins/dsa](https://github.com/alexmullins/dsa)

### CVE-2016-3962

<code>
Stack-based buffer overflow in the NTP time-server interface on Meinberg IMS-LANTIME M3000, IMS-LANTIME M1000, IMS-LANTIME M500, LANTIME M900, LANTIME M600, LANTIME M400, LANTIME M300, LANTIME M200, LANTIME M100, SyncFire 1100, and LCES devices with firmware before 6.20.004 allows remote attackers to obtain sensitive information, modify data, or cause a denial of service via a crafted parameter in a POST request.
</code>

- [securifera/CVE-2016-3962-Exploit](https://github.com/securifera/CVE-2016-3962-Exploit)

### CVE-2016-4010

<code>
Magento CE and EE before 2.0.6 allows remote attackers to conduct PHP objection injection attacks and execute arbitrary PHP code via crafted serialized shopping cart data.
</code>

- [brianwrf/Magento-CVE-2016-4010](https://github.com/brianwrf/Magento-CVE-2016-4010)

### CVE-2016-4117

<code>
Adobe Flash Player 21.0.0.226 and earlier allows remote attackers to execute arbitrary code via unspecified vectors, as exploited in the wild in May 2016.
</code>

- [amit-raut/CVE-2016-4117-Report](https://github.com/amit-raut/CVE-2016-4117-Report)
- [hybridious/CVE-2016-4117](https://github.com/hybridious/CVE-2016-4117)

### CVE-2016-4438

<code>
The REST plugin in Apache Struts 2 2.3.19 through 2.3.28.1 allows remote attackers to execute arbitrary code via a crafted expression.
</code>

- [jason3e7/CVE-2016-4438](https://github.com/jason3e7/CVE-2016-4438)
- [tafamace/CVE-2016-4438](https://github.com/tafamace/CVE-2016-4438)

### CVE-2016-4463

<code>
Stack-based buffer overflow in Apache Xerces-C++ before 3.1.4 allows context-dependent attackers to cause a denial of service via a deeply nested DTD.
</code>

- [arntsonl/CVE-2016-4463](https://github.com/arntsonl/CVE-2016-4463)

### CVE-2016-4622

<code>
WebKit in Apple iOS before 9.3.3, Safari before 9.1.2, and tvOS before 9.2.2 allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted web site, a different vulnerability than CVE-2016-4589, CVE-2016-4623, and CVE-2016-4624.
</code>

- [saelo/jscpwn](https://github.com/saelo/jscpwn)
- [hdbreaker/WebKit-CVE-2016-4622](https://github.com/hdbreaker/WebKit-CVE-2016-4622)

### CVE-2016-4631

<code>
ImageIO in Apple iOS before 9.3.3, OS X before 10.11.6, tvOS before 9.2.2, and watchOS before 2.2.2 allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted TIFF file.
</code>

- [hansnielsen/tiffdisabler](https://github.com/hansnielsen/tiffdisabler)

### CVE-2016-4655

<code>
The kernel in Apple iOS before 9.3.5 allows attackers to obtain sensitive information from memory via a crafted app.
</code>

- [jndok/PegasusX](https://github.com/jndok/PegasusX)
- [Cryptiiiic/skybreak](https://github.com/Cryptiiiic/skybreak)

### CVE-2016-4657

<code>
WebKit in Apple iOS before 9.3.5 allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted web site.
</code>

- [Mimoja/CVE-2016-4657-NintendoSwitch](https://github.com/Mimoja/CVE-2016-4657-NintendoSwitch)
- [Traiver/CVE-2016-4657-Switch-Browser-Binary](https://github.com/Traiver/CVE-2016-4657-Switch-Browser-Binary)
- [iDaN5x/Switcheroo](https://github.com/iDaN5x/Switcheroo)
- [vigneshyaadav27/webkit-vulnerability](https://github.com/vigneshyaadav27/webkit-vulnerability)

### CVE-2016-4669

<code>
An issue was discovered in certain Apple products. iOS before 10.1 is affected. macOS before 10.12.1 is affected. tvOS before 10.0.1 is affected. watchOS before 3.1 is affected. The issue involves the &quot;Kernel&quot; component. It allows local users to execute arbitrary code in a privileged context or cause a denial of service (MIG code mishandling and system crash) via unspecified vectors.
</code>

- [i-o-s/CVE-2016-4669](https://github.com/i-o-s/CVE-2016-4669)

### CVE-2016-4845

<code>
Cross-site request forgery (CSRF) vulnerability on I-O DATA DEVICE HVL-A2.0, HVL-A3.0, HVL-A4.0, HVL-AT1.0S, HVL-AT2.0, HVL-AT3.0, HVL-AT4.0, HVL-AT2.0A, HVL-AT3.0A, and HVL-AT4.0A devices with firmware before 2.04 allows remote attackers to hijack the authentication of arbitrary users for requests that delete content.
</code>

- [kaito834/cve-2016-4845_csrf](https://github.com/kaito834/cve-2016-4845_csrf)

### CVE-2016-4861

<code>
The (1) order and (2) group methods in Zend_Db_Select in the Zend Framework before 1.12.20 might allow remote attackers to conduct SQL injection attacks by leveraging failure to remove comments from an SQL statement before validation.
</code>

- [KosukeShimofuji/CVE-2016-4861](https://github.com/KosukeShimofuji/CVE-2016-4861)

### CVE-2016-4971

<code>
GNU wget before 1.18 allows remote servers to write to arbitrary files by redirecting a request from HTTP to a crafted FTP resource.
</code>

- [BlueCocoa/CVE-2016-4971](https://github.com/BlueCocoa/CVE-2016-4971)
- [mbadanoiu/CVE-2016-4971](https://github.com/mbadanoiu/CVE-2016-4971)
- [dinidhu96/IT19013756_-CVE-2016-4971-](https://github.com/dinidhu96/IT19013756_-CVE-2016-4971-)

### CVE-2016-4977

<code>
When processing authorization requests using the whitelabel views in Spring Security OAuth 2.0.0 to 2.0.9 and 1.0.0 to 1.0.5, the response_type parameter value was executed as Spring SpEL which enabled a malicious user to trigger remote code execution via the crafting of the value for response_type.
</code>

- [GEIGEI123/CVE-2016-4977-POC](https://github.com/GEIGEI123/CVE-2016-4977-POC)

### CVE-2016-5195

<code>
Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka &quot;Dirty COW.&quot;
</code>

- [KosukeShimofuji/CVE-2016-5195](https://github.com/KosukeShimofuji/CVE-2016-5195)
- [ASRTeam/CVE-2016-5195](https://github.com/ASRTeam/CVE-2016-5195)
- [timwr/CVE-2016-5195](https://github.com/timwr/CVE-2016-5195)
- [xlucas/dirtycow.cr](https://github.com/xlucas/dirtycow.cr)
- [istenrot/centos-dirty-cow-ansible](https://github.com/istenrot/centos-dirty-cow-ansible)
- [pgporada/ansible-role-cve](https://github.com/pgporada/ansible-role-cve)
- [sideeffect42/DirtyCOWTester](https://github.com/sideeffect42/DirtyCOWTester)
- [scumjr/dirtycow-vdso](https://github.com/scumjr/dirtycow-vdso)
- [gbonacini/CVE-2016-5195](https://github.com/gbonacini/CVE-2016-5195)
- [DavidBuchanan314/cowroot](https://github.com/DavidBuchanan314/cowroot)
- [aishee/scan-dirtycow](https://github.com/aishee/scan-dirtycow)
- [oleg-fiksel/ansible_CVE-2016-5195_check](https://github.com/oleg-fiksel/ansible_CVE-2016-5195_check)
- [ldenevi/CVE-2016-5195](https://github.com/ldenevi/CVE-2016-5195)
- [whu-enjoy/CVE-2016-5195](https://github.com/whu-enjoy/CVE-2016-5195)
- [ndobson/inspec_CVE-2016-5195](https://github.com/ndobson/inspec_CVE-2016-5195)
- [linhlt247/DirtyCOW_CVE-2016-5195](https://github.com/linhlt247/DirtyCOW_CVE-2016-5195)
- [sribaba/android-CVE-2016-5195](https://github.com/sribaba/android-CVE-2016-5195)
- [esc0rtd3w/org.cowpoop.moooooo](https://github.com/esc0rtd3w/org.cowpoop.moooooo)
- [nu11secur1ty/Protect-CVE-2016-5195-DirtyCow](https://github.com/nu11secur1ty/Protect-CVE-2016-5195-DirtyCow)
- [hyln9/VIKIROOT](https://github.com/hyln9/VIKIROOT)
- [droidvoider/dirtycow-replacer](https://github.com/droidvoider/dirtycow-replacer)
- [FloridSleeves/os-experiment-4](https://github.com/FloridSleeves/os-experiment-4)
- [arbll/dirtycow](https://github.com/arbll/dirtycow)
- [titanhp/Dirty-COW-CVE-2016-5195-Testing](https://github.com/titanhp/Dirty-COW-CVE-2016-5195-Testing)
- [acidburnmi/CVE-2016-5195-master](https://github.com/acidburnmi/CVE-2016-5195-master)
- [xpcmdshell/derpyc0w](https://github.com/xpcmdshell/derpyc0w)
- [Brucetg/DirtyCow-EXP](https://github.com/Brucetg/DirtyCow-EXP)
- [jas502n/CVE-2016-5195](https://github.com/jas502n/CVE-2016-5195)
- [imust6226/dirtcow](https://github.com/imust6226/dirtcow)
- [shanuka-ashen/Dirty-Cow-Explanation-CVE-2016-5195-](https://github.com/shanuka-ashen/Dirty-Cow-Explanation-CVE-2016-5195-)
- [dulanjaya23/Dirty-Cow-CVE-2016-5195-](https://github.com/dulanjaya23/Dirty-Cow-CVE-2016-5195-)
- [KaviDk/dirtyCow](https://github.com/KaviDk/dirtyCow)

### CVE-2016-5345

<code>
Buffer overflow in the Qualcomm radio driver in Android before 2017-01-05 on Android One devices allows local users to gain privileges via a crafted application, aka Android internal bug 32639452 and Qualcomm internal bug CR1079713.
</code>

- [NickStephens/cve-2016-5345](https://github.com/NickStephens/cve-2016-5345)

### CVE-2016-5639

<code>
Directory traversal vulnerability in cgi-bin/login.cgi on Crestron AirMedia AM-100 devices with firmware before 1.4.0.13 allows remote attackers to read arbitrary files via a .. (dot dot) in the src parameter.
</code>

- [xfox64x/CVE-2016-5639](https://github.com/xfox64x/CVE-2016-5639)

### CVE-2016-5640

<code>
Directory traversal vulnerability in cgi-bin/rftest.cgi on Crestron AirMedia AM-100 devices with firmware before 1.4.0.13 allows remote attackers to execute arbitrary commands via a .. (dot dot) in the ATE_COMMAND parameter.
</code>

- [vpnguy-zz/CrestCrack](https://github.com/vpnguy-zz/CrestCrack)
- [xfox64x/CVE-2016-5640](https://github.com/xfox64x/CVE-2016-5640)

### CVE-2016-5696

<code>
net/ipv4/tcp_input.c in the Linux kernel before 4.7 does not properly determine the rate of challenge ACK segments, which makes it easier for remote attackers to hijack TCP sessions via a blind in-window attack.
</code>

- [Gnoxter/mountain_goat](https://github.com/Gnoxter/mountain_goat)
- [violentshell/rover](https://github.com/violentshell/rover)
- [jduck/challack](https://github.com/jduck/challack)
- [bplinux/chackd](https://github.com/bplinux/chackd)
- [nogoegst/grill](https://github.com/nogoegst/grill)

### CVE-2016-5699

<code>
CRLF injection vulnerability in the HTTPConnection.putheader function in urllib2 and urllib in CPython (aka Python) before 2.7.10 and 3.x before 3.4.4 allows remote attackers to inject arbitrary HTTP headers via CRLF sequences in a URL.
</code>

- [bunseokbot/CVE-2016-5699-poc](https://github.com/bunseokbot/CVE-2016-5699-poc)
- [shajinzheng/cve-2016-5699-jinzheng-sha](https://github.com/shajinzheng/cve-2016-5699-jinzheng-sha)

### CVE-2016-5734

<code>
phpMyAdmin 4.0.x before 4.0.10.16, 4.4.x before 4.4.15.7, and 4.6.x before 4.6.3 does not properly choose delimiters to prevent use of the preg_replace e (aka eval) modifier, which might allow remote attackers to execute arbitrary PHP code via a crafted string, as demonstrated by the table search-and-replace implementation.
</code>

- [KosukeShimofuji/CVE-2016-5734](https://github.com/KosukeShimofuji/CVE-2016-5734)

### CVE-2016-6187

<code>
The apparmor_setprocattr function in security/apparmor/lsm.c in the Linux kernel before 4.6.5 does not validate the buffer size, which allows local users to gain privileges by triggering an AppArmor setprocattr hook.
</code>

- [vnik5287/cve-2016-6187-poc](https://github.com/vnik5287/cve-2016-6187-poc)

### CVE-2016-6210

<code>
sshd in OpenSSH before 7.3, when SHA256 or SHA512 are used for user password hashing, uses BLOWFISH hashing on a static password when the username does not exist, which allows remote attackers to enumerate users by leveraging the timing difference between responses when a large password is provided.
</code>

- [justlce/CVE-2016-6210-Exploit](https://github.com/justlce/CVE-2016-6210-Exploit)

### CVE-2016-6271

<code>
The Bzrtp library (aka libbzrtp) 1.0.x before 1.0.4 allows man-in-the-middle attackers to conduct spoofing attacks by leveraging a missing HVI check on DHPart2 packet reception.
</code>

- [gteissier/CVE-2016-6271](https://github.com/gteissier/CVE-2016-6271)

### CVE-2016-6317

<code>
Action Record in Ruby on Rails 4.2.x before 4.2.7.1 does not properly consider differences in parameter handling between the Active Record component and the JSON implementation, which allows remote attackers to bypass intended database-query restrictions and perform NULL checks or trigger missing WHERE clauses via a crafted request, as demonstrated by certain &quot;[nil]&quot; values, a related issue to CVE-2012-2660, CVE-2012-2694, and CVE-2013-0155.
</code>

- [kavgan/vuln_test_repo_public_ruby_gemfile_cve-2016-6317](https://github.com/kavgan/vuln_test_repo_public_ruby_gemfile_cve-2016-6317)

### CVE-2016-6366

<code>
Buffer overflow in Cisco Adaptive Security Appliance (ASA) Software through 9.4.2.3 on ASA 5500, ASA 5500-X, ASA Services Module, ASA 1000V, ASAv, Firepower 9300 ASA Security Module, PIX, and FWSM devices allows remote authenticated users to execute arbitrary code via crafted IPv4 SNMP packets, aka Bug ID CSCva92151 or EXTRABACON.
</code>

- [RiskSense-Ops/CVE-2016-6366](https://github.com/RiskSense-Ops/CVE-2016-6366)

### CVE-2016-6515

<code>
The auth_password function in auth-passwd.c in sshd in OpenSSH before 7.3 does not limit password lengths for password authentication, which allows remote attackers to cause a denial of service (crypt CPU consumption) via a long string.
</code>

- [opsxcq/exploit-CVE-2016-6515](https://github.com/opsxcq/exploit-CVE-2016-6515)
- [cved-sources/cve-2016-6515](https://github.com/cved-sources/cve-2016-6515)

### CVE-2016-6516

<code>
Race condition in the ioctl_file_dedupe_range function in fs/ioctl.c in the Linux kernel through 4.7 allows local users to cause a denial of service (heap-based buffer overflow) or possibly gain privileges by changing a certain count value, aka a &quot;double fetch&quot; vulnerability.
</code>

- [wpengfei/CVE-2016-6516-exploit](https://github.com/wpengfei/CVE-2016-6516-exploit)

### CVE-2016-6584
- [ViralSecurityGroup/KNOXout](https://github.com/ViralSecurityGroup/KNOXout)

### CVE-2016-6662

<code>
Oracle MySQL through 5.5.52, 5.6.x through 5.6.33, and 5.7.x through 5.7.15; MariaDB before 5.5.51, 10.0.x before 10.0.27, and 10.1.x before 10.1.17; and Percona Server before 5.5.51-38.1, 5.6.x before 5.6.32-78.0, and 5.7.x before 5.7.14-7 allow local users to create arbitrary configurations and bypass certain protection mechanisms by setting general_log_file to a my.cnf configuration. NOTE: this can be leveraged to execute arbitrary code with root privileges by setting malloc_lib. NOTE: the affected MySQL version information is from Oracle's October 2016 CPU. Oracle has not commented on third-party claims that the issue was silently patched in MySQL 5.5.52, 5.6.33, and 5.7.15.
</code>

- [konstantin-kelemen/mysqld_safe-CVE-2016-6662-patch](https://github.com/konstantin-kelemen/mysqld_safe-CVE-2016-6662-patch)
- [meersjo/ansible-mysql-cve-2016-6662](https://github.com/meersjo/ansible-mysql-cve-2016-6662)
- [KosukeShimofuji/CVE-2016-6662](https://github.com/KosukeShimofuji/CVE-2016-6662)
- [Ashrafdev/MySQL-Remote-Root-Code-Execution](https://github.com/Ashrafdev/MySQL-Remote-Root-Code-Execution)
- [boompig/cve-2016-6662](https://github.com/boompig/cve-2016-6662)
- [MAYASEVEN/CVE-2016-6662](https://github.com/MAYASEVEN/CVE-2016-6662)

### CVE-2016-6663

<code>
Race condition in Oracle MySQL before 5.5.52, 5.6.x before 5.6.33, 5.7.x before 5.7.15, and 8.x before 8.0.1; MariaDB before 5.5.52, 10.0.x before 10.0.28, and 10.1.x before 10.1.18; Percona Server before 5.5.51-38.2, 5.6.x before 5.6.32-78-1, and 5.7.x before 5.7.14-8; and Percona XtraDB Cluster before 5.5.41-37.0, 5.6.x before 5.6.32-25.17, and 5.7.x before 5.7.14-26.17 allows local users with certain permissions to gain privileges by leveraging use of my_copystat by REPAIR TABLE to repair a MyISAM table.
</code>

- [firebroo/CVE-2016-6663](https://github.com/firebroo/CVE-2016-6663)

### CVE-2016-6754

<code>
A remote code execution vulnerability in Webview in Android 5.0.x before 5.0.2, 5.1.x before 5.1.1, and 6.x before 2016-11-05 could enable a remote attacker to execute arbitrary code when the user is navigating to a website. This issue is rated as High due to the possibility of remote code execution in an unprivileged process. Android ID: A-31217937.
</code>

- [secmob/BadKernel](https://github.com/secmob/BadKernel)

### CVE-2016-6798

<code>
In the XSS Protection API module before 1.0.12 in Apache Sling, the method XSS.getValidXML() uses an insecure SAX parser to validate the input string, which allows for XXE attacks in all scripts which use this method to validate user input, potentially allowing an attacker to read sensitive data on the filesystem, perform same-site-request-forgery (SSRF), port-scanning behind the firewall or DoS the application.
</code>

- [tafamace/CVE-2016-6798](https://github.com/tafamace/CVE-2016-6798)

### CVE-2016-6801

<code>
Cross-site request forgery (CSRF) vulnerability in the CSRF content-type check in Jackrabbit-Webdav in Apache Jackrabbit 2.4.x before 2.4.6, 2.6.x before 2.6.6, 2.8.x before 2.8.3, 2.10.x before 2.10.4, 2.12.x before 2.12.4, and 2.13.x before 2.13.3 allows remote attackers to hijack the authentication of unspecified victims for requests that create a resource via an HTTP POST request with a (1) missing or (2) crafted Content-Type header.
</code>

- [TSNGL21/CVE-2016-6801](https://github.com/TSNGL21/CVE-2016-6801)

### CVE-2016-7117

<code>
Use-after-free vulnerability in the __sys_recvmmsg function in net/socket.c in the Linux kernel before 4.5.2 allows remote attackers to execute arbitrary code via vectors involving a recvmmsg system call that is mishandled during error processing.
</code>

- [KosukeShimofuji/CVE-2016-7117](https://github.com/KosukeShimofuji/CVE-2016-7117)

### CVE-2016-7190

<code>
The Chakra JavaScript engine in Microsoft Edge allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted web site, aka &quot;Scripting Engine Memory Corruption Vulnerability,&quot; a different vulnerability than CVE-2016-3386, CVE-2016-3389, and CVE-2016-7194.
</code>

- [0xcl/cve-2016-7190](https://github.com/0xcl/cve-2016-7190)

### CVE-2016-7200

<code>
The Chakra JavaScript scripting engine in Microsoft Edge allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted web site, aka &quot;Scripting Engine Memory Corruption Vulnerability,&quot; a different vulnerability than CVE-2016-7201, CVE-2016-7202, CVE-2016-7203, CVE-2016-7208, CVE-2016-7240, CVE-2016-7242, and CVE-2016-7243.
</code>

- [theori-io/chakra-2016-11](https://github.com/theori-io/chakra-2016-11)

### CVE-2016-7255

<code>
The kernel-mode drivers in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, and 1607, and Windows Server 2016 allow local users to gain privileges via a crafted application, aka &quot;Win32k Elevation of Privilege Vulnerability.&quot;
</code>

- [heh3/CVE-2016-7255](https://github.com/heh3/CVE-2016-7255)
- [FSecureLABS/CVE-2016-7255](https://github.com/FSecureLABS/CVE-2016-7255)
- [homjxi0e/CVE-2016-7255](https://github.com/homjxi0e/CVE-2016-7255)
- [yuvatia/page-table-exploitation](https://github.com/yuvatia/page-table-exploitation)
- [bbolmin/cve-2016-7255_x86_x64](https://github.com/bbolmin/cve-2016-7255_x86_x64)

### CVE-2016-7434

<code>
The read_mru_list function in NTP before 4.2.8p9 allows remote attackers to cause a denial of service (crash) via a crafted mrulist query.
</code>

- [opsxcq/exploit-CVE-2016-7434](https://github.com/opsxcq/exploit-CVE-2016-7434)
- [shekkbuilder/CVE-2016-7434](https://github.com/shekkbuilder/CVE-2016-7434)
- [cved-sources/cve-2016-7434](https://github.com/cved-sources/cve-2016-7434)

### CVE-2016-7608

<code>
An issue was discovered in certain Apple products. macOS before 10.12.2 is affected. The issue involves the &quot;IOFireWireFamily&quot; component, which allows local users to obtain sensitive information from kernel memory via unspecified vectors.
</code>

- [bazad/IOFireWireFamily-overflow](https://github.com/bazad/IOFireWireFamily-overflow)

### CVE-2016-7855

<code>
Use-after-free vulnerability in Adobe Flash Player before 23.0.0.205 on Windows and OS X and before 11.2.202.643 on Linux allows remote attackers to execute arbitrary code via unspecified vectors, as exploited in the wild in October 2016.
</code>

- [swagatbora90/CheckFlashPlayerVersion](https://github.com/swagatbora90/CheckFlashPlayerVersion)

### CVE-2016-8007

<code>
Authentication bypass vulnerability in McAfee Host Intrusion Prevention Services (HIPS) 8.0 Patch 7 and earlier allows authenticated users to manipulate the product's registry keys via specific conditions.
</code>

- [dmaasland/mcafee-hip-CVE-2016-8007](https://github.com/dmaasland/mcafee-hip-CVE-2016-8007)

### CVE-2016-8016

<code>
Information exposure in Intel Security VirusScan Enterprise Linux (VSEL) 2.0.3 (and earlier) allows authenticated remote attackers to obtain the existence of unauthorized files on the system via a URL parameter.
</code>

- [opsxcq/exploit-CVE-2016-8016-25](https://github.com/opsxcq/exploit-CVE-2016-8016-25)

### CVE-2016-8367

<code>
An issue was discovered in Schneider Electric Magelis HMI Magelis GTO Advanced Optimum Panels, all versions, Magelis GTU Universal Panel, all versions, Magelis STO5xx and STU Small panels, all versions, Magelis XBT GH Advanced Hand-held Panels, all versions, Magelis XBT GK Advanced Touchscreen Panels with Keyboard, all versions, Magelis XBT GT Advanced Touchscreen Panels, all versions, and Magelis XBT GTW Advanced Open Touchscreen Panels (Windows XPe). An attacker can open multiple connections to a targeted web server and keep connections open preventing new connections from being made, rendering the web server unavailable during an attack.
</code>

- [0xICF/PanelShock](https://github.com/0xICF/PanelShock)

### CVE-2016-8462

<code>
An information disclosure vulnerability in the bootloader could enable a local attacker to access data outside of its permission level. This issue is rated as High because it could be used to access sensitive data. Product: Android. Versions: N/A. Android ID: A-32510383.
</code>

- [CunningLogic/PixelDump_CVE-2016-8462](https://github.com/CunningLogic/PixelDump_CVE-2016-8462)

### CVE-2016-8467

<code>
An elevation of privilege vulnerability in the bootloader could enable a local attacker to execute arbitrary modem commands on the device. This issue is rated as High because it is a local permanent denial of service (device interoperability: completely permanent or requiring re-flashing the entire operating system). Product: Android. Versions: N/A. Android ID: A-30308784.
</code>

- [roeeh/bootmodechecker](https://github.com/roeeh/bootmodechecker)

### CVE-2016-8610

<code>
A denial of service flaw was found in OpenSSL 0.9.8, 1.0.1, 1.0.2 through 1.0.2h, and 1.1.0 in the way the TLS/SSL protocol defined processing of ALERT packets during a connection handshake. A remote attacker could use this flaw to make a TLS/SSL server consume an excessive amount of CPU and fail to accept connections from other clients.
</code>

- [cujanovic/CVE-2016-8610-PoC](https://github.com/cujanovic/CVE-2016-8610-PoC)

### CVE-2016-8636

<code>
Integer overflow in the mem_check_range function in drivers/infiniband/sw/rxe/rxe_mr.c in the Linux kernel before 4.9.10 allows local users to cause a denial of service (memory corruption), obtain sensitive information from kernel memory, or possibly have unspecified other impact via a write or read request involving the &quot;RDMA protocol over infiniband&quot; (aka Soft RoCE) technology.
</code>

- [jigerjain/Integer-Overflow-test](https://github.com/jigerjain/Integer-Overflow-test)

### CVE-2016-8655

<code>
Race condition in net/packet/af_packet.c in the Linux kernel through 4.8.12 allows local users to gain privileges or cause a denial of service (use-after-free) by leveraging the CAP_NET_RAW capability to change a socket version, related to the packet_set_ring and packet_setsockopt functions.
</code>

- [scarvell/cve-2016-8655](https://github.com/scarvell/cve-2016-8655)
- [LakshmiDesai/CVE-2016-8655](https://github.com/LakshmiDesai/CVE-2016-8655)
- [KosukeShimofuji/CVE-2016-8655](https://github.com/KosukeShimofuji/CVE-2016-8655)
- [agkunkle/chocobo](https://github.com/agkunkle/chocobo)
- [martinmullins/CVE-2016-8655_Android](https://github.com/martinmullins/CVE-2016-8655_Android)

### CVE-2016-8735

<code>
Remote code execution is possible with Apache Tomcat before 6.0.48, 7.x before 7.0.73, 8.x before 8.0.39, 8.5.x before 8.5.7, and 9.x before 9.0.0.M12 if JmxRemoteLifecycleListener is used and an attacker can reach JMX ports. The issue exists because this listener wasn't updated for consistency with the CVE-2016-3427 Oracle patch that affected credential types.
</code>

- [ianxtianxt/CVE-2016-8735](https://github.com/ianxtianxt/CVE-2016-8735)

### CVE-2016-8740

<code>
The mod_http2 module in the Apache HTTP Server 2.4.17 through 2.4.23, when the Protocols configuration includes h2 or h2c, does not restrict request-header length, which allows remote attackers to cause a denial of service (memory consumption) via crafted CONTINUATION frames in an HTTP/2 request.
</code>

- [lcfpadilha/mac0352-ep4](https://github.com/lcfpadilha/mac0352-ep4)

### CVE-2016-8776

<code>
Huawei P9 phones with software EVA-AL10C00,EVA-CL10C00,EVA-DL10C00,EVA-TL10C00 and P9 Lite phones with software VNS-L21C185 allow attackers to bypass the factory reset protection (FRP) to enter some functional modules without authorization and perform operations to update the Google account.
</code>

- [maviroxz/CVE-2016-8776](https://github.com/maviroxz/CVE-2016-8776)

### CVE-2016-8858

<code>
** DISPUTED ** The kex_input_kexinit function in kex.c in OpenSSH 6.x and 7.x through 7.3 allows remote attackers to cause a denial of service (memory consumption) by sending many duplicate KEXINIT requests.  NOTE: a third party reports that &quot;OpenSSH upstream does not consider this as a security issue.&quot;
</code>

- [dag-erling/kexkill](https://github.com/dag-erling/kexkill)

### CVE-2016-8869

<code>
The register method in the UsersModelRegistration class in controllers/user.php in the Users component in Joomla! before 3.6.4 allows remote attackers to gain privileges by leveraging incorrect use of unfiltered data when registering on a site.
</code>

- [sunsunza2009/Joomla-3.4.4-3.6.4_CVE-2016-8869_and_CVE-2016-8870](https://github.com/sunsunza2009/Joomla-3.4.4-3.6.4_CVE-2016-8869_and_CVE-2016-8870)
- [rustyJ4ck/JoomlaCVE20168869](https://github.com/rustyJ4ck/JoomlaCVE20168869)
- [cved-sources/cve-2016-8869](https://github.com/cved-sources/cve-2016-8869)

### CVE-2016-8870

<code>
The register method in the UsersModelRegistration class in controllers/user.php in the Users component in Joomla! before 3.6.4, when registration has been disabled, allows remote attackers to create user accounts by leveraging failure to check the Allow User Registration configuration setting.
</code>

- [cved-sources/cve-2016-8870](https://github.com/cved-sources/cve-2016-8870)

### CVE-2016-9066

<code>
A buffer overflow resulting in a potentially exploitable crash due to memory allocation issues when handling large amounts of incoming data. This vulnerability affects Thunderbird &lt; 45.5, Firefox ESR &lt; 45.5, and Firefox &lt; 50.
</code>

- [saelo/foxpwn](https://github.com/saelo/foxpwn)

### CVE-2016-9079

<code>
A use-after-free vulnerability in SVG Animation has been discovered. An exploit built on this vulnerability has been discovered in the wild targeting Firefox and Tor Browser users on Windows. This vulnerability affects Firefox &lt; 50.0.2, Firefox ESR &lt; 45.5.1, and Thunderbird &lt; 45.5.1.
</code>

- [LakshmiDesai/CVE-2016-9079](https://github.com/LakshmiDesai/CVE-2016-9079)
- [dangokyo/CVE-2016-9079](https://github.com/dangokyo/CVE-2016-9079)

### CVE-2016-9192

<code>
A vulnerability in Cisco AnyConnect Secure Mobility Client for Windows could allow an authenticated, local attacker to install and execute an arbitrary executable file with privileges equivalent to the Microsoft Windows operating system SYSTEM account. More Information: CSCvb68043. Known Affected Releases: 4.3(2039) 4.3(748). Known Fixed Releases: 4.3(4019) 4.4(225).
</code>

- [serializingme/cve-2016-9192](https://github.com/serializingme/cve-2016-9192)

### CVE-2016-9244

<code>
A BIG-IP virtual server configured with a Client SSL profile that has the non-default Session Tickets option enabled may leak up to 31 bytes of uninitialized memory. A remote attacker may exploit this vulnerability to obtain Secure Sockets Layer (SSL) session IDs from other sessions. It is possible that other data from uninitialized memory may be returned as well.
</code>

- [EgeBalci/Ticketbleed](https://github.com/EgeBalci/Ticketbleed)
- [glestel/minion-ticket-bleed-plugin](https://github.com/glestel/minion-ticket-bleed-plugin)

### CVE-2016-9838

<code>
An issue was discovered in components/com_users/models/registration.php in Joomla! before 3.6.5. Incorrect filtering of registration form data stored to the session on a validation error enables a user to gain access to a registered user's account and reset the user's group mappings, username, and password, as demonstrated by submitting a form that targets the `registration.register` task.
</code>

- [cved-sources/cve-2016-9838](https://github.com/cved-sources/cve-2016-9838)

### CVE-2016-9920

<code>
steps/mail/sendmail.inc in Roundcube before 1.1.7 and 1.2.x before 1.2.3, when no SMTP server is configured and the sendmail program is enabled, does not properly restrict the use of custom envelope-from addresses on the sendmail command line, which allows remote authenticated users to execute arbitrary code via a modified HTTP request that sends a crafted e-mail message.
</code>

- [t0kx/exploit-CVE-2016-9920](https://github.com/t0kx/exploit-CVE-2016-9920)


## 2015
### CVE-2015-0006

<code>
The Network Location Awareness (NLA) service in Microsoft Windows Server 2003 SP2, Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, and Windows Server 2012 Gold and R2 does not perform mutual authentication to determine a domain connection, which allows remote attackers to trigger an unintended permissive configuration by spoofing DNS and LDAP responses on a local network, aka &quot;NLA Security Feature Bypass Vulnerability.&quot;
</code>

- [bugch3ck/imposter](https://github.com/bugch3ck/imposter)

### CVE-2015-0057

<code>
win32k.sys in the kernel-mode drivers in Microsoft Windows Server 2003 SP2, Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, and Windows RT Gold and 8.1 allows local users to gain privileges via a crafted application, aka &quot;Win32k Elevation of Privilege Vulnerability.&quot;
</code>

- [55-AA/CVE-2015-0057](https://github.com/55-AA/CVE-2015-0057)

### CVE-2015-0072

<code>
Cross-site scripting (XSS) vulnerability in Microsoft Internet Explorer 9 through 11 allows remote attackers to bypass the Same Origin Policy and inject arbitrary web script or HTML via vectors involving an IFRAME element that triggers a redirect, a second IFRAME element that does not trigger a redirect, and an eval of a WindowProxy object, aka &quot;Universal XSS (UXSS).&quot;
</code>

- [dbellavista/uxss-poc](https://github.com/dbellavista/uxss-poc)

### CVE-2015-0204

<code>
The ssl3_get_key_exchange function in s3_clnt.c in OpenSSL before 0.9.8zd, 1.0.0 before 1.0.0p, and 1.0.1 before 1.0.1k allows remote SSL servers to conduct RSA-to-EXPORT_RSA downgrade attacks and facilitate brute-force decryption by offering a weak ephemeral RSA key in a noncompliant role, related to the &quot;FREAK&quot; issue.  NOTE: the scope of this CVE is only client code based on OpenSSL, not EXPORT_RSA issues associated with servers or other TLS implementations.
</code>

- [felmoltor/FreakVulnChecker](https://github.com/felmoltor/FreakVulnChecker)
- [scottjpack/Freak-Scanner](https://github.com/scottjpack/Freak-Scanner)
- [AbhishekGhosh/FREAK-Attack-CVE-2015-0204-Testing-Script](https://github.com/AbhishekGhosh/FREAK-Attack-CVE-2015-0204-Testing-Script)
- [niccoX/patch-openssl-CVE-2014-0291_CVE-2015-0204](https://github.com/niccoX/patch-openssl-CVE-2014-0291_CVE-2015-0204)

### CVE-2015-0231

<code>
Use-after-free vulnerability in the process_nested_data function in ext/standard/var_unserializer.re in PHP before 5.4.37, 5.5.x before 5.5.21, and 5.6.x before 5.6.5 allows remote attackers to execute arbitrary code via a crafted unserialize call that leverages improper handling of duplicate numerical keys within the serialized properties of an object.  NOTE: this vulnerability exists because of an incomplete fix for CVE-2014-8142.
</code>

- [3xp10it/php_cve-2014-8142_cve-2015-0231](https://github.com/3xp10it/php_cve-2014-8142_cve-2015-0231)

### CVE-2015-0235

<code>
Heap-based buffer overflow in the __nss_hostname_digits_dots function in glibc 2.2, and other 2.x versions before 2.18, allows context-dependent attackers to execute arbitrary code via vectors related to the (1) gethostbyname or (2) gethostbyname2 function, aka &quot;GHOST.&quot;
</code>

- [fser/ghost-checker](https://github.com/fser/ghost-checker)
- [mikesplain/CVE-2015-0235-cookbook](https://github.com/mikesplain/CVE-2015-0235-cookbook)
- [aaronfay/CVE-2015-0235-test](https://github.com/aaronfay/CVE-2015-0235-test)
- [piyokango/ghost](https://github.com/piyokango/ghost)
- [LyricalSecurity/GHOSTCHECK-cve-2015-0235](https://github.com/LyricalSecurity/GHOSTCHECK-cve-2015-0235)
- [mholzinger/CVE-2015-0235_GHOST](https://github.com/mholzinger/CVE-2015-0235_GHOST)
- [adherzog/ansible-CVE-2015-0235-GHOST](https://github.com/adherzog/ansible-CVE-2015-0235-GHOST)
- [favoretti/lenny-libc6](https://github.com/favoretti/lenny-libc6)
- [nickanderson/cfengine-CVE_2015_0235](https://github.com/nickanderson/cfengine-CVE_2015_0235)
- [koudaiii-archives/cookbook-update-glibc](https://github.com/koudaiii-archives/cookbook-update-glibc)
- [F88/ghostbusters15](https://github.com/F88/ghostbusters15)
- [JustDenisYT/ghosttester](https://github.com/JustDenisYT/ghosttester)
- [tobyzxj/CVE-2015-0235](https://github.com/tobyzxj/CVE-2015-0235)
- [makelinux/CVE-2015-0235-workaround](https://github.com/makelinux/CVE-2015-0235-workaround)
- [arm13/ghost_exploit](https://github.com/arm13/ghost_exploit)
- [alanmeyer/CVE-glibc](https://github.com/alanmeyer/CVE-glibc)
- [r0otshell/CVE-2015-0235](https://github.com/r0otshell/CVE-2015-0235)
- [chayim/GHOSTCHECK-cve-2015-0235](https://github.com/chayim/GHOSTCHECK-cve-2015-0235)

### CVE-2015-0313

<code>
Use-after-free vulnerability in Adobe Flash Player before 13.0.0.269 and 14.x through 16.x before 16.0.0.305 on Windows and OS X and before 11.2.202.442 on Linux allows remote attackers to execute arbitrary code via unspecified vectors, as exploited in the wild in February 2015, a different vulnerability than CVE-2015-0315, CVE-2015-0320, and CVE-2015-0322.
</code>

- [SecurityObscurity/cve-2015-0313](https://github.com/SecurityObscurity/cve-2015-0313)

### CVE-2015-0345

<code>
Cross-site scripting (XSS) vulnerability in Adobe ColdFusion 10 before Update 16 and 11 before Update 5 allows remote attackers to inject arbitrary web script or HTML via unspecified vectors.
</code>

- [BishopFox/coldfusion-10-11-xss](https://github.com/BishopFox/coldfusion-10-11-xss)

### CVE-2015-0568

<code>
Use-after-free vulnerability in the msm_set_crop function in drivers/media/video/msm/msm_camera.c in the MSM-Camera driver for the Linux kernel 3.x, as used in Qualcomm Innovation Center (QuIC) Android contributions for MSM devices and other products, allows attackers to gain privileges or cause a denial of service (memory corruption) via an application that makes a crafted ioctl call.
</code>

- [betalphafai/CVE-2015-0568](https://github.com/betalphafai/CVE-2015-0568)

### CVE-2015-0816

<code>
Mozilla Firefox before 37.0, Firefox ESR 31.x before 31.6, and Thunderbird before 31.6 do not properly restrict resource: URLs, which makes it easier for remote attackers to execute arbitrary JavaScript code with chrome privileges by leveraging the ability to bypass the Same Origin Policy, as demonstrated by the resource: URL associated with PDF.js.
</code>

- [Afudadi/Firefox-35-37-Exploit](https://github.com/Afudadi/Firefox-35-37-Exploit)

### CVE-2015-1130

<code>
The XPC implementation in Admin Framework in Apple OS X before 10.10.3 allows local users to bypass authentication and obtain admin privileges via unspecified vectors.
</code>

- [Shmoopi/RootPipe-Demo](https://github.com/Shmoopi/RootPipe-Demo)
- [sideeffect42/RootPipeTester](https://github.com/sideeffect42/RootPipeTester)

### CVE-2015-1140

<code>
Buffer overflow in IOHIDFamily in Apple OS X before 10.10.3 allows local users to gain privileges via unspecified vectors.
</code>

- [kpwn/vpwn](https://github.com/kpwn/vpwn)

### CVE-2015-1157

<code>
CoreText in Apple iOS 8.x through 8.3 allows remote attackers to cause a denial of service (reboot and messaging disruption) via crafted Unicode text that is not properly handled during display truncation in the Notifications feature, as demonstrated by Arabic characters in (1) an SMS message or (2) a WhatsApp message.
</code>

- [perillamint/CVE-2015-1157](https://github.com/perillamint/CVE-2015-1157)

### CVE-2015-1318

<code>
The crash reporting feature in Apport 2.13 through 2.17.x before 2.17.1 allows local users to gain privileges via a crafted usr/share/apport/apport file in a namespace (container).
</code>

- [ScottyBauer/CVE-2015-1318](https://github.com/ScottyBauer/CVE-2015-1318)

### CVE-2015-1328

<code>
The overlayfs implementation in the linux (aka Linux kernel) package before 3.19.0-21.21 in Ubuntu through 15.04 does not properly check permissions for file creation in the upper filesystem directory, which allows local users to obtain root access by leveraging a configuration in which overlayfs is permitted in an arbitrary mount namespace.
</code>

- [SR7-HACKING/LINUX-VULNERABILITY-CVE-2015-1328](https://github.com/SR7-HACKING/LINUX-VULNERABILITY-CVE-2015-1328)

### CVE-2015-1427

<code>
The Groovy scripting engine in Elasticsearch before 1.3.8 and 1.4.x before 1.4.3 allows remote attackers to bypass the sandbox protection mechanism and execute arbitrary shell commands via a crafted script.
</code>

- [t0kx/exploit-CVE-2015-1427](https://github.com/t0kx/exploit-CVE-2015-1427)
- [cved-sources/cve-2015-1427](https://github.com/cved-sources/cve-2015-1427)

### CVE-2015-1474

<code>
Multiple integer overflows in the GraphicBuffer::unflatten function in platform/frameworks/native/libs/ui/GraphicBuffer.cpp in Android through 5.0 allow attackers to gain privileges or cause a denial of service (memory corruption) via vectors that trigger a large number of (1) file descriptors or (2) integer values.
</code>

- [p1gl3t/CVE-2015-1474_poc](https://github.com/p1gl3t/CVE-2015-1474_poc)

### CVE-2015-1528

<code>
Integer overflow in the native_handle_create function in libcutils/native_handle.c in Android before 5.1.1 LMY48M allows attackers to obtain a different application's privileges or cause a denial of service (Binder heap memory corruption) via a crafted application, aka internal bug 19334482.
</code>

- [secmob/PoCForCVE-2015-1528](https://github.com/secmob/PoCForCVE-2015-1528)
- [kanpol/PoCForCVE-2015-1528](https://github.com/kanpol/PoCForCVE-2015-1528)

### CVE-2015-1538

<code>
Integer overflow in the SampleTable::setSampleToChunkParams function in SampleTable.cpp in libstagefright in Android before 5.1.1 LMY48I allows remote attackers to execute arbitrary code via crafted atoms in MP4 data that trigger an unchecked multiplication, aka internal bug 20139950, a related issue to CVE-2015-4496.
</code>

- [oguzhantopgul/cve-2015-1538-1](https://github.com/oguzhantopgul/cve-2015-1538-1)
- [renjithsasidharan/cve-2015-1538-1](https://github.com/renjithsasidharan/cve-2015-1538-1)
- [jduck/cve-2015-1538-1](https://github.com/jduck/cve-2015-1538-1)
- [marZiiw/Stagefright_CVE-2015-1538-1](https://github.com/marZiiw/Stagefright_CVE-2015-1538-1)
- [niranjanshr13/Stagefright-cve-2015-1538-1](https://github.com/niranjanshr13/Stagefright-cve-2015-1538-1)
- [Tharana/Android-vulnerability-exploitation](https://github.com/Tharana/Android-vulnerability-exploitation)
- [Tharana/vulnerability-exploitation](https://github.com/Tharana/vulnerability-exploitation)

### CVE-2015-1560

<code>
SQL injection vulnerability in the isUserAdmin function in include/common/common-Func.php in Centreon (formerly Merethis Centreon) 2.5.4 and earlier (fixed in Centreon web 2.7.0) allows remote attackers to execute arbitrary SQL commands via the sid parameter to include/common/XmlTree/GetXmlTree.php.
</code>

- [Iansus/Centreon-CVE-2015-1560_1561](https://github.com/Iansus/Centreon-CVE-2015-1560_1561)

### CVE-2015-1579

<code>
Directory traversal vulnerability in the Elegant Themes Divi theme for WordPress allows remote attackers to read arbitrary files via a .. (dot dot) in the img parameter in a revslider_show_image action to wp-admin/admin-ajax.php.  NOTE: this vulnerability may be a duplicate of CVE-2014-9734.
</code>

- [paralelo14/WordPressMassExploiter](https://github.com/paralelo14/WordPressMassExploiter)
- [paralelo14/CVE-2015-1579](https://github.com/paralelo14/CVE-2015-1579)

### CVE-2015-1592

<code>
Movable Type Pro, Open Source, and Advanced before 5.2.12 and Pro and Advanced 6.0.x before 6.0.7 does not properly use the Perl Storable::thaw function, which allows remote attackers to include and execute arbitrary local Perl files and possibly execute arbitrary code via unspecified vectors.
</code>

- [lightsey/cve-2015-1592](https://github.com/lightsey/cve-2015-1592)

### CVE-2015-1635

<code>
HTTP.sys in Microsoft Windows 7 SP1, Windows Server 2008 R2 SP1, Windows 8, Windows 8.1, and Windows Server 2012 Gold and R2 allows remote attackers to execute arbitrary code via crafted HTTP requests, aka &quot;HTTP.sys Remote Code Execution Vulnerability.&quot;
</code>

- [xPaw/HTTPsys](https://github.com/xPaw/HTTPsys)
- [Zx7ffa4512-Python/Project-CVE-2015-1635](https://github.com/Zx7ffa4512-Python/Project-CVE-2015-1635)
- [technion/erlvulnscan](https://github.com/technion/erlvulnscan)
- [wiredaem0n/chk-ms15-034](https://github.com/wiredaem0n/chk-ms15-034)
- [1337r00t/Remove-IIS-RIIS](https://github.com/1337r00t/Remove-IIS-RIIS)
- [bongbongco/MS15-034](https://github.com/bongbongco/MS15-034)
- [aedoo/CVE-2015-1635-POC](https://github.com/aedoo/CVE-2015-1635-POC)
- [limkokhole/CVE-2015-1635](https://github.com/limkokhole/CVE-2015-1635)

### CVE-2015-1641

<code>
Microsoft Word 2007 SP3, Office 2010 SP2, Word 2010 SP2, Word 2013 SP1, Word 2013 RT SP1, Word for Mac 2011, Office Compatibility Pack SP3, Word Automation Services on SharePoint Server 2010 SP2 and 2013 SP1, and Office Web Apps Server 2010 SP2 and 2013 SP1 allow remote attackers to execute arbitrary code via a crafted RTF document, aka &quot;Microsoft Office Memory Corruption Vulnerability.&quot;
</code>

- [Cyberclues/rtf_exploit_extractor](https://github.com/Cyberclues/rtf_exploit_extractor)

### CVE-2015-1701

<code>
Win32k.sys in the kernel-mode drivers in Microsoft Windows Server 2003 SP2, Vista SP2, and Server 2008 SP2 allows local users to gain privileges via a crafted application, as exploited in the wild in April 2015, aka &quot;Win32k Elevation of Privilege Vulnerability.&quot;
</code>

- [hfiref0x/CVE-2015-1701](https://github.com/hfiref0x/CVE-2015-1701)

### CVE-2015-1805

<code>
The (1) pipe_read and (2) pipe_write implementations in fs/pipe.c in the Linux kernel before 3.16 do not properly consider the side effects of failed __copy_to_user_inatomic and __copy_from_user_inatomic calls, which allows local users to cause a denial of service (system crash) or possibly gain privileges via a crafted application, aka an &quot;I/O vector array overrun.&quot;
</code>

- [panyu6325/CVE-2015-1805](https://github.com/panyu6325/CVE-2015-1805)
- [dosomder/iovyroot](https://github.com/dosomder/iovyroot)
- [FloatingGuy/cve-2015-1805](https://github.com/FloatingGuy/cve-2015-1805)
- [mobilelinux/iovy_root_research](https://github.com/mobilelinux/iovy_root_research)

### CVE-2015-1855

<code>
verify_certificate_identity in the OpenSSL extension in Ruby before 2.0.0 patchlevel 645, 2.1.x before 2.1.6, and 2.2.x before 2.2.2 does not properly validate hostnames, which allows remote attackers to spoof servers via vectors related to (1) multiple wildcards, (1) wildcards in IDNA names, (3) case sensitivity, and (4) non-ASCII characters.
</code>

- [vpereira/CVE-2015-1855](https://github.com/vpereira/CVE-2015-1855)

### CVE-2015-2080

<code>
The exception handling code in Eclipse Jetty before 9.2.9.v20150224 allows remote attackers to obtain sensitive information from process memory via illegal characters in an HTTP header, aka JetLeak.
</code>

- [BizarreNULL/CVE-2015-2080](https://github.com/BizarreNULL/CVE-2015-2080)

### CVE-2015-2153

<code>
The rpki_rtr_pdu_print function in print-rpki-rtr.c in the TCP printer in tcpdump before 4.7.2 allows remote attackers to cause a denial of service (out-of-bounds read or write and crash) via a crafted header length in an RPKI-RTR Protocol Data Unit (PDU).
</code>

- [arntsonl/CVE-2015-2153](https://github.com/arntsonl/CVE-2015-2153)

### CVE-2015-2208

<code>
The saveObject function in moadmin.php in phpMoAdmin 1.1.2 allows remote attackers to execute arbitrary commands via shell metacharacters in the object parameter.
</code>

- [ptantiku/cve-2015-2208](https://github.com/ptantiku/cve-2015-2208)

### CVE-2015-2231
- [rednaga/adups-get-super-serial](https://github.com/rednaga/adups-get-super-serial)

### CVE-2015-2291

<code>
(1) IQVW32.sys before 1.3.1.0 and (2) IQVW64.sys before 1.3.1.0 in the Intel Ethernet diagnostics driver for Windows allows local users to cause a denial of service or possibly execute arbitrary code with kernel privileges via a crafted (a) 0x80862013, (b) 0x8086200B, (c) 0x8086200F, or (d) 0x80862007 IOCTL call.
</code>

- [Tare05/Intel-CVE-2015-2291](https://github.com/Tare05/Intel-CVE-2015-2291)

### CVE-2015-2315

<code>
Cross-site scripting (XSS) vulnerability in the WPML plugin before 3.1.9 for WordPress allows remote attackers to inject arbitrary web script or HTML via the target parameter in a reminder_popup action to the default URI.
</code>

- [weidongl74/cve-2015-2315-report](https://github.com/weidongl74/cve-2015-2315-report)

### CVE-2015-2546

<code>
The kernel-mode driver in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT Gold and 8.1, and Windows 10 allows local users to gain privileges via a crafted application, aka &quot;Win32k Memory Corruption Elevation of Privilege Vulnerability,&quot; a different vulnerability than CVE-2015-2511, CVE-2015-2517, and CVE-2015-2518.
</code>

- [k0keoyo/CVE-2015-2546-Exploit](https://github.com/k0keoyo/CVE-2015-2546-Exploit)

### CVE-2015-2794

<code>
The installation wizard in DotNetNuke (DNN) before 7.4.1 allows remote attackers to reinstall the application and gain SuperUser access via a direct request to Install/InstallWizard.aspx.
</code>

- [styx00/DNN_CVE-2015-2794](https://github.com/styx00/DNN_CVE-2015-2794)
- [wilsc0w/CVE-2015-2794-finder](https://github.com/wilsc0w/CVE-2015-2794-finder)

### CVE-2015-2900

<code>
The AddUserFinding add_userfinding2 function in Medicomp MEDCIN Engine before 2.22.20153.226 allows remote attackers to cause a denial of service (out-of-bounds write) or possibly have unspecified other impact via a crafted packet on port 8190.
</code>

- [securifera/CVE-2015-2900-Exploit](https://github.com/securifera/CVE-2015-2900-Exploit)

### CVE-2015-2925

<code>
The prepend_path function in fs/dcache.c in the Linux kernel before 4.2.4 does not properly handle rename actions inside a bind mount, which allows local users to bypass an intended container protection mechanism by renaming a directory, related to a &quot;double-chroot attack.&quot;
</code>

- [Kagami/docker_cve-2015-2925](https://github.com/Kagami/docker_cve-2015-2925)

### CVE-2015-3043

<code>
Adobe Flash Player before 13.0.0.281 and 14.x through 17.x before 17.0.0.169 on Windows and OS X and before 11.2.202.457 on Linux allows attackers to execute arbitrary code or cause a denial of service (memory corruption) via unspecified vectors, as exploited in the wild in April 2015, a different vulnerability than CVE-2015-0347, CVE-2015-0350, CVE-2015-0352, CVE-2015-0353, CVE-2015-0354, CVE-2015-0355, CVE-2015-0360, CVE-2015-3038, CVE-2015-3041, and CVE-2015-3042.
</code>

- [whitehairman/Exploit](https://github.com/whitehairman/Exploit)

### CVE-2015-3073

<code>
Adobe Reader and Acrobat 10.x before 10.1.14 and 11.x before 11.0.11 on Windows and OS X allow attackers to bypass intended restrictions on JavaScript API execution via unspecified vectors, a different vulnerability than CVE-2015-3060, CVE-2015-3061, CVE-2015-3062, CVE-2015-3063, CVE-2015-3064, CVE-2015-3065, CVE-2015-3066, CVE-2015-3067, CVE-2015-3068, CVE-2015-3069, CVE-2015-3071, CVE-2015-3072, and CVE-2015-3074.
</code>

- [reigningshells/CVE-2015-3073](https://github.com/reigningshells/CVE-2015-3073)

### CVE-2015-3152

<code>
Oracle MySQL before 5.7.3, Oracle MySQL Connector/C (aka libmysqlclient) before 6.1.3, and MariaDB before 5.5.44 use the --ssl option to mean that SSL is optional, which allows man-in-the-middle attackers to spoof servers via a cleartext-downgrade attack, aka a &quot;BACKRONYM&quot; attack.
</code>

- [duo-labs/mysslstrip](https://github.com/duo-labs/mysslstrip)

### CVE-2015-3224

<code>
request.rb in Web Console before 2.1.3, as used with Ruby on Rails 3.x and 4.x, does not properly restrict the use of X-Forwarded-For headers in determining a client's IP address, which allows remote attackers to bypass the whitelisted_ips protection mechanism via a crafted request.
</code>

- [0x00-0x00/CVE-2015-3224](https://github.com/0x00-0x00/CVE-2015-3224)
- [0xEval/cve-2015-3224](https://github.com/0xEval/cve-2015-3224)

### CVE-2015-3306

<code>
The mod_copy module in ProFTPD 1.3.5 allows remote attackers to read and write to arbitrary files via the site cpfr and site cpto commands.
</code>

- [chcx/cpx_proftpd](https://github.com/chcx/cpx_proftpd)
- [nootropics/propane](https://github.com/nootropics/propane)
- [t0kx/exploit-CVE-2015-3306](https://github.com/t0kx/exploit-CVE-2015-3306)
- [davidtavarez/CVE-2015-3306](https://github.com/davidtavarez/CVE-2015-3306)
- [cved-sources/cve-2015-3306](https://github.com/cved-sources/cve-2015-3306)
- [hackarada/cve-2015-3306](https://github.com/hackarada/cve-2015-3306)

### CVE-2015-3337

<code>
Directory traversal vulnerability in Elasticsearch before 1.4.5 and 1.5.x before 1.5.2, when a site plugin is enabled, allows remote attackers to read arbitrary files via unspecified vectors.
</code>

- [jas502n/CVE-2015-3337](https://github.com/jas502n/CVE-2015-3337)

### CVE-2015-3456

<code>
The Floppy Disk Controller (FDC) in QEMU, as used in Xen 4.5.x and earlier and KVM, allows local guest users to cause a denial of service (out-of-bounds write and guest crash) or possibly execute arbitrary code via the (1) FD_CMD_READ_ID, (2) FD_CMD_DRIVE_SPECIFICATION_COMMAND, or other unspecified commands, aka VENOM.
</code>

- [vincentbernat/cve-2015-3456](https://github.com/vincentbernat/cve-2015-3456)
- [MauroEldritch/venom](https://github.com/MauroEldritch/venom)

### CVE-2015-3636

<code>
The ping_unhash function in net/ipv4/ping.c in the Linux kernel before 4.0.3 does not initialize a certain list data structure during an unhash operation, which allows local users to gain privileges or cause a denial of service (use-after-free and system crash) by leveraging the ability to make a SOCK_DGRAM socket system call for the IPPROTO_ICMP or IPPROTO_ICMPV6 protocol, and then making a connect system call after a disconnect.
</code>

- [betalphafai/cve-2015-3636_crash](https://github.com/betalphafai/cve-2015-3636_crash)
- [askk/libping_unhash_exploit_POC](https://github.com/askk/libping_unhash_exploit_POC)
- [ludongxu/cve-2015-3636](https://github.com/ludongxu/cve-2015-3636)
- [fi01/CVE-2015-3636](https://github.com/fi01/CVE-2015-3636)
- [android-rooting-tools/libpingpong_exploit](https://github.com/android-rooting-tools/libpingpong_exploit)
- [debugfan/rattle_root](https://github.com/debugfan/rattle_root)
- [a7vinx/CVE-2015-3636](https://github.com/a7vinx/CVE-2015-3636)

### CVE-2015-3825
- [roeeh/conscryptchecker](https://github.com/roeeh/conscryptchecker)

### CVE-2015-3837

<code>
The OpenSSLX509Certificate class in org/conscrypt/OpenSSLX509Certificate.java in Android before 5.1.1 LMY48I improperly includes certain context data during serialization and deserialization, which allows attackers to execute arbitrary code via an application that sends a crafted Intent, aka internal bug 21437603.
</code>

- [itibs/IsildursBane](https://github.com/itibs/IsildursBane)

### CVE-2015-3839

<code>
The updateMessageStatus function in Android 5.1.1 and earlier allows local users to cause a denial of service (NULL pointer exception and process crash).
</code>

- [mabin004/cve-2015-3839_PoC](https://github.com/mabin004/cve-2015-3839_PoC)

### CVE-2015-3864

<code>
Integer underflow in the MPEG4Extractor::parseChunk function in MPEG4Extractor.cpp in libstagefright in mediaserver in Android before 5.1.1 LMY48M allows remote attackers to execute arbitrary code via crafted MPEG-4 data, aka internal bug 23034759.  NOTE: this vulnerability exists because of an incomplete fix for CVE-2015-3824.
</code>

- [pwnaccelerator/stagefright-cve-2015-3864](https://github.com/pwnaccelerator/stagefright-cve-2015-3864)
- [eudemonics/scaredycat](https://github.com/eudemonics/scaredycat)
- [HenryVHuang/CVE-2015-3864](https://github.com/HenryVHuang/CVE-2015-3864)

### CVE-2015-4495

<code>
The PDF reader in Mozilla Firefox before 39.0.3, Firefox ESR 38.x before 38.1.1, and Firefox OS before 2.2 allows remote attackers to bypass the Same Origin Policy, and read arbitrary files or gain privileges, via vectors involving crafted JavaScript code and a native setter, as exploited in the wild in August 2015.
</code>

- [vincd/CVE-2015-4495](https://github.com/vincd/CVE-2015-4495)

### CVE-2015-4852

<code>
The WLS Security component in Oracle WebLogic Server 10.3.6.0, 12.1.2.0, 12.1.3.0, and 12.2.1.0 allows remote attackers to execute arbitrary commands via a crafted serialized Java object in T3 protocol traffic to TCP port 7001, related to oracle_common/modules/com.bea.core.apache.commons.collections.jar. NOTE: the scope of this CVE is limited to the WebLogic Server product.
</code>

- [roo7break/serialator](https://github.com/roo7break/serialator)
- [AndersonSingh/serialization-vulnerability-scanner](https://github.com/AndersonSingh/serialization-vulnerability-scanner)

### CVE-2015-4870

<code>
Unspecified vulnerability in Oracle MySQL Server 5.5.45 and earlier, and 5.6.26 and earlier, allows remote authenticated users to affect availability via unknown vectors related to Server : Parser.
</code>

- [OsandaMalith/CVE-2015-4870](https://github.com/OsandaMalith/CVE-2015-4870)

### CVE-2015-5119

<code>
Use-after-free vulnerability in the ByteArray class in the ActionScript 3 (AS3) implementation in Adobe Flash Player 13.x through 13.0.0.296 and 14.x through 18.0.0.194 on Windows and OS X and 11.x through 11.2.202.468 on Linux allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via crafted Flash content that overrides a valueOf function, as exploited in the wild in July 2015.
</code>

- [jvazquez-r7/CVE-2015-5119](https://github.com/jvazquez-r7/CVE-2015-5119)
- [portcullislabs/CVE-2015-5119_walkthrough](https://github.com/portcullislabs/CVE-2015-5119_walkthrough)
- [dangokyo/CVE-2015-5119](https://github.com/dangokyo/CVE-2015-5119)

### CVE-2015-5195

<code>
ntp_openssl.m4 in ntpd in NTP before 4.2.7p112 allows remote attackers to cause a denial of service (segmentation fault) via a crafted statistics or filegen configuration command that is not enabled during compilation.
</code>

- [theglife214/CVE-2015-5195](https://github.com/theglife214/CVE-2015-5195)

### CVE-2015-5254

<code>
Apache ActiveMQ 5.x before 5.13.0 does not restrict the classes that can be serialized in the broker, which allows remote attackers to execute arbitrary code via a crafted serialized Java Message Service (JMS) ObjectMessage object.
</code>

- [jas502n/CVE-2015-5254](https://github.com/jas502n/CVE-2015-5254)

### CVE-2015-5290

<code>
A Denial of Service vulnerability exists in ircd-ratbox 3.0.9 in the MONITOR Command Handler.
</code>

- [skyhighwings/CVE-2015-5290](https://github.com/skyhighwings/CVE-2015-5290)

### CVE-2015-5374

<code>
A vulnerability has been identified in Firmware variant PROFINET IO for EN100 Ethernet module : All versions &lt; V1.04.01; Firmware variant Modbus TCP for EN100 Ethernet module : All versions &lt; V1.11.00; Firmware variant DNP3 TCP for EN100 Ethernet module : All versions &lt; V1.03; Firmware variant IEC 104 for EN100 Ethernet module : All versions &lt; V1.21; EN100 Ethernet module included in SIPROTEC Merging Unit 6MU80 : All versions &lt; 1.02.02. Specially crafted packets sent to port 50000/UDP could cause a denial-of-service of the affected device. A manual reboot may be required to recover the service of the device.
</code>

- [can/CVE-2015-5374-DoS-PoC](https://github.com/can/CVE-2015-5374-DoS-PoC)

### CVE-2015-5454

<code>
Cross-site scripting (XSS) vulnerability in Nucleus CMS allows remote attackers to inject arbitrary web script or HTML via the title parameter when adding a new item.
</code>

- [security-breachlock/CVE-2015-5454](https://github.com/security-breachlock/CVE-2015-5454)

### CVE-2015-5477

<code>
named in ISC BIND 9.x before 9.9.7-P2 and 9.10.x before 9.10.2-P3 allows remote attackers to cause a denial of service (REQUIRE assertion failure and daemon exit) via TKEY queries.
</code>

- [robertdavidgraham/cve-2015-5477](https://github.com/robertdavidgraham/cve-2015-5477)
- [elceef/tkeypoc](https://github.com/elceef/tkeypoc)
- [hmlio/vaas-cve-2015-5477](https://github.com/hmlio/vaas-cve-2015-5477)
- [knqyf263/cve-2015-5477](https://github.com/knqyf263/cve-2015-5477)
- [ilanyu/cve-2015-5477](https://github.com/ilanyu/cve-2015-5477)
- [denmilu/ShareDoc_cve-2015-5477](https://github.com/denmilu/ShareDoc_cve-2015-5477)
- [xycloops123/TKEY-remote-DoS-vulnerability-exploit](https://github.com/xycloops123/TKEY-remote-DoS-vulnerability-exploit)

### CVE-2015-5602

<code>
sudoedit in Sudo before 1.8.15 allows local users to gain privileges via a symlink attack on a file whose full path is defined using multiple wildcards in /etc/sudoers, as demonstrated by &quot;/home/*/*/file.txt.&quot;
</code>

- [t0kx/privesc-CVE-2015-5602](https://github.com/t0kx/privesc-CVE-2015-5602)
- [cved-sources/cve-2015-5602](https://github.com/cved-sources/cve-2015-5602)

### CVE-2015-5932

<code>
The kernel in Apple OS X before 10.11.1 allows local users to gain privileges by leveraging an unspecified &quot;type confusion&quot; during Mach task processing.
</code>

- [jndok/tpwn-bis](https://github.com/jndok/tpwn-bis)

### CVE-2015-5995

<code>
Mediabridge Medialink MWN-WAPR300N devices with firmware 5.07.50 and Tenda N3 Wireless N150 devices allow remote attackers to obtain administrative access via a certain admin substring in an HTTP Cookie header.
</code>

- [shaheemirza/TendaSpill](https://github.com/shaheemirza/TendaSpill)

### CVE-2015-6086

<code>
Microsoft Internet Explorer 9 through 11 allows remote attackers to obtain sensitive information from process memory via a crafted web site, aka &quot;Internet Explorer Information Disclosure Vulnerability.&quot;
</code>

- [payatu/CVE-2015-6086](https://github.com/payatu/CVE-2015-6086)

### CVE-2015-6095

<code>
Kerberos in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT Gold and 8.1, and Windows 10 Gold and 1511 mishandles password changes, which allows physically proximate attackers to bypass authentication, and conduct decryption attacks against certain BitLocker configurations, by connecting to an unintended Key Distribution Center (KDC), aka &quot;Windows Kerberos Security Feature Bypass.&quot;
</code>

- [JackOfMostTrades/bluebox](https://github.com/JackOfMostTrades/bluebox)

### CVE-2015-6132

<code>
Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT Gold and 8.1, and Windows 10 Gold and 1511 mishandle library loading, which allows local users to gain privileges via a crafted application, aka &quot;Windows Library Loading Remote Code Execution Vulnerability.&quot;
</code>

- [hexx0r/CVE-2015-6132](https://github.com/hexx0r/CVE-2015-6132)

### CVE-2015-6357

<code>
The rule-update feature in Cisco FireSIGHT Management Center (MC) 5.2 through 5.4.0.1 does not verify the X.509 certificate of the support.sourcefire.com SSL server, which allows man-in-the-middle attackers to spoof this server and provide an invalid package, and consequently execute arbitrary code, via a crafted certificate, aka Bug ID CSCuw06444.
</code>

- [mattimustang/firepwner](https://github.com/mattimustang/firepwner)

### CVE-2015-6576

<code>
Bamboo 2.2 before 5.8.5 and 5.9.x before 5.9.7 allows remote attackers with access to the Bamboo web interface to execute arbitrary Java code via an unspecified resource.
</code>

- [CallMeJonas/CVE-2015-6576](https://github.com/CallMeJonas/CVE-2015-6576)

### CVE-2015-6606

<code>
The Secure Element Evaluation Kit (aka SEEK or SmartCard API) plugin in Android before 5.1.1 LMY48T allows attackers to gain privileges via a crafted application, as demonstrated by obtaining Signature or SignatureOrSystem access, aka internal bug 22301786.
</code>

- [michaelroland/omapi-cve-2015-6606-exploit](https://github.com/michaelroland/omapi-cve-2015-6606-exploit)

### CVE-2015-6612

<code>
libmedia in Android before 5.1.1 LMY48X and 6.0 before 2015-11-01 allows attackers to gain privileges via a crafted application, aka internal bug 23540426.
</code>

- [secmob/CVE-2015-6612](https://github.com/secmob/CVE-2015-6612)
- [flankerhqd/cve-2015-6612poc-forM](https://github.com/flankerhqd/cve-2015-6612poc-forM)

### CVE-2015-6620

<code>
libstagefright in Android before 5.1.1 LMY48Z and 6.0 before 2015-12-01 allows attackers to gain privileges via a crafted application, as demonstrated by obtaining Signature or SignatureOrSystem access, aka internal bugs 24123723 and 24445127.
</code>

- [flankerhqd/CVE-2015-6620-POC](https://github.com/flankerhqd/CVE-2015-6620-POC)
- [flankerhqd/mediacodecoob](https://github.com/flankerhqd/mediacodecoob)

### CVE-2015-6637

<code>
The MediaTek misc-sd driver in Android before 5.1.1 LMY49F and 6.0 before 2016-01-01 allows attackers to gain privileges via a crafted application, aka internal bug 25307013.
</code>

- [betalphafai/CVE-2015-6637](https://github.com/betalphafai/CVE-2015-6637)

### CVE-2015-6639

<code>
The Widevine QSEE TrustZone application in Android 5.x before 5.1.1 LMY49F and 6.0 before 2016-01-01 allows attackers to gain privileges via a crafted application that leverages QSEECOM access, aka internal bug 24446875.
</code>

- [laginimaineb/cve-2015-6639](https://github.com/laginimaineb/cve-2015-6639)
- [laginimaineb/ExtractKeyMaster](https://github.com/laginimaineb/ExtractKeyMaster)

### CVE-2015-6640

<code>
The prctl_set_vma_anon_name function in kernel/sys.c in Android before 5.1.1 LMY49F and 6.0 before 2016-01-01 does not ensure that only one vma is accessed in a certain update action, which allows attackers to gain privileges or cause a denial of service (vma list corruption) via a crafted application, aka internal bug 20017123.
</code>

- [betalphafai/CVE-2015-6640](https://github.com/betalphafai/CVE-2015-6640)

### CVE-2015-6835

<code>
The session deserializer in PHP before 5.4.45, 5.5.x before 5.5.29, and 5.6.x before 5.6.13 mishandles multiple php_var_unserialize calls, which allow remote attackers to execute arbitrary code or cause a denial of service (use-after-free) via crafted session content.
</code>

- [ockeghem/CVE-2015-6835-checker](https://github.com/ockeghem/CVE-2015-6835-checker)

### CVE-2015-6967

<code>
Unrestricted file upload vulnerability in the My Image plugin in Nibbleblog before 4.0.5 allows remote administrators to execute arbitrary code by uploading a file with an executable extension, then accessing it via a direct request to the file in content/private/plugins/my_image/image.php.
</code>

- [VanTekken/CVE-2015-6967](https://github.com/VanTekken/CVE-2015-6967)

### CVE-2015-7214

<code>
Mozilla Firefox before 43.0 and Firefox ESR 38.x before 38.5 allow remote attackers to bypass the Same Origin Policy via data: and view-source: URIs.
</code>

- [llamakko/CVE-2015-7214](https://github.com/llamakko/CVE-2015-7214)

### CVE-2015-7297

<code>
SQL injection vulnerability in Joomla! 3.2 before 3.4.4 allows remote attackers to execute arbitrary SQL commands via unspecified vectors, a different vulnerability than CVE-2015-7858.
</code>

- [CCrashBandicot/ContentHistory](https://github.com/CCrashBandicot/ContentHistory)

### CVE-2015-7501

<code>
Red Hat JBoss A-MQ 6.x; BPM Suite (BPMS) 6.x; BRMS 6.x and 5.x; Data Grid (JDG) 6.x; Data Virtualization (JDV) 6.x and 5.x; Enterprise Application Platform 6.x, 5.x, and 4.3.x; Fuse 6.x; Fuse Service Works (FSW) 6.x; Operations Network (JBoss ON) 3.x; Portal 6.x; SOA Platform (SOA-P) 5.x; Web Server (JWS) 3.x; Red Hat OpenShift/xPAAS 3.x; and Red Hat Subscription Asset Manager 1.3 allow remote attackers to execute arbitrary commands via a crafted serialized Java object, related to the Apache Commons Collections (ACC) library.
</code>

- [ianxtianxt/CVE-2015-7501](https://github.com/ianxtianxt/CVE-2015-7501)

### CVE-2015-7545

<code>
The (1) git-remote-ext and (2) unspecified other remote helper programs in Git before 2.3.10, 2.4.x before 2.4.10, 2.5.x before 2.5.4, and 2.6.x before 2.6.1 do not properly restrict the allowed protocols, which might allow remote attackers to execute arbitrary code via a URL in a (a) .gitmodules file or (b) unknown other sources in a submodule.
</code>

- [avuserow/bug-free-chainsaw](https://github.com/avuserow/bug-free-chainsaw)

### CVE-2015-7547

<code>
Multiple stack-based buffer overflows in the (1) send_dg and (2) send_vc functions in the libresolv library in the GNU C Library (aka glibc or libc6) before 2.23 allow remote attackers to cause a denial of service (crash) or possibly execute arbitrary code via a crafted DNS response that triggers a call to the getaddrinfo function with the AF_UNSPEC or AF_INET6 address family, related to performing &quot;dual A/AAAA DNS queries&quot; and the libnss_dns.so.2 NSS module.
</code>

- [fjserna/CVE-2015-7547](https://github.com/fjserna/CVE-2015-7547)
- [cakuzo/CVE-2015-7547](https://github.com/cakuzo/CVE-2015-7547)
- [t0r0t0r0/CVE-2015-7547](https://github.com/t0r0t0r0/CVE-2015-7547)
- [JustDenisYT/glibc-patcher](https://github.com/JustDenisYT/glibc-patcher)
- [rexifiles/rex-sec-glibc](https://github.com/rexifiles/rex-sec-glibc)
- [babykillerblack/CVE-2015-7547](https://github.com/babykillerblack/CVE-2015-7547)
- [jgajek/cve-2015-7547](https://github.com/jgajek/cve-2015-7547)
- [eSentire/cve-2015-7547-public](https://github.com/eSentire/cve-2015-7547-public)
- [bluebluelan/CVE-2015-7547-proj-master](https://github.com/bluebluelan/CVE-2015-7547-proj-master)
- [miracle03/CVE-2015-7547-master](https://github.com/miracle03/CVE-2015-7547-master)
- [Amilaperera12/Glibc-Vulnerability-Exploit-CVE-2015-7547](https://github.com/Amilaperera12/Glibc-Vulnerability-Exploit-CVE-2015-7547)

### CVE-2015-7755

<code>
Juniper ScreenOS 6.2.0r15 through 6.2.0r18, 6.3.0r12 before 6.3.0r12b, 6.3.0r13 before 6.3.0r13b, 6.3.0r14 before 6.3.0r14b, 6.3.0r15 before 6.3.0r15b, 6.3.0r16 before 6.3.0r16b, 6.3.0r17 before 6.3.0r17b, 6.3.0r18 before 6.3.0r18b, 6.3.0r19 before 6.3.0r19b, and 6.3.0r20 before 6.3.0r21 allows remote attackers to obtain administrative access by entering an unspecified password during a (1) SSH or (2) TELNET session.
</code>

- [hdm/juniper-cve-2015-7755](https://github.com/hdm/juniper-cve-2015-7755)
- [cinno/CVE-2015-7755-POC](https://github.com/cinno/CVE-2015-7755-POC)

### CVE-2015-7808

<code>
The vB_Api_Hook::decodeArguments method in vBulletin 5 Connect 5.1.2 through 5.1.9 allows remote attackers to conduct PHP object injection attacks and execute arbitrary PHP code via a crafted serialized object in the arguments parameter to ajax/api/hook/decodeArguments.
</code>

- [Prajithp/CVE-2015-7808](https://github.com/Prajithp/CVE-2015-7808)

### CVE-2015-8088

<code>
Heap-based buffer overflow in the HIFI driver in Huawei Mate 7 phones with software MT7-UL00 before MT7-UL00C17B354, MT7-TL10 before MT7-TL10C00B354, MT7-TL00 before MT7-TL00C01B354, and MT7-CL00 before MT7-CL00C92B354 and P8 phones with software GRA-TL00 before GRA-TL00C01B220SP01, GRA-CL00 before GRA-CL00C92B220, GRA-CL10 before GRA-CL10C92B220, GRA-UL00 before GRA-UL00C00B220, and GRA-UL10 before GRA-UL10C00B220 allows attackers to cause a denial of service (reboot) or execute arbitrary code via a crafted application.
</code>

- [Pray3r/CVE-2015-8088](https://github.com/Pray3r/CVE-2015-8088)

### CVE-2015-8103

<code>
The Jenkins CLI subsystem in Jenkins before 1.638 and LTS before 1.625.2 allows remote attackers to execute arbitrary code via a crafted serialized Java object, related to a problematic webapps/ROOT/WEB-INF/lib/commons-collections-*.jar file and the &quot;Groovy variant in 'ysoserial'&quot;.
</code>

- [cved-sources/cve-2015-8103](https://github.com/cved-sources/cve-2015-8103)

### CVE-2015-8277

<code>
Multiple buffer overflows in (1) lmgrd and (2) Vendor Daemon in Flexera FlexNet Publisher before 11.13.1.2 Security Update 1 allow remote attackers to execute arbitrary code via a crafted packet with opcode (a) 0x107 or (b) 0x10a.
</code>

- [securifera/CVE-2015-8277-Exploit](https://github.com/securifera/CVE-2015-8277-Exploit)

### CVE-2015-8299

<code>
Buffer overflow in the Group messages monitor (Falcon) in KNX ETS 4.1.5 (Build 3246) allows remote attackers to execute arbitrary code via a crafted KNXnet/IP UDP packet.
</code>

- [kernoelpanic/CVE-2015-8299](https://github.com/kernoelpanic/CVE-2015-8299)

### CVE-2015-8543

<code>
The networking implementation in the Linux kernel through 4.3.3, as used in Android and other products, does not validate protocol identifiers for certain protocol families, which allows local users to cause a denial of service (NULL function pointer dereference and system crash) or possibly gain privileges by leveraging CLONE_NEWUSER support to execute a crafted SOCK_RAW application.
</code>

- [bittorrent3389/CVE-2015-8543_for_SLE12SP1](https://github.com/bittorrent3389/CVE-2015-8543_for_SLE12SP1)

### CVE-2015-8562

<code>
Joomla! 1.5.x, 2.x, and 3.x before 3.4.6 allow remote attackers to conduct PHP object injection attacks and execute arbitrary PHP code via the HTTP User-Agent header, as exploited in the wild in December 2015.
</code>

- [ZaleHack/joomla_rce_CVE-2015-8562](https://github.com/ZaleHack/joomla_rce_CVE-2015-8562)
- [RobinHoutevelts/Joomla-CVE-2015-8562-PHP-POC](https://github.com/RobinHoutevelts/Joomla-CVE-2015-8562-PHP-POC)
- [atcasanova/cve-2015-8562-exploit](https://github.com/atcasanova/cve-2015-8562-exploit)
- [thejackerz/scanner-exploit-joomla-CVE-2015-8562](https://github.com/thejackerz/scanner-exploit-joomla-CVE-2015-8562)
- [paralelo14/CVE-2015-8562](https://github.com/paralelo14/CVE-2015-8562)
- [VoidSec/Joomla_CVE-2015-8562](https://github.com/VoidSec/Joomla_CVE-2015-8562)
- [xnorkl/Joomla_Payload](https://github.com/xnorkl/Joomla_Payload)

### CVE-2015-8651

<code>
Integer overflow in Adobe Flash Player before 18.0.0.324 and 19.x and 20.x before 20.0.0.267 on Windows and OS X and before 11.2.202.559 on Linux, Adobe AIR before 20.0.0.233, Adobe AIR SDK before 20.0.0.233, and Adobe AIR SDK &amp; Compiler before 20.0.0.233 allows attackers to execute arbitrary code via unspecified vectors.
</code>

- [Gitlabpro/The-analysis-of-the-cve-2015-8651](https://github.com/Gitlabpro/The-analysis-of-the-cve-2015-8651)

### CVE-2015-8660

<code>
The ovl_setattr function in fs/overlayfs/inode.c in the Linux kernel through 4.3.3 attempts to merge distinct setattr operations, which allows local users to bypass intended access restrictions and modify the attributes of arbitrary overlay files via a crafted application.
</code>

- [whu-enjoy/CVE-2015-8660](https://github.com/whu-enjoy/CVE-2015-8660)

### CVE-2015-8710

<code>
The htmlParseComment function in HTMLparser.c in libxml2 allows attackers to obtain sensitive information, cause a denial of service (out-of-bounds heap memory access and application crash), or possibly have unspecified other impact via an unclosed HTML comment.
</code>

- [Karm/CVE-2015-8710](https://github.com/Karm/CVE-2015-8710)

### CVE-2015-9251

<code>
jQuery before 3.0.0 is vulnerable to Cross-site Scripting (XSS) attacks when a cross-domain Ajax request is performed without the dataType option, causing text/javascript responses to be executed.
</code>

- [halkichi0308/CVE-2015-9251](https://github.com/halkichi0308/CVE-2015-9251)


## 2014
### CVE-2014-0038

<code>
The compat_sys_recvmmsg function in net/compat.c in the Linux kernel before 3.13.2, when CONFIG_X86_X32 is enabled, allows local users to gain privileges via a recvmmsg system call with a crafted timeout pointer parameter.
</code>

- [saelo/cve-2014-0038](https://github.com/saelo/cve-2014-0038)
- [kiruthikan99/IT19115276](https://github.com/kiruthikan99/IT19115276)

### CVE-2014-0050

<code>
MultipartStream.java in Apache Commons FileUpload before 1.3.1, as used in Apache Tomcat, JBoss Web, and other products, allows remote attackers to cause a denial of service (infinite loop and CPU consumption) via a crafted Content-Type header that bypasses a loop's intended exit conditions.
</code>

- [jrrdev/cve-2014-0050](https://github.com/jrrdev/cve-2014-0050)

### CVE-2014-0094

<code>
The ParametersInterceptor in Apache Struts before 2.3.16.2 allows remote attackers to &quot;manipulate&quot; the ClassLoader via the class parameter, which is passed to the getClass method.
</code>

- [HasegawaTadamitsu/CVE-2014-0094-test-program-for-struts1](https://github.com/HasegawaTadamitsu/CVE-2014-0094-test-program-for-struts1)

### CVE-2014-0114

<code>
Apache Commons BeanUtils, as distributed in lib/commons-beanutils-1.8.0.jar in Apache Struts 1.x through 1.3.10 and in other products requiring commons-beanutils through 1.9.2, does not suppress the class property, which allows remote attackers to &quot;manipulate&quot; the ClassLoader and execute arbitrary code via the class parameter, as demonstrated by the passing of this parameter to the getClass method of the ActionForm object in Struts 1.
</code>

- [rgielen/struts1filter](https://github.com/rgielen/struts1filter)
- [ricedu/struts1-patch](https://github.com/ricedu/struts1-patch)
- [anob3it/strutt-cve-2014-0114](https://github.com/anob3it/strutt-cve-2014-0114)

### CVE-2014-0130

<code>
Directory traversal vulnerability in actionpack/lib/abstract_controller/base.rb in the implicit-render implementation in Ruby on Rails before 3.2.18, 4.0.x before 4.0.5, and 4.1.x before 4.1.1, when certain route globbing configurations are enabled, allows remote attackers to read arbitrary files via a crafted request.
</code>

- [omarkurt/cve-2014-0130](https://github.com/omarkurt/cve-2014-0130)

### CVE-2014-0160

<code>
The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.
</code>

- [FiloSottile/Heartbleed](https://github.com/FiloSottile/Heartbleed)
- [titanous/heartbleeder](https://github.com/titanous/heartbleeder)
- [DominikTo/bleed](https://github.com/DominikTo/bleed)
- [cyphar/heartthreader](https://github.com/cyphar/heartthreader)
- [jdauphant/patch-openssl-CVE-2014-0160](https://github.com/jdauphant/patch-openssl-CVE-2014-0160)
- [musalbas/heartbleed-masstest](https://github.com/musalbas/heartbleed-masstest)
- [obayesshelton/CVE-2014-0160-Scanner](https://github.com/obayesshelton/CVE-2014-0160-Scanner)
- [Lekensteyn/pacemaker](https://github.com/Lekensteyn/pacemaker)
- [isgroup-srl/openmagic](https://github.com/isgroup-srl/openmagic)
- [fb1h2s/CVE-2014-0160](https://github.com/fb1h2s/CVE-2014-0160)
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
- [mpgn/heartbleed-PoC](https://github.com/mpgn/heartbleed-PoC)
- [xanas/heartbleed.py](https://github.com/xanas/heartbleed.py)
- [iSCInc/heartbleed](https://github.com/iSCInc/heartbleed)
- [marstornado/cve-2014-0160-Yunfeng-Jiang](https://github.com/marstornado/cve-2014-0160-Yunfeng-Jiang)
- [hmlio/vaas-cve-2014-0160](https://github.com/hmlio/vaas-cve-2014-0160)
- [hybridus/heartbleedscanner](https://github.com/hybridus/heartbleedscanner)
- [Xyl2k/CVE-2014-0160-Chrome-Plugin](https://github.com/Xyl2k/CVE-2014-0160-Chrome-Plugin)
- [kaosV20/Heartexploit](https://github.com/kaosV20/Heartexploit)
- [caiqiqi/OpenSSL-HeartBleed-CVE-2014-0160-PoC](https://github.com/caiqiqi/OpenSSL-HeartBleed-CVE-2014-0160-PoC)
- [Saymeis/HeartBleed](https://github.com/Saymeis/HeartBleed)
- [cved-sources/cve-2014-0160](https://github.com/cved-sources/cve-2014-0160)
- [cheese-hub/heartbleed](https://github.com/cheese-hub/heartbleed)
- [artofscripting/cmty-ssl-heartbleed-CVE-2014-0160-HTTP-HTTPS](https://github.com/artofscripting/cmty-ssl-heartbleed-CVE-2014-0160-HTTP-HTTPS)
- [cldme/heartbleed-bug](https://github.com/cldme/heartbleed-bug)
- [hack3r-0m/heartbleed_fix_updated](https://github.com/hack3r-0m/heartbleed_fix_updated)

### CVE-2014-0166

<code>
The wp_validate_auth_cookie function in wp-includes/pluggable.php in WordPress before 3.7.2 and 3.8.x before 3.8.2 does not properly determine the validity of authentication cookies, which makes it easier for remote attackers to obtain access via a forged cookie.
</code>

- [Ettack/POC-CVE-2014-0166](https://github.com/Ettack/POC-CVE-2014-0166)

### CVE-2014-0195

<code>
The dtls1_reassemble_fragment function in d1_both.c in OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h does not properly validate fragment lengths in DTLS ClientHello messages, which allows remote attackers to execute arbitrary code or cause a denial of service (buffer overflow and application crash) via a long non-initial fragment.
</code>

- [ricedu/CVE-2014-0195](https://github.com/ricedu/CVE-2014-0195)

### CVE-2014-0196

<code>
The n_tty_write function in drivers/tty/n_tty.c in the Linux kernel through 3.14.3 does not properly manage tty driver access in the &quot;LECHO &amp; !OPOST&quot; case, which allows local users to cause a denial of service (memory corruption and system crash) or gain privileges by triggering a race condition involving read and write operations with long strings.
</code>

- [SunRain/CVE-2014-0196](https://github.com/SunRain/CVE-2014-0196)
- [tempbottle/CVE-2014-0196](https://github.com/tempbottle/CVE-2014-0196)

### CVE-2014-0224

<code>
OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h does not properly restrict processing of ChangeCipherSpec messages, which allows man-in-the-middle attackers to trigger use of a zero-length master key in certain OpenSSL-to-OpenSSL communications, and consequently hijack sessions or obtain sensitive information, via a crafted TLS handshake, aka the &quot;CCS Injection&quot; vulnerability.
</code>

- [Tripwire/OpenSSL-CCS-Inject-Test](https://github.com/Tripwire/OpenSSL-CCS-Inject-Test)
- [iph0n3/CVE-2014-0224](https://github.com/iph0n3/CVE-2014-0224)
- [droptables/ccs-eval](https://github.com/droptables/ccs-eval)
- [ssllabs/openssl-ccs-cve-2014-0224](https://github.com/ssllabs/openssl-ccs-cve-2014-0224)
- [secretnonempty/CVE-2014-0224](https://github.com/secretnonempty/CVE-2014-0224)

### CVE-2014-0291
- [niccoX/patch-openssl-CVE-2014-0291_CVE-2015-0204](https://github.com/niccoX/patch-openssl-CVE-2014-0291_CVE-2015-0204)

### CVE-2014-0521

<code>
Adobe Reader and Acrobat 10.x before 10.1.10 and 11.x before 11.0.07 on Windows and OS X do not properly implement JavaScript APIs, which allows remote attackers to obtain sensitive information via a crafted PDF document.
</code>

- [molnarg/cve-2014-0521](https://github.com/molnarg/cve-2014-0521)

### CVE-2014-0816

<code>
Unspecified vulnerability in Norman Security Suite 10.1 and earlier allows local users to gain privileges via unknown vectors.
</code>

- [tandasat/CVE-2014-0816](https://github.com/tandasat/CVE-2014-0816)

### CVE-2014-0993

<code>
Buffer overflow in the Vcl.Graphics.TPicture.Bitmap implementation in the Visual Component Library (VCL) in Embarcadero Delphi XE6 20.0.15596.9843 and C++ Builder XE6 20.0.15596.9843 allows remote attackers to execute arbitrary code via a crafted BMP file.
</code>

- [helpsystems/Embarcadero-Workaround](https://github.com/helpsystems/Embarcadero-Workaround)

### CVE-2014-10069

<code>
Hitron CVE-30360 devices use a 578A958E3DD933FC DES key that is shared across different customers' installations, which makes it easier for attackers to obtain sensitive information by decrypting a backup configuration file, as demonstrated by a password hash in the um_auth_account_password field.
</code>

- [Manouchehri/hitron-cfg-decrypter](https://github.com/Manouchehri/hitron-cfg-decrypter)

### CVE-2014-1266

<code>
The SSLVerifySignedServerKeyExchange function in libsecurity_ssl/lib/sslKeyExchange.c in the Secure Transport feature in the Data Security component in Apple iOS 6.x before 6.1.6 and 7.x before 7.0.6, Apple TV 6.x before 6.0.2, and Apple OS X 10.9.x before 10.9.2 does not check the signature in a TLS Server Key Exchange message, which allows man-in-the-middle attackers to spoof SSL servers by (1) using an arbitrary private key for the signing step or (2) omitting the signing step.
</code>

- [landonf/Testability-CVE-2014-1266](https://github.com/landonf/Testability-CVE-2014-1266)
- [linusyang/SSLPatch](https://github.com/linusyang/SSLPatch)
- [gabrielg/CVE-2014-1266-poc](https://github.com/gabrielg/CVE-2014-1266-poc)

### CVE-2014-1303

<code>
Heap-based buffer overflow in Apple Safari 7.0.2 allows remote attackers to execute arbitrary code and bypass a sandbox protection mechanism via unspecified vectors, as demonstrated by Liang Chen during a Pwn2Own competition at CanSecWest 2014.
</code>

- [RKX1209/CVE-2014-1303](https://github.com/RKX1209/CVE-2014-1303)

### CVE-2014-1322

<code>
The kernel in Apple OS X through 10.9.2 places a kernel pointer into an XNU object data structure accessible from user space, which makes it easier for local users to bypass the ASLR protection mechanism by reading an unspecified attribute of the object.
</code>

- [raymondpittman/IPC-Memory-Mac-OSX-Exploit](https://github.com/raymondpittman/IPC-Memory-Mac-OSX-Exploit)

### CVE-2014-1447

<code>
Race condition in the virNetServerClientStartKeepAlive function in libvirt before 1.2.1 allows remote attackers to cause a denial of service (libvirtd crash) by closing a connection before a keepalive response is sent.
</code>

- [tagatac/libvirt-CVE-2014-1447](https://github.com/tagatac/libvirt-CVE-2014-1447)

### CVE-2014-160
- [menrcom/CVE-2014-160](https://github.com/menrcom/CVE-2014-160)
- [GitMirar/heartbleed_exploit](https://github.com/GitMirar/heartbleed_exploit)

### CVE-2014-1677

<code>
Technicolor TC7200 with firmware STD6.01.12 could allow remote attackers to obtain sensitive information.
</code>

- [tihmstar/freePW_tc7200Eploit](https://github.com/tihmstar/freePW_tc7200Eploit)

### CVE-2014-1773

<code>
Microsoft Internet Explorer 9 through 11 allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted web site, aka &quot;Internet Explorer Memory Corruption Vulnerability,&quot; a different vulnerability than CVE-2014-1783, CVE-2014-1784, CVE-2014-1786, CVE-2014-1795, CVE-2014-1805, CVE-2014-2758, CVE-2014-2759, CVE-2014-2765, CVE-2014-2766, and CVE-2014-2775.
</code>

- [day6reak/CVE-2014-1773](https://github.com/day6reak/CVE-2014-1773)

### CVE-2014-2064

<code>
The loadUserByUsername function in hudson/security/HudsonPrivateSecurityRealm.java in Jenkins before 1.551 and LTS before 1.532.2 allows remote attackers to determine whether a user exists via vectors related to failed login attempts.
</code>

- [Naramsim/Offensive](https://github.com/Naramsim/Offensive)

### CVE-2014-2323

<code>
SQL injection vulnerability in mod_mysql_vhost.c in lighttpd before 1.4.35 allows remote attackers to execute arbitrary SQL commands via the host name, related to request_check_hostname.
</code>

- [cirocosta/lighty-sqlinj-demo](https://github.com/cirocosta/lighty-sqlinj-demo)

### CVE-2014-2324

<code>
Multiple directory traversal vulnerabilities in (1) mod_evhost and (2) mod_simple_vhost in lighttpd before 1.4.35 allow remote attackers to read arbitrary files via a .. (dot dot) in the host name, related to request_check_hostname.
</code>

- [sp4c30x1/uc_httpd_exploit](https://github.com/sp4c30x1/uc_httpd_exploit)

### CVE-2014-2630

<code>
Unspecified vulnerability in HP Operations Agent 11.00, when Glance is used, allows local users to gain privileges via unknown vectors.
</code>

- [redtimmy/perf-exploiter](https://github.com/redtimmy/perf-exploiter)

### CVE-2014-2734

<code>
** DISPUTED ** The openssl extension in Ruby 2.x does not properly maintain the state of process memory after a file is reopened, which allows remote attackers to spoof signatures within the context of a Ruby script that attempts signature verification after performing a certain sequence of filesystem operations.  NOTE: this issue has been disputed by the Ruby OpenSSL team and third parties, who state that the original demonstration PoC contains errors and redundant or unnecessarily-complex code that does not appear to be related to a demonstration of the issue. As of 20140502, CVE is not aware of any public comment by the original researcher.
</code>

- [gdisneyleugers/CVE-2014-2734](https://github.com/gdisneyleugers/CVE-2014-2734)
- [adrienthebo/cve-2014-2734](https://github.com/adrienthebo/cve-2014-2734)

### CVE-2014-3120

<code>
The default configuration in Elasticsearch before 1.2 enables dynamic scripting, which allows remote attackers to execute arbitrary MVEL expressions and Java code via the source parameter to _search.  NOTE: this only violates the vendor's intended security policy if the user does not run Elasticsearch in its own independent virtual machine.
</code>

- [jeffgeiger/es_inject](https://github.com/jeffgeiger/es_inject)
- [echohtp/ElasticSearch-CVE-2014-3120](https://github.com/echohtp/ElasticSearch-CVE-2014-3120)

### CVE-2014-3153

<code>
The futex_requeue function in kernel/futex.c in the Linux kernel through 3.14.5 does not ensure that calls have two different futex addresses, which allows local users to gain privileges via a crafted FUTEX_REQUEUE command that facilitates unsafe waiter modification.
</code>

- [timwr/CVE-2014-3153](https://github.com/timwr/CVE-2014-3153)
- [android-rooting-tools/libfutex_exploit](https://github.com/android-rooting-tools/libfutex_exploit)
- [geekben/towelroot](https://github.com/geekben/towelroot)
- [lieanu/CVE-2014-3153](https://github.com/lieanu/CVE-2014-3153)
- [zerodavinci/CVE-2014-3153-exploit](https://github.com/zerodavinci/CVE-2014-3153-exploit)
- [c3c/CVE-2014-3153](https://github.com/c3c/CVE-2014-3153)
- [dangtunguyen/TowelRoot](https://github.com/dangtunguyen/TowelRoot)

### CVE-2014-3341

<code>
The SNMP module in Cisco NX-OS 7.0(3)N1(1) and earlier on Nexus 5000 and 6000 devices provides different error messages for invalid requests depending on whether the VLAN ID exists, which allows remote attackers to enumerate VLANs via a series of requests, aka Bug ID CSCup85616.
</code>

- [ehabhussein/snmpvlan](https://github.com/ehabhussein/snmpvlan)

### CVE-2014-3466

<code>
Buffer overflow in the read_server_hello function in lib/gnutls_handshake.c in GnuTLS before 3.1.25, 3.2.x before 3.2.15, and 3.3.x before 3.3.4 allows remote servers to cause a denial of service (memory corruption) or possibly execute arbitrary code via a long session id in a ServerHello message.
</code>

- [azet/CVE-2014-3466_PoC](https://github.com/azet/CVE-2014-3466_PoC)

### CVE-2014-3566

<code>
The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other products, uses nondeterministic CBC padding, which makes it easier for man-in-the-middle attackers to obtain cleartext data via a padding-oracle attack, aka the &quot;POODLE&quot; issue.
</code>

- [mikesplain/CVE-2014-3566-poodle-cookbook](https://github.com/mikesplain/CVE-2014-3566-poodle-cookbook)
- [stdevel/poodle_protector](https://github.com/stdevel/poodle_protector)
- [ashmastaflash/mangy-beast](https://github.com/ashmastaflash/mangy-beast)
- [mpgn/poodle-PoC](https://github.com/mpgn/poodle-PoC)

### CVE-2014-3625

<code>
Directory traversal vulnerability in Pivotal Spring Framework 3.0.4 through 3.2.x before 3.2.12, 4.0.x before 4.0.8, and 4.1.x before 4.1.2 allows remote attackers to read arbitrary files via unspecified vectors, related to static resource handling.
</code>

- [ilmila/springcss-cve-2014-3625](https://github.com/ilmila/springcss-cve-2014-3625)
- [gforresu/SpringPathTraversal](https://github.com/gforresu/SpringPathTraversal)

### CVE-2014-3704

<code>
The expandArguments function in the database abstraction API in Drupal core 7.x before 7.32 does not properly construct prepared statements, which allows remote attackers to conduct SQL injection attacks via an array containing crafted keys.
</code>

- [happynote3966/CVE-2014-3704](https://github.com/happynote3966/CVE-2014-3704)

### CVE-2014-4014

<code>
The capabilities implementation in the Linux kernel before 3.14.8 does not properly consider that namespaces are inapplicable to inodes, which allows local users to bypass intended chmod restrictions by first creating a user namespace, as demonstrated by setting the setgid bit on a file with group ownership of root.
</code>

- [vnik5287/cve-2014-4014-privesc](https://github.com/vnik5287/cve-2014-4014-privesc)

### CVE-2014-4076

<code>
Microsoft Windows Server 2003 SP2 allows local users to gain privileges via a crafted IOCTL call to (1) tcpip.sys or (2) tcpip6.sys, aka &quot;TCP/IP Elevation of Privilege Vulnerability.&quot;
</code>

- [fungoshacks/CVE-2014-4076](https://github.com/fungoshacks/CVE-2014-4076)

### CVE-2014-4109

<code>
Microsoft Internet Explorer 6 through 11 allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted web site, aka &quot;Internet Explorer Memory Corruption Vulnerability,&quot; a different vulnerability than CVE-2014-2799, CVE-2014-4059, CVE-2014-4065, CVE-2014-4079, CVE-2014-4081, CVE-2014-4083, CVE-2014-4085, CVE-2014-4088, CVE-2014-4090, CVE-2014-4094, CVE-2014-4097, CVE-2014-4100, CVE-2014-4103, CVE-2014-4104, CVE-2014-4105, CVE-2014-4106, CVE-2014-4107, CVE-2014-4108, CVE-2014-4110, and CVE-2014-4111.
</code>

- [day6reak/CVE-2014-4109](https://github.com/day6reak/CVE-2014-4109)

### CVE-2014-4113

<code>
win32k.sys in the kernel-mode drivers in Microsoft Windows Server 2003 SP2, Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, and Windows RT Gold and 8.1 allows local users to gain privileges via a crafted application, as exploited in the wild in October 2014, aka &quot;Win32k.sys Elevation of Privilege Vulnerability.&quot;
</code>

- [johnjohnsp1/CVE-2014-4113](https://github.com/johnjohnsp1/CVE-2014-4113)
- [nsxz/Exploit-CVE-2014-4113](https://github.com/nsxz/Exploit-CVE-2014-4113)
- [sam-b/CVE-2014-4113](https://github.com/sam-b/CVE-2014-4113)

### CVE-2014-4140

<code>
Microsoft Internet Explorer 8 through 11 allows remote attackers to bypass the ASLR protection mechanism via a crafted web site, aka &quot;Internet Explorer ASLR Bypass Vulnerability.&quot;
</code>

- [day6reak/CVE-2014-4140](https://github.com/day6reak/CVE-2014-4140)

### CVE-2014-4210

<code>
Unspecified vulnerability in the Oracle WebLogic Server component in Oracle Fusion Middleware 10.0.2.0 and 10.3.6.0 allows remote attackers to affect confidentiality via vectors related to WLS - Web Services.
</code>

- [NoneNotNull/SSRFX](https://github.com/NoneNotNull/SSRFX)
- [0xn0ne/weblogicScanner](https://github.com/0xn0ne/weblogicScanner)

### CVE-2014-4321
- [android-rooting-tools/libmsm_vfe_read_exploit](https://github.com/android-rooting-tools/libmsm_vfe_read_exploit)

### CVE-2014-4322

<code>
drivers/misc/qseecom.c in the QSEECOM driver for the Linux kernel 3.x, as used in Qualcomm Innovation Center (QuIC) Android contributions for MSM devices and other products, does not validate certain offset, length, and base values within an ioctl call, which allows attackers to gain privileges or cause a denial of service (memory corruption) via a crafted application.
</code>

- [retme7/CVE-2014-4322_poc](https://github.com/retme7/CVE-2014-4322_poc)
- [laginimaineb/cve-2014-4322](https://github.com/laginimaineb/cve-2014-4322)
- [askk/CVE-2014-4322_adaptation](https://github.com/askk/CVE-2014-4322_adaptation)
- [koozxcv/CVE-2014-4322](https://github.com/koozxcv/CVE-2014-4322)

### CVE-2014-4323

<code>
The mdp_lut_hw_update function in drivers/video/msm/mdp.c in the MDP display driver for the Linux kernel 3.x, as used in Qualcomm Innovation Center (QuIC) Android contributions for MSM devices and other products, does not validate certain start and length values within an ioctl call, which allows attackers to gain privileges via a crafted application.
</code>

- [marcograss/cve-2014-4323](https://github.com/marcograss/cve-2014-4323)

### CVE-2014-4377

<code>
Integer overflow in CoreGraphics in Apple iOS before 8 and Apple TV before 7 allows remote attackers to execute arbitrary code or cause a denial of service (application crash) via a crafted PDF document.
</code>

- [feliam/CVE-2014-4377](https://github.com/feliam/CVE-2014-4377)
- [davidmurray/CVE-2014-4377](https://github.com/davidmurray/CVE-2014-4377)

### CVE-2014-4378

<code>
CoreGraphics in Apple iOS before 8 and Apple TV before 7 allows remote attackers to obtain sensitive information or cause a denial of service (out-of-bounds read and application crash) via a crafted PDF document.
</code>

- [feliam/CVE-2014-4378](https://github.com/feliam/CVE-2014-4378)

### CVE-2014-4481

<code>
Integer overflow in CoreGraphics in Apple iOS before 8.1.3, Apple OS X before 10.10.2, and Apple TV before 7.0.3 allows remote attackers to execute arbitrary code or cause a denial of service (application crash) via a crafted PDF document.
</code>

- [feliam/CVE-2014-4481](https://github.com/feliam/CVE-2014-4481)

### CVE-2014-4511

<code>
Gitlist before 0.5.0 allows remote attackers to execute arbitrary commands via shell metacharacters in the file name in the URI of a request for a (1) blame, (2) file, or (3) stats page, as demonstrated by requests to blame/master/, master/, and stats/master/.
</code>

- [michaelsss1/gitlist-RCE](https://github.com/michaelsss1/gitlist-RCE)

### CVE-2014-4671

<code>
Adobe Flash Player before 13.0.0.231 and 14.x before 14.0.0.145 on Windows and OS X and before 11.2.202.394 on Linux, Adobe AIR before 14.0.0.137 on Android, Adobe AIR SDK before 14.0.0.137, and Adobe AIR SDK &amp; Compiler before 14.0.0.137 do not properly restrict the SWF file format, which allows remote attackers to conduct cross-site request forgery (CSRF) attacks against JSONP endpoints, and obtain sensitive information, via a crafted OBJECT element with SWF content satisfying the character-set requirements of a callback API.
</code>

- [cph/rabl-old](https://github.com/cph/rabl-old)

### CVE-2014-4699

<code>
The Linux kernel before 3.15.4 on Intel processors does not properly restrict use of a non-canonical value for the saved RIP address in the case of a system call that does not use IRET, which allows local users to leverage a race condition and gain privileges, or cause a denial of service (double fault), via a crafted application that makes ptrace and fork system calls.
</code>

- [vnik5287/cve-2014-4699-ptrace](https://github.com/vnik5287/cve-2014-4699-ptrace)

### CVE-2014-4936

<code>
The upgrade functionality in Malwarebytes Anti-Malware (MBAM) consumer before 2.0.3 and Malwarebytes Anti-Exploit (MBAE) consumer 1.04.1.1012 and earlier allow man-in-the-middle attackers to execute arbitrary code by spoofing the update server and uploading an executable.
</code>

- [0x3a/CVE-2014-4936](https://github.com/0x3a/CVE-2014-4936)

### CVE-2014-4943

<code>
The PPPoL2TP feature in net/l2tp/l2tp_ppp.c in the Linux kernel through 3.15.6 allows local users to gain privileges by leveraging data-structure differences between an l2tp socket and an inet socket.
</code>

- [redes-2015/l2tp-socket-bug](https://github.com/redes-2015/l2tp-socket-bug)

### CVE-2014-5284

<code>
host-deny.sh in OSSEC before 2.8.1 writes to temporary files with predictable filenames without verifying ownership, which allows local users to modify access restrictions in hosts.deny and gain root privileges by creating the temporary files before automatic IP blocking is performed.
</code>

- [mbadanoiu/CVE-2014-5284](https://github.com/mbadanoiu/CVE-2014-5284)

### CVE-2014-6271

<code>
GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka &quot;ShellShock.&quot;  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.
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
- [pwnGuy/shellshock-shell](https://github.com/pwnGuy/shellshock-shell)
- [vonnyfly/shellshock_crawler](https://github.com/vonnyfly/shellshock_crawler)
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
- [akiraaisha/shellshocker-python](https://github.com/akiraaisha/shellshocker-python)
- [kelleykong/cve-2014-6271-mengjia-kong](https://github.com/kelleykong/cve-2014-6271-mengjia-kong)
- [huanlu/cve-2014-6271-huan-lu](https://github.com/huanlu/cve-2014-6271-huan-lu)
- [sunnyjiang/shellshocker-android](https://github.com/sunnyjiang/shellshocker-android)
- [P0cL4bs/ShellShock-CGI-Scan](https://github.com/P0cL4bs/ShellShock-CGI-Scan)
- [hmlio/vaas-cve-2014-6271](https://github.com/hmlio/vaas-cve-2014-6271)
- [opsxcq/exploit-CVE-2014-6271](https://github.com/opsxcq/exploit-CVE-2014-6271)
- [Pilou-Pilou/docker_CVE-2014-6271.](https://github.com/Pilou-Pilou/docker_CVE-2014-6271.)
- [zalalov/CVE-2014-6271](https://github.com/zalalov/CVE-2014-6271)
- [0x00-0x00/CVE-2014-6271](https://github.com/0x00-0x00/CVE-2014-6271)
- [kowshik-sundararajan/CVE-2014-6271](https://github.com/kowshik-sundararajan/CVE-2014-6271)
- [w4fz5uck5/ShockZaum-CVE-2014-6271](https://github.com/w4fz5uck5/ShockZaum-CVE-2014-6271)
- [Aruthw/CVE-2014-6271](https://github.com/Aruthw/CVE-2014-6271)
- [cved-sources/cve-2014-6271](https://github.com/cved-sources/cve-2014-6271)
- [shawntns/exploit-CVE-2014-6271](https://github.com/shawntns/exploit-CVE-2014-6271)
- [Sindadziy/cve-2014-6271](https://github.com/Sindadziy/cve-2014-6271)
- [wenyu1999/bash-shellshock](https://github.com/wenyu1999/bash-shellshock)
- [Sindayifu/CVE-2019-14287-CVE-2014-6271](https://github.com/Sindayifu/CVE-2019-14287-CVE-2014-6271)
- [Any3ite/CVE-2014-6271](https://github.com/Any3ite/CVE-2014-6271)
- [somhm-solutions/Shell-Shock](https://github.com/somhm-solutions/Shell-Shock)
- [rashmikadileeshara/CVE-2014-6271-Shellshock-](https://github.com/rashmikadileeshara/CVE-2014-6271-Shellshock-)
- [Dilith006/CVE-2014-6271](https://github.com/Dilith006/CVE-2014-6271)

### CVE-2014-6287

<code>
The findMacroMarker function in parserLib.pas in Rejetto HTTP File Server (aks HFS or HttpFileServer) 2.3x before 2.3c allows remote attackers to execute arbitrary programs via a %00 sequence in a search action.
</code>

- [roughiz/cve-2014-6287.py](https://github.com/roughiz/cve-2014-6287.py)

### CVE-2014-6332

<code>
OleAut32.dll in OLE in Microsoft Windows Server 2003 SP2, Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, and Windows RT Gold and 8.1 allows remote attackers to execute arbitrary code via a crafted web site, as demonstrated by an array-redimensioning attempt that triggers improper handling of a size value in the SafeArrayDimen function, aka &quot;Windows OLE Automation Array Remote Code Execution Vulnerability.&quot;
</code>

- [MarkoArmitage/metasploit-framework](https://github.com/MarkoArmitage/metasploit-framework)
- [tjjh89017/cve-2014-6332](https://github.com/tjjh89017/cve-2014-6332)
- [mourr/CVE-2014-6332](https://github.com/mourr/CVE-2014-6332)

### CVE-2014-6577

<code>
Unspecified vulnerability in the XML Developer's Kit for C component in Oracle Database Server 11.2.0.3, 11.2.0.4, 12.1.0.1, and 12.1.0.2 allows remote authenticated users to affect confidentiality via unknown vectors.  NOTE: the previous information is from the January 2015 CPU. Oracle has not commented on the original researcher's claim that this is an XML external entity (XXE) vulnerability in the XML parser, which allows attackers to conduct internal port scanning, perform SSRF attacks, or cause a denial of service via a crafted (1) http: or (2) ftp: URI.
</code>

- [SecurityArtWork/oracle-xxe-sqli](https://github.com/SecurityArtWork/oracle-xxe-sqli)

### CVE-2014-6598

<code>
Unspecified vulnerability in the Oracle Communications Diameter Signaling Router component in Oracle Communications Applications 3.x, 4.x, and 5.0 allows remote attackers to affect confidentiality, integrity, and availability via vectors related to Signaling - DPI.
</code>

- [KPN-CISO/DRA_writeup](https://github.com/KPN-CISO/DRA_writeup)

### CVE-2014-7169

<code>
GNU Bash through 4.3 bash43-025 processes trailing strings after certain malformed function definitions in the values of environment variables, which allows remote attackers to write to files or possibly have unknown other impact via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution.  NOTE: this vulnerability exists because of an incomplete fix for CVE-2014-6271.
</code>

- [chef-boneyard/bash-shellshock](https://github.com/chef-boneyard/bash-shellshock)
- [gina-alaska/bash-cve-2014-7169-cookbook](https://github.com/gina-alaska/bash-cve-2014-7169-cookbook)

### CVE-2014-7236

<code>
Eval injection vulnerability in lib/TWiki/Plugins.pm in TWiki before 6.0.1 allows remote attackers to execute arbitrary Perl code via the debugenableplugins parameter to do/view/Main/WebHome.
</code>

- [m0nad/CVE-2014-7236_Exploit](https://github.com/m0nad/CVE-2014-7236_Exploit)

### CVE-2014-7911

<code>
luni/src/main/java/java/io/ObjectInputStream.java in the java.io.ObjectInputStream implementation in Android before 5.0.0 does not verify that deserialization will result in an object that met the requirements for serialization, which allows attackers to execute arbitrary code via a crafted finalize method for a serialized object in an ArrayMap Parcel within an intent sent to system_service, as demonstrated by the finalize method of android.os.BinderProxy, aka Bug 15874291.
</code>

- [retme7/CVE-2014-7911_poc](https://github.com/retme7/CVE-2014-7911_poc)
- [ele7enxxh/CVE-2014-7911](https://github.com/ele7enxxh/CVE-2014-7911)
- [heeeeen/CVE-2014-7911poc](https://github.com/heeeeen/CVE-2014-7911poc)
- [GeneBlue/cve-2014-7911-exp](https://github.com/GeneBlue/cve-2014-7911-exp)
- [koozxcv/CVE-2014-7911](https://github.com/koozxcv/CVE-2014-7911)
- [koozxcv/CVE-2014-7911-CVE-2014-4322_get_root_privilege](https://github.com/koozxcv/CVE-2014-7911-CVE-2014-4322_get_root_privilege)
- [mabin004/cve-2014-7911](https://github.com/mabin004/cve-2014-7911)
- [CytQ/CVE-2014-7911_poc](https://github.com/CytQ/CVE-2014-7911_poc)

### CVE-2014-7920

<code>
mediaserver in Android 2.2 through 5.x before 5.1 allows attackers to gain privileges.  NOTE: This is a different vulnerability than CVE-2014-7921.
</code>

- [laginimaineb/cve-2014-7920-7921](https://github.com/laginimaineb/cve-2014-7920-7921)
- [Vinc3nt4H/cve-2014-7920-7921_update](https://github.com/Vinc3nt4H/cve-2014-7920-7921_update)

### CVE-2014-8110

<code>
Multiple cross-site scripting (XSS) vulnerabilities in the web based administration console in Apache ActiveMQ 5.x before 5.10.1 allow remote attackers to inject arbitrary web script or HTML via unspecified vectors.
</code>

- [tafamace/CVE-2014-8110](https://github.com/tafamace/CVE-2014-8110)

### CVE-2014-8142

<code>
Use-after-free vulnerability in the process_nested_data function in ext/standard/var_unserializer.re in PHP before 5.4.36, 5.5.x before 5.5.20, and 5.6.x before 5.6.4 allows remote attackers to execute arbitrary code via a crafted unserialize call that leverages improper handling of duplicate keys within the serialized properties of an object, a different vulnerability than CVE-2004-1019.
</code>

- [3xp10it/php_cve-2014-8142_cve-2015-0231](https://github.com/3xp10it/php_cve-2014-8142_cve-2015-0231)

### CVE-2014-8244

<code>
Linksys SMART WiFi firmware on EA2700 and EA3500 devices; before 2.1.41 build 162351 on E4200v2 and EA4500 devices; before 1.1.41 build 162599 on EA6200 devices; before 1.1.40 build 160989 on EA6300, EA6400, EA6500, and EA6700 devices; and before 1.1.42 build 161129 on EA6900 devices allows remote attackers to obtain sensitive information or modify data via a JNAP action in a JNAP/ HTTP request.
</code>

- [JollyJumbuckk/LinksysLeaks](https://github.com/JollyJumbuckk/LinksysLeaks)

### CVE-2014-8609

<code>
The addAccount method in src/com/android/settings/accounts/AddAccountSettings.java in the Settings application in Android before 5.0.0 does not properly create a PendingIntent, which allows attackers to use the SYSTEM uid for broadcasting an intent with arbitrary component, action, or category information via a third-party authenticator in a crafted application, aka Bug 17356824.
</code>

- [locisvv/Vulnerable-CVE-2014-8609](https://github.com/locisvv/Vulnerable-CVE-2014-8609)

### CVE-2014-8682

<code>
Multiple SQL injection vulnerabilities in Gogs (aka Go Git Service) 0.3.1-9 through 0.5.x before 0.5.6.1105 Beta allow remote attackers to execute arbitrary SQL commands via the q parameter to (1) api/v1/repos/search, which is not properly handled in models/repo.go, or (2) api/v1/users/search, which is not properly handled in models/user.go.
</code>

- [nihal1306/gogs](https://github.com/nihal1306/gogs)

### CVE-2014-8729
- [inso-/TORQUE-Resource-Manager-2.5.x-2.5.13-stack-based-buffer-overflow-exploit-CVE-2014-8729-CVE-2014-878](https://github.com/inso-/TORQUE-Resource-Manager-2.5.x-2.5.13-stack-based-buffer-overflow-exploit-CVE-2014-8729-CVE-2014-878)

### CVE-2014-8757

<code>
LG On-Screen Phone (OSP) before 4.3.010 allows remote attackers to bypass authorization via a crafted request.
</code>

- [irsl/lgosp-poc](https://github.com/irsl/lgosp-poc)

### CVE-2014-9016

<code>
The password hashing API in Drupal 7.x before 7.34 and the Secure Password Hashes (aka phpass) module 6.x-2.x before 6.x-2.1 for Drupal allows remote attackers to cause a denial of service (CPU and memory consumption) via a crafted request.
</code>

- [c0r3dump3d/wp_drupal_timing_attack](https://github.com/c0r3dump3d/wp_drupal_timing_attack)
- [Primus27/WordPress-Long-Password-Denial-of-Service](https://github.com/Primus27/WordPress-Long-Password-Denial-of-Service)

### CVE-2014-9222

<code>
AllegroSoft RomPager 4.34 and earlier, as used in Huawei Home Gateway products and other vendors and products, allows remote attackers to gain privileges via a crafted cookie that triggers memory corruption, aka the &quot;Misfortune Cookie&quot; vulnerability.
</code>

- [BenChaliah/MIPS-CVE-2014-9222](https://github.com/BenChaliah/MIPS-CVE-2014-9222)

### CVE-2014-9295

<code>
Multiple stack-based buffer overflows in ntpd in NTP before 4.2.8 allow remote attackers to execute arbitrary code via a crafted packet, related to (1) the crypto_recv function when the Autokey Authentication feature is used, (2) the ctl_putdata function, and (3) the configure function.
</code>

- [MacMiniVault/NTPUpdateSnowLeopard](https://github.com/MacMiniVault/NTPUpdateSnowLeopard)

### CVE-2014-9301

<code>
Server-side request forgery (SSRF) vulnerability in the proxy servlet in Alfresco Community Edition before 5.0.a allows remote attackers to trigger outbound requests to intranet servers, conduct port scans, and read arbitrary files via a crafted URI in the endpoint parameter.
</code>

- [ottimo/burp-alfresco-referer-proxy-cve-2014-9301](https://github.com/ottimo/burp-alfresco-referer-proxy-cve-2014-9301)

### CVE-2014-9322

<code>
arch/x86/kernel/entry_64.S in the Linux kernel before 3.17.5 does not properly handle faults associated with the Stack Segment (SS) segment register, which allows local users to gain privileges by triggering an IRET instruction that leads to access to a GS Base address from the wrong space.
</code>

- [RKX1209/CVE-2014-9322](https://github.com/RKX1209/CVE-2014-9322)

### CVE-2014-9390

<code>
Git before 1.8.5.6, 1.9.x before 1.9.5, 2.0.x before 2.0.5, 2.1.x before 2.1.4, and 2.2.x before 2.2.1 on Windows and OS X; Mercurial before 3.2.3 on Windows and OS X; Apple Xcode before 6.2 beta 3; mine; libgit2; Egit; and JGit allow remote Git servers to execute arbitrary commands via a tree containing a crafted .git/config file with (1) an ignorable Unicode codepoint, (2) a git~1/config representation, or (3) mixed case that is improperly handled on a case-insensitive filesystem.
</code>

- [mmetince/CVE-2014-9390](https://github.com/mmetince/CVE-2014-9390)
- [hakatashi/CVE-2014-9390](https://github.com/hakatashi/CVE-2014-9390)

### CVE-2014-9707

<code>
EmbedThis GoAhead 3.0.0 through 3.4.1 does not properly handle path segments starting with a . (dot), which allows remote attackers to conduct directory traversal attacks, cause a denial of service (heap-based buffer overflow and crash), or possibly execute arbitrary code via a crafted URI.
</code>

- [zhw-01/cve-2014-9707](https://github.com/zhw-01/cve-2014-9707)


## 2013
### CVE-2013-0156

<code>
active_support/core_ext/hash/conversions.rb in Ruby on Rails before 2.3.15, 3.0.x before 3.0.19, 3.1.x before 3.1.10, and 3.2.x before 3.2.11 does not properly restrict casts of string values, which allows remote attackers to conduct object-injection attacks and execute arbitrary code, or cause a denial of service (memory and CPU consumption) involving nested XML entity references, by leveraging Action Pack support for (1) YAML type conversion or (2) Symbol type conversion.
</code>

- [terracatta/name_reverser](https://github.com/terracatta/name_reverser)
- [heroku/heroku-CVE-2013-0156](https://github.com/heroku/heroku-CVE-2013-0156)
- [josal/crack-0.1.8-fixed](https://github.com/josal/crack-0.1.8-fixed)
- [bsodmike/rails-exploit-cve-2013-0156](https://github.com/bsodmike/rails-exploit-cve-2013-0156)
- [R3dKn33/CVE-2013-0156](https://github.com/R3dKn33/CVE-2013-0156)

### CVE-2013-0229

<code>
The ProcessSSDPRequest function in minissdp.c in the SSDP handler in MiniUPnP MiniUPnPd before 1.4 allows remote attackers to cause a denial of service (service crash) via a crafted request that triggers a buffer over-read.
</code>

- [lochiiconnectivity/vulnupnp](https://github.com/lochiiconnectivity/vulnupnp)

### CVE-2013-0269

<code>
The JSON gem before 1.5.5, 1.6.x before 1.6.8, and 1.7.x before 1.7.7 for Ruby allows remote attackers to cause a denial of service (resource consumption) or bypass the mass assignment protection mechanism via a crafted JSON document that triggers the creation of arbitrary Ruby symbols or certain internal objects, as demonstrated by conducting a SQL injection attack against Ruby on Rails, aka &quot;Unsafe Object Creation Vulnerability.&quot;
</code>

- [heroku/heroku-CVE-2013-0269](https://github.com/heroku/heroku-CVE-2013-0269)

### CVE-2013-0333

<code>
lib/active_support/json/backends/yaml.rb in Ruby on Rails 2.3.x before 2.3.16 and 3.0.x before 3.0.20 does not properly convert JSON data to YAML data for processing by a YAML parser, which allows remote attackers to execute arbitrary code, conduct SQL injection attacks, or bypass authentication via crafted data that triggers unsafe decoding, a different vulnerability than CVE-2013-0156.
</code>

- [heroku/heroku-CVE-2013-0333](https://github.com/heroku/heroku-CVE-2013-0333)

### CVE-2013-1081

<code>
Directory traversal vulnerability in MDM.php in Novell ZENworks Mobile Management (ZMM) 2.6.1 and 2.7.0 allows remote attackers to include and execute arbitrary local files via the language parameter.
</code>

- [steponequit/CVE-2013-1081](https://github.com/steponequit/CVE-2013-1081)

### CVE-2013-1300

<code>
win32k.sys in the kernel-mode drivers in Microsoft Windows XP SP2 and SP3, Windows Server 2003 SP2, Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows Server 2012, and Windows RT does not properly handle objects in memory, which allows local users to gain privileges via a crafted application, aka &quot;Win32k Memory Allocation Vulnerability.&quot;
</code>

- [Meatballs1/cve-2013-1300](https://github.com/Meatballs1/cve-2013-1300)

### CVE-2013-1488

<code>
The Java Runtime Environment (JRE) component in Oracle Java SE 7 Update 17 and earlier, and OpenJDK 6 and 7, allows remote attackers to execute arbitrary code via unspecified vectors involving reflection, Libraries, &quot;improper toString calls,&quot; and the JDBC driver manager, as demonstrated by James Forshaw during a Pwn2Own competition at CanSecWest 2013.
</code>

- [v-p-b/buherablog-cve-2013-1488](https://github.com/v-p-b/buherablog-cve-2013-1488)

### CVE-2013-1491

<code>
The Java Runtime Environment (JRE) component in Oracle Java SE 7 Update 17 and earlier, 6 Update 43 and earlier, 5.0 Update 41 and earlier, and JavaFX 2.2.7 and earlier allows remote attackers to execute arbitrary code via vectors related to 2D, as demonstrated by Joshua Drake during a Pwn2Own competition at CanSecWest 2013.
</code>

- [guhe120/CVE20131491-JIT](https://github.com/guhe120/CVE20131491-JIT)

### CVE-2013-1690

<code>
Mozilla Firefox before 22.0, Firefox ESR 17.x before 17.0.7, Thunderbird before 17.0.7, and Thunderbird ESR 17.x before 17.0.7 do not properly handle onreadystatechange events in conjunction with page reloading, which allows remote attackers to cause a denial of service (application crash) or possibly execute arbitrary code via a crafted web site that triggers an attempt to execute data at an unmapped memory location.
</code>

- [vlad902/annotated-fbi-tbb-exploit](https://github.com/vlad902/annotated-fbi-tbb-exploit)

### CVE-2013-1775

<code>
sudo 1.6.0 through 1.7.10p6 and sudo 1.8.0 through 1.8.6p6 allows local users or physically proximate attackers to bypass intended time restrictions and retain privileges without re-authenticating by setting the system clock and sudo user timestamp to the epoch.
</code>

- [bekhzod0725/perl-CVE-2013-1775](https://github.com/bekhzod0725/perl-CVE-2013-1775)

### CVE-2013-1965

<code>
Apache Struts Showcase App 2.0.0 through 2.3.13, as used in Struts 2 before 2.3.14.3, allows remote attackers to execute arbitrary OGNL code via a crafted parameter name that is not properly handled when invoking a redirect.
</code>

- [cinno/CVE-2013-1965](https://github.com/cinno/CVE-2013-1965)

### CVE-2013-2028

<code>
The ngx_http_parse_chunked function in http/ngx_http_parse.c in nginx 1.3.9 through 1.4.0 allows remote attackers to cause a denial of service (crash) and execute arbitrary code via a chunked Transfer-Encoding request with a large chunk size, which triggers an integer signedness error and a stack-based buffer overflow.
</code>

- [danghvu/nginx-1.4.0](https://github.com/danghvu/nginx-1.4.0)
- [kitctf/nginxpwn](https://github.com/kitctf/nginxpwn)
- [tachibana51/CVE-2013-2028-x64-bypass-ssp-and-pie-PoC](https://github.com/tachibana51/CVE-2013-2028-x64-bypass-ssp-and-pie-PoC)

### CVE-2013-2072

<code>
Buffer overflow in the Python bindings for the xc_vcpu_setaffinity call in Xen 4.0.x, 4.1.x, and 4.2.x allows local administrators with permissions to configure VCPU affinity to cause a denial of service (memory corruption and xend toolstack crash) and possibly gain privileges via a crafted cpumap.
</code>

- [bl4ck5un/cve-2013-2072](https://github.com/bl4ck5un/cve-2013-2072)

### CVE-2013-2094

<code>
The perf_swevent_init function in kernel/events/core.c in the Linux kernel before 3.8.9 uses an incorrect integer data type, which allows local users to gain privileges via a crafted perf_event_open system call.
</code>

- [realtalk/cve-2013-2094](https://github.com/realtalk/cve-2013-2094)
- [hiikezoe/libperf_event_exploit](https://github.com/hiikezoe/libperf_event_exploit)
- [Pashkela/CVE-2013-2094](https://github.com/Pashkela/CVE-2013-2094)
- [tarunyadav/fix-cve-2013-2094](https://github.com/tarunyadav/fix-cve-2013-2094)
- [timhsutw/cve-2013-2094](https://github.com/timhsutw/cve-2013-2094)
- [vnik5287/CVE-2013-2094](https://github.com/vnik5287/CVE-2013-2094)

### CVE-2013-2186

<code>
The DiskFileItem class in Apache Commons FileUpload, as used in Red Hat JBoss BRMS 5.3.1; JBoss Portal 4.3 CP07, 5.2.2, and 6.0.0; and Red Hat JBoss Web Server 1.0.2 allows remote attackers to write to arbitrary files via a NULL byte in a file name in a serialized instance.
</code>

- [GrrrDog/ACEDcup](https://github.com/GrrrDog/ACEDcup)
- [SPlayer1248/Payload_CVE_2013_2186](https://github.com/SPlayer1248/Payload_CVE_2013_2186)
- [SPlayer1248/CVE_2013_2186](https://github.com/SPlayer1248/CVE_2013_2186)

### CVE-2013-2217

<code>
cache.py in Suds 0.4, when tempdir is set to None, allows local users to redirect SOAP queries and possibly have other unspecified impact via a symlink attack on a cache file with a predictable name in /tmp/suds/.
</code>

- [Osirium/suds](https://github.com/Osirium/suds)

### CVE-2013-225
- [ninj4c0d3r/ShellEvil](https://github.com/ninj4c0d3r/ShellEvil)

### CVE-2013-2595

<code>
The device-initialization functionality in the MSM camera driver for the Linux kernel 2.6.x and 3.x, as used in Qualcomm Innovation Center (QuIC) Android contributions for MSM devices and other products, enables MSM_CAM_IOCTL_SET_MEM_MAP_INFO ioctl calls for an unrestricted mmap interface, which allows attackers to gain privileges via a crafted application.
</code>

- [fi01/libmsm_cameraconfig_exploit](https://github.com/fi01/libmsm_cameraconfig_exploit)

### CVE-2013-2596

<code>
Integer overflow in the fb_mmap function in drivers/video/fbmem.c in the Linux kernel before 3.8.9, as used in a certain Motorola build of Android 4.1.2 and other products, allows local users to create a read-write memory mapping for the entirety of kernel memory, and consequently gain privileges, via crafted /dev/graphics/fb0 mmap2 system calls, as demonstrated by the Motochopper pwn program.
</code>

- [hiikezoe/libfb_mem_exploit](https://github.com/hiikezoe/libfb_mem_exploit)

### CVE-2013-2597

<code>
Stack-based buffer overflow in the acdb_ioctl function in audio_acdb.c in the acdb audio driver for the Linux kernel 2.6.x and 3.x, as used in Qualcomm Innovation Center (QuIC) Android contributions for MSM devices and other products, allows attackers to gain privileges via an application that leverages /dev/msm_acdb access and provides a large size value in an ioctl argument.
</code>

- [fi01/libmsm_acdb_exploit](https://github.com/fi01/libmsm_acdb_exploit)

### CVE-2013-2729

<code>
Integer overflow in Adobe Reader and Acrobat 9.x before 9.5.5, 10.x before 10.1.7, and 11.x before 11.0.03 allows attackers to execute arbitrary code via unspecified vectors, a different vulnerability than CVE-2013-2727.
</code>

- [feliam/CVE-2013-2729](https://github.com/feliam/CVE-2013-2729)

### CVE-2013-2730

<code>
Buffer overflow in Adobe Reader and Acrobat 9.x before 9.5.5, 10.x before 10.1.7, and 11.x before 11.0.03 allows attackers to execute arbitrary code via unspecified vectors, a different vulnerability than CVE-2013-2733.
</code>

- [feliam/CVE-2013-2730](https://github.com/feliam/CVE-2013-2730)

### CVE-2013-2842

<code>
Use-after-free vulnerability in Google Chrome before 27.0.1453.93 allows remote attackers to cause a denial of service or possibly have unspecified other impact via vectors related to the handling of widgets.
</code>

- [173210/spider](https://github.com/173210/spider)

### CVE-2013-2977

<code>
Integer overflow in IBM Notes 8.5.x before 8.5.3 FP4 Interim Fix 1 and 9.x before 9.0 Interim Fix 1 on Windows, and 8.5.x before 8.5.3 FP5 and 9.x before 9.0.1 on Linux, allows remote attackers to execute arbitrary code via a malformed PNG image in a previewed e-mail message, aka SPR NPEI96K82Q.
</code>

- [lagartojuancho/CVE-2013-2977](https://github.com/lagartojuancho/CVE-2013-2977)

### CVE-2013-3319

<code>
The GetComputerSystem method in the HostControl service in SAP Netweaver 7.03 allows remote attackers to obtain sensitive information via a crafted SOAP request to TCP port 1128.
</code>

- [integrity-sa/cve-2013-3319](https://github.com/integrity-sa/cve-2013-3319)

### CVE-2013-3651

<code>
LOCKON EC-CUBE 2.11.2 through 2.12.4 allows remote attackers to conduct unspecified PHP code-injection attacks via a crafted string, related to data/class/SC_CheckError.php and data/class/SC_FormParam.php.
</code>

- [motikan2010/CVE-2013-3651](https://github.com/motikan2010/CVE-2013-3651)

### CVE-2013-3664

<code>
Trimble SketchUp (formerly Google SketchUp) before 2013 (13.0.3689) allows remote attackers to execute arbitrary code via a crafted color palette table in a MAC Pict texture, which triggers an out-of-bounds stack write.  NOTE: this vulnerability exists because of an incomplete fix for CVE-2013-3662.  NOTE: this issue was SPLIT due to different affected products and codebases (ADT1); CVE-2013-7388 has been assigned to the paintlib issue.
</code>

- [lagartojuancho/CVE-2013-3664_MAC](https://github.com/lagartojuancho/CVE-2013-3664_MAC)
- [lagartojuancho/CVE-2013-3664_BMP](https://github.com/lagartojuancho/CVE-2013-3664_BMP)

### CVE-2013-4002

<code>
XMLscanner.java in Apache Xerces2 Java Parser before 2.12.0, as used in the Java Runtime Environment (JRE) in IBM Java 5.0 before 5.0 SR16-FP3, 6 before 6 SR14, 6.0.1 before 6.0.1 SR6, and 7 before 7 SR5 as well as Oracle Java SE 7u40 and earlier, Java SE 6u60 and earlier, Java SE 5.0u51 and earlier, JRockit R28.2.8 and earlier, JRockit R27.7.6 and earlier, Java SE Embedded 7u40 and earlier, and possibly other products allows remote attackers to cause a denial of service via vectors related to XML attribute names.
</code>

- [tafamace/CVE-2013-4002](https://github.com/tafamace/CVE-2013-4002)

### CVE-2013-4175

<code>
MySecureShell 1.31 has a Local Denial of Service Vulnerability
</code>

- [hartwork/mysecureshell-issues](https://github.com/hartwork/mysecureshell-issues)

### CVE-2013-4348

<code>
The skb_flow_dissect function in net/core/flow_dissector.c in the Linux kernel through 3.12 allows remote attackers to cause a denial of service (infinite loop) via a small value in the IHL field of a packet with IPIP encapsulation.
</code>

- [bl4ck5un/cve-2013-4348](https://github.com/bl4ck5un/cve-2013-4348)

### CVE-2013-4378

<code>
Cross-site scripting (XSS) vulnerability in HtmlSessionInformationsReport.java in JavaMelody 1.46 and earlier allows remote attackers to inject arbitrary web script or HTML via a crafted X-Forwarded-For header.
</code>

- [theratpack/grails-javamelody-sample-app](https://github.com/theratpack/grails-javamelody-sample-app)

### CVE-2013-4434

<code>
Dropbear SSH Server before 2013.59 generates error messages for a failed logon attempt with different time delays depending on whether the user account exists, which allows remote attackers to discover valid usernames.
</code>

- [styx00/Dropbear_CVE-2013-4434](https://github.com/styx00/Dropbear_CVE-2013-4434)

### CVE-2013-4784

<code>
The HP Integrated Lights-Out (iLO) BMC implementation allows remote attackers to bypass authentication and execute arbitrary IPMI commands by using cipher suite 0 (aka cipher zero) and an arbitrary password.
</code>

- [alexoslabs/ipmitest](https://github.com/alexoslabs/ipmitest)

### CVE-2013-5065

<code>
NDProxy.sys in the kernel in Microsoft Windows XP SP2 and SP3 and Server 2003 SP2 allows local users to gain privileges via a crafted application, as exploited in the wild in November 2013.
</code>

- [Friarfukd/RobbinHood](https://github.com/Friarfukd/RobbinHood)

### CVE-2013-5211

<code>
The monlist feature in ntp_request.c in ntpd in NTP before 4.2.7p26 allows remote attackers to cause a denial of service (traffic amplification) via forged (1) REQ_MON_GETLIST or (2) REQ_MON_GETLIST_1 requests, as exploited in the wild in December 2013.
</code>

- [dani87/ntpscanner](https://github.com/dani87/ntpscanner)
- [suedadam/ntpscanner](https://github.com/suedadam/ntpscanner)
- [sepehrdaddev/ntpdos](https://github.com/sepehrdaddev/ntpdos)

### CVE-2013-5664

<code>
Cross-site scripting (XSS) vulnerability in the web-based device-management API browser in Palo Alto Networks PAN-OS before 4.1.13 and 5.0.x before 5.0.6 allows remote attackers to inject arbitrary web script or HTML via crafted data, aka Ref ID 50908.
</code>

- [phusion/rails-cve-2012-5664-test](https://github.com/phusion/rails-cve-2012-5664-test)

### CVE-2013-5842

<code>
Unspecified vulnerability in Oracle Java SE 7u40 and earlier, Java SE 6u60 and earlier, Java SE 5.0u51 and earlier, and Java SE Embedded 7u40 and earlier allows remote attackers to affect confidentiality, integrity, and availability via unknown vectors related to Libraries, a different vulnerability than CVE-2013-5850.
</code>

- [guhe120/CVE-2013-5842](https://github.com/guhe120/CVE-2013-5842)

### CVE-2013-6117

<code>
Dahua DVR 2.608.0000.0 and 2.608.GV00.0 allows remote attackers to bypass authentication and obtain sensitive information including user credentials, change user passwords, clear log files, and perform other actions via a request to TCP port 37777.
</code>

- [milo2012/CVE-2013-6117](https://github.com/milo2012/CVE-2013-6117)

### CVE-2013-6282

<code>
The (1) get_user and (2) put_user API functions in the Linux kernel before 3.5.5 on the v6k and v7 ARM platforms do not validate certain addresses, which allows attackers to read or modify the contents of arbitrary kernel memory locations via a crafted application, as exploited in the wild against Android devices in October and November 2013.
</code>

- [fi01/libput_user_exploit](https://github.com/fi01/libput_user_exploit)
- [fi01/libget_user_exploit](https://github.com/fi01/libget_user_exploit)
- [jeboo/bypasslkm](https://github.com/jeboo/bypasslkm)
- [timwr/CVE-2013-6282](https://github.com/timwr/CVE-2013-6282)

### CVE-2013-6375

<code>
Xen 4.2.x and 4.3.x, when using Intel VT-d for PCI passthrough, does not properly flush the TLB after clearing a present translation table entry, which allows local guest administrators to cause a denial of service or gain privileges via unspecified vectors related to an &quot;inverted boolean parameter.&quot;
</code>

- [bl4ck5un/cve-2013-6375](https://github.com/bl4ck5un/cve-2013-6375)

### CVE-2013-6668

<code>
Multiple unspecified vulnerabilities in Google V8 before 3.24.35.10, as used in Google Chrome before 33.0.1750.146, allow attackers to cause a denial of service or possibly have other impact via unknown vectors.
</code>

- [sdneon/CveTest](https://github.com/sdneon/CveTest)

### CVE-2013-6987

<code>
Multiple directory traversal vulnerabilities in the FileBrowser components in Synology DiskStation Manager (DSM) before 4.3-3810 Update 3 allow remote attackers to read, write, and delete arbitrary files via a .. (dot dot) in the (1) path parameter to file_delete.cgi or (2) folder_path parameter to file_share.cgi in webapi/FileStation/; (3) dlink parameter to fbdownload/; or unspecified parameters to (4) html5_upload.cgi, (5) file_download.cgi, (6) file_sharing.cgi, (7) file_MVCP.cgi, or (8) file_rename.cgi in webapi/FileStation/.
</code>

- [Sciota/CVE-2013-6987](https://github.com/Sciota/CVE-2013-6987)


## 2012
### CVE-2012-0003

<code>
Unspecified vulnerability in winmm.dll in Windows Multimedia Library in Windows Media Player (WMP) in Microsoft Windows XP SP2 and SP3, Server 2003 SP2, Vista SP2, and Server 2008 SP2 allows remote attackers to execute arbitrary code via a crafted MIDI file, aka &quot;MIDI Remote Code Execution Vulnerability.&quot;
</code>

- [k0keoyo/CVE-2012-0003_eXP](https://github.com/k0keoyo/CVE-2012-0003_eXP)

### CVE-2012-0056

<code>
The mem_write function in the Linux kernel before 3.2.2, when ASLR is disabled, does not properly check permissions when writing to /proc/&lt;pid&gt;/mem, which allows local users to gain privileges by modifying process memory, as demonstrated by Mempodipper.
</code>

- [srclib/CVE-2012-0056](https://github.com/srclib/CVE-2012-0056)
- [pythonone/CVE-2012-0056](https://github.com/pythonone/CVE-2012-0056)

### CVE-2012-0152

<code>
The Remote Desktop Protocol (RDP) service in Microsoft Windows Server 2008 R2 and R2 SP1 and Windows 7 Gold and SP1 allows remote attackers to cause a denial of service (application hang) via a series of crafted packets, aka &quot;Terminal Server Denial of Service Vulnerability.&quot;
</code>

- [rutvijjethwa/RDP_jammer](https://github.com/rutvijjethwa/RDP_jammer)

### CVE-2012-1675

<code>
The TNS Listener, as used in Oracle Database 11g 11.1.0.7, 11.2.0.2, and 11.2.0.3, and 10g 10.2.0.3, 10.2.0.4, and 10.2.0.5, as used in Oracle Fusion Middleware, Enterprise Manager, E-Business Suite, and possibly other products, allows remote attackers to execute arbitrary database commands by performing a remote registration of a database (1) instance or (2) service name that already exists, then conducting a man-in-the-middle (MITM) attack to hijack database connections, aka &quot;TNS Poison.&quot;
</code>

- [bongbongco/CVE-2012-1675](https://github.com/bongbongco/CVE-2012-1675)

### CVE-2012-1723

<code>
Unspecified vulnerability in the Java Runtime Environment (JRE) component in Oracle Java SE 7 update 4 and earlier, 6 update 32 and earlier, 5 update 35 and earlier, and 1.4.2_37 and earlier allows remote attackers to affect confidentiality, integrity, and availability via unknown vectors related to Hotspot.
</code>

- [EthanNJC/CVE-2012-1723](https://github.com/EthanNJC/CVE-2012-1723)

### CVE-2012-1823

<code>
sapi/cgi/cgi_main.c in PHP before 5.3.12 and 5.4.x before 5.4.2, when configured as a CGI script (aka php-cgi), does not properly handle query strings that lack an = (equals sign) character, which allows remote attackers to execute arbitrary code by placing command-line options in the query string, related to lack of skipping a certain php_getopt for the 'd' case.
</code>

- [drone789/CVE-2012-1823](https://github.com/drone789/CVE-2012-1823)
- [gamamaru6005/oscp_scripts-1](https://github.com/gamamaru6005/oscp_scripts-1)
- [noondi/metasploitable2](https://github.com/noondi/metasploitable2)

### CVE-2012-1876

<code>
Microsoft Internet Explorer 6 through 9, and 10 Consumer Preview, does not properly handle objects in memory, which allows remote attackers to execute arbitrary code by attempting to access a nonexistent object, leading to a heap-based buffer overflow, aka &quot;Col Element Remote Code Execution Vulnerability,&quot; as demonstrated by VUPEN during a Pwn2Own competition at CanSecWest 2012.
</code>

- [WizardVan/CVE-2012-1876](https://github.com/WizardVan/CVE-2012-1876)

### CVE-2012-1889

<code>
Microsoft XML Core Services 3.0, 4.0, 5.0, and 6.0 accesses uninitialized memory locations, which allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted web site.
</code>

- [whu-enjoy/CVE-2012-1889](https://github.com/whu-enjoy/CVE-2012-1889)
- [l-iberty/cve-2012-1889](https://github.com/l-iberty/cve-2012-1889)

### CVE-2012-2122

<code>
sql/password.c in Oracle MySQL 5.1.x before 5.1.63, 5.5.x before 5.5.24, and 5.6.x before 5.6.6, and MariaDB 5.1.x before 5.1.62, 5.2.x before 5.2.12, 5.3.x before 5.3.6, and 5.5.x before 5.5.23, when running in certain environments with certain implementations of the memcmp function, allows remote attackers to bypass authentication by repeatedly authenticating with the same incorrect password, which eventually causes a token comparison to succeed due to an improperly-checked return value.
</code>

- [Avinza/CVE-2012-2122-scanner](https://github.com/Avinza/CVE-2012-2122-scanner)

### CVE-2012-2688

<code>
Unspecified vulnerability in the _php_stream_scandir function in the stream implementation in PHP before 5.3.15 and 5.4.x before 5.4.5 has unknown impact and remote attack vectors, related to an &quot;overflow.&quot;
</code>

- [shelld3v/CVE-2012-2688](https://github.com/shelld3v/CVE-2012-2688)

### CVE-2012-3137

<code>
The authentication protocol in Oracle Database Server 10.2.0.3, 10.2.0.4, 10.2.0.5, 11.1.0.7, 11.2.0.2, and 11.2.0.3 allows remote attackers to obtain the session key and salt for arbitrary users, which leaks information about the cryptographic hash and makes it easier to conduct brute force password guessing attacks, aka &quot;stealth password cracking vulnerability.&quot;
</code>

- [hantwister/o5logon-fetch](https://github.com/hantwister/o5logon-fetch)
- [r1-/cve-2012-3137](https://github.com/r1-/cve-2012-3137)

### CVE-2012-3153

<code>
Unspecified vulnerability in the Oracle Reports Developer component in Oracle Fusion Middleware 11.1.1.4, 11.1.1.6, and 11.1.2.0 allows remote attackers to affect confidentiality and integrity via unknown vectors related to Servlet.  NOTE: the previous information is from the October 2012 CPU. Oracle has not commented on claims from the original researcher that the PARSEQUERY function allows remote attackers to obtain database credentials via reports/rwservlet/parsequery, and that this issue occurs in earlier versions.  NOTE: this can be leveraged with CVE-2012-3152 to execute arbitrary code by uploading a .jsp file.
</code>

- [Mekanismen/pwnacle-fusion](https://github.com/Mekanismen/pwnacle-fusion)

### CVE-2012-3716

<code>
CoreText in Apple Mac OS X 10.7.x before 10.7.5 allows remote attackers to execute arbitrary code or cause a denial of service (out-of-bounds write or read) via a crafted text glyph.
</code>

- [d4rkcat/killosx](https://github.com/d4rkcat/killosx)

### CVE-2012-4220

<code>
diagchar_core.c in the Qualcomm Innovation Center (QuIC) Diagnostics (aka DIAG) kernel-mode driver for Android 2.3 through 4.2 allows attackers to execute arbitrary code or cause a denial of service (incorrect pointer dereference) via an application that uses crafted arguments in a local diagchar_ioctl call.
</code>

- [hiikezoe/diaggetroot](https://github.com/hiikezoe/diaggetroot)
- [poliva/root-zte-open](https://github.com/poliva/root-zte-open)

### CVE-2012-4431

<code>
org/apache/catalina/filters/CsrfPreventionFilter.java in Apache Tomcat 6.x before 6.0.36 and 7.x before 7.0.32 allows remote attackers to bypass the cross-site request forgery (CSRF) protection mechanism via a request that lacks a session identifier.
</code>

- [Michael-Main/CVE-2012-4431](https://github.com/Michael-Main/CVE-2012-4431)

### CVE-2012-4681

<code>
Multiple vulnerabilities in the Java Runtime Environment (JRE) component in Oracle Java SE 7 Update 6 and earlier allow remote attackers to execute arbitrary code via a crafted applet that bypasses SecurityManager restrictions by (1) using com.sun.beans.finder.ClassFinder.findClass and leveraging an exception with the forName method to access restricted classes from arbitrary packages such as sun.awt.SunToolkit, then (2) using &quot;reflection with a trusted immediate caller&quot; to leverage the getField method to access and modify private fields, as exploited in the wild in August 2012 using Gondzz.class and Gondvv.class.
</code>

- [benjholla/CVE-2012-4681-Armoring](https://github.com/benjholla/CVE-2012-4681-Armoring)
- [ZH3FENG/PoCs-CVE_2012_4681](https://github.com/ZH3FENG/PoCs-CVE_2012_4681)

### CVE-2012-4792

<code>
Use-after-free vulnerability in Microsoft Internet Explorer 6 through 8 allows remote attackers to execute arbitrary code via a crafted web site that triggers access to an object that (1) was not properly allocated or (2) is deleted, as demonstrated by a CDwnBindInfo object, and exploited in the wild in December 2012.
</code>

- [WizardVan/CVE-2012-4792](https://github.com/WizardVan/CVE-2012-4792)

### CVE-2012-4929

<code>
The TLS protocol 1.2 and earlier, as used in Mozilla Firefox, Google Chrome, Qt, and other products, can encrypt compressed data without properly obfuscating the length of the unencrypted data, which allows man-in-the-middle attackers to obtain plaintext HTTP headers by observing length differences during a series of guesses in which a string in an HTTP request potentially matches an unknown string in an HTTP header, aka a &quot;CRIME&quot; attack.
</code>

- [mpgn/CRIME-poc](https://github.com/mpgn/CRIME-poc)

### CVE-2012-5106

<code>
Stack-based buffer overflow in FreeFloat FTP Server 1.0 allows remote authenticated users to execute arbitrary code via a long string in a PUT command.
</code>

- [war4uthor/CVE-2012-5106](https://github.com/war4uthor/CVE-2012-5106)

### CVE-2012-5575

<code>
Apache CXF 2.5.x before 2.5.10, 2.6.x before CXF 2.6.7, and 2.7.x before CXF 2.7.4 does not verify that a specified cryptographic algorithm is allowed by the WS-SecurityPolicy AlgorithmSuite definition before decrypting, which allows remote attackers to force CXF to use weaker cryptographic algorithms than intended and makes it easier to decrypt communications, aka &quot;XML Encryption backwards compatibility attack.&quot;
</code>

- [tafamace/CVE-2012-5575](https://github.com/tafamace/CVE-2012-5575)

### CVE-2012-5613

<code>
** DISPUTED **  MySQL 5.5.19 and possibly other versions, and MariaDB 5.5.28a and possibly other versions, when configured to assign the FILE privilege to users who should not have administrative privileges, allows remote authenticated users to gain privileges by leveraging the FILE privilege to create files as the MySQL administrator.  NOTE: the vendor disputes this issue, stating that this is only a vulnerability when the administrator does not follow recommendations in the product's installation documentation.  NOTE: it could be argued that this should not be included in CVE because it is a configuration issue.
</code>

- [Hood3dRob1n/MySQL-Fu.rb](https://github.com/Hood3dRob1n/MySQL-Fu.rb)
- [w4fz5uck5/UDFPwn-CVE-2012-5613](https://github.com/w4fz5uck5/UDFPwn-CVE-2012-5613)

### CVE-2012-5664
- [phusion/rails-cve-2012-5664-test](https://github.com/phusion/rails-cve-2012-5664-test)

### CVE-2012-5958

<code>
Stack-based buffer overflow in the unique_service_name function in ssdp/ssdp_server.c in the SSDP parser in the portable SDK for UPnP Devices (aka libupnp, formerly the Intel SDK for UPnP devices) before 1.6.18 allows remote attackers to execute arbitrary code via a UDP packet with a crafted string that is not properly handled after a certain pointer subtraction.
</code>

- [lochiiconnectivity/vulnupnp](https://github.com/lochiiconnectivity/vulnupnp)

### CVE-2012-5960

<code>
Stack-based buffer overflow in the unique_service_name function in ssdp/ssdp_server.c in the SSDP parser in the portable SDK for UPnP Devices (aka libupnp, formerly the Intel SDK for UPnP devices) before 1.6.18 allows remote attackers to execute arbitrary code via a long UDN (aka upnp:rootdevice) field in a UDP packet.
</code>

- [finn79426/CVE-2012-5960-PoC](https://github.com/finn79426/CVE-2012-5960-PoC)

### CVE-2012-6066

<code>
freeSSHd.exe in freeSSHd through 1.2.6 allows remote attackers to bypass authentication via a crafted session, as demonstrated by an OpenSSH client with modified versions of ssh.c and sshconnect2.c.
</code>

- [bongbongco/CVE-2012-6066](https://github.com/bongbongco/CVE-2012-6066)

### CVE-2012-6636

<code>
The Android API before 17 does not properly restrict the WebView.addJavascriptInterface method, which allows remote attackers to execute arbitrary methods of Java objects by using the Java Reflection API within crafted JavaScript code that is loaded into the WebView component in an application targeted to API level 16 or earlier, a related issue to CVE-2013-4710.
</code>

- [xckevin/AndroidWebviewInjectDemo](https://github.com/xckevin/AndroidWebviewInjectDemo)


## 2011
### CVE-2011-0228

<code>
The Data Security component in Apple iOS before 4.2.10 and 4.3.x before 4.3.5 does not check the basicConstraints parameter during validation of X.509 certificate chains, which allows man-in-the-middle attackers to spoof an SSL server by using a non-CA certificate to sign a certificate for an arbitrary domain.
</code>

- [jan0/isslfix](https://github.com/jan0/isslfix)

### CVE-2011-1237

<code>
Use-after-free vulnerability in win32k.sys in the kernel-mode drivers in Microsoft Windows XP SP2 and SP3, Windows Server 2003 SP2, Windows Vista SP1 and SP2, Windows Server 2008 Gold, SP2, R2, and R2 SP1, and Windows 7 Gold and SP1 allows local users to gain privileges via a crafted application that leverages incorrect driver object management, a different vulnerability than other &quot;Vulnerability Type 1&quot; CVEs listed in MS11-034, aka &quot;Win32k Use After Free Vulnerability.&quot;
</code>

- [BrunoPujos/CVE-2011-1237](https://github.com/BrunoPujos/CVE-2011-1237)

### CVE-2011-1249

<code>
The Ancillary Function Driver (AFD) in afd.sys in Microsoft Windows XP SP2 and SP3, Windows Server 2003 SP2, Windows Vista SP1 and SP2, Windows Server 2008 Gold, SP2, R2, and R2 SP1, and Windows 7 Gold and SP1 does not properly validate user-mode input, which allows local users to gain privileges via a crafted application, aka &quot;Ancillary Function Driver Elevation of Privilege Vulnerability.&quot;
</code>

- [Madusanka99/OHTS](https://github.com/Madusanka99/OHTS)

### CVE-2011-1473

<code>
** DISPUTED ** OpenSSL before 0.9.8l, and 0.9.8m through 1.x, does not properly restrict client-initiated renegotiation within the SSL and TLS protocols, which might make it easier for remote attackers to cause a denial of service (CPU consumption) by performing many renegotiations within a single connection, a different vulnerability than CVE-2011-5094.  NOTE: it can also be argued that it is the responsibility of server deployments, not a security library, to prevent or limit renegotiation when it is inappropriate within a specific environment.
</code>

- [c826/bash-tls-reneg-attack](https://github.com/c826/bash-tls-reneg-attack)
- [zjt674449039/cve-2011-1473](https://github.com/zjt674449039/cve-2011-1473)

### CVE-2011-1475

<code>
The HTTP BIO connector in Apache Tomcat 7.0.x before 7.0.12 does not properly handle HTTP pipelining, which allows remote attackers to read responses intended for other clients in opportunistic circumstances by examining the application data in HTTP packets, related to &quot;a mix-up of responses for requests from different users.&quot;
</code>

- [samaujs/CVE-2011-1475](https://github.com/samaujs/CVE-2011-1475)

### CVE-2011-1485

<code>
Race condition in the pkexec utility and polkitd daemon in PolicyKit (aka polkit) 0.96 allows local users to gain privileges by executing a setuid program from pkexec, related to the use of the effective user ID instead of the real user ID.
</code>

- [Pashkela/CVE-2011-1485](https://github.com/Pashkela/CVE-2011-1485)

### CVE-2011-1571

<code>
Unspecified vulnerability in the XSL Content portlet in Liferay Portal Community Edition (CE) 5.x and 6.x before 6.0.6 GA, when Apache Tomcat is used, allows remote attackers to execute arbitrary commands via unknown vectors.
</code>

- [noobpk/CVE-2011-1571](https://github.com/noobpk/CVE-2011-1571)

### CVE-2011-1575

<code>
The STARTTLS implementation in ftp_parser.c in Pure-FTPd before 1.0.30 does not properly restrict I/O buffering, which allows man-in-the-middle attackers to insert commands into encrypted FTP sessions by sending a cleartext command that is processed after TLS is in place, related to a &quot;plaintext command injection&quot; attack, a similar issue to CVE-2011-0411.
</code>

- [masamoon/cve-2011-1575-poc](https://github.com/masamoon/cve-2011-1575-poc)

### CVE-2011-1720

<code>
The SMTP server in Postfix before 2.5.13, 2.6.x before 2.6.10, 2.7.x before 2.7.4, and 2.8.x before 2.8.3, when certain Cyrus SASL authentication methods are enabled, does not create a new server handle after client authentication fails, which allows remote attackers to cause a denial of service (heap memory corruption and daemon crash) or possibly execute arbitrary code via an invalid AUTH command with one method followed by an AUTH command with a different method.
</code>

- [nbeguier/postfix_exploit](https://github.com/nbeguier/postfix_exploit)

### CVE-2011-1974

<code>
NDISTAPI.sys in the NDISTAPI driver in Remote Access Service (RAS) in Microsoft Windows XP SP2 and SP3 and Windows Server 2003 SP2 does not properly validate user-mode input, which allows local users to gain privileges via a crafted application, aka &quot;NDISTAPI Elevation of Privilege Vulnerability.&quot;
</code>

- [hittlle/CVE-2011-1974-PoC](https://github.com/hittlle/CVE-2011-1974-PoC)

### CVE-2011-2461

<code>
Cross-site scripting (XSS) vulnerability in the Adobe Flex SDK 3.x and 4.x before 4.6 allows remote attackers to inject arbitrary web script or HTML via vectors related to the loading of modules from different domains.
</code>

- [ikkisoft/ParrotNG](https://github.com/ikkisoft/ParrotNG)
- [u-maxx/magento-swf-patched-CVE-2011-2461](https://github.com/u-maxx/magento-swf-patched-CVE-2011-2461)
- [edmondscommerce/CVE-2011-2461_Magento_Patch](https://github.com/edmondscommerce/CVE-2011-2461_Magento_Patch)

### CVE-2011-2894

<code>
Spring Framework 3.0.0 through 3.0.5, Spring Security 3.0.0 through 3.0.5 and 2.0.0 through 2.0.6, and possibly other versions deserialize objects from untrusted sources, which allows remote attackers to bypass intended security restrictions and execute untrusted code by (1) serializing a java.lang.Proxy instance and using InvocationHandler, or (2) accessing internal AOP interfaces, as demonstrated using deserialization of a DefaultListableBeanFactory instance to execute arbitrary commands via the java.lang.Runtime class.
</code>

- [pwntester/SpringBreaker](https://github.com/pwntester/SpringBreaker)

### CVE-2011-3026

<code>
Integer overflow in libpng, as used in Google Chrome before 17.0.963.56, allows remote attackers to cause a denial of service or possibly have unspecified other impact via unknown vectors that trigger an integer truncation.
</code>

- [argp/cve-2011-3026-firefox](https://github.com/argp/cve-2011-3026-firefox)

### CVE-2011-3192

<code>
The byterange filter in the Apache HTTP Server 1.3.x, 2.0.x through 2.0.64, and 2.2.x through 2.2.19 allows remote attackers to cause a denial of service (memory and CPU consumption) via a Range header that expresses multiple overlapping ranges, as exploited in the wild in August 2011, a different vulnerability than CVE-2007-0086.
</code>

- [tkisason/KillApachePy](https://github.com/tkisason/KillApachePy)
- [limkokhole/CVE-2011-3192](https://github.com/limkokhole/CVE-2011-3192)
- [stcmjp/cve-2011-3192](https://github.com/stcmjp/cve-2011-3192)

### CVE-2011-3368

<code>
The mod_proxy module in the Apache HTTP Server 1.3.x through 1.3.42, 2.0.x through 2.0.64, and 2.2.x through 2.2.21 does not properly interact with use of (1) RewriteRule and (2) ProxyPassMatch pattern matches for configuration of a reverse proxy, which allows remote attackers to send requests to intranet servers via a malformed URI containing an initial @ (at sign) character.
</code>

- [SECFORCE/CVE-2011-3368](https://github.com/SECFORCE/CVE-2011-3368)
- [colorblindpentester/CVE-2011-3368](https://github.com/colorblindpentester/CVE-2011-3368)

### CVE-2011-3389

<code>
The SSL protocol, as used in certain configurations in Microsoft Windows and Microsoft Internet Explorer, Mozilla Firefox, Google Chrome, Opera, and other products, encrypts data by using CBC mode with chained initialization vectors, which allows man-in-the-middle attackers to obtain plaintext HTTP headers via a blockwise chosen-boundary attack (BCBA) on an HTTPS session, in conjunction with JavaScript code that uses (1) the HTML5 WebSocket API, (2) the Java URLConnection API, or (3) the Silverlight WebClient API, aka a &quot;BEAST&quot; attack.
</code>

- [mpgn/BEAST-PoC](https://github.com/mpgn/BEAST-PoC)

### CVE-2011-3556

<code>
Unspecified vulnerability in the Java Runtime Environment component in Oracle Java SE JDK and JRE 7, 6 Update 27 and earlier, 5.0 Update 31 and earlier, 1.4.2_33 and earlier, and JRockit R28.1.4 and earlier allows remote attackers to affect confidentiality, integrity, and availability, related to RMI, a different vulnerability than CVE-2011-3557.
</code>

- [sk4la/cve_2011_3556](https://github.com/sk4la/cve_2011_3556)

### CVE-2011-3872

<code>
Puppet 2.6.x before 2.6.12 and 2.7.x before 2.7.6, and Puppet Enterprise (PE) Users 1.0, 1.1, and 1.2 before 1.2.4, when signing an agent certificate, adds the Puppet master's certdnsnames values to the X.509 Subject Alternative Name field of the certificate, which allows remote attackers to spoof a Puppet master via a man-in-the-middle (MITM) attack against an agent that uses an alternate DNS name for the master, aka &quot;AltNames Vulnerability.&quot;
</code>

- [puppetlabs/puppetlabs-cve20113872](https://github.com/puppetlabs/puppetlabs-cve20113872)

### CVE-2011-4107

<code>
The simplexml_load_string function in the XML import plug-in (libraries/import/xml.php) in phpMyAdmin 3.4.x before 3.4.7.1 and 3.3.x before 3.3.10.5 allows remote authenticated users to read arbitrary files via XML data containing external entity references, aka an XML external entity (XXE) injection attack.
</code>

- [SECFORCE/CVE-2011-4107](https://github.com/SECFORCE/CVE-2011-4107)

### CVE-2011-4862

<code>
Buffer overflow in libtelnet/encrypt.c in telnetd in FreeBSD 7.3 through 9.0, MIT Kerberos Version 5 Applications (aka krb5-appl) 1.0.2 and earlier, Heimdal 1.5.1 and earlier, GNU inetutils, and possibly other products allows remote attackers to execute arbitrary code via a long encryption key, as exploited in the wild in December 2011.
</code>

- [hdbreaker/GO-CVE-2011-4862](https://github.com/hdbreaker/GO-CVE-2011-4862)
- [lol-fi/cve-2011-4862](https://github.com/lol-fi/cve-2011-4862)
- [kpawar2410/CVE-2011-4862](https://github.com/kpawar2410/CVE-2011-4862)

### CVE-2011-4872

<code>
Multiple HTC Android devices including Desire HD FRG83D and GRI40, Glacier FRG83, Droid Incredible FRF91, Thunderbolt 4G FRG83D, Sensation Z710e GRI40, Sensation 4G GRI40, Desire S GRI40, EVO 3D GRI40, and EVO 4G GRI40 allow remote attackers to obtain 802.1X Wi-Fi credentials and SSID via a crafted application that uses the android.permission.ACCESS_WIFI_STATE permission to call the toString method on the WifiConfiguration class.
</code>

- [Chiggins/CVE-2011-4872](https://github.com/Chiggins/CVE-2011-4872)

### CVE-2011-4905

<code>
Apache ActiveMQ before 5.6.0 allows remote attackers to cause a denial of service (file-descriptor exhaustion and broker crash or hang) by sending many openwire failover:tcp:// connection requests.
</code>

- [Michael-Main/CVE-2011-4905](https://github.com/Michael-Main/CVE-2011-4905)

### CVE-2011-4919

<code>
mpack 1.6 has information disclosure via eavesdropping on mails sent by other users
</code>

- [hartwork/mpacktrafficripper](https://github.com/hartwork/mpacktrafficripper)


## 2010
### CVE-2010-0426

<code>
sudo 1.6.x before 1.6.9p21 and 1.7.x before 1.7.2p4, when a pseudo-command is enabled, permits a match between the name of the pseudo-command and the name of an executable file in an arbitrary directory, which allows local users to gain privileges via a crafted executable file, as demonstrated by a file named sudoedit in a user's home directory.
</code>

- [t0kx/privesc-CVE-2010-0426](https://github.com/t0kx/privesc-CVE-2010-0426)
- [cved-sources/cve-2010-0426](https://github.com/cved-sources/cve-2010-0426)

### CVE-2010-0738

<code>
The JMX-Console web application in JBossAs in Red Hat JBoss Enterprise Application Platform (aka JBoss EAP or JBEAP) 4.2 before 4.2.0.CP09 and 4.3 before 4.3.0.CP08 performs access control only for the GET and POST methods, which allows remote attackers to send requests to this application's GET handler by using a different method.
</code>

- [ChristianPapathanasiou/jboss-autopwn](https://github.com/ChristianPapathanasiou/jboss-autopwn)
- [gitcollect/jboss-autopwn](https://github.com/gitcollect/jboss-autopwn)

### CVE-2010-1205

<code>
Buffer overflow in pngpread.c in libpng before 1.2.44 and 1.4.x before 1.4.3, as used in progressive applications, might allow remote attackers to execute arbitrary code via a PNG image that triggers an additional data row.
</code>

- [mk219533/CVE-2010-1205](https://github.com/mk219533/CVE-2010-1205)

### CVE-2010-1411

<code>
Multiple integer overflows in the Fax3SetupState function in tif_fax3.c in the FAX3 decoder in LibTIFF before 3.9.3, as used in ImageIO in Apple Mac OS X 10.5.8 and Mac OS X 10.6 before 10.6.4, allow remote attackers to execute arbitrary code or cause a denial of service (application crash) via a crafted TIFF file that triggers a heap-based buffer overflow.
</code>

- [MAVProxyUser/httpfuzz-robomiller](https://github.com/MAVProxyUser/httpfuzz-robomiller)

### CVE-2010-2075

<code>
UnrealIRCd 3.2.8.1, as distributed on certain mirror sites from November 2009 through June 2010, contains an externally introduced modification (Trojan Horse) in the DEBUG3_DOLOG_SYSTEM macro, which allows remote attackers to execute arbitrary commands.
</code>

- [M4LV0/UnrealIRCd-3.2.8.1-RCE](https://github.com/M4LV0/UnrealIRCd-3.2.8.1-RCE)

### CVE-2010-3332

<code>
Microsoft .NET Framework 1.1 SP1, 2.0 SP1 and SP2, 3.5, 3.5 SP1, 3.5.1, and 4.0, as used for ASP.NET in Microsoft Internet Information Services (IIS), provides detailed error codes during decryption attempts, which allows remote attackers to decrypt and modify encrypted View State (aka __VIEWSTATE) form data, and possibly forge cookies or read application files, via a padding oracle attack, aka &quot;ASP.NET Padding Oracle Vulnerability.&quot;
</code>

- [bongbongco/MS10-070](https://github.com/bongbongco/MS10-070)

### CVE-2010-3333

<code>
Stack-based buffer overflow in Microsoft Office XP SP3, Office 2003 SP3, Office 2007 SP2, Office 2010, Office 2004 and 2008 for Mac, Office for Mac 2011, and Open XML File Format Converter for Mac allows remote attackers to execute arbitrary code via crafted RTF data, aka &quot;RTF Stack Buffer Overflow Vulnerability.&quot;
</code>

- [whiteHat001/cve-2010-3333](https://github.com/whiteHat001/cve-2010-3333)

### CVE-2010-3437

<code>
Integer signedness error in the pkt_find_dev_from_minor function in drivers/block/pktcdvd.c in the Linux kernel before 2.6.36-rc6 allows local users to obtain sensitive information from kernel memory or cause a denial of service (invalid pointer dereference and system crash) via a crafted index value in a PKT_CTRL_CMD_STATUS ioctl call.
</code>

- [huang-emily/CVE-2010-3437](https://github.com/huang-emily/CVE-2010-3437)

### CVE-2010-3490

<code>
Directory traversal vulnerability in page.recordings.php in the System Recordings component in the configuration interface in FreePBX 2.8.0 and earlier allows remote authenticated administrators to create arbitrary files via a .. (dot dot) in the usersnum parameter to admin/config.php, as demonstrated by creating a .php file under the web root.
</code>

- [moayadalmalat/CVE-2010-3490](https://github.com/moayadalmalat/CVE-2010-3490)

### CVE-2010-3600

<code>
Unspecified vulnerability in the Client System Analyzer component in Oracle Database Server 11.1.0.7 and 11.2.0.1 and Enterprise Manager Grid Control 10.2.0.5 allows remote attackers to affect confidentiality, integrity, and availability via unknown vectors. NOTE: the previous information was obtained from the January 2011 CPU.  Oracle has not commented on claims from a reliable third party coordinator that this issue involves an exposed JSP script that accepts XML uploads in conjunction with NULL bytes in an unspecified parameter that allow execution of arbitrary code.
</code>

- [LAITRUNGMINHDUC/CVE-2010-3600-PythonHackOracle11gR2](https://github.com/LAITRUNGMINHDUC/CVE-2010-3600-PythonHackOracle11gR2)

### CVE-2010-3847

<code>
elf/dl-load.c in ld.so in the GNU C Library (aka glibc or libc6) through 2.11.2, and 2.12.x through 2.12.1, does not properly handle a value of $ORIGIN for the LD_AUDIT environment variable, which allows local users to gain privileges via a crafted dynamic shared object (DSO) located in an arbitrary directory.
</code>

- [magisterquis/cve-2010-3847](https://github.com/magisterquis/cve-2010-3847)

### CVE-2010-3904

<code>
The rds_page_copy_user function in net/rds/page.c in the Reliable Datagram Sockets (RDS) protocol implementation in the Linux kernel before 2.6.36 does not properly validate addresses obtained from user space, which allows local users to gain privileges via crafted use of the sendmsg and recvmsg system calls.
</code>

- [redhatkaty/-cve-2010-3904-report](https://github.com/redhatkaty/-cve-2010-3904-report)

### CVE-2010-3971

<code>
Use-after-free vulnerability in the CSharedStyleSheet::Notify function in the Cascading Style Sheets (CSS) parser in mshtml.dll, as used in Microsoft Internet Explorer 6 through 8 and other products, allows remote attackers to execute arbitrary code or cause a denial of service (application crash) via a self-referential @import rule in a stylesheet, aka &quot;CSS Memory Corruption Vulnerability.&quot;
</code>

- [nektra/CVE-2010-3971-hotpatch](https://github.com/nektra/CVE-2010-3971-hotpatch)

### CVE-2010-4221

<code>
Multiple stack-based buffer overflows in the pr_netio_telnet_gets function in netio.c in ProFTPD before 1.3.3c allow remote attackers to execute arbitrary code via vectors involving a TELNET IAC escape character to a (1) FTP or (2) FTPS server.
</code>

- [M31MOTH/cve-2010-4221](https://github.com/M31MOTH/cve-2010-4221)

### CVE-2010-4258

<code>
The do_exit function in kernel/exit.c in the Linux kernel before 2.6.36.2 does not properly handle a KERNEL_DS get_fs value, which allows local users to bypass intended access_ok restrictions, overwrite arbitrary kernel memory locations, and gain privileges by leveraging a (1) BUG, (2) NULL pointer dereference, or (3) page fault, as demonstrated by vectors involving the clear_child_tid feature and the splice system call.
</code>

- [johnreginald/CVE-2010-4258](https://github.com/johnreginald/CVE-2010-4258)

### CVE-2010-4476

<code>
The Double.parseDouble method in Java Runtime Environment (JRE) in Oracle Java SE and Java for Business 6 Update 23 and earlier, 5.0 Update 27 and earlier, and 1.4.2_29 and earlier, as used in OpenJDK, Apache, JBossweb, and other products, allows remote attackers to cause a denial of service via a crafted string that triggers an infinite loop of estimations during conversion to a double-precision binary floating-point number, as demonstrated using 2.2250738585072012e-308.
</code>

- [grzegorzblaszczyk/CVE-2010-4476-check](https://github.com/grzegorzblaszczyk/CVE-2010-4476-check)

### CVE-2010-4669

<code>
The Neighbor Discovery (ND) protocol implementation in the IPv6 stack in Microsoft Windows XP, Windows Server 2003, Windows Vista, Windows Server 2008, and Windows 7 allows remote attackers to cause a denial of service (CPU consumption and system hang) by sending many Router Advertisement (RA) messages with different source addresses, as demonstrated by the flood_router6 program in the thc-ipv6 package.
</code>

- [quinn-samuel-perry/CVE-2010-4669](https://github.com/quinn-samuel-perry/CVE-2010-4669)

### CVE-2010-4804

<code>
The Android browser in Android before 2.3.4 allows remote attackers to obtain SD card contents via crafted content:// URIs, related to (1) BrowserActivity.java and (2) BrowserSettings.java in com/android/browser/.
</code>

- [thomascannon/android-cve-2010-4804](https://github.com/thomascannon/android-cve-2010-4804)

### CVE-2010-5327

<code>
Liferay Portal through 6.2.10 allows remote authenticated users to execute arbitrary shell commands via a crafted Velocity template.
</code>

- [Michael-Main/CVE-2010-5327](https://github.com/Michael-Main/CVE-2010-5327)


## 2009
### CVE-2009-0229

<code>
The Windows Printing Service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP2, Vista Gold, SP1, and SP2, and Server 2008 SP2 allows local users to read arbitrary files via a crafted separator page, aka &quot;Print Spooler Read File Vulnerability.&quot;
</code>

- [zveriu/CVE-2009-0229-PoC](https://github.com/zveriu/CVE-2009-0229-PoC)

### CVE-2009-0473

<code>
Open redirect vulnerability in the web interface in the Rockwell Automation ControlLogix 1756-ENBT/A EtherNet/IP Bridge Module allows remote attackers to redirect users to arbitrary web sites and conduct phishing attacks via unspecified vectors.
</code>

- [akbarq/CVE-2009-0473](https://github.com/akbarq/CVE-2009-0473)

### CVE-2009-0689

<code>
Array index error in the (1) dtoa implementation in dtoa.c (aka pdtoa.c) and the (2) gdtoa (aka new dtoa) implementation in gdtoa/misc.c in libc, as used in multiple operating systems and products including in FreeBSD 6.4 and 7.2, NetBSD 5.0, OpenBSD 4.5, Mozilla Firefox 3.0.x before 3.0.15 and 3.5.x before 3.5.4, K-Meleon 1.5.3, SeaMonkey 1.1.8, and other products, allows context-dependent attackers to cause a denial of service (application crash) and possibly execute arbitrary code via a large precision value in the format argument to a printf function, which triggers incorrect memory allocation and a heap-based buffer overflow during conversion to a floating-point number.
</code>

- [Fullmetal5/str2hax](https://github.com/Fullmetal5/str2hax)

### CVE-2009-1151

<code>
Static code injection vulnerability in setup.php in phpMyAdmin 2.11.x before 2.11.9.5 and 3.x before 3.1.3.1 allows remote attackers to inject arbitrary PHP code into a configuration file via the save action.
</code>

- [minervais/pocs](https://github.com/minervais/pocs)

### CVE-2009-1244

<code>
Unspecified vulnerability in the virtual machine display function in VMware Workstation 6.5.1 and earlier; VMware Player 2.5.1 and earlier; VMware ACE 2.5.1 and earlier; VMware Server 1.x before 1.0.9 build 156507 and 2.x before 2.0.1 build 156745; VMware Fusion before 2.0.4 build 159196; VMware ESXi 3.5; and VMware ESX 3.0.2, 3.0.3, and 3.5 allows guest OS users to execute arbitrary code on the host OS via unknown vectors, a different vulnerability than CVE-2008-4916.
</code>

- [piotrbania/vmware_exploit_pack_CVE-2009-1244](https://github.com/piotrbania/vmware_exploit_pack_CVE-2009-1244)

### CVE-2009-1324

<code>
Stack-based buffer overflow in Mini-stream ASX to MP3 Converter 3.0.0.7 allows remote attackers to execute arbitrary code via a long URI in a playlist (.m3u) file.
</code>

- [war4uthor/CVE-2009-1324](https://github.com/war4uthor/CVE-2009-1324)

### CVE-2009-1330

<code>
Stack-based buffer overflow in Easy RM to MP3 Converter allows remote attackers to execute arbitrary code via a long filename in a playlist (.pls) file.
</code>

- [adenkiewicz/CVE-2009-1330](https://github.com/adenkiewicz/CVE-2009-1330)
- [war4uthor/CVE-2009-1330](https://github.com/war4uthor/CVE-2009-1330)
- [exploitwritter/CVE-2009-1330_EasyRMToMp3Converter](https://github.com/exploitwritter/CVE-2009-1330_EasyRMToMp3Converter)

### CVE-2009-1437

<code>
Stack-based buffer overflow in PortableApps CoolPlayer Portable (aka CoolPlayer+ Portable) 2.19.6 and earlier allows remote attackers to execute arbitrary code via a long string in a malformed playlist (.m3u) file. NOTE: this may overlap CVE-2008-3408.
</code>

- [HanseSecure/CVE-2009-1437](https://github.com/HanseSecure/CVE-2009-1437)

### CVE-2009-1904

<code>
The BigDecimal library in Ruby 1.8.6 before p369 and 1.8.7 before p173 allows context-dependent attackers to cause a denial of service (application crash) via a string argument that represents a large number, as demonstrated by an attempted conversion to the Float data type.
</code>

- [NZKoz/bigdecimal-segfault-fix](https://github.com/NZKoz/bigdecimal-segfault-fix)

### CVE-2009-2692

<code>
The Linux kernel 2.6.0 through 2.6.30.4, and 2.4.4 through 2.4.37.4, does not initialize all function pointers for socket operations in proto_ops structures, which allows local users to trigger a NULL pointer dereference and gain privileges by using mmap to map page zero, placing arbitrary code on this page, and then invoking an unavailable operation, as demonstrated by the sendpage operation (sock_sendpage function) on a PF_PPPOX socket.
</code>

- [jdvalentini/CVE-2009-2692](https://github.com/jdvalentini/CVE-2009-2692)

### CVE-2009-2698

<code>
The udp_sendmsg function in the UDP implementation in (1) net/ipv4/udp.c and (2) net/ipv6/udp.c in the Linux kernel before 2.6.19 allows local users to gain privileges or cause a denial of service (NULL pointer dereference and system crash) via vectors involving the MSG_MORE flag and a UDP socket.
</code>

- [xiaoxiaoleo/CVE-2009-2698](https://github.com/xiaoxiaoleo/CVE-2009-2698)

### CVE-2009-3103

<code>
Array index error in the SMBv2 protocol implementation in srv2.sys in Microsoft Windows Vista Gold, SP1, and SP2, Windows Server 2008 Gold and SP2, and Windows 7 RC allows remote attackers to execute arbitrary code or cause a denial of service (system crash) via an &amp; (ampersand) character in a Process ID High header field in a NEGOTIATE PROTOCOL REQUEST packet, which triggers an attempted dereference of an out-of-bounds memory location, aka &quot;SMBv2 Negotiation Vulnerability.&quot; NOTE: some of these details are obtained from third party information.
</code>

- [mazding/ms09050](https://github.com/mazding/ms09050)

### CVE-2009-4092

<code>
Cross-site request forgery (CSRF) vulnerability in user.php in Simplog 0.9.3.2, and possibly earlier, allows remote attackers to hijack the authentication of administrators and users for requests that change passwords.
</code>

- [xiaoyu-iid/Simplog-Exploit](https://github.com/xiaoyu-iid/Simplog-Exploit)

### CVE-2009-4118

<code>
The StartServiceCtrlDispatcher function in the cvpnd service (cvpnd.exe) in Cisco VPN client for Windows before 5.0.06.0100 does not properly handle an ERROR_FAILED_SERVICE_CONTROLLER_CONNECT error, which allows local users to cause a denial of service (service crash and VPN connection loss) via a manual start of cvpnd.exe while the cvpnd service is running.
</code>

- [alt3kx/CVE-2009-4118](https://github.com/alt3kx/CVE-2009-4118)

### CVE-2009-4137

<code>
The loadContentFromCookie function in core/Cookie.php in Piwik before 0.5 does not validate strings obtained from cookies before calling the unserialize function, which allows remote attackers to execute arbitrary code or upload arbitrary files via vectors related to the __destruct function in the Piwik_Config class; php://filter URIs; the __destruct functions in Zend Framework, as demonstrated by the Zend_Log destructor; the shutdown functions in Zend Framework, as demonstrated by the Zend_Log_Writer_Mail class; the render function in the Piwik_View class; Smarty templates; and the _eval function in Smarty.
</code>

- [Alexeyan/CVE-2009-4137](https://github.com/Alexeyan/CVE-2009-4137)

### CVE-2009-4660

<code>
Stack-based buffer overflow in the AntServer Module (AntServer.exe) in BigAnt IM Server 2.50 allows remote attackers to execute arbitrary code via a long GET request to TCP port 6660.
</code>

- [war4uthor/CVE-2009-4660](https://github.com/war4uthor/CVE-2009-4660)

### CVE-2009-5147

<code>
DL::dlopen in Ruby 1.8, 1.9.0, 1.9.2, 1.9.3, 2.0.0 before patchlevel 648, and 2.1 before 2.1.8 opens libraries with tainted names.
</code>

- [vpereira/CVE-2009-5147](https://github.com/vpereira/CVE-2009-5147)
- [zhangyongbo100/-Ruby-dl-handle.c-CVE-2009-5147-](https://github.com/zhangyongbo100/-Ruby-dl-handle.c-CVE-2009-5147-)


## 2008
### CVE-2008-0128

<code>
The SingleSignOn Valve (org.apache.catalina.authenticator.SingleSignOn) in Apache Tomcat before 5.5.21 does not set the secure flag for the JSESSIONIDSSO cookie in an https session, which can cause the cookie to be sent in http requests and make it easier for remote attackers to capture this cookie.
</code>

- [ngyanch/4062-1](https://github.com/ngyanch/4062-1)

### CVE-2008-0166

<code>
OpenSSL 0.9.8c-1 up to versions before 0.9.8g-9 on Debian-based operating systems uses a random number generator that generates predictable numbers, which makes it easier for remote attackers to conduct brute force guessing attacks against cryptographic keys.
</code>

- [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)
- [avarx/vulnkeys](https://github.com/avarx/vulnkeys)
- [nu11secur1ty/debian-ssh](https://github.com/nu11secur1ty/debian-ssh)

### CVE-2008-0228

<code>
Cross-site request forgery (CSRF) vulnerability in apply.cgi in the Linksys WRT54GL Wireless-G Broadband Router with firmware 4.30.9 allows remote attackers to perform actions as administrators.
</code>

- [SpiderLabs/TWSL2011-007_iOS_code_workaround](https://github.com/SpiderLabs/TWSL2011-007_iOS_code_workaround)

### CVE-2008-1611

<code>
Stack-based buffer overflow in TFTP Server SP 1.4 for Windows allows remote attackers to cause a denial of service or execute arbitrary code via a long filename in a read or write request.
</code>

- [Axua/CVE-2008-1611](https://github.com/Axua/CVE-2008-1611)

### CVE-2008-1613

<code>
SQL injection vulnerability in ioRD.asp in RedDot CMS 7.5 Build 7.5.0.48, and possibly other versions including 6.5 and 7.0, allows remote attackers to execute arbitrary SQL commands via the LngId parameter.
</code>

- [SECFORCE/CVE-2008-1613](https://github.com/SECFORCE/CVE-2008-1613)

### CVE-2008-2938

<code>
Directory traversal vulnerability in Apache Tomcat 4.1.0 through 4.1.37, 5.5.0 through 5.5.26, and 6.0.0 through 6.0.16, when allowLinking and UTF-8 are enabled, allows remote attackers to read arbitrary files via encoded directory traversal sequences in the URI, a different vulnerability than CVE-2008-2370.  NOTE: versions earlier than 6.0.18 were reported affected, but the vendor advisory lists 6.0.16 as the last affected version.
</code>

- [Naramsim/Offensive](https://github.com/Naramsim/Offensive)

### CVE-2008-4250

<code>
The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2, Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary code via a crafted RPC request that triggers the overflow during path canonicalization, as exploited in the wild by Gimmiv.A in October 2008, aka &quot;Server Service Vulnerability.&quot;
</code>

- [thunderstrike9090/Conflicker_analysis_scripts](https://github.com/thunderstrike9090/Conflicker_analysis_scripts)

### CVE-2008-4609

<code>
The TCP implementation in (1) Linux, (2) platforms based on BSD Unix, (3) Microsoft Windows, (4) Cisco products, and probably other operating systems allows remote attackers to cause a denial of service (connection queue exhaustion) via multiple vectors that manipulate information in the TCP state table, as demonstrated by sockstress.
</code>

- [marcelki/sockstress](https://github.com/marcelki/sockstress)

### CVE-2008-4654

<code>
Stack-based buffer overflow in the parse_master function in the Ty demux plugin (modules/demux/ty.c) in VLC Media Player 0.9.0 through 0.9.4 allows remote attackers to execute arbitrary code via a TiVo TY media file with a header containing a crafted size value.
</code>

- [bongbongco/CVE-2008-4654](https://github.com/bongbongco/CVE-2008-4654)
- [KernelErr/VLC-CVE-2008-4654-Exploit](https://github.com/KernelErr/VLC-CVE-2008-4654-Exploit)

### CVE-2008-5416

<code>
Heap-based buffer overflow in Microsoft SQL Server 2000 SP4, 8.00.2050, 8.00.2039, and earlier; SQL Server 2000 Desktop Engine (MSDE 2000) SP4; SQL Server 2005 SP2 and 9.00.1399.06; SQL Server 2000 Desktop Engine (WMSDE) on Windows Server 2003 SP1 and SP2; and Windows Internal Database (WYukon) SP2 allows remote authenticated users to cause a denial of service (access violation exception) or execute arbitrary code by calling the sp_replwritetovarbin extended stored procedure with a set of invalid parameters that trigger memory overwrite, aka &quot;SQL Server sp_replwritetovarbin Limited Memory Overwrite Vulnerability.&quot;
</code>

- [SECFORCE/CVE-2008-5416](https://github.com/SECFORCE/CVE-2008-5416)

### CVE-2008-6827

<code>
The ListView control in the Client GUI (AClient.exe) in Symantec Altiris Deployment Solution 6.x before 6.9.355 SP1 allows local users to gain SYSTEM privileges and execute arbitrary commands via a &quot;Shatter&quot; style attack on the &quot;command prompt&quot; hidden GUI button to (1) overwrite the CommandLine parameter to cmd.exe to use SYSTEM privileges and (2) modify the DLL that is loaded using the LoadLibrary API function.
</code>

- [alt3kx/CVE-2008-6827](https://github.com/alt3kx/CVE-2008-6827)

### CVE-2008-6970

<code>
SQL injection vulnerability in dosearch.inc.php in UBB.threads 7.3.1 and earlier allows remote attackers to execute arbitrary SQL commands via the Forum[] array parameter.
</code>

- [KyomaHooin/CVE-2008-6970](https://github.com/KyomaHooin/CVE-2008-6970)

### CVE-2008-7220

<code>
Unspecified vulnerability in Prototype JavaScript framework (prototypejs) before 1.6.0.2 allows attackers to make &quot;cross-site ajax requests&quot; via unknown vectors.
</code>

- [followboy1999/CVE-2008-7220](https://github.com/followboy1999/CVE-2008-7220)


## 2007
### CVE-2007-0038

<code>
Stack-based buffer overflow in the animated cursor code in Microsoft Windows 2000 SP4 through Vista allows remote attackers to execute arbitrary code or cause a denial of service (persistent reboot) via a large length value in the second (or later) anih block of a RIFF .ANI, cur, or .ico file, which results in memory corruption when processing cursors, animated cursors, and icons, a variant of CVE-2005-0416, as originally demonstrated using Internet Explorer 6 and 7. NOTE: this might be a duplicate of CVE-2007-1765; if so, then CVE-2007-0038 should be preferred.
</code>

- [Axua/CVE-2007-0038](https://github.com/Axua/CVE-2007-0038)

### CVE-2007-0843

<code>
The ReadDirectoryChangesW API function on Microsoft Windows 2000, XP, Server 2003, and Vista does not check permissions for child objects, which allows local users to bypass permissions by opening a directory with LIST (READ) access and using ReadDirectoryChangesW to monitor changes of files that do not have LIST permissions, which can be leveraged to determine filenames, access times, and other sensitive information.
</code>

- [z3APA3A/spydir](https://github.com/z3APA3A/spydir)

### CVE-2007-1567

<code>
Stack-based buffer overflow in War FTP Daemon 1.65, and possibly earlier, allows remote attackers to cause a denial of service or execute arbitrary code via unspecified vectors, as demonstrated by warftp_165.tar by Immunity.  NOTE: this might be the same issue as CVE-1999-0256, CVE-2000-0131, or CVE-2006-2171, but due to Immunity's lack of details, this cannot be certain.
</code>

- [war4uthor/CVE-2007-1567](https://github.com/war4uthor/CVE-2007-1567)

### CVE-2007-2447

<code>
The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters involving the (1) SamrChangePassword function, when the &quot;username map script&quot; smb.conf option is enabled, and allows remote authenticated users to execute commands via shell metacharacters involving other MS-RPC functions in the (2) remote printer and (3) file share management.
</code>

- [noondi/metasploitable2](https://github.com/noondi/metasploitable2)
- [amriunix/CVE-2007-2447](https://github.com/amriunix/CVE-2007-2447)
- [b1fair/smb_usermap](https://github.com/b1fair/smb_usermap)
- [Unam3dd/exploit_smb_usermap_script](https://github.com/Unam3dd/exploit_smb_usermap_script)
- [JoseBarrios/CVE-2007-2447](https://github.com/JoseBarrios/CVE-2007-2447)
- [3x1t1um/CVE-2007-2447](https://github.com/3x1t1um/CVE-2007-2447)

### CVE-2007-3830

<code>
Cross-site scripting (XSS) vulnerability in alert.php in ISS Proventia Network IPS GX5108 1.3 and GX5008 1.5 allows remote attackers to inject arbitrary web script or HTML via the reminder parameter.
</code>

- [alt3kx/CVE-2007-3830](https://github.com/alt3kx/CVE-2007-3830)

### CVE-2007-3831

<code>
PHP remote file inclusion in main.php in ISS Proventia Network IPS GX5108 1.3 and GX5008 1.5 allows remote attackers to execute arbitrary PHP code via a URL in the page parameter.
</code>

- [alt3kx/CVE-2007-3831](https://github.com/alt3kx/CVE-2007-3831)

### CVE-2007-4607

<code>
Buffer overflow in the EasyMailSMTPObj ActiveX control in emsmtp.dll 6.0.1 in the Quiksoft EasyMail SMTP Object, as used in Postcast Server Pro 3.0.61 and other products, allows remote attackers to execute arbitrary code via a long argument to the SubmitToExpress method, a different vulnerability than CVE-2007-1029. NOTE: this may have been fixed in version 6.0.3.15.
</code>

- [joeyrideout/CVE-2007-4607](https://github.com/joeyrideout/CVE-2007-4607)

### CVE-2007-5036

<code>
Multiple buffer overflows in the AirDefense Airsensor M520 with firmware 4.3.1.1 and 4.4.1.4 allow remote authenticated users to cause a denial of service (HTTPS service outage) via a crafted query string in an HTTPS request to (1) adLog.cgi, (2) post.cgi, or (3) ad.cgi, related to the &quot;files filter.&quot;
</code>

- [alt3kx/CVE-2007-5036](https://github.com/alt3kx/CVE-2007-5036)

### CVE-2007-6638

<code>
March Networks DVR 3204 stores sensitive information under the web root with insufficient access control, which allows remote attackers to obtain usernames, passwords, device names, and IP addresses via a direct request for scripts/logfiles.tar.gz.
</code>

- [alt3kx/CVE-2007-6638](https://github.com/alt3kx/CVE-2007-6638)


## 2006
### CVE-2006-1236

<code>
Buffer overflow in the SetUp function in socket/request.c in CrossFire 1.9.0 allows remote attackers to execute arbitrary code via a long setup sound command, a different vulnerability than CVE-2006-1010.
</code>

- [Axua/CVE-2006-1236](https://github.com/Axua/CVE-2006-1236)

### CVE-2006-3592

<code>
Unspecified vulnerability in the command line interface (CLI) in Cisco Unified CallManager (CUCM) 5.0(1) through 5.0(3a) allows local users to execute arbitrary commands with elevated privileges via unspecified vectors, involving &quot;certain CLI commands,&quot; aka bug CSCse11005.
</code>

- [adenkiewicz/CVE-2006-3592](https://github.com/adenkiewicz/CVE-2006-3592)

### CVE-2006-3747

<code>
Off-by-one error in the ldap scheme handling in the Rewrite module (mod_rewrite) in Apache 1.3 from 1.3.28, 2.0.46 and other versions before 2.0.59, and 2.2, when RewriteEngine is enabled, allows remote attackers to cause a denial of service (application crash) and possibly execute arbitrary code via crafted URLs that are not properly handled using certain rewrite rules.
</code>

- [spinfoo/CVE-2006-3747](https://github.com/spinfoo/CVE-2006-3747)

### CVE-2006-4777

<code>
Heap-based buffer overflow in the DirectAnimation Path Control (DirectAnimation.PathControl) COM object (daxctle.ocx) for Internet Explorer 6.0 SP1, on Chinese and possibly other Windows distributions, allows remote attackers to execute arbitrary code via unknown manipulations in arguments to the KeyFrame method, possibly related to an integer overflow, as demonstrated by daxctle2, and a different vulnerability than CVE-2006-4446.
</code>

- [Mario1234/js-driveby-download-CVE-2006-4777](https://github.com/Mario1234/js-driveby-download-CVE-2006-4777)

### CVE-2006-4814

<code>
The mincore function in the Linux kernel before 2.4.33.6 does not properly lock access to user space, which has unspecified impact and attack vectors, possibly related to a deadlock.
</code>

- [tagatac/linux-CVE-2006-4814](https://github.com/tagatac/linux-CVE-2006-4814)

### CVE-2006-6184

<code>
Multiple stack-based buffer overflows in Allied Telesyn TFTP Server (AT-TFTP) 1.9, and possibly earlier, allow remote attackers to cause a denial of service (crash) or execute arbitrary code via a long filename in a (1) GET or (2) PUT command.
</code>

- [b03902043/CVE-2006-6184](https://github.com/b03902043/CVE-2006-6184)


## 2005
### CVE-2005-1125

<code>
Race condition in libsafe 2.0.16 and earlier, when running in multi-threaded applications, allows attackers to bypass libsafe protection and exploit other vulnerabilities before the _libsafe_die function call is completed.
</code>

- [tagatac/libsafe-CVE-2005-1125](https://github.com/tagatac/libsafe-CVE-2005-1125)

### CVE-2005-2428

<code>
Lotus Domino R5 and R6 WebMail, with &quot;Generate HTML for all fields&quot; enabled, stores sensitive data from names.nsf in hidden form fields, which allows remote attackers to read the HTML source to obtain sensitive information such as (1) the password hash in the HTTPPassword field, (2) the password change date in the HTTPPasswordChangeDate field, (3) the client platform in the ClntPltfrm field, (4) the client machine name in the ClntMachine field, and (5) the client Lotus Domino release in the ClntBld field, a different vulnerability than CVE-2005-2696.
</code>

- [schwankner/CVE-2005-2428-IBM-Lotus-Domino-R8-Password-Hash-Extraction-Exploit](https://github.com/schwankner/CVE-2005-2428-IBM-Lotus-Domino-R8-Password-Hash-Extraction-Exploit)


## 2004
### CVE-2004-0558

<code>
The Internet Printing Protocol (IPP) implementation in CUPS before 1.1.21 allows remote attackers to cause a denial of service (service hang) via a certain UDP packet to the IPP port.
</code>

- [fibonascii/CVE-2004-0558](https://github.com/fibonascii/CVE-2004-0558)

### CVE-2004-1561

<code>
Buffer overflow in Icecast 2.0.1 and earlier allows remote attackers to execute arbitrary code via an HTTP request with a large number of headers.
</code>

- [ivanitlearning/CVE-2004-1561](https://github.com/ivanitlearning/CVE-2004-1561)

### CVE-2004-1769

<code>
The &quot;Allow cPanel users to reset their password via email&quot; feature in cPanel 9.1.0 build 34 and earlier, including 8.x, allows remote attackers to execute arbitrary code via the user parameter to resetpass.
</code>

- [sinkaroid/shiguresh](https://github.com/sinkaroid/shiguresh)

### CVE-2004-2167

<code>
Multiple buffer overflows in LaTeX2rtf 1.9.15, and possibly other versions, allow remote attackers to execute arbitrary code via (1) the expandmacro function, and possibly (2) Environments and (3) TranslateCommand.
</code>

- [uzzzval/cve-2004-2167](https://github.com/uzzzval/cve-2004-2167)

### CVE-2004-2271

<code>
Buffer overflow in MiniShare 1.4.1 and earlier allows remote attackers to execute arbitrary code via a long HTTP GET request.
</code>

- [kkirsche/CVE-2004-2271](https://github.com/kkirsche/CVE-2004-2271)
- [PercussiveElbow/CVE-2004-2271-MiniShare-1.4.1-Buffer-Overflow](https://github.com/PercussiveElbow/CVE-2004-2271-MiniShare-1.4.1-Buffer-Overflow)
- [war4uthor/CVE-2004-2271](https://github.com/war4uthor/CVE-2004-2271)
- [pwncone/CVE-2004-2271-MiniShare-1.4.1-BOF](https://github.com/pwncone/CVE-2004-2271-MiniShare-1.4.1-BOF)

### CVE-2004-2549

<code>
Nortel Wireless LAN (WLAN) Access Point (AP) 2220, 2221, and 2225 allow remote attackers to cause a denial of service (service crash) via a TCP request with a large string, followed by 8 newline characters, to (1) the Telnet service on TCP port 23 and (2) the HTTP service on TCP port 80, possibly due to a buffer overflow.
</code>

- [alt3kx/CVE-2004-2549](https://github.com/alt3kx/CVE-2004-2549)


## 2003
### CVE-2003-0222

<code>
Stack-based buffer overflow in Oracle Net Services for Oracle Database Server 9i release 2 and earlier allows attackers to execute arbitrary code via a &quot;CREATE DATABASE LINK&quot; query containing a connect string with a long USING parameter.
</code>

- [phamthanhsang280477/CVE-2003-0222](https://github.com/phamthanhsang280477/CVE-2003-0222)

### CVE-2003-0264

<code>
Multiple buffer overflows in SLMail 5.1.0.4420 allows remote attackers to execute arbitrary code via (1) a long EHLO argument to slmail.exe, (2) a long XTRN argument to slmail.exe, (3) a long string to POPPASSWD, or (4) a long password to the POP3 server.
</code>

- [adenkiewicz/CVE-2003-0264](https://github.com/adenkiewicz/CVE-2003-0264)
- [fyoderxx/slmail-exploit](https://github.com/fyoderxx/slmail-exploit)
- [war4uthor/CVE-2003-0264](https://github.com/war4uthor/CVE-2003-0264)
- [pwncone/CVE-2003-0264-SLmail-5.5](https://github.com/pwncone/CVE-2003-0264-SLmail-5.5)


## 2002
### CVE-2002-0200

<code>
Cyberstop Web Server for Windows 0.1 allows remote attackers to cause a denial of service via an HTTP request for an MS-DOS device name.
</code>

- [alt3kx/CVE-2002-0200](https://github.com/alt3kx/CVE-2002-0200)

### CVE-2002-0201

<code>
Cyberstop Web Server for Windows 0.1 allows remote attackers to cause a denial of service (crash) and possibly execute arbitrary code via a long HTTP GET request, possibly triggering a buffer overflow.
</code>

- [alt3kx/CVE-2002-0201](https://github.com/alt3kx/CVE-2002-0201)

### CVE-2002-0288

<code>
Directory traversal vulnerability in Phusion web server 1.0 allows remote attackers to read arbitrary files via a ... (triple dot dot) in the HTTP request.
</code>

- [alt3kx/CVE-2002-0288](https://github.com/alt3kx/CVE-2002-0288)

### CVE-2002-0289

<code>
Buffer overflow in Phusion web server 1.0 allows remote attackers to cause a denial of service and execute arbitrary code via a long HTTP request.
</code>

- [alt3kx/CVE-2002-0289](https://github.com/alt3kx/CVE-2002-0289)

### CVE-2002-0346

<code>
Cross-site scripting vulnerability in Cobalt RAQ 4 allows remote attackers to execute arbitrary script as other Cobalt users via Javascript in a URL to (1) service.cgi or (2) alert.cgi.
</code>

- [alt3kx/CVE-2002-0346](https://github.com/alt3kx/CVE-2002-0346)

### CVE-2002-0347

<code>
Directory traversal vulnerability in Cobalt RAQ 4 allows remote attackers to read password-protected files, and possibly files outside the web root, via a .. (dot dot) in an HTTP request.
</code>

- [alt3kx/CVE-2002-0347](https://github.com/alt3kx/CVE-2002-0347)

### CVE-2002-0348

<code>
service.cgi in Cobalt RAQ 4 allows remote attackers to cause a denial of service, and possibly execute arbitrary code, via a long service argument.
</code>

- [alt3kx/CVE-2002-0348](https://github.com/alt3kx/CVE-2002-0348)

### CVE-2002-0448

<code>
Xerver Free Web Server 2.10 and earlier allows remote attackers to cause a denial of service (crash) via an HTTP request that contains many &quot;C:/&quot; sequences.
</code>

- [alt3kx/CVE-2002-0448](https://github.com/alt3kx/CVE-2002-0448)

### CVE-2002-0740

<code>
Buffer overflow in slrnpull for the SLRN package, when installed setuid or setgid, allows local users to gain privileges via a long -d (SPOOLDIR) argument.
</code>

- [alt3kx/CVE-2002-0740](https://github.com/alt3kx/CVE-2002-0740)

### CVE-2002-0991

<code>
Buffer overflows in the cifslogin command for HP CIFS/9000 Client A.01.06 and earlier, based on the Sharity package, allows local users to gain root privileges via long (1) -U, (2) -D, (3) -P, (4) -S, (5) -N, or (6) -u parameters.
</code>

- [alt3kx/CVE-2002-0991](https://github.com/alt3kx/CVE-2002-0991)


## 2001
### CVE-2001-0680

<code>
Directory traversal vulnerability in ftpd in QPC QVT/Net 4.0 and AVT/Term 5.0 allows a remote attacker to traverse directories on the web server via a &quot;dot dot&quot; attack in a LIST (ls) command.
</code>

- [alt3kx/CVE-2001-0680](https://github.com/alt3kx/CVE-2001-0680)

### CVE-2001-0758

<code>
Directory traversal vulnerability in Shambala 4.5 allows remote attackers to escape the FTP root directory via &quot;CWD ...&quot;  command.
</code>

- [alt3kx/CVE-2001-0758](https://github.com/alt3kx/CVE-2001-0758)

### CVE-2001-0931

<code>
Directory traversal vulnerability in Cooolsoft PowerFTP Server 2.03 allows attackers to list or read arbitrary files and directories via a .. (dot dot) in (1) LS or (2) GET.
</code>

- [alt3kx/CVE-2001-0931](https://github.com/alt3kx/CVE-2001-0931)

### CVE-2001-0932

<code>
Buffer overflow in Cooolsoft PowerFTP Server 2.03 allows remote attackers to cause a denial of service and possibly execute arbitrary code via a long command.
</code>

- [alt3kx/CVE-2001-0932](https://github.com/alt3kx/CVE-2001-0932)

### CVE-2001-0933

<code>
Cooolsoft PowerFTP Server 2.03 allows remote attackers to list the contents of arbitrary drives via a ls (LIST) command that includes the drive letter as an argument, e.g. &quot;ls C:&quot;.
</code>

- [alt3kx/CVE-2001-0933](https://github.com/alt3kx/CVE-2001-0933)

### CVE-2001-0934

<code>
Cooolsoft PowerFTP Server 2.03 allows remote attackers to obtain the physical path of the server root via the pwd command, which lists the full pathname.
</code>

- [alt3kx/CVE-2001-0934](https://github.com/alt3kx/CVE-2001-0934)

### CVE-2001-1442

<code>
Buffer overflow in innfeed for ISC InterNetNews (INN) before 2.3.0 allows local users in the &quot;news&quot; group to gain privileges via a long -c command line argument.
</code>

- [alt3kx/CVE-2001-1442](https://github.com/alt3kx/CVE-2001-1442)


## 2000
### CVE-2000-0170

<code>
Buffer overflow in the man program in Linux allows local users to gain privileges via the MANPAGER environmental variable.
</code>

- [mike182/exploit](https://github.com/mike182/exploit)

### CVE-2000-0979

<code>
File and Print Sharing service in Windows 95, Windows 98, and Windows Me does not properly check the password for a file share, which allows remote attackers to bypass share access controls by sending a 1-byte password that matches the first character of the real password, aka the &quot;Share Level Password&quot; vulnerability.
</code>

- [Z6543/CVE-2000-0979](https://github.com/Z6543/CVE-2000-0979)


## 1999
### CVE-1999-0532
- [websecnl/Bulk_CVE-1999-0532_Scanner](https://github.com/websecnl/Bulk_CVE-1999-0532_Scanner)


