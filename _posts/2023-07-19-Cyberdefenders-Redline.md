---
title: "Cyberdefenders : RedLine"
date: 2023-07-19 14:00:00 +0200
categories: [Forensics]
tags: [volatility]
---

# Introduction

We're given a *.zip* which contains a memory dump in the form of a file named *MemoryDump.mem*. The challenge will need us to work with *Volatility* to retrieve artifacts that will help us identify the malware we're dealing with.

> With Volatility3, we don't need to specify the profile to decode the memory dump anymore. Volatility guesses it on its own so we can go straight to the point.
{: .prompt-info}

# Q1 : What is the name of the suspicious process?

We can extract the list of the process that were running as the memory got dumped:
```bash
$ vol -f MemoryDump.mem windows.pslist
```
![Q1 - Volatility pslist](/_posts/2023-07-19-Cyberdefenders-Redline/q1.png)

Most of the processes are native Windows programs that don't seem suspicious. The last one (*oneetx.exe*) catches our attention. With a quick Google Search, it turns out that it is indeed malicious.

Answer > __oneetx.exe__

# Q2 : What is the child process name of the suspicious process?

Let's have a clearer view of the processes hierarchy:
```shell
$ vol -f MemoryDump.mem windows.pstree
Volatility 3 Framework 2.4.1
Progress:  100.00               PDB scanning finished                        
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime

4       0       System  0xad8185883180  157     -       N/A     False   2023-05-21 22:27:10.000000      N/A
* 1280  4       MemCompression  0xad8187835080  62      -       N/A     False   2023-05-21 22:27:49.000000      N/A
* 108   4       Registry        0xad81858f2080  4       -       N/A     False   2023-05-21 22:26:54.000000      N/A
* 332   4       smss.exe        0xad81860dc040  2       -       N/A     False   2023-05-21 22:27:10.000000      N/A
452     444     csrss.exe       0xad81861cd080  12      -       0       False   2023-05-21 22:27:22.000000      N/A
528     520     csrss.exe       0xad8186f1b140  14      -       1       False   2023-05-21 22:27:25.000000      N/A
552     444     wininit.exe     0xad8186f2b080  1       -       0       False   2023-05-21 22:27:25.000000      N/A
...
5896    8844    oneetx.exe      0xad8189b41080  5       -       1       True    2023-05-21 22:30:56.000000      N/A
* 7732  5896    rundll32.exe    0xad818d1912c0  1       -       1       True    2023-05-21 22:31:53.000000      N/A
```
The malicious process *oneetx.exe* launched a *rundll32.exe* process which means that it (presumably) executed some of its own library.

Answer > __rundll32.exe__

# Q3 : What is the memory protection applied to the suspicious process memory region?

While allocating memory ressource to a process, the operating system applies a "Memory Protection" to its allocated space. It essentially works on the same principle as Unix file permissions with Read, Write, and Execute as 3 unique rights.
Volatility has a module which scans the memory dump to check if some programs have unusual rights on their allocated space.
```console
$ vol -f MemoryDump.mem windows.malfind
Volatility 3 Framework 2.4.1
Progress:  100.00               PDB scanning finished                        
PID     Process Start VPN       End VPN Tag     Protection      CommitCharge    PrivateMemory   File output     Hexdump Disasm

5896    oneetx.exe      0x400000        0x437fff        VadS    PAGE_EXECUTE_READWRITE  56      1       Disabled
4d 5a 90 00 03 00 00 00 MZ......
04 00 00 00 ff ff 00 00 ........
b8 00 00 00 00 00 00 00 ........
40 00 00 00 00 00 00 00 @.......
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 01 00 00 ........
0x400000:       dec     ebp
0x400001:       pop     edx
0x400002:       nop
0x400003:       add     byte ptr [ebx], al
0x400005:       add     byte ptr [eax], al
0x400007:       add     byte ptr [eax + eax], al
0x40000a:       add     byte ptr [eax], al
```
The process named *oneetx.exe* has unusual rights. We can see the *PAGE_EXECUTE_READWRITE* being set which is a suspicious right (akin to 777). With both "Write" and "Execute", a program is able to run code that alters itself.

Answer > __PAGE_EXECUTE_READWRITE__

# Q4 : What is the name of the process responsible for the VPN connection?

We can use the plugin *windows.netscan* to show us active connections and listeners at the time of the dump.
```console
$ vol -f MemoryDump.mem windows.netscan
Volatility 3 Framework 2.4.1

Offset  Proto   LocalAddr       LocalPort       ForeignAddr     ForeignPort     State   PID     Owner   Created

0xad81861e2310  TCPv4   0.0.0.0 49668   0.0.0.0 0       LISTENING       1840    spoolsv.exe     2023-05-21 22:28:09.000000 
0xad81861e2310  TCPv6   ::      49668   ::      0       LISTENING       1840    spoolsv.exe     2023-05-21 22:28:09.000000 
0xad81861e2470  TCPv4   0.0.0.0 5040    0.0.0.0 0       LISTENING       1196    svchost.exe     2023-05-21 22:30:31.000000 
0xad81861e2730  TCPv4   0.0.0.0 135     0.0.0.0 0       LISTENING       952     svchost.exe     2023-05-21 22:27:36.000000
...
0xad8189a30a20  TCPv4   192.168.190.141 53660   38.121.43.65    443     CLOSED  4628    tun2socks.exe   2023-05-21 22:00:25.000000
...
0xad818df1d920  TCPv4   192.168.190.141 55433   38.121.43.65    443     CLOSED  4628    tun2socks.exe   2023-05-21 23:00:02.000000 
...
```
There are a few TCP connections to distant 443 ports, but the relevant ones seem to be those initiated by the *tun2socks.exe* process. Tun2Socks is a networking tool allowing its user to "proxi-fy" or tunnel any outbound connection.

By using the same command as for the Q2, we can easily get it's parent process name.
```console
$ vol -f MemoryDump.mem windows.pstree
Volatility 3 Framework 2.4.1

PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime
...
588     520     winlogon.exe    0xad8186f450c0  5       -       1       False   2023-05-21 22:27:25.000000      N/A
* 1016  588     dwm.exe 0xad81876e4340  15      -       1       False   2023-05-21 22:27:38.000000      N/A
* 3556  588     userinit.exe    0xad818c02f340  0       -       1       False   2023-05-21 22:30:28.000000      2023-05-21 22:30:43.000000 
** 3580 3556    explorer.exe    0xad818c047340  76      -       1       False   2023-05-21 22:30:28.000000      N/A
*** 6724        3580    Outline.exe     0xad818e578080  0       -       1       True    2023-05-21 22:36:09.000000      2023-05-21 23:01:24.000000 
**** 4224       6724    Outline.exe     0xad818e88b080  0       -       1       True    2023-05-21 22:36:23.000000      2023-05-21 23:01:24.000000 
**** 4628       6724    tun2socks.exe   0xad818de82340  0       -       1       True    2023-05-21 22:40:10.000000      2023-05-21 23:01:24.000000
...
```
*winlogon.exe* is launched during user authentication and runs Windows Desktop *explorer.exe*. All user programs are then its child processes. The process responsible for running the VPN connection is *Outline.exe*.

Answer > __Outline.exe__

# Q5 : What is the attacker's IP address?

By running the same plugin as before, we can see some other interesting connections.
```console
$ vol -f MemoryDump.mem windows.netscan
Volatility 3 Framework 2.4.1

Offset  Proto   LocalAddr       LocalPort       ForeignAddr     ForeignPort     State   PID     Owner   Created
...
0xad818de4aa20  TCPv4   10.0.85.2       55462   77.91.124.20    80      CLOSED  5896    oneetx.exe      2023-05-21 23:01:22.000000
...
```
The command shows that there were an outbound HTTP connection (port 80) initiated by the program *oneetx.exe*. A quick Google Search confirms that this IP address is known to be malicious.

Answer -> __77.91.124[.]20__

# Q6 : Based on the previous artifacts. What is the name of the malware family?

With the name of the malicious program and the IP address of the attacker, we can quickly find reports from [any.run](https://any.run/report/fbe652fd97a26061c5e6b68468ecf653f7038d1e976bb657ff81117dcb5ecb85/c6f39f4c-07fc-43b0-b8ec-b25ada62aba7) and [Abuse.ch](https://bazaar.abuse.ch/sample/74b102111f7d344a2c0cb7a77d73c968aff7f6a4b67c3457643d9a61c12d2aef/) that reveals that this malware is from the *RedLine Stealer* family. These malware has been discovered in 2020 and is a Trojan used to steal data such as passwords or crypto wallets.

Answer > __RedLine Stealer__

# Q7 : What is the full URL of the PHP file that the attacker visited?

Since we can narrow our search to the IP address that we previously found, we can simply search for all strings in the memory dump that contains this IP address. We can also probably use the running *msedge.exe* process to get the history of the HTTP connections.
```console
$ strings MemoryDump.mem | grep http[:]//77.91.124[.]20
http://77.91.124.20/ E
http://77.91.124.20/store/gamel
http://77.91.124.20/ E
http://77.91.124.20/DSC01491/
http://77.91.124.20/DSC01491/
http://77.91.124.20/store/games/index.php
http://77.91.124.20/store/games/index.php
http://77.91.124.20/store/games/index.php
```

Answer > __http[:]//77.91.124[.]20/store/games/index.php__

# Q8 : What is the full path of the malicious executable?

Let's us the *filescan* plugin to get a list of files written to disk that are cached in memory.

```console
$ vol -f MemoryDump.mem windows.filescan | grep oneetx    
0xad818d436c70.0\Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe  216
0xad818da36c30  \Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe  216
0xad818ef1a0b0  \Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe  216
```
Answer > __C:\Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe__

# Conclusion

This challenge has us using basic Volatility commands to identify the traces a malware of the Redline Stealer family can leave in memory.

# Ressources

[Stormshield CTI - Malware RedLine : d’une extension Chrome à une campagne malveillante d’envergure](https://www.stormshield.com/fr/actus/malware-redline-extension-chrome-campagne-malveillante-envergure/)
