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
```shell
$ vol -f MemoryDump.mem windows.pslist
```
![Q1 - Volatility pslist](/assets/posts_img/2023-07-19-Cyberdefenders-Redline/q1.png)

Most of the processes are native Windows programs that don't seem suspicious. The last one (*oneetx.exe*) catches our attention. With a quick Google Search, it turns out that it is indeed malicious.

Answer > __oneetx.exe__

# Q2 : What is the child process name of the suspicious process?

Let's have a clearer view of the processes hierarchy:
```shell
$ vol -f MemoryDump.mem windows.pstree
```
![Q2 - Volatility pstree](/assets/posts_img/2023-07-19-Cyberdefenders-Redline/q2.png)

The malicious process *oneetx.exe* launched a *rundll32.exe* process which means that it (presumably) executed some of its own library.

Answer > __rundll32.exe__

# Q3 : What is the memory protection applied to the suspicious process memory region?

While allocating memory ressource to a process, the operating system applies a "Memory Protection" to its allocated space. It essentially works on the same principle as Unix file permissions with Read, Write, and Execute as 3 unique rights.
Volatility has a module which scans the memory dump to check if some programs have unusual rights on their allocated space.
```shell
$ vol -f MemoryDump.mem windows.malfind
```
![Q3 - Volatility malfind](/assets/posts_img/2023-07-19-Cyberdefenders-Redline/q3.png)

The process named *oneetx.exe* has unusual rights. We can see the *PAGE_EXECUTE_READWRITE* being set which is a suspicious right (akin to 777). With both "Write" and "Execute", a program is able to run code that alters itself.

Answer > __PAGE_EXECUTE_READWRITE__

# Q4 : What is the name of the process responsible for the VPN connection?

We can use the plugin *windows.netscan* to show us active connections and listeners at the time of the dump.
```shell
$ vol -f MemoryDump.mem windows.netscan
```
![Q4 - Volatility netscan](/assets/posts_img/2023-07-19-Cyberdefenders-Redline/q4_1.png)

There are a few TCP connections to distant 443 ports, but the relevant ones seem to be those initiated by the *tun2socks.exe* process. Tun2Socks is a networking tool allowing its user to "proxi-fy" or tunnel any outbound connection.

By using the same command as for the Q2, we can easily get it's parent process name.
```shell
$ vol -f MemoryDump.mem windows.pstree
```
![Q4 - Volatility pstree 2](/assets/posts_img/2023-07-19-Cyberdefenders-Redline/q4_2.png)

*winlogon.exe* is launched during user authentication and runs Windows Desktop *explorer.exe*. All user programs are then its child processes. The process responsible for running the VPN connection is *Outline.exe*.

Answer > __Outline.exe__

# Q5 : What is the attacker's IP address?

By running the same plugin as before, we can see some other interesting connections.
```shell
$ vol -f MemoryDump.mem windows.netscan
```
![Q5 - Volatility netscan 2](/assets/posts_img/2023-07-19-Cyberdefenders-Redline/q5.png)

The command shows that there were an outbound HTTP connection (port 80) initiated by the program *oneetx.exe*. A quick Google Search confirms that this IP address is known to be malicious.

Answer -> __77.91.124[.]20__

# Q6 : Based on the previous artifacts. What is the name of the malware family?

With the name of the malicious program and the IP address of the attacker, we can quickly find reports from [any.run](https://any.run/report/fbe652fd97a26061c5e6b68468ecf653f7038d1e976bb657ff81117dcb5ecb85/c6f39f4c-07fc-43b0-b8ec-b25ada62aba7) and [Abuse.ch](https://bazaar.abuse.ch/sample/74b102111f7d344a2c0cb7a77d73c968aff7f6a4b67c3457643d9a61c12d2aef/) that reveals that this malware is from the *RedLine Stealer* family. These malware has been discovered in 2020 and is a Trojan used to steal data such as passwords or crypto wallets.

Answer > __RedLine Stealer__

# Q7 : What is the full URL of the PHP file that the attacker visited?

Since we can narrow our search to the IP address that we previously found, we can simply search for all strings in the memory dump that contains this IP address. We can also probably use the running *msedge.exe* process to get the history of the HTTP connections.
```shell
$ strings MemoryDump.mem | grep http[:]//77.91.124[.]20
```
![Q7 - Volatility netscan 2](/assets/posts_img/2023-07-19-Cyberdefenders-Redline/q7.png)

Answer > __http[:]//77.91.124[.]20/store/games/index.php__

# Q8 : What is the full path of the malicious executable?

Let's us the *filescan* plugin to get a list of files written to disk that are cached in memory.

```console
$ vol -f MemoryDump.mem windows.filescan | grep oneetx    
```
![Q8 - Volatility netscan 2](/assets/posts_img/2023-07-19-Cyberdefenders-Redline/q8.png)

Answer > __C:\Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe__

# Conclusion

This challenge has us using basic Volatility commands to identify the traces a malware of the Redline Stealer family can leave in memory.

# Ressources

[Stormshield CTI - Malware RedLine : d’une extension Chrome à une campagne malveillante d’envergure](https://www.stormshield.com/fr/actus/malware-redline-extension-chrome-campagne-malveillante-envergure/)
