# Black Energy

## Brief Introduction & History of Black Energy Malware

This family of malware is pretty interesting and has evolved a bit from its humble origins. Originally, the malware has been primarily designed to conduct Distributed Denial of Service (DDoS) operations, but over the years developed modular capabilities to expand its destructive features while adding an espionage component (i.e. swiping credentials, keylogging, etc…). Therefore, primary targets appear to be industrial control systems and banking fraud with command and control services being housed in Russia and victims being in the countries of Georgia and Ukraine (~2008–2015). The delivery of this malware seems to be primarily facilitated through spear-phishing campaigns that contain malicious Office documents (i.e. Word, PowerPoint, etc…).

## Black Energy Version 2

Version 2 of the malware, the version that is contained within the memory image, consists of multiple phases. Identifying how this malware works will help guide our investigation into the memory of the compromised host. Check the link at the bottom by Secureworks for more details.

### 1. Dropper:

The initial stages of the malware involves decrypting and decompressing a malicious driver that will eventually be installed as a service (randomly named). This is going to provide the “foundation” of the rootkit. This stage is also capable of escalating its privileges to facilitate the installation of the bad driver.

### 2. Rootkit:

The driver that is installed as a service is then used to unpack and decrypt the primary rootkit contained within the initial process. The new driver that is unpacked is then used to inject a DLL into a running process on the system.

# Analyzing the Memory Image

## 1. Context of the Image

I’ll be using the “new” version of [Volatility](https://github.com/volatilityfoundation/volatility3) to parse the memory image, which doesn’t require the analyst to declare the profile (operating system & version) of the memory dump. However, if you’re using the older [version](https://github.com/volatilityfoundation/volatility), you’ll need to determine the correct profile to get valid output by scanning the Kernel Debugger Data block (`kdbg`).

The KDBG structure contains a pointer to `PsActiveProcessHead` which is able to track active process links. Every active process is contained within an `EPROCESS` block that has forward/backward links and tracks: the Process Environment Block (`PEB`), ownership/token information, handles, threads, and contains a pointer to the Virtual Address Descriptor (`VAD`) Tree.

```bash
########################
# Volatility 2
########################
# store the image in env variable
export VOLATILITY_LOCATION=file://path/to/image

# determine profile with vol2
vol2 -f $img kdbgscan

# validate that the return profile is correct. If the following
# doesn't produce good output, then it's not the correct profile
vol2 --profile=$profile pslist
vol2 --profile=$profile psscan
vol2 --profile=$profile filescan
vol2 --profile=$profile hivescan

# if the results look to be valid, add the profile to an env variable
export VOATILITY_PROFILE=$profile

########################
# Volatility 3
########################
# kdbgscan for vol3
vol3 -qf $img windows.info
```

## 2. Analyzing Process Objects

Basic steps of analyzing a memory image is to start by simply listing processes. To make things easier for us, we are just going to list the names of the processes and how many times they occur. The reason being, malware will some times: copy the name of a known good process (i.e. seeing more than one `lsass.exe` is weird and probably malware), use one-off misspelling of good processes ( `svchost.exe` vs. `scvhost.exe` ), etc… This filtering will make identifying anomalies easier. Essentially what we are doing is long-tail analysis. 

```bash
# the remainder of the examples are using vol3
# listing processes
vol3 -qf $img -r pretty windows.pslist | awk -F '|' '{print $4}' | sort | uniq -c 
```

![image](https://github.com/user-attachments/assets/bbc82068-edd8-4e7a-8b4f-ee136215204d)


Next step is obtaining process relationships and to look for weird associations (i.e. `svchost.exe` should be a child of `services.exe` and user processes should be children of `explorer.exe` and so on).

```bash
# process tree
vol3 -qf $img -r pretty windows.pstree | awk -F '|' '{print $1, $2, $4}'
```

![image](https://github.com/user-attachments/assets/0ed05d58-42bd-4f92-8781-b58966a78c8c)


If you want, or are able to, you can now dump the `rootkit.exe` process to investigate it further (i.e. submit hashes to virustotal (VT), reverse engineer, etc…). Since we have an idea of which process is probably malicious, we can start building a timeline of the incident by doing the following: 

```bash
# attempt to dump the process
vol3 -qf $img --pid 964 --dump

# building a timeline of the infection
vol3 -qf $img -r pretty windows.pstree --pid 964 | awk -F '|' '{print $1, $2, $4, $5, $10}'
```

![image](https://github.com/user-attachments/assets/976beec3-e9f3-4017-be82-208501b10547)


## 3. Identifying Malicious Service and Initial Rootkit Driver

Since we know the initial infection will start a randomly named service that contains a malicious driver to unpack the main rootkit, we can list services and cross-reference its contents by parsing the SYSTEM registry hive:

```bash
# listing services
vol3 -qf $img windows.svcscan  | awk '{print $7}'

# checking the service registry key for drivers
vol3 -qf $img windows.registry.printkey --key "controlset001\\services\\hvklkzdz" | egrep '(\.sys|\.dll)'
```

![image](https://github.com/user-attachments/assets/bc5654ee-a6bc-428b-9a88-5c3ace6accd9)


![image](https://github.com/user-attachments/assets/cdc37ac4-bb39-4670-a4b6-b4031dcc2b4c)


Next, lets confirm our suspicions by determining when this driver first appeared. If it is around the execution time of `rootkit.exe` we should dig deeper into this sample.

The `$MFT`, or Master File Table, is a critical structure in Windows and NTFS filesystems. It tracks: every file on the system, change log information, what clusters on disk have been allocated, which clusters are bad, and so on. Of the data that can be extracted from the `$MFT`, it will contain `$STANDARD_INFORMATION` timestamps (times you see in File Explorer) and `$FILE_NAME` timestamps. This is how we are going to determine the driver’s creation date.

```bash
# creation time of the malicious driver 
vol3 -qf $img windows.mftscan.MFTScan | grep $driverName
```

![image](https://github.com/user-attachments/assets/8846e4fd-ad9a-4bc9-84a8-8337a49af86e)


This driver does appear at the time of execution, so now we should extract the malicious file for further analysis (i.e. [VT](https://www.virustotal.com/gui/file/9e16a02f9d73e173d9fb9f7e18d8ab8619264a5b26e21c126211dc90fdb4f148/details) look up, reverse engineer, etc…).

```bash 
# getting the memory address of the file
vol3 -qf $img windows.filescan | grep $driverName

# dumping the file
vol3 -qf $img windows.dumpfiles --physaddr $addr

# hash, i'm on macOS so use md5sum if you're on linux
md5 file*
```

![image](https://github.com/user-attachments/assets/b5a1ead4-e0a6-43e2-b1b7-f7c3ec9fa5af)


## 4. Identifying Code Injection

With the initial infection out of the way, the next step is to identify code injection. The three criteria that need to be met to identify injection are:

### 1. Abnormal Page Permissions

 - Different regions of memory have different permissions based off the function they serve. For example, private memory contains data related to the stack, heap, and other application data and should not have execute permissions. The big thing to look out for is `EXECUTE_READWRITE` permissions.

### 2. Page Contains Executable Code

- This requires some analysis on your part. Look for stack frames and MZ headers.

### 3. Not Mapped to Disk

- In other words, it doesn’t exists on the file system.

Easiest place to start is with the `malfind` plugin. This plugin will identify any memory section that meets the three requirements above. Please note that the plugin will do its best to determine if the page contains executable code, but will normally contain a number of false-positives.

```bash 
#malfind
vol3 -qf $img windows.malfind
```

![image](https://github.com/user-attachments/assets/942b2853-b961-44c9-98ab-f5d339b22c6c)


Now we need to determine the malicious DLL that was used to inject into the `svchost.exe` process.

To do that we can use the `ldrmodules` plugin to identify associated DLLs. This plugin will track the following lists from the `PEB`: `InLoadOrder`, `InInitizationOrder`, and `InModuleOrder`. We should expect to find where on disk the binary/DLL is mapped and all listed DLLs should be present in all three lists (the process executable will be missing from `InInitializationOrder`). Be aware that 32-bit DLLs and and JIT compiled DLLs will generate false positives.

```bash
# ldrmodules
vol3 -qf $img windows.ldrmodules --pid 880 | grep -i false
```

![image](https://github.com/user-attachments/assets/427b558c-296d-4225-bb1e-6e2c1535e921)


We know that another driver was used to extract the main rootkit, so we can check for file handles to this process to see if we can identify it.

```bash
# listing handles and dumping the bad svchost file
vol3 -qf $img windows.handles --pid 880 | grep "File" | egrep '\.sys'
vol3 -qf $img windows.pslist --pid 880 --dump 
```

![image](https://github.com/user-attachments/assets/5901575b-b78b-455f-8ffa-722f38b5df51)

![image](https://github.com/user-attachments/assets/ed2ab35b-77ff-467e-8f6f-5bf176175057)


## 5. User Attribution

We can use `getsids` to determine with what user context these processes were running. Note, the first entry is the user and the rest are group information.

```bash 
# determining user profile that ran the malware 
vol3 -qf $img windows.getsids --pid 964 880 
```

![image](https://github.com/user-attachments/assets/7e946ca7-f636-4d6a-a968-b49c441a389b)


We can also prove that `CyberDefenders` user launched the process by checking the `UserAssist` registry key (evidence of application execution found in `NTUSER.dat`).

```bash
# userassist key
vol3 -qf $img -r pretty windows.registry.userassist | grep rootkit
```

![image](https://github.com/user-attachments/assets/2133d0a2-f0f2-4b7b-ab75-449547e92e15)


We can also probably determine what the user was doing with the `notepad.exe` processes by dumping the contents of the `RecentDocs` key, which is also located in `NTUSER.DAT`. *NOTE: refer to the process list earlier, there was a notepad.exe process.*

```bash 
# determine offset for the NTUSER.dat hive *Not Pictured*
vol3 -qf $img windows.registry.hivelist

# list recent docs key
vol3 -qf windows.registry.printkey --offset 0xe1982970 --key "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"

# listing all the text documents
vol3 -qf $img windows.registry.printkey --offset 0xe1982970 --key "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs\\.txt"
```

![image](https://github.com/user-attachments/assets/5ad960f3-0f95-4712-9a7b-98409be75f78)


![image](https://github.com/user-attachments/assets/d28f4ad2-3205-43c1-bd76-771a3046a60e)


We can find and dump these files to see if they contain anything interesting.

```bash
# file scan for flag.txt.txt and Key.txt  
vol3 -qf $img windows.filescan | egrep '(flag\.txt\.txt|Key\.txt)'  
  
# dumpfiles  
vol3 -qf $img windows.dumpfiles --physaddr $addr
```

![image](https://github.com/user-attachments/assets/72679d00-6fc4-49f7-9dce-3258289755ce)

![image](https://github.com/user-attachments/assets/77e8503d-e793-41bd-9ac9-6ab9678a7c1a)

![image](https://github.com/user-attachments/assets/1b2b56ce-e9ea-4871-bd25-52175650dd5f)


# References
- [https://pureadmin.qub.ac.uk/ws/portalfiles/portal/86558342/Threat_Analysis_of_BlackEnergy_Malware_for_Synchrophasor_based_Real_time_Control_and_Monitoring_in_Smart_Grid.pdf](https://pureadmin.qub.ac.uk/ws/portalfiles/portal/86558342/Threat_Analysis_of_BlackEnergy_Malware_for_Synchrophasor_based_Real_time_Control_and_Monitoring_in_Smart_Grid.pdf)
- [https://www.incibe.es/sites/default/files/2024-02/INCIBE-CERT_ICS_ANALYSIS_STUDY_BLACKENERGY_2024_v1.0.pdf](https://www.incibe.es/sites/default/files/2024-02/INCIBE-CERT_ICS_ANALYSIS_STUDY_BLACKENERGY_2024_v1.0.pdf)
- [https://www.cyber.nj.gov/threat-landscape/malware/trojans/blackenergy](https://www.cyber.nj.gov/threat-landscape/malware/trojans/blackenergy)
- https://www.virusbulletin.com/virusbulletin/2017/07/vb2016-paper-blackenergy-what-we-really-know-about-notorious-cyber-attacks/?source=post_page-----4dc553308c8d---------------------------------------
- https://www.secureworks.com/research/blackenergy2?source=post_page-----4dc553308c8d---------------------------------------
