# Windows privilege escalation
This is a Python based module for fast checking of common vulnerabilities affecting windows which lead to privilege escalation

## How to use?
The usage is trivial
```
C:\> python escalate.py all
[INFO] Found named pipe //./pipe\lsass
[INFO] Found named pipe //./pipe\protected_storage
[INFO] Found named pipe //./pipe\ntsvcs
[INFO] Found named pipe //./pipe\scerpc
[INFO] Found named pipe //./pipe\plugplay
[INFO] Found named pipe //./pipe\Winsock2\CatalogChangeListener-2f8-0
[INFO] Found named pipe //./pipe\epmapper
[INFO] Found named pipe //./pipe\Winsock2\CatalogChangeListener-190-0
[INFO] Found named pipe //./pipe\LSM_API_service
[INFO] Found named pipe //./pipe\eventlog
[INFO] Found named pipe //./pipe\Winsock2\CatalogChangeListener-34c-0
[INFO] Found named pipe //./pipe\atsvc
[INFO] Found named pipe //./pipe\Winsock2\CatalogChangeListener-3f0-0
[INFO] Found named pipe //./pipe\wkssvc
[INFO] Found named pipe //./pipe\keysvc
[INFO] Found named pipe //./pipe\trkwks
[INFO] Found named pipe //./pipe\vgauth-service
[INFO] Found named pipe //./pipe\srvsvc
[INFO] Found named pipe //./pipe\Winsock2\CatalogChangeListener-200-0
[INFO] Found named pipe //./pipe\TermSrv_API_service
[INFO] Found named pipe //./pipe\Winsock2\CatalogChangeListener-86c-0
[INFO] Found named pipe //./pipe\Winsock2\CatalogChangeListener-210-0
[INFO] Found named pipe //./pipe\browser
[INFO] Found named pipe //./pipe\MsFteWds
[INFO] Found named pipe //./pipe\PIPE_EVENTROOT\CIMV2SCM EVENT PROVIDER
[INFO] Found named pipe //./pipe\W32TIME_ALT
[INFO] Found elevated process System Idle Process
[INFO] Found elevated process smss.exe
[INFO] Found elevated process csrss.exe
[INFO] Found elevated process csrss.exe
[INFO] Found elevated process winlogon.exe
[INFO] Found elevated process lsm.exe
[INFO] Found elevated process vmacthlp.exe
[INFO] Found elevated process viritsvc.exe
[INFO] Found elevated process spoolsv.exe
[INFO] Found elevated process WVSScheduler.exe
[INFO] Found elevated process sqlwriter.exe
[INFO] Found elevated process VGAuthService.exe
[INFO] Found elevated process vmtoolsd.exe
[INFO] Found elevated process sppsvc.exe
[INFO] Found elevated process WmiPrvSE.exe
[INFO] Found elevated process dllhost.exe
[INFO] Found elevated process msdtc.exe
[INFO] Found elevated process SearchIndexer.exe
[VULN] Environment path C:\Program Files\EasyPHP-DevServer-14.1VC9\binaries\php\php_runningversion is WRITEABLE
[VULN] Service viritsvclite is VULNERABLE C:\VEXPLite\
[VULN] Elevated process WVSScheduler.exe with pid 1740 on port 8183 TCP
>     [INFO] Port 8183 (WVSScheduler.exe) won't answer to dummy packet
[VULN] Process viritsvc.exe may be VULNERABLE we have write permission on C:\VEXPLite
```
## Additional features?

Plese make a pull request if you want to add additional features!

### The End

Bye!
\#dzonerzy
