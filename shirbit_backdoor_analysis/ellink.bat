@echo off
net stop "<service_name>"
PING 127.0.0.1 -n 20
net start "<service_name>"
PING 127.0.0.1
%windir%\\system32\\rundll32.exe advapi32.dll,ProcessIdleTasks
del %0