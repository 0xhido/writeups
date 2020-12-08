@echo off
net stop "<current_service_name>"
PING 127.0.0.1 -n 20
del "<current_conf_path>"
:loop 
del "<current_execution_path>"
if Exist "<current_execution_path>" GOTO loop
move "<current_execution_dir>\<name>" "<current_execution_path>"
net start "<service_name>"
PING 127.0.0.1 -n 20
%windir%\\system32\\rundll32.exe advapi32.dll,ProcessIdleTasks
del %0 