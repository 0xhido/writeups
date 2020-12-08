@REM If service does not exist

@echo OFF
:loop
del "<current_execution_path>"
if Exist "<current_execution_path>" GOTO loop
%windir%\system32\rundll32.exe advapi32.dll,ProcessIdleTasks

@REM If service exists

@ECHO OFF 
SET PROG=%"%<directoryName>\%"%
SET SERVICE_EXE=%"%<fileName>%"%
SET FIRSTPART=%WINDIR%"\Microsoft.NET\Framework\v"
SET SECONDPART="\InstallUtil.exe"
SET SERVICENAME=%"%<serviceName>%"%
SET DOTNETVER=4.0.30319
IF EXIST %FIRSTPART%%DOTNETVER%%SECONDPART% GOTO install
SET DOTNETVER=2.0.50727
IF EXIST %FIRSTPART%%DOTNETVER%%SECONDPART% GOTO install
SET DOTNETVER=1.1.4322
IF EXIST %FIRSTPART%%DOTNETVER%%SECONDPART% GOTO install
SET DOTNETVER=1.0.3705
IF EXIST %FIRSTPART%%DOTNETVER%%SECONDPART% GOTO install
GOTO fail
:install
%FIRSTPART%%DOTNETVER%%SECONDPART% /U /name="%SERVICENAME%" "%PROG%%SERVICE_EXE%"
GOTO end
:fail
echo FAILURE-- Could not find.NET Framework install
:end
del "%PROG%%SERVICE_EXE%"
del "%PROG%%SERVICENAME%".*
del %0
%windir%\system32\rundll32.exe advapi32.dll,ProcessIdleTasks