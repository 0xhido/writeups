
## Installation
---

The malware installed as a service and **waits for 200*1000 ~ 200*3000 milliseconds** before execution.

Once started, the malware **checks if it already ran on the system** by checking if the registry key, `SOFTWARE\\Microsoft\\Default`, equals to `140`.

If its the first run, it **installed itself by setting 2 registry keys**: 

- Saving the current execution path inside: `Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Signature`
- Setting installation flag for next execution (`SOFTWARE\\Microsoft\\Default = 140`)

Next, the malware creates configuration file and save its current path under, `Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Updater`.

The default configurations are:

```json
{
    "EmbedId":"ltQTLPxCdaCY_El]jb!B", // encryption key
    "InternetNeeded":true,
    "LogEnabled":false,
    "UseCache":false,
    "Interval":10,
    "Relays":
        [
            "http:\\\\5.2.73.67\\Panel\\new\\File\\css\\boot.php", 
            "http:\\\\185.142.98.32\\Scripts\\_Data\\25\\lastupdate.php",
            "http:\\\\185.142.97.81\\css\\v1\\template\\main.php"
        ], 
    "DeviceIdSalt":"k+xpGkuWOF5JRREJudQkd3tU6F+rzW24BEaryEl70WH3YUKTM1FxELCie7Xbpg82y4UrjPWh5zkKmMXWF5hU4g==",
    "PublicKeyToken":"e5VtH3ptjMofUBfncDnwUpzYqLB\\/Z+3DOpVUw7n8Mr4=",
    "SessionKey":"eOL1awi41Bl2FW5pqSKFLvO3aHpVeaE0befM7sYJ718=",
    "servers":[]
}
```
The malware uses the `EmbedId` as encryption key and encrypts the `Relays` and write the configuration file on disk.

Checks for internet connection by sending requests to `servers` defined inside the configuration file or default list of servers:

- hxxp://windowsupdate.microsoft.com
- hxxp://windowsupdate.microsoft.nsatc.net
- hxxp://download.windowsupdate.com
- hxxp://download.microsoft.com

The malware:

1. Picks random server
2. Checks if it needs to use proxy server

  - The proxy ip decrypted from `EmbedId` using `PublicKeyToken`
  - The proxy port encrypted from `EmbedId` using `SessionKey`

3. Sends message to the server
4. If there's not response from the server the malware waits random time (30~40, 30~80, 30~160, 30~320, 30~640 seconds) and tries again. 

**Note:** The malware waits for internet connection and won't continue it execution without it.

The malware reads the `NodeId` from `Software\\Microsoft\\Windows\\CurrentVersion\\EyeD` if it is not exists it creates it by filling the following structure using WMI queries:

```cs
public struct RegisterModel
{
    public string version; // 2.15.5
    public string os; // Win32_OperatingSystem.Caption,Version
    public string identifier; // Win32_Processor
    public string embedid;  // inside configuration file
    public string ostype; // Win32_OperatingSystem.ProductType
}
```

The information sent to the attacker for registration, the C&C server responses with `NodeId` for that client. Same as before, the malware won't continue it execution without getting `NodeId`.

## Backdoor Functionality
---

Once the client registered, the attacker starts sending commands through it C&C server.

**Update relay list**
*Command type: 2*  
*Payload: `relays_array`*  

The malware checks each address inside `relays_array`. The check preformed by sending a POST message to the relay with unique data, `chk=Test`. If more than half failed, it requests from the server to send more.

Finally, it encrypts the array and update the configuration file.

**Get system info**  
*Command type: 3*  
*Payload: -*  

Sends the following data to the server (using WMI):

- Domain name - `Win32_ComputerSystem.Domain`
- Host name
- Local time
- Time zone
- User name
- Processor Architecture - `Win32_Processor.AddressWidth`
- Is it laptop? - if `Win32_Battery` exists

**Update malware engine**  
*Command type: 6*  
*Payload: `name`, `hash`, `content`*  

The malware create update script under `%TEMP%\\updater.bat` which responsible for replacing the current malware executable with the new one and restart the service.

After execution, the script deletes itself using `del %0` command.

**Self deletion**  
*Command type: 7*  
*Payload: -*  

First, the malware removes its registry foothold:

- Installation path - `SOFTWARE\\Microsoft\\Default`
- Autorun installation - `Software\\Microsoft\\Windows\\CurrentVersion\\Run\\ipsecservice`
- File location - `Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Signature`
- Config location - `Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Updater`
- NodeId - `Software\\Microsoft\\Windows\\CurrentVersion\\EyeD`

Then, it creates removal script `%TEMP%\\remover.bat` which responsible for uninstalling the created service, remove all files with the malware name (`<name>.*`) and self deletion using `del %0` command.

**Sleep**  
*Command type: 8*  
*Payload: -*  

Sleeps for `Config.Interval` seconds.

**Get engine version**  
*Command type: 11*  
*Payload: -* 

The malware sends the current engine version (default is 2.15.5).

**Download and start new executable**  
*Command type: 12*  
*Payload: `name`, `hash`, `content`* 

The new executable will be located inside `%TEMP%\\name`, `content` is base64 encoded.

After the new file is created inside `%TEMP%\\name`, the malware executes it and send ACK to the attacker.

**Download and start executable from url**  
*Command type: 13*  
*Payload: `name`, `hash`, `content`*  

The malware creates new file: `%TEMP%\\name`. The content of the file downloaded from the url located inside `base64_decode(content)`.

Once, the file's downloaded, the malware executes it.

**Commands execution**  
*Command type: 14*  
*Payload: `command_line`* 

Command execution could preform using 3 processes: 

- `%TEMP%\VBE.exe` - If the file exists 
- `powershell.exe` - If `HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\PowerShell\\1\\Install` exists (which means the powershell available)
- `cmd.exe` - If none of the above found

The new process will start with as `ProcessWindowStyle.Hidden` and the command-line: `<VBE|powershell|cmd> /C <command_line>`.

The output will be written to `stdout` which sent back to the attacker when the new process terminated.

*On error, `%TEMP%\VBE.exe` is deleted and replaced with a copy of `%SYSTEM32%\\WindowsPowerShell\\v1.0\\powershell.exe` (or `%SYSTEM32%\\cmd.exe` if powershell doesn't exist).*

**File uploading**  
*Command type: 15*  
*Payload: `file_path`* 

The function sends to the attacker a file according to the `file_path`. The file's data is base64 encoded. The returned payload is:

```cs
FileModel fileModel = new FileModel
{
    name = Path.GetFileName(payload),
    hash = PublicFunction.FileMd5Hashing(payload),
    content = EncodingClass.Base64ByteEncoding(plainData)
};
```

**Update configuration**  
*Command type: 16*  
*Payload: `name`, `hash`, `content`* 

The configuration that could be changed are: `LogEnabled` and `Interval` inside `ConfigModel` according to `name`. The new value located inside `content`.

**Get process ID**  
*Command type: 17*  
*Payload: -* 

Sends the malware process ID.



## Configurations
---

*Logging:*  
When logging is enabled, the malware creates new file inside to current execution path with the name `<file_name>.lgo`. The log file contains code number, message,  function and timestamp. The logs are encrypted using `MD5(NodeId)` as encryption key.

*Interval:*  
Used when sleep command passed to the malware (`cmdType` = 8). The malware will sleep for `Config.Interval` seconds.

## Communication Protocol
---

**Malware -> C&C Server**

The message fields are:

- `NodeId`
- `MessageId`
- `Payload`
- `CommandType`

The message payload encrypted with `MD5(MessageIdString)` as encryption key.

Messages sent to given relay address of to one of the `Relays` inside to configuration file.

*Message types:*

- 0 - Register new client
- 1 - Get command
- 4 - Command ACK / command output
- 9 - CRC Error
- 10 - Operation failed
- 11 - Engine version
- 15 - uploaded file
- 17 - Send process id

**C&C Server -> Malware**

The reply message fields are:

- `type`
- `id`
- `node`
- `payload`

The message's payload decrypted with `MD5(MessageIdString)` as decryption key.

*Message types:*

- 5 - Update `NodeId` from `payload` (response to 0)
- 8 - No command/Command failed