## Registry Keys Used for DLL Injection

1. **AppInit_DLLs**
   - *Location:* `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`
   - *Description:* Specifies DLLs to be loaded into every process that loads User32.dll during startup.

2. **Image File Execution Options**
   - *Location:* `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
   - *Description:* Allows specific settings to be applied to executables; malware can use this to load a DLL when a certain executable is launched.

3. **App Paths**
   - *Location:* `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths`
   - *Description:* Allows applications to specify executable paths associated with application names; malware can misuse this to point to a malicious DLL.

4. **Run and RunOnce Keys**
   - *Locations:*
     - `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
     - `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce`
     - `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run`
     - `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce`
   - *Description:* Specifies programs to run automatically at user logon or system startup; malware can add entries to load a process that injects a malicious DLL.

5. **Environment Variables (PATH Modification)**
   - *Locations:* `HKEY_CURRENT_USER\Environment` or `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`
   - *Description:* Malware can modify the `PATH` variable to include a directory containing a malicious DLL.

6. **Explorer Browser Helper Objects (BHOs)**
   - *Location:* `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
   - *Description:* Allows registration of DLLs to extend browser functionality; malware can register a DLL here for injection into browser processes.

7. **Known DLLs**
   - *Location:* `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\KnownDLLs`
   - *Description:* Although not directly related to injection, malware may tamper with this to redirect system DLL loading.

8. **Winlogon Notifiers**
   - *Location:* `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify`
   - *Description:* Allows DLLs to be loaded into the Winlogon process for system event notifications.

9. **Shell Extensions**
   - *Location:* `HKEY_CLASSES_ROOT\*\shellex\ContextMenuHandlers`
   - *Description:* Contains context menu handlers for different file types; malware can register DLLs here for process injection when right-clicking files.

10. **Winsock LSP (Layered Service Provider)**
    - *Location:* `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinSock2\Catalog9`
    - *Description:* Malware can install Layered Service Providers to intercept network communications by injecting DLLs.

11. **Service Control Manager**
    - *Location:* `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services`
    - *Description:* Malware can create or modify services to execute and load DLLs during system startup.

12. **Scheduled Tasks**
    - *Location:* `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks`
    - *Description:* Malware can create or modify scheduled tasks to execute processes that load malicious DLLs.

13. **Active Setup**
    - *Location:* `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components`
    - *Description:* Allows components to be installed for new user profiles; malware can misuse this to run DLLs during user login.

14. **Startup Programs**
    - *Locations:*
      - `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
      - `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce`
      - `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run`
      - `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce`
    - *Description:* Malware can add entries here to automatically run processes that load malicious DLLs.

15. **Global Flags**
    - *Location:* `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\GlobalFlag`
    - *Description:* Malware might modify global flags to influence system behavior, potentially affecting DLL loading.

16. **Security Packages**
    - *Location:* `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\Security Packages`
    - *Description:* Malware can register as a security package DLL to intercept authentication and other system functions.

17. **Notification Packages**
    - *Location:* `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify`
    - *Description:* Allows DLLs to be loaded into the Winlogon process for various system event notifications.

18. **Network Provider Order**
    - *Location:* `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\NetworkProvider\Order`
    - *Description:* Malware can modify network provider order settings to load DLLs for handling network-related operations.

19. **Service DLLs**
    - *Location:* `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services`
    - *Description:* Malware can modify service configuration settings to specify DLLs that are loaded during service startup.

**Note:** Modifying these registry keys for malicious purposes is illegal and unethical. The examples provided are for educational purposes to understand potential security risks associated with unauthorized registry modifications and DLL injection techniques. Proper security measures should be implemented to prevent and detect unauthorized system changes.
