# To-Safe-Mode-And-Beyond
A tool for leveraging elevated acess over a computer to boot the computer into Windows Safe Mode, alter settings, and then boot back into Normal Mode.

To compile:

csc.exe /out:"c:\users\public\combined.dll" "c:\users\public\program.cs"

To run:

powershell.exe -command "set-location -path c:\windows\diagnostics\system\networking; import-module .\UtilityFunctions.ps1; RegSnapin ..\..\..\..\users\public\combined.dll;[Program.Stage0]::Main()"


**NOTES**

This program has been structured in stages (stage0, stage1, and stage2). In the example above, Main is being called. The code will make the necessary registry edits to call stage1/main1 and stage2/main2 as it progresses using the same method of execution as shown above.

stage0:
If run from an elevated context, the following things will happen in stage 0:

1. If you are in possession of compromised domain credentials, these can be hardcoded into the program so that can interactive logon type 2 can be performed. Once this is done, they are then cached can be used to login to Safe Mode. This is just optional and not enabled by default.
2. A new local account is created and added to the local Administrators group (see code to change the default user/pass)
3. The new local account credentials are added to registry to be used for logging on to the computer automatically
4. In the event that BitLocker might be present and interfere with a restart, the program will attempt to suspend BitLocker
5. The BCD store is modified to cause the computer to boot into Safe Mode at next restart
6. A RunOnce registry entry is added to call stage 1 in the program
7. The computer is forcibly restarted

stage1:
Once in Safe Mode, there are a lot of potential options and nothing malicious is actually done with this code as it's just a PoC. For now, the following things will happen in stage 1:

1. The computer will logon automatically with the local account that was created in stage0
2. Some text will be written to c:\users\public\safemode.txt to show that things are actually happening while in Safe Mode
3. Attempt to take ownership, assign necessary permissions, and then disable a Windows that doesn't actually exist (just need to replace with an actual service)
4. The BCD store is modified to cause the computer to boot back into Normal Mode at next restart
5. A RunOnce registry entry is added to call stage 2 in the program
6. The computer is forcibly restarted 

stage2:
Since this is just a PoC, not much happens in stage2. For now, the following things will happen in stage 2:

1. The computer will logon automatically with the local account that was created in stage0
2. The computer will disable the previously set auto logon
