# ke-hide
Windows 7 32-bit kernel mode driver that demonstrates various techniques used by rootkits.

Features:
- hook tcpip.sys to hide connections on given port
- hook system services:
  - NtWriteFile
  - NtCreateFile
  - NtQuerySystemInformation - hide process information
  - NtOpenProcess - make it impossible to get a handle to the process
- hook interrupt service routines
- enable writing to read-only pages using Control Register Zero (CR0)
- register callbacks to make it impossible to get a handle to the process or its threads
- set "verified image" flag for the process
- create the process from within the driver by calling CreateProcessW from the context of a specified process
- disable process creation notifications
- steal System process token
- hide process from various linked lists (MmProcessLinks, ActiveProcessLinks, SessionProcessLinks)
