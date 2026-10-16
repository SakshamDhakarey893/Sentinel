' ==============================================================================
' Sentinel Relay Server — Silent Background Launcher (Windows)
' Launches sentinel-backend.exe with no CMD window visible.
' ==============================================================================

Set objFSO = CreateObject("Scripting.FileSystemObject")
strScriptDir = objFSO.GetParentFolderName(WScript.ScriptFullName)
strSentinelDir = objFSO.GetParentFolderName(strScriptDir)

strExePath = strSentinelDir & "\backend\target\release\sentinel-backend.exe"

If Not objFSO.FileExists(strExePath) Then
    strExePath = strSentinelDir & "\backend\target\debug\sentinel-backend.exe"
End If

If Not objFSO.FileExists(strExePath) Then
    MsgBox "Could not find sentinel-backend.exe. Please build it first with: cargo build --release", 16, "Sentinel Backend Not Found"
    WScript.Quit 1
End If

Set objShell = CreateObject("WScript.Shell")
objShell.CurrentDirectory = strSentinelDir & "\backend"

' Run with window style 0 (hidden) and bWaitOnReturn = False
objShell.Run """" & strExePath & """", 0, False
