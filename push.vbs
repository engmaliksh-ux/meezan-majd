Set WshShell = WScript.CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

proj = "C:\Users\Wataan-ps\PycharmProjects\meezan-majd"
lockFile = proj & "\.git\index.lock"

' حذف index.lock تلقائياً إذا كان موجوداً
If fso.FileExists(lockFile) Then
    On Error Resume Next
    fso.DeleteFile lockFile, True
    On Error GoTo 0
End If

' git add
WshShell.Run "cmd /c cd /d """ & proj & """ && git add -A", 0, True

' git commit بتاريخ تلقائي
ts = Year(Now) & "-" & Right("0"&Month(Now),2) & "-" & Right("0"&Day(Now),2) & " " & Right("0"&Hour(Now),2) & ":" & Right("0"&Minute(Now),2)
WshShell.Run "cmd /c cd /d """ & proj & """ && git commit -m ""auto: " & ts & """", 0, True

' git push
ret = WshShell.Run("cmd /c cd /d """ & proj & """ && git push origin main", 0, True)

If ret = 0 Then
    MsgBox "تم رفع التغييرات بنجاح!" & Chr(13) & "الموقع سيتحدث خلال ثوانٍ.", 64, "ميزان مجد"
Else
    MsgBox "تحقق من الاتصال وحاول مجدداً.", 48, "ميزان مجد — خطأ"
End If
