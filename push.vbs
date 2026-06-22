Set WshShell = WScript.CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

proj = "C:\Users\Wataan-ps\PycharmProjects\meezan-majd"

' git add
WshShell.Run "cmd /c cd /d """ & proj & """ && git add .", 0, True

' git commit
WshShell.Run "cmd /c cd /d """ & proj & """ && git commit -m ""auto: update " & Now() & """", 0, True

' git push
WshShell.Run "cmd /c cd /d """ & proj & """ && git push origin main", 0, True

MsgBox "تم رفع التغييرات بنجاح! الموقع سيتحدث خلال ثوانٍ.", 64, "ميزان مجد — Deploy"
