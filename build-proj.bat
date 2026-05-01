call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
msbuild VaultFs.sln /p:Configuration=Release /p:Platform=x64
pause
