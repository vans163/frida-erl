REM "C:\Program Files (x86)\Microsoft Visual Studio 10.0\VC\bin\vcvars32.bat"
REM VC Community 2017

REM "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvarsall.bat" x86

"C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Tools\MSVC\14.10.25017\bin\HostX86\x86\cl.exe"^
 /I "C:\Program Files\erl8.3\erts-8.3\include"^
 /I "..\priv\9.1.20-core-win-i386"^
 "..\priv\9.1.20-core-win-i386\frida-core.lib"^
 "C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Lib\Gdi32.lib"^
 "C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Lib\user32.lib"^
 "C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Lib\advapi32.lib"^
 "C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Lib\ole32.lib"^
 "C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Lib\shell32.lib"^
 /O2 /LD /MD /out:"../priv/build/frida_nif_win_i386.dll" frida_nif.c