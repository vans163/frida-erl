REM "C:\Program Files (x86)\Microsoft Visual Studio 10.0\VC\bin\vcvars32.bat"
REM VC Community 2017

REM "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
REM "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Tools\MSVC\14.10.25017\bin\HostX86\x86\cl.exe" /I "C:\Program Files\erl8.3\erts-8.3\include" /I "..\priv\9.1.20-core-win-i386" /LD /MD /Fe frida_nif.c

"C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Tools\MSVC\14.10.25017\bin\HostX64\x64\cl.exe"^
 /I "C:\Program Files\erl8.3\erts-8.3\include"^
 /I "..\priv\9.1.20-core-win-x86_64"^
 "..\priv\9.1.20-core-win-x86_64\frida-core.lib"^
 /GS /GL /W3 /Gy /Zc:wchar_t /Zi /Gm- /O2^
 /Zc:inline /fp:precise /D "NDEBUG" /D "_CONSOLE" /D "_UNICODE" /D "UNICODE"^
 /errorReport:prompt /WX- /Zc:forScope /Gd /Oi /EHsc /nologo^
 "C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Lib\x64\Gdi32.lib"^
 "C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Lib\x64\user32.lib"^
 "C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Lib\x64\advapi32.lib"^
 "C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Lib\x64\ole32.lib"^
 "C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Lib\x64\shell32.lib"^
 "C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Lib\x64\kernel32.lib"^
 "C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Lib\x64\winspool.lib"^
 "C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Lib\x64\comdlg32.lib"^
 "C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Lib\x64\oleaut32.lib"^
 "C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Lib\x64\uuid.lib"^
 "C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Lib\x64\odbc32.lib"^
 "C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Lib\x64\odbccp32.lib"^
 /LTCG:incremental /NXCOMPAT^
 /DYNAMICBASE "kernel32.lib" "user32.lib" "gdi32.lib" "winspool.lib" "comdlg32.lib" "advapi32.lib"^
 "shell32.lib" "ole32.lib" "oleaut32.lib" "uuid.lib" "odbc32.lib" "odbccp32.lib"^
 /DEBUG /MACHINE:X64 /OPT:REF /INCREMENTAL:NO^
 /OPT:ICF /ERRORREPORT:PROMPT /NOLOGO /TLBID:1^
 /LD /MD /Fe frida_nif.c