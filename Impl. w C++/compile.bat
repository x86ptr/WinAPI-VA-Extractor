@ECHO OFF

if not exist "build" (
    mkdir "build"
) 

:: cl.exe /EHsc /nologo /Od /MT /GS- /DNDEBUG main.cpp /link /SUBSYSTEM:CONSOLE /MACHINE:x86 /OUT:.\build\main.exe

cl.exe /EHsc /nologo /Od /MT /GS- /DNDEBUG main.cpp /link /SUBSYSTEM:CONSOLE /MACHINE:x64 /OUT:.\build\main.exe

del main.obj