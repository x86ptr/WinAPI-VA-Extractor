@ECHO OFF

if not exist "build" (
    mkdir "build"
) 

nasm -fwin64 shellcode.asm -o .\\build\\shellcode.obj
nasm -fwin64 lib\\x64_lib.asm -o .\\build\\x64_lib.obj
ld -s .\\build\\shellcode.obj .\\build\\x64_lib.obj -o .\\build\\shellcode.exe