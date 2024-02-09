@ECHO OFF

if not exist "build" (
    mkdir "build"
) 

nasm -fwin32 shellcode.asm -o .\\build\\shellcode.obj
nasm -fwin32 lib\\x32_lib.asm -o .\\build\\x32_lib.obj
ld -m i386pe -s .\\build\\shellcode.obj .\\build\\x32_lib.obj -o .\\build\\shellcode.exe