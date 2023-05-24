import pefile
import os

# Assembles and Links the shellcode
os.system("nasm -fwin64 shellcode.asm -o shellcode.obj")
os.system(f"nasm -fwin64 lib/x64_lib.asm -o x64_lib.obj")
os.system(f"ld -s shellcode.obj x64_lib.obj -o shellcode.exe ")

os.system("del shellcode.obj && del x64_lib.obj")

user_input = input("Output: (Binary|C) >> ")

# Opens the PE file
pe = pefile.PE("shellcode.exe")
# Reads the .text section data
pe_data = pe.get_section_by_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint).get_data()

# Extracts the shellcode from PE
i = len(pe_data) - 1;
while(i >= 0):
    if pe_data[i] == 0xc3:
        try:
            os.mkdir("output")
        except:
            pass
        if user_input == "Binary" or user_input == "B":
            with open(f"{os.getcwd()}\\output\\shellcode.bin", "wb") as file:
                file.write(pe_data[0:i + 1])
            pe.close()
            print("[+] Payload was saved in /output/shellcode.bin")
            break
        elif user_input == "C":
            shellcode = ""
            for i in range(i + 1):
                shellcode += f"\\x{hex(pe_data[i])[2:].rjust(2, '0')}"
            with open(f"{os.getcwd()}\\output\\shellcode.txt", "w") as file:
                file.write(shellcode)
            pe.close()
            print("[+] Payload was saved in /output/shellcode.txt")
            break
        else:
            print("Invalid options!")
            break
    i -= 1
    
os.system("del shellcode.exe")