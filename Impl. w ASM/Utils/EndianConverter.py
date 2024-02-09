import sys

def LittleEndianConvertor(string, padding):
    l = list()
    s = ""
    for i in range(len(string)):
        if i != 0 and i % padding == 0:
            l.append(s)
            s = ""
        s += string[i]
        if i == len(string) - 1:
            l.append(s)
    l.reverse()
    for index in range(len(l)):
        l[index] = l[index][::-1]
        print("0x", end="")
        for i in l[index]:
            print(hex(ord(i))[2::], end="")
        print()
        
if len(sys.argv) != 3:
    print("Usage: python EndianConverter.py <arch> <string>")
    exit(-1)

padding = 8
if sys.argv[1] == "x32" or sys.argv[1] == "x86":
    padding = 4;
    
LittleEndianConvertor(sys.argv[2], padding)
