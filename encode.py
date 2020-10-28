import argparse
import binascii
import string

# x86 only on eax register

# initialize eax http://phrack.org/issues/57/15.html#article
# push 'aaaa'                       ; 'a' 'a' 'a' 'a'
# pop eax                          ;EAX now contains 'aaaa'.
# xor eax,'aaaa'


valid_ascii =  string.ascii_letters 
valid_ascii += string.digits
valid_ascii += """!"#$%&'()*+,-./@`:;<=>?[]\^_~|{}"""

valid_ascii = valid_ascii.encode("ascii")
#lol
def bruteforce(b):
    for x in valid_ascii:
        for y in valid_ascii:
            for z in valid_ascii:
                summ = x + y + z

                if  summ == b:
                    return bytes([x, y, z])
    return None


parser = argparse.ArgumentParser(description="Encode a shellcode to printable with sub ")

parser.add_argument('shellcode')

args = parser.parse_args()

shellcode = b""

with open(args.shellcode, "rb") as f:
    shellcode = f.read()


if len(shellcode) % 4 != 0 :
    print("shellcode must be 4 bytes divisible")


print("PUSH 'aaaa'")
print("POP eax")
print("XOR eax, 'aaaa'") # eax is now 0

chunks_count = int(len(shellcode) / 4)

chunks = []

for i in range(0, chunks_count - 1):
    chunk = bytearray(shellcode[i * 4: (i * 4) + 4])
    chunk.reverse()
    two_complement = 0xffffffff - int(binascii.hexlify(chunk), 16) + 1

    two_complement = two_complement.to_bytes(4, 'big')

    sub1 = bytearray([0,0,0,0])
    sub2 = bytearray([0,0,0,0])
    sub3 = bytearray([0,0,0,0])

    carry = False
    subCount = 0
    converted = False

    while(not converted):
        for i in reversed(range(0, 4)):
            b = two_complement[i]

            if carry:
                b = b - 1 # decrease byte because of carry
                carry = False 

            brute = bruteforce(int(b))

            # optimized encoder to often use only 3 sub instead of 50
            if brute == None:
                b = ((b + 0x100) & 0xFFF) # try adding 0x100 to the byte
                carry = True
        
            brute = bruteforce(b)
           
            if brute == None:
                #print("Can't encode chunk... retrying")
                # not clean (before optimizing above i was bruteforcing with always subbing 0x55555555
                
                two_complement = ((int(binascii.hexlify(two_complement), 16) - 0x55555555) & 0xFFFFFFFF).to_bytes(4, 'big')
                
                subCount += 1
                carry = False # reset carry
                break # exit for and retry with 0x55555555 added
            
            sub1[i] = brute[0]
            sub2[i] = brute[1]
            sub3[i] = brute[2]

            # no issues
            if i == 0: 
                converted = True



        

        
    print("SUB eax," + hex(int(binascii.hexlify(sub1), 16)))
    print("SUB eax," + hex(int(binascii.hexlify(sub2), 16)))
    print("SUB eax," + hex(int(binascii.hexlify(sub3), 16)))
    
    for i in range(subCount):
        print("SUB eax,0x55555555")
    
    print("push eax")


