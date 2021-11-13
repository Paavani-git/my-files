from Crypto.Cipher import AES  
from Crypto.Util.Padding import pad,unpad  
from os import *  
  
key = b"Yellow submarine"  
iv = b"A happy cbc mode"  
  
  
def encrypt(pt): 
    return (AES.new(key,AES.MODE_CBC,iv)).encrypt(pad(pt.encode(),16))  
  
def decrypt(ct): 
    if len(ct)%16 == 0: 
        return (AES.new(key,AES.MODE_CBC,iv)).decrypt(ct) 
    elif len(ct)%16 != 0: 
        return (unpad((AES.new(key,AES.MODE_CBC,iv)).decrypt(ct) , 16))  
 
def blocks(ct,blocksize = 16):    
    return [ct[i:i+blocksize] for i in range(0,len(ct),blocksize)]   
                                                                                    
 
pt = 'In stream ciphers, IVs are loaded into the keyed internal secret state of the cipher, after which a number of cipher rounds are executed prior to releasing the first bit of o/p'

ct = encrypt(pt)
pt = decrypt(ct)

# Take 1st 16 bytes of ct add it with "\x00"*16 and add same 1st 16 bytes of ct

ct = ct[:16] + b"\x00"*16 + ct[:16]
pt = decrypt(ct)    
iv_detected = ""
for i in range(16):         
    iv_detected += chr(pt[i] ^ pt[32+i])           # pt1^pt3 => (dec(ct1)^(dec(ct1))^(iv^(b"\x00"))      

print("IV_ detected:",iv_detected.encode())
print("IV:",iv)