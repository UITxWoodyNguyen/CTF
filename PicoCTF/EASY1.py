#Problem Link: https://play.picoctf.org/practice/challenge/43?category=2&difficulty=2&page=3
import string

alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KEY = "SOLVECRYPTO"
flag = "UFJKXQZQUNB"

def encrypt (flag):
    encrypted = ""
    for i in range(len(flag)):
        if (ord(flag[i]) - ord(KEY[i]) >= 0):
            encrypted += alphabet[ord(flag[i]) - ord(KEY[i])]
        else:
            encrypted += alphabet[ord(flag[i]) - ord(KEY[i]) + 26]
    return encrypted

print(encrypt(flag))  
