from functions import *
import os

pem = Private_Key()
pub = Public_Key(pem.makeGPrime())
choice = raw_input("Do you want to E:ncrypt or D:ecrypt:")
if choice =="E":
    Efile = raw_input("Select file:")
    pub.encryptFile(Efile)
if choice =="D":
    Dfile = raw_input("Select file:")
    pem.decryptFile(Dfile)
