import numpy as np
import pickle
import os.path
import random
import csv
from backend import *
#Private Key: (S, DG, P), where DG is an efficient decoding algorithm for G
class Private_Key:
	def __init__(self,S=None,P=None):
		self.G = np.matrix([
		[1,0,0,0,0,1,1,1],
		[0,1,0,0,1,0,1,1],
		[0,0,1,0,1,1,0,1],
		[0,0,0,1,1,1,1,0]
		], dtype=int)
		self.H = np.matrix([
		[0,1,1,1,1,0,0,0],
		[1,0,1,1,0,1,0,0],
		[1,1,0,1,0,0,1,0],
		[1,1,1,0,0,0,0,1]
		], dtype=int)
		if S == None:
			self.S = Modlo(gen_S_Matrix(4))
		else:
			self.S = S

		if P == None:
			self.P = Modlo(gen_P_Matrix(8))
		else:
			self.P = P

	def makeGPrime(self):
		res = Modlo(self.S*self.G*self.P)
		return res
#cP ^-1 = (Ms) G xor z P^-1
	def decrypt(self,c):
		cP = c * Modlo(self.P.I.astype(int))
		m = Not(cP,Nerror_Syndrome(self.H,Modlo(self.H*cHat.T)))
		return Modlo(m[0,0:4] * Modlo(self.S.I.astype(int)))

	def decryptFile(self,f):
		cf = open(f,"rb")
		cb1 = cf.read(1)
		cb2 = cf.read(1)

		mf = open(f+".decrypted","wb")

		while cb1 and cb2:

			c_1 = '{0:08b}'.format(ord(cb1))[0:8]
 			c1_l = []
			m1 = ""
			for s in c_1:
				c1_l.append(s)
			c_1_m = np.matrix(c1_l,dtype=int)

			d1 = self.decrypt(c_1_m)

			for d in range(0,d1.size):
				m1 += str(d1.item(d))

			c_2 = '{0:08b}'.format(ord(cb2))[0:8]
 			c2_l = []
			m2 = ""
			for s in c_2:
				c2_l.append(s)
			c_2_m = np.matrix(c2_l,dtype=int)

			d2 = self.decrypt(c_2_m)

			for d in range(0,d2.size):
				m2 += str(d2.item(d))

			mf.write(chr(int(m1+m2,2)))
			cb1 = cf.read(1)
			cb2 = cf.read(1)

		mf.close()
		cf.close()
#Public Key: (G, t)
class Public_Key:
	def __init__(self,GPrime):
		self.GPrime = GPrime
#c = mG XOR z.
	def encrypt(self,m):
		z = random.randint(1,7)
		c = Not(Modlo(m*self.GPrime),z)
		return c

	def encryptFile(self,f):

		mf = open(f,"rb")
		m = mf.read(1)

		cf = open(f+".encrypted","wb")

		while m:
			m_1 = '{0:08b}'.format(ord(m))[0:4]
			m1_l = []
			c1 = ""
			for s in m_1:
				m1_l.append(s)
			m_1_m = np.matrix(m1_l,dtype=int)

			d1 = self.encrypt(m_1_m)
			for d in range(0,d1.size):
				c1 += str(d1.item(d))
			cf.write(chr(int(c1,2)))

			m_2 = '{0:08b}'.format(ord(m))[4:]
			m2_l = []
			c2 = ""
			for s in m_2:
				m2_l.append(s)
			m_2_m = np.matrix(m2_l,dtype=int)

			d2 = self.encrypt(m_2_m)
			for d in range(0,d2.size):
				c2 += str(d2.item(d))
			cf.write(chr(int(c2,2)))

			m = mf.read(1)

		cf.close()
		mf.close()
