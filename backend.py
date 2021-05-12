import numpy as np
#S random binary of non singular matrix K*K
def gen_S_Matrix(k):
    sMaybe = np.matrix(np.random.randint(0,2,k*k).reshape(k,k).astype(int))
    while True:
		try:
			sMaybe.getI()
			return sMaybe
		except:
			sMaybe = np.matrix(np.random.randint(0,2,k*k).reshape(k,k).astype(int))


def gen_P_Matrix(n,keep=False):
    p = np.identity(n,dtype=int)
    if keep:
        return np.matrix(p).reshape(n,n)
    else:
        return np.matrix(np.random.permutation(p))
#P N*N random permutation matrix
def Modlo(C):
    D = C.copy()
    D.fill(2)
    return np.remainder(C,D)
def Not(C,n):
    if n == 0:
		return C
    if n == -1:
		index = random.randint(1,C.size -1)
    else:
		index = n
    if C[0,index-1] == 1:
		C[0,index-1] = 0
    else:
		C[0,index-1] = 1
    return C

def allZeros(d):
	zc = 0
	for x in d:
		if x == 0:
			zc += 1
	if zc == len(d):
		return True
	else:
		return False
#error syndrome
def error_Syndrome(H,d):
	t = H.T.tolist()
	s = d.T.tolist()[0]

	if allZeros(s):
		return 0
	try:
		return t.index(s) + 1
	except:
		return 0
