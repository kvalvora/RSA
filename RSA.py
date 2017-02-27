import time
import sys
import binascii
import math
sys.setrecursionlimit(4*2048)

def xgcd(a, b): #Extended Euclidean Algorithm
    """
    Returns g, x, y such that g = x*a + y*b = gcd(a,b).
    """
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = xgcd(b % a, a)
        return (g, x - (b // a) * y, y)

def my_pow_SqMul(x,e,n):
    ''' Performs modular exponentiation (b^e mod m)
        using the square and multiply algorithm'''
    e_bin=bin(e)
    t=len(e_bin)
    x1=x
    for i in range(3,t):
        x1=(x1*x1)%n   #sqauring everytime regardless of bit value
        if (e_bin[i]=="1"):
           x1=(x1*x)%n    #multiply only if bit value is 1
     
    return x1


def integer_ceil(a, b):
    '''Return the ceil integer of a div b.'''
    q, mod = divmod(a, b)
    if mod:
        q += 1
    return q

def i2osp(x, x_len):
    '''Converts the integer x to its big-endian representation of length
       x_len.
    '''
    if (x > 256**x_len):
        print ('Integer too large')
    h = hex(x)[2:]
    if h[-1] == 'L':
        h = h[:-1]
    if len(h) & 1 == 1:
        h = '0%s' % h
    x = binascii.unhexlify(h)
    return (b'\x00' * int(x_len-len(x)) + x)

def os2ip(x):
    '''Converts the byte string x representing an integer reprented using the
       big-endian convient to an integer.
    '''
    h = binascii.hexlify(x)
    return (int(h, 16))

def MGF(seed,maskLen):
    '''returns a mask of length maskLen, generated from seed using SHA-256'''
    import hashlib

    hLen = hashlib.sha256().digest_size
    if (maskLen > 0x10000):
        print('Error, mask too long')
    T = b''
    for i in xrange(0, integer_ceil(maskLen, hLen)):
        C = i2osp(i, 4)
        T = T + hashlib.sha256(seed + C).digest()

    return T[:maskLen]

def RSAKeyGen(p,q):
    phi=(p-1)*(q-1)
    e=(2**16)+1
    d=xgcd(e,phi)
    #print d
    return (e,d)


def RSAESencrypt(N,e,m,L=bytearray()):
    '''Performs RSA PKCS #1 v2.1 encryption using the public key <N,e>
        on message m (optinal: label L). Ciphertext c is returned.
        N and e are integers, m, L, and c are byte arrays'''

    import hashlib
    import os

    mLen = len(m)
    hLen = hashlib.sha256().digest_size # since we use SHA256

    # check lengths
    k=((len(bin(N))-2)/8)
    if (mLen>k-11):
        print'Error, message too long'
        return
    # generate DB
    ps=os.urandom(k-mLen-3)    
    # generate EM
    em = (b'\x00\x02' + ps + b'\x00' + m)
    # perform encryption
    m1=os2ip(em)
    c1=my_pow_SqMul(m1,e,N)
    c=i2osp(c1,k)

    return c


def RSAESdecrypt(N,d,c,L=bytearray()):
    '''Performs RSA PKCS #1 v2.1 decryption using the private key <N,d>
        on ciphertext c (optinal: label L). Message m is returned.
        N and d are integers, m, L, and c are byte arrays'''

    import hashlib
    import os

    cLen = len(c)
    hLen = hashlib.sha256().digest_size # since we use SHA256

    # check lengths
    k=(len(bin(N))-2)/8
    if (cLen!=k | k<11):
        print ('Decryption error')
        return
    # decrypt C
    c1=os2ip(c)
    if (c1<=0 & c1>N-1):
        print ('Error, ciphertext representative out of range')
        return
    
    m = my_pow_SqMul(c1,d,N)
    em=i2osp(m,k)
    # separate EM
    i = em.find(b'\x00', 2)
    em1=em[i+1:]

    return em1
    


# Testing RSA encryption and decryption
p = 8176662165573700613347344450959887037086515168356394479546398903326976319674343656956828452558146536261756580874692178418735952635936011308339369316896181
q = 13062362680240858986014063047218740765842583586324085493117801839987719301360641696613806125427125208683501703668298486807198605540347486024024409678675789
N = p*q
e = 2**16+1
d = 95305639297136535129830247353885048571790931736897092024327830574503233416208940851818667509421055075611745557004095412620624213281032376171998990351263574092801357243118351700307075125243451771395731520183667695423762834718377372357353733379277776224241008883890378073612334038347526558549705139740335907073

### Test MGF:
print('Starting MGF Test: ')
seed = bytearray()
for cnt in range(33):
    seed.append(cnt)

check = MGF(seed,42)

correct = bytearray(b'_\xf0\x98\xa3\xa9\xe7\xa9=\xc6\x04\x99\xf1\xa6\xfb\xf6\x8cW\x9c\x90B\xd6\x9cEs\x1d\xf9\xd7\xa8\x0e\xfb)\xaf\xc0\xc9\n=\x9e\x8a\x11\x18o;')
if len(check)!=42:
    print('error: wrong output length')
elif(check != correct):
    print('failed: wrong output')
else:
    print('passed')


# Test RSA Encryption and decryption:
print('Starting first RSA Test: ')

m = (b'\x02\xff')
c = RSAESencrypt(N,e,m)
mp = RSAESdecrypt(N,d,c)
if (mp!=m):
    print('failed: message not recovered')
else:
    print('passed')

print('Starting second RSA Test: ')
m = correct
c = RSAESencrypt(N,e,m)
mp = RSAESdecrypt(N,d,c)
if (mp!=m):
    print('failed: message not recovered')
else:
    print('passed')

print('Starting first RSA Failure Test: ')

m = correct+correct+correct
try:
    c = RSAESencrypt(N,e,m)
except IOError:
    print('passed')
else:
    print('failed')

print('Starting second RSA Failure Test: ')

c = (b"A\xe0\xe5\xe6G)\xbc\x04\xd3'\xe50@/\xddiy\xff\xd0\x8b\xc8U\x10p\xf5v{`\xa7\x19o\xe5\xb3X~\x10\xbf7eN\x9ey\x9f\x1d\xe9\xe8\x89\xbcxX\xee\x95\xf5\xdf\xc7M\x91\xc3\x84C\x15]a\xf9\xcf]\xb4r\x06\xb8QL\x86\x19^NF\xd2\xf6|\xeb\x10G\xc6\x0b\x87\x07\xd1O\xff(\xadk\xe1Cj\xfc\xbc=\xee\x16cc\xb69\xb3\xcb\x92 e+G\x1f\x85&~4p\xc2\x8f]\xf2\xfb\xee\xa6\xe2oJ")
try:
    m = RSAESdecrypt(N,e,c)
except IOError:
    print('passed')
else:
    print('failed')


