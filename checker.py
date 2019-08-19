import argparse
import hashlib
import random
import subprocess
import numpy as np
import filecmp

TEXT_NOT_VALID="Verification FAILURE, values does not correspond"
TEXT_VALID="Verification SUCCESS, all values are good"
ITERATIONS=155000
LOG_P=2048
TIMEDITERATIONS=300000000000
KLENGTH=256

parser = argparse.ArgumentParser()
parser.add_argument('path_to_tweetfile')
parser.add_argument('path_to_valuefile')
parser.add_argument('path_to_imagefile')
parser.add_argument('path_to_encryptimagefile')
args = parser.parse_args()

number=0
witness=0
commitment=0
COMMIT_N=0
COMMIT_P=0
COMMIT_Q=0

#read value
with open(args.path_to_valuefile) as valuefile:
    listvalue=valuefile.readlines()
    for line in listvalue:
        split=line.split(': ')
        if split[0] == "Beacon value":
            number=split[1].lower()
        elif split[0] == "Witness":
            witness=split[1].lower()
        elif split[0] == "Commitment":
            commitment=split[1].lower()
        elif split[0] == "n":
            COMMIT_N=split[1].lower()


if( number==0 or witness==0 or commitment==0 or COMMIT_N==0):
    print("Values not read correctly, check the file formating")
    exit()

#correction of python readline
if(number[-1]=='\n'):
    number=number[:-1]
if(witness[-1]=='\n'):
    witness=witness[:-1]
if(commitment[-1]=='\n'):
    commitment=commitment[:-1]
if(COMMIT_N[-1]=='\n'):
    COMMIT_N=COMMIT_N[:-1]


################################## function def #######################

# Miller-Rabin primality test copy from check for eliptic  curve
def is_probable_prime(n, k = 3):
    
    assert n >= 2, "Error in is_probable_prime: input (%d) is < 2" % n
    
    # First check if n is divisible by any of the prime numbers < 1000
    low_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
                  59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
                  127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
                  191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
                  257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
                  331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397,
                  401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
                  467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557,
                  563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619,
                  631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
                  709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787,
                  797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863,
                  877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953,
                  967, 971, 977, 983, 991, 997]
        
    for prime in low_primes:
        if (n % prime == 0):
            return False

    # Perform the real Miller-Rabin test
    s = 1
    mask=2
    while ((n&mask) ==0):
        mask =mask <<1
        s=s+1
    d = (n >> s)

    # test the base a to see if it is a witness for the compositeness of n
    def try_composite(a):
        pod=pow(a, d, n)
        if ( (pod == 1) or (pod == n-1) ):
            return False
        i=1
        while(i < s):
            pod=(pod*pod) % n
            if (pod == n-1):
                return False
            i=i+1
        return True # n is definitely composite

    if try_composite(2):
        return False
    for i in range(k-1):
        a = random.randrange(2, n)
        if try_composite(a):
            return False

    return True # no base tested showed n as composite



def tho_inv(n,primemod,flip):
    ret=0
    if( (n&1) == 0):
        ret = pow(n,2,primemod)
    else:
        ret = primemod - pow(n,2,primemod) #((n*n) % primemod)

    ret = (ret ^ flip)
    
    if( (ret >= primemod) or (ret == 0) ):
        ret = (ret ^ flip)
    
    return ret


def generate(s,i,w,a):
    hexa=""
    locali=i
    localw=w
    hexa=hashlib.sha512( bytearray(s+(hex(locali)[2:]),"ascii")).hexdigest()
    while(ord(hexa[0])<ord('8')):
        hexa=hashlib.sha512(bytearray(hexa,"ascii")).hexdigest()
    locali+=1
    localw-=1
    while(localw>0):
        hexa=hexa + hashlib.sha512( bytearray(s+(hex(locali)[2:]),"ascii")).hexdigest()
        locali=locali+1
        localw=localw-1

    hexa=hexa[:w*128]
    
    intprime=int(hexa,16)

    if(intprime&1 == 0):
        intprime=intprime+1
    if(a==4):
        if(intprime&2 == 0):
            intprime=intprime+2

    while ( not(is_probable_prime(intprime)) ):
        intprime=intprime+a

    return intprime



######################################################################

#SHA512(tweetfile)
with open(args.path_to_tweetfile,mode='rb') as tweetfile:
    S0=hashlib.sha512(tweetfile.read()).hexdigest()

#SHA512(imagefile)
with open(args.path_to_imagefile,mode='rb') as imagefile:
    S1=hashlib.sha512(imagefile.read()).hexdigest()

#check n
comp=generate(S1,1,2,2)
comq=generate(S1,3,2,2)
comn=int(COMMIT_N,16)

#check commit
if( (comp*comq) != comn ):
    print(TEXT_NOT_VALID)
    exit()


#creation of seed which is SHA512( SHA512(tweetfile) || SHA512(imagefile) ) || hex(n)
S=hashlib.sha512( bytearray(S0+S1,"ascii") ).hexdigest()
seed_string=S+COMMIT_N


#check commitment

compc= hashlib.sha512( bytearray(S,"ascii") ).hexdigest()
if( compc != commitment ):
    print(TEXT_NOT_VALID)
    exit()


#check encrypted image
kcomm=pow(int(commitment,16), pow(2,TIMEDITERATIONS,(comp-1)*(comq-1)) ,comn)
kpass_num = kcomm % (2**KLENGTH)
kpass=np.base_repr(kpass_num,36).lower()

subprocess.check_call("openssl aes-256-cbc -d -in "+args.path_to_encryptimagefile+" -out "+args.path_to_imagefile+".decrypt -pass pass:"+kpass,shell=True)
if (not(filecmp.cmp(args.path_to_imagefile, args.path_to_imagefile+".decrypt", shallow=False))):
    print(TEXT_NOT_VALID)
    exit()


#check number, witness
if( hashlib.sha512( bytearray(witness,"ascii") ).hexdigest() != number ):
    print(TEXT_NOT_VALID)
    exit()





#generate prime p
nb_block=LOG_P//512
hexa=""

p=generate(seed_string,1,nb_block,4)




#invert iteration
hexa=""
for i in range(5 ,5 + nb_block):
    hexa=hexa + hashlib.sha512( bytearray(seed_string+(hex(i)[2:]),"ascii")).hexdigest()

thoinv_seed_test = (int(hexa,16) % p)
witness_num = int(witness,16)

flip = (2** (p.bit_length()>>1) ) -1

for i in range(ITERATIONS):
    witness_num=tho_inv(witness_num,p,flip)


if (thoinv_seed_test != witness_num):
    print(TEXT_NOT_VALID)
    exit()


print(TEXT_VALID)
