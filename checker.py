import argparse
import hashlib
import random
import subprocess
import numpy as np

TEXT_NOT_VALID="Verification FAILLURE, values does not correspond"
TEXT_VALID="Verification SUCCESS, all values are good"
ITERATIONS=155000
LOG_P=2048
TIMEDITERATIONS=300000000000
KLENGTH=256

parser = argparse.ArgumentParser()
parser.add_argument('path_to_tweetfile')
parser.add_argument('path_to_valuefile')
parser.add_argument('path_to_imagefile')
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
        split=line.split(' : ')
        if split[0] == "Random Number":
            number=split[1].lower()
        elif split[0] == "Witness":
            witness=split[1].lower()
        elif split[0] == "Timed Commitment":
            commitment=split[1].lower()
        elif split[0] == "COMMIT_N":
            COMMIT_N=split[1].lower()
        elif split[0] == "COMMIT_P":
            COMMIT_P=split[1].lower()
        elif split[0] == "COMMIT_Q":
            COMMIT_Q=split[1].lower()


if( number==0 or witness==0 or commitment==0 or COMMIT_N==0 or COMMIT_P==0 or COMMIT_Q==0):
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
if(COMMIT_P[-1]=='\n'):
    COMMIT_P=COMMIT_P[:-1]
if(COMMIT_Q[-1]=='\n'):
    COMMIT_Q=COMMIT_Q[:-1]

comp=int(COMMIT_P,16)
comq=int(COMMIT_Q,16)
comn=int(COMMIT_N,16)

#check commit
if( (comp*comq) != comn ):
    print(TEXT_NOT_VALID)
    exit()


#using commit to get image

kcomm=pow(int(commitment,16), pow(2,TIMEDITERATIONS,(comp-1)*(comq-1)) ,comn)
kpass_num = kcomm % (2**KLENGTH)
kpass=np.base_repr(kpass_num,36).lower()

subprocess.run("openssl aes-256-cbc -d -in "+args.path_to_imagefile+" -out "+args.path_to_imagefile+".decrypt -pass pass:"+kpass,shell=True,check=True)



#creation of seed which is SHA512( SHA512(tweetfile) || SHA512(imagefile) )

#SHA512(tweetfile)
with open(args.path_to_tweetfile,mode='rb') as tweetfile:
    S0=hashlib.sha512(tweetfile.read()).hexdigest()

#SHA512(imagefile)
with open(args.path_to_imagefile+".decrypt",mode='rb') as imagefile:
    S1=hashlib.sha512(imagefile.read()).hexdigest()


S=S0+S1
seed_string= hashlib.sha512( bytearray(S,"ascii") ).hexdigest()

#check seed, commitment
#if( hashlib.sha512( bytearray(seed_string,"ascii") ).hexdigest() != commitment):
#    print(TEXT_NOT_VALID)
#    exit()


#check number, witness
if( hashlib.sha512( bytearray(witness,"ascii") ).hexdigest() != number ):
    print(TEXT_NOT_VALID)
    exit()


################################## function def #######################

# Miller-Rabin primality test copy from check for eliptic  curve
def is_probable_prime(n, k = 25):

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
    s = 0
    d = n - 1
    while True:
        quotient, remainder = divmod(d, 2)
        if remainder == 1:
            break
        s += 1
        d = quotient

    # test the base a to see if it is a witness for the compositeness of n
    def try_composite(a):
        if pow(a, d, n) == 1:
            return False
        for i in range(s):
            if pow(a, 2**i * d, n) == n-1:
                return False
        return True # n is definitely composite

    for i in range(k):
        a = random.randrange(2, n)
        if try_composite(a):
            return False

    return True # no base tested showed n as composite



def tho_inv(n,primemod):
    ret=0
    if( (n%2) == 0):
        ret = pow(n,2,primemod)
    else:
        ret = primemod - pow(n,2,primemod) #((n*n) % primemod)

    flip = (2** (primemod.bit_length()>>1) ) -1

    ret = (ret ^ flip)

    if( (ret >= primemod) or (ret == 0) ):
        ret = (ret ^ flip)

    return ret


######################################################################



#generate prime p
nb_block=LOG_P//512
hexa=""


for i in range(nb_block):
    hexa=hexa+hashlib.sha512(  bytearray(seed_string+"prime"+( chr( ord('0') +i  ) ),"ascii")  ).hexdigest()

p=int(hexa,16)


extract_msb= 2**(LOG_P-1)
if( (p & extract_msb) == 0):
    p=p+extract_msb

if(p%2 == 0):
    p=p+1
else:
    p=p+2

while ( (p%4 !=3) or not(is_probable_prime(p)) ):
    p=p+2


#invert iteration
hexa=""
for i in range(nb_block):
    hexa=hexa+hashlib.sha512(  bytearray(seed_string+"seed"+( chr( ord('0') +i  ) ),"ascii")  ).hexdigest()

thoinv_seed_test = (int(hexa,16) % p)
witness_num = int(witness,16)


for i in range(ITERATIONS):
    witness_num=tho_inv(witness_num,p)


if (thoinv_seed_test != witness_num):
    print(TEXT_NOT_VALID)
    exit()


print(TEXT_VALID)
