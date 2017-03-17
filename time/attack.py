import sys, subprocess
import math, random
import time
# import gmpy2
# from gmpy2 import mpz
# from gmpy2 import unpack


# Globals and constants
######################

# Count num interactions
count = 1

# Total num attacks
numAttacks = 20000

wordSize = 64
numWords = 16
b = 2 ** wordSize
numBits = 1024
global numLimbs
global omega
global rhoSq

######################

########## Montgomery stuff ############

def getNumLimbs( val ):
	return int(math.ceil(math.log( val, b )))

def unpackLimbs( x, b ):
	result = []
	if x == 0:
		return [0]
	while x:
		x, temp = divmod(x, b)
		result.append(temp)
	result.extend([0]*(numLimbs-len(result)))
	return result

def montRhoSq():

	# print numLimbs * wordSize
	t = 1
	for i in range (int(2 * numLimbs * wordSize)):
		t += t
		if t >= N:
			t -= N

	return t

def montOmega():

	omega = 1

	for i in range(0, wordSize-1):
		omega = (omega * omega * N) % b
		# if omega >= b:
		# 	omega -= b

	return -omega % b

def montMul( x, y ):
	redFlag = False
	x_limbs = unpackLimbs( x, b )
	y_limbs = unpackLimbs( y, b )
	# y_limbs.extend([0]*(numLimbs-len(y_limbs)))

	r = 0
	x0 = x_limbs[0]

	for i in range( numLimbs ):
		r_limbs = unpackLimbs( r, b )
		r0 = r_limbs[0]
		yi = y_limbs[i]
		u = ((r0 + yi * x0) * omega) % b

		r = ( r + yi * x + u * N ) / b

	if r >= N:
		redFlag = True
		r -= N
	return r, redFlag

def montExp( m, x, y ):		# x ** y

	# x_mont = montMul( x, rhoSq )[0]

	# for i in range(0, len(y)):
	# 	m = montMul( m, m )[0]
	#
	# 	if y[i] == '1':
	# 		m = montMul( m, x )[0]
	#
	# m_temp = montMul( m, m )[0]

	m_temp = m

	# If key bit is 1
	m_temp = montMul( m_temp, x )[0]
	m1, flag1 = montMul( m_temp, m_temp )

	# If key bit is 0
	m0, flag0 = montMul( m, m )

	return m0, flag0, m1, flag1


########################################

######### Attack the target stuff ########

def interact( G ) :
	times = []

	for guess in G:
		# Send label, G to attack target.
		target_in.write( "%X\n"  %  guess ); target_in.flush()

		# Receive error code from attack target.
		times.append(int( target_out.readline().strip() ))
		target_out.readline().strip()

		global count
		count += 1

	return times

def genCiphertexts():
	ciphertexts = []
	for i in range(numAttacks):
		ctext = random.getrandbits(1024)
		while ctext > N:		# ensure less than N
			ctext = random.getrandbits(1024)
		ciphertexts.append(ctext)

	return ciphertexts


def attack( c_guesses ):

	print '*** Starting attack'
	# Secret key first bit is 1
	secretKey = '1'

	# Get time taken by guesses to attack target
	times = interact( c_guesses )

	mm_cguesses = []		# Build list of the exponent guesses in montgomery form
	mm_mvals = []		# Build list of the m values for binexp in montgomery form
	mm_one = montMul(1, rhoSq)[0]
	mm_one_sq = montMul( mm_one, mm_one )[0]

	# Perform initial steps of binary exponentiation
	for i, guess in enumerate(c_guesses):
		mm_guess = montMul( guess, rhoSq )[0]
		mm_cguesses.append( mm_guess )
		mm_mvals.append(mm_one_sq)
		mm_mvals[i] = montMul( mm_mvals[i], mm_cguesses[i] )[0]
		mm_mvals[i] = montMul( mm_mvals[i], mm_mvals[i] )[0]

	iteration = 1
	while iteration < 64:
		print '\nIteration ', iteration, '\n'

		val0Red = []
		val0noRed = []
		val1Red = []
		val1noRed = []
		new_mm_mvals1 = []
		new_mm_mvals0 = []


		start = time.time()
		for i in range(numAttacks):
			m0, flag0, m1, flag1 = montExp( mm_mvals[i], mm_cguesses[i], secretKey )
			if flag1:
				val1Red.append(times[i])
			else:
				val1noRed.append(times[i])
			if flag0:
				val0Red.append(times[i])
			else:
				val0noRed.append(times[i])

			new_mm_mvals0.append(m0)
			new_mm_mvals1.append(m1)
		print 'Time taken on attack loop: ', time.time() - start


		# Get differences between averages
		val0RedAvg = sum(val0Red) / float(len(val0Red))
		val0noRedAvg = sum(val0noRed) / float(len(val0noRed))
		diff1 = abs(val0RedAvg - val0noRedAvg)


		val1RedAvg = sum(val1Red) / float(len(val1Red))
		val1noRedAvg = sum(val1noRed) / float(len(val1noRed))
		diff2 = abs(val1RedAvg - val1noRedAvg)

		print '* Avg time diff for Hi = 0: ', diff1
		print '* Avg time diff for Hi = 1: ', diff2

		if abs(diff1 - diff2) < 8:
			print '** Time diff. too small, possible error; re-computing with new ctexts'
			c_guesses = genCiphertexts()
			mm_cguesses = []		# Build list of the exponent guesses in montgomery form
			for guess in c_guesses:
				mm_guess = montMul( guess, rhoSq )[0]
				mm_cguesses.append( mm_guess )
			continue
		elif diff1 > diff2:
			secretKey += '0'
			iteration += 1
			mm_mvals = new_mm_mvals0
		else:
			secretKey += '1'
			iteration += 1
			mm_mvals = new_mm_mvals1

		print 'Current secretKey: ', secretKey

	return secretKey

#################################

if ( __name__ == "__main__" ) :
	# Produce a sub-process representing the attack target.
	target = subprocess.Popen( args   = sys.argv[ 1 ],
								stdout = subprocess.PIPE,
								stdin  = subprocess.PIPE )

	# Construct handles to attack target standard input and output.
	target_out = target.stdout
	target_in  = target.stdin


	# Retrieve parameters from conf
	parameters = []

	for line in open(sys.argv[2]):
		parameters.append(line)

	N = long(parameters[0], 16)
	e = int(parameters[1], 16)

	numLimbs = getNumLimbs( N )
	# numLimbs = 3

	rhoSq = montRhoSq()
	omega  = montOmega()
	# print 'rho', rhoSq
	# print 'omega', omega

	# Generate random ciphertexts
	ciphertexts = genCiphertexts()

	key = attack( ciphertexts )

	# Generate a plaintext from the target
	test_message = random.getrandbits(1024)
	while test_message > N:		# ensure less than N
		test_message = random.getrandbits(1024)

	test_ctxt = pow( test_message, e, N )
	target_in.write( "%X\n"  %  test_ctxt ); target_in.flush()
	target_out.readline().strip()		# Ignore time output
	test_message_out = int(target_out.readline().strip(), 16)

	# ### -- Testing stuff --- ### #

	# rhoSq = 1000 ** 2
	# omega = 997

	# test3_mm = montMul( 1000, rhoSq )[0]
	# test3 = montMul( test3_mm, 1 )[0]
	# print 'mont form of x: ', test3_mm_x
	# print 'mont form of y: ', test3_mm_y
	# # test_one = montMul( 1, rhoSq )[0]
	# test3 = montMul( 123, 456, 667, 10 )[0]
	# print test3
	# x = long('6553311D0BFD02B98DE2B30A4BE05ABA1091FB8A6B2E18461ACDADCA76E452229FA8610519C795C8793F45035A70346D30A5956132594FDAA26371B4226566744AE72A084C4FAD8F4CA65FBD0C76AD2D49E15F167E082A4234A551C5790FBCC3539933DC092344AF7EB25AEB74260EEFFB6E3CD3171D6E1D2F070745210DBED9',16)
	# y = '1010101010111111110101010101111111101010101011111110100010101010'
	#
	# print montExp(x,y)

	# key = '1110001001100101100100011011101000101011010110011001101101010001'
	# test_decrypt =  pow( test_ctxt, int( key, 2 ), N )
	# print test_message_out
	# print test_decrypt

	# ####################################### #


	success = False
	while success == False:
		print len(key)
		if test_message_out == pow( test_ctxt, int( key[:-1] + '1', 2 ), N ):
			key = key[:-1]
			key += '1'
			success = True
			break
		elif test_message_out == pow( test_ctxt, int( key[:-1] + '0', 2 ), N ):
			key = key[:-1]
			key += '0'
			success = True
			break
		else:
			print 'Did not recover key successfully'
			print "%X" % long(key, 2)
			ciphertexts = genCiphertexts()
			key = attack( ciphertexts )
			print 'Num interations: ', count


	print "Key is %X" % long(key, 2)
	print 'Num interations: ', count
