import sys, subprocess
import math
from hashlib import sha1

# Globals and constants
######################

# Count num interactions
count = 1

######################

# TODO: Work out why hash label test is failing in eme decode, try and test a few more things
def interact( G ) :
	# Send label, G to attack target.
	target_in.write( "%s\n"  %  ( "%X" % l ) ); target_in.flush()
	target_in.write( "%s\n" % ( "%X" % G ).zfill(256) ); target_in.flush()

	# Receive error code from attack target.
	err = int( target_out.readline().strip() )

	global count
	count += 1

	return err

# Returns f^e * c (mod n)
def rsaExp( f ):
	return ( pow( f, e, N ) * c ) % N


# step 1 of Manger attack
def step1():
	print '******\nIn Step 1'
	f1 = 2
	query = rsaExp( f1 )
	response = interact( query )

	while response != 1:
		f1 *= 2
		query = rsaExp( f1 )
		response = interact( query )

	# if response != 1:
	# 	print '\n***\nError: could not complete step 1 correctly. Errcode', response, '\n***\n'
	# 	sys.exit()

	return f1

def step2( f1 ):
	print 'In Step 2'
	f1_half = f1 / 2
	f2 = ( ( N + B ) / B ) * f1_half

	query = rsaExp( f2 )
	response = interact( query )

	while response != 2:
		f2 += f1_half
		query = rsaExp( f2 )
		response = interact( query )

	if response != 2:
		print '*\nError: could not complete step 2 correctly. Errcode', response, '*\n'
		sys.exit()

	return f2

def step3( f2 ):
	print 'In Step 3'
	m_min = ( N + f2 - 1 ) / f2
	m_max = ( N + B ) / f2
	f3 = 0
	while m_min != m_max:
		f_tmp = ( 2 * B ) / ( m_max - m_min )
		i = ( f_tmp * m_min ) / N

		f3 =  ( ( i * N ) + m_min - 1 ) / m_min
		query = rsaExp( f3 )
		response = interact( query )

		if response == 1:
			# print 'Step 3; response code 1'
			m_min = ( ( i * N ) + B + f3 - 1 ) / f3

		elif response == 2:
			# print 'Step 3; response code 2'
			m_max = ( ( i * N ) + B ) / f3

		if m_min > m_max:
			print '\n***\nStep 3 Error: could not find correct response. Errcode', response, '\n***\n'
			sys.exit()


	# print hex(m_min)
	# print m_min
	# Check if recovered OAEP message is correct
	c_vrfy = pow( m_min, e, N )
	if c_vrfy == c:
		print '\n***\nEME-encoded message recovered successfully!'
		print 'message: ', ( "%X" % m_min ), '\n***\n'

	return ( "%X" % m_min ).zfill(256)

def EME_decode( EM ):
	print 'In EME_decode'
	hLen = 20	# sha1 output is 20 octets long
	lhash = sha1( ( "%X" % l ) ).hexdigest()

	Y, maskedSeed, maskedDB = EM[:2], EM[2:2+2*hLen], EM[42:]

	seedMask = MGF( maskedDB, 2*hLen)

	seed = int( maskedSeed, 16 ) ^ int( seedMask, 16 )
	seed = ( "%X" % seed )

	dbMask = MGF( seed, k - 2*hLen - 2 )

	DB = int( maskedDB, 16 ) ^ int( dbMask, 16 )
	DB = ( "%X" % DB )

	sep_index = DB.find('01', 2*hLen)
	if sep_index == -1:
		print 'Error, 0x01 not found in DB in EME-decode'
		sys.exit()
	lhash_d, PS, Ox01, M = DB[:2*hLen], DB[2*hLen:sep_index], DB[sep_index:sep_index+2:], DB[sep_index+2:]

	# if 	int( lhash_d, 16 ) != int( lhash, 16 ):
	# 	print 'Error, hash labels not equal in EME-decode'
	# 	print lhash, '\n'
	# 	print lhash_d, '\n'
	# 	sys.exit()
	if int( Y, 16 ) != 0:
		print 'Error, Y not equal to 0 in EME-decode'
		sys.exit()

	return M

def I2OSP( x, xLen ):

	if x >= 256 ** xLen:
		print 'Error: integer too large'
		sys.exit()

	result = ( "%X" % x )

	return result.zfill( 2 * xLen )

def MGF( Z, zLen ):
	hLen = 20	# sha1 output is 20 octets long

	if zLen > ( 2 ** 32 ) * hLen:
		print 'Error: mask too long'
		sys.exit()

	T = ''

	for i in range( zLen / hLen ):
		C = I2OSP( i, 4 )
		# print str(Z + C).decode('hex'), '\n\n'
		T += sha1( (Z + C).decode('hex') ).hexdigest()

	return T[:2*zLen]

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

	N = long(parameters[0],16)
	e = long(parameters[1],16)
	l = long(parameters[2],16)
	# l = parameters[2]
	c = long(parameters[3],16)

	k = len( parameters[0] ) / 2
	B = 2 ** (8 * (k-1))

	# Execute a function representing the attacker.
	f1 = step1()
	f2 = step2( f1 )
	em = step3( f2 )
	m = EME_decode( em )

	# c_test = pow(long(m,16), e, N)
	# print 'C test: ', c_test
	# print 'Actual C: ', c

	print 'Message recovered: ', m, '\n'

	print 'Num interactions: ', count
