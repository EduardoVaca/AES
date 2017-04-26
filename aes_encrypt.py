"""
AES Cipher implementation
Eduardo Vaca
A01207563
Fernando Lobato
Course: Information Security
"""
import sys
import os
import collections

BLOCK_SIZE = 16 # This is bytes

SBOX = 	[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
            0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
            0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
            0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
            0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
            0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
            0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
            0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
            0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
            0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
            0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
            0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
            0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
            0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
            0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
            0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
            0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
            0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
            0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
            0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
            0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
            0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
            0x54, 0xbb, 0x16]


RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

def get_blocks_from_file(filename):
	"""Generate 16 byte blocks from file.
	If the last block is not of len 16 then 0x01, 0x00, 0x00... 0x00 is added.
	Params:
		- filename: Name of the file to be read
	Returns:
		- List of bytearrays representing each block.
	"""
	file_content = open(filename, 'rb')
	blocks = []
	while True:
		data = bytearray(file_content.read(BLOCK_SIZE))
		if not data:
			break
		blocks.append(data)
	if len(blocks[-1]) < BLOCK_SIZE:
		blocks[-1] += bytearray([1] + [0 for _ in range(BLOCK_SIZE - len(blocks[-1]) - 1)])
	else:		
		blocks.append(bytearray([1] + [0 for _ in range(BLOCK_SIZE - 1)]))
	return blocks


def sub_bytes(state):
	"""Apply simple substitution byte by byte using operantions in GF(2^8)
	Params:
		- state: bytearray of 16 bytes.
	Returns:
		- bytearray of 16 bytes with substitution applied.
	"""
	return bytearray([SBOX[x] for x in state])


def shift_rows(state):
	"""Apply row shifting in a block of bytes (16 bytes)
	Params:
		- state: bytearray of 16 bytes.
	Returns:
		- bytearray of 16 bytes with shift applied.
	"""	
	row_size = 4
	for i in range(row_size):
		d = collections.deque(state[i*row_size: i*row_size+row_size])
		d.rotate(i)
		state[i*row_size: i*row_size+row_size] = list(d)
	return state


def mix_columns(state):
	"""Apply additions and multiplications in GF(2^8)
	Params:
		- state: bytearray of 16 bytes.
	"""
	for i in range(0, 16, 4):
		a0 = state[i]
		a1 = state[i + 1]
		a2 = state[i + 2]
		a3 = state[i + 3]
		state[i] = gmul(2, a0)^gmul(3, a1)^a2^a3
		state[i + 1] = gmul(2, a1)^gmul(3, a2)^a0^a3
		state[i + 2] = gmul(2, a2)^gmul(3, a3)^a0^a1
		state[i + 3] = gmul(2, a3)^gmul(3, a0)^a1^a2
	return state


def gmul(a, b):
	"""Apply multiplication in GF(2^m) using Shift-and-add method.
	Params:
		- a: Fist element for multiplication in the GF.
		- b: Second element for the multiplication in the GF.
	Returns:
		- The result of multiplication.
	"""
	c = 0
	if (a & 1) == 1:
		c = b

	for _ in range(1, 8):
		hi_bit = (b & 0x80)
		b <<= 1
		b &= 0xff # Get rid of the most significant bit outside 2 bytes.
		if hi_bit == 0x80:
			b ^= 0x1b
		a >>= 1
		if (a & 1) == 1:
			c ^= b
	return c

def rotate(sub_key):
	""" Rotates the first column of a block for the expanded key
		
		PARAMS
		------
			sub_key: list with bytes to rotate

		RETURNS
		-------
			rotated list of bytes

	"""
	temp = sub_key[:]
	
	sub_key[0] = temp[1]
	sub_key[1] = temp[2]
	sub_key[2] = temp[3]
	sub_key[3] = temp[0]

	return sub_key

def expand_key(key):
	""" Expands a 16 byte key into a 176 byte key.
		
		PARAMS
		------
			key: a 16 byte random key in hex representation

		RETURNS
		-------
			176 byte key in hex representation.
	"""
	expanded_key = []
	[expanded_key.append(byte) for byte in key]
	temp = bytearray(4)
	
	i = 16
	r_const = 0

	while(i < 176):

		temp = [expanded_key[a + i - 4] for a in range(4)]

		if i % 16 == 0:
			temp = rotate(temp)
			
			for a in range(4):
				temp[a] = SBOX[temp[a]]
			
			temp[0] = temp[0] ^ RCON[r_const]
	
			r_const += 1

		for j in range(4):
			val = expanded_key[i - 16] ^ temp[j]
			expanded_key.append(val)
			i += 1

	return expanded_key


def generate_key(num_bytes=16, int_representation=False):
	""" Generates a random key of the number of bytes specified.

		PARAMS:
		-------
			- num_bytes: size of key in bytes (default = 16 which
			is 128 bits.)
			- int_representation: boolean value if the key should
			be returned in byte or int representation. default is
			False.

		RETURNS:
		--------
			- random_key: key in byte representation. If int_representation
			is set to True, returns the key as integer value.
	"""
	random_key = os.urandom(num_bytes)
	
	if int_representation:
		random_key = int.from_bytes(random_key, byteorder='big')
	
	return random_key

def main(filename):
	""" Generate Key
	"""
	random_key = generate_key()
	# random_key = b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c'
	expanded_key = expand_key(random_key) 

	blocks = get_blocks_from_file(filename)

	print('Last block: {}'.format(blocks[-1]))
	print('Subbytes: {}'.format(sub_bytes(blocks[-1])))	
	print('Shift rows: {}'.format(shift_rows(blocks[-1])))	
	test = [0x87, 0x6e, 0x46, 0xa6, 0xf2, 0x4c, 0xe7, 0x8c, 0x4d, 0x90, 0x4a, 0xd8, 0x97, 0xec, 0xc3, 0x95]
	test = mix_columns(test)
	print('Applying mixColumns to:')
	print(test)
	for e in test:
		print(format(e, '02x'), end=' ')
	print()


if __name__ == '__main__':
	if len(sys.argv) < 2:
		sys.exit('Usage: %s: [filename]' % sys.argv[0])
	else:
		main(sys.argv[1])