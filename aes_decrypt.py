import sys
import collections
import itertools


BLOCK_SIZE = 16 # This is bytes

INV_SBOX = [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
			0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e,
			0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
			0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9,
			0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64,
			0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70,
			0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
			0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3,
			0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 
			0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2,
			0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 
			0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29,
			0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
			0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd,
			0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
			0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9,
			0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c,
			0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69,
			0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]

def get_expanded_key_from_file():
	""" Gets the expanded key from the file generated in encryption AES.
		RETURNS
		-------
			expanded_key as bytearray.
	"""
	file_content = open('cipher_key.txt', 'rb')
	data = file_content.read()
	file_content.close()
	return bytearray(data)


def get_file_ext_from_file():
	""" Get the file extension from the file generated in encryption AES.
		RETURNS
		-------
			file extension.
	"""
	file_content = open('cipher_ext.txt', 'r')
	ext = file_content.read()
	file_content.close()
	return ext


def get_blocks_from_file():
	""" Gets the ciphered blocks from the file generated in encryption AES.
		RETURNS
		-------
			ciphered blocks.
	"""
	file_content = open('cipher.txt', 'rb')
	blocks = []
	while True:
		data = bytearray(file_content.read(BLOCK_SIZE))
		if not data:
			break
		blocks.append(data)
	file_content.close()
	return blocks


def inv_shift_rows(state):
	""" Apply row shifting in a block of bytes (16 bytes)
	
		PARAMS
		------
			state: bytearray of 16 bytes.

		RETURNS
		-------
			bytearray of 16 bytes with shift applied.
	"""
	state = change_order_between_cols_rows(state)
	row_size = 4
	for i in range(row_size):
		d = collections.deque(state[i*row_size: i*row_size+row_size])
		d.rotate(i)
		state[i*row_size: i*row_size+row_size] = list(d)
	return change_order_between_cols_rows(state)


def inv_sub_bytes(state):
	"""Apply simple substitution byte by byte using operantions in GF(2^8)
		
		PARAMS
		------
			state: bytearray of 16 bytes.
		
		RETURNS
		-------
			bytearray of 16 bytes with substitution applied.
	"""
	return bytearray([INV_SBOX[x] for x in state])


def inv_add_round_key(state, key_block):
	""" Apply XOR between the key_block and state

		PARAMS
		------
			state: bytearray of 16 bytes.

		
		RETURNS
		-------
			state with XOR applied.
	"""
	return bytearray([state[i]^key_block[i] for i in range(16)])


def inv_mix_columns(state):
	""" Apply additions and multiplications in GF(2^8)
		
		PARAMS
		------
			state: bytearray of 16 bytes.


		RETURNS
		-------
			state with mixed columns
	"""
	for i in range(0, 16, 4):		
		a0 = state[i]
		a1 = state[i + 1]
		a2 = state[i + 2]
		a3 = state[i + 3]
		state[i] = gmul(14, a0)^gmul(11, a1)^gmul(13, a2)^gmul(9, a3)		
		state[i + 1] = gmul(9, a0)^gmul(14, a1)^gmul(11, a2)^gmul(13, a3)
		state[i + 2] = gmul(13, a0)^gmul(9, a1)^gmul(14, a2)^gmul(11, a3)
		state[i + 3] = gmul(11, a0)^gmul(13, a1)^gmul(9, a2)^gmul(14, a3)
	return state


def gmul(a, b):
	""" Apply multiplication in GF(2^m) using Shift-and-add method.
		
		PARAMS
		------
			a: Fist element for multiplication in the GF.
			b: Second element for the multiplication in the GF.

		RETURNS
		-------
			the result of multiplication.
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


def change_order_between_cols_rows(state):
	""" Change the order of the array between cols and rows of its matrix representation.

		PARAMS
		------
			state: state: bytearray of 16 bytes.

		RETURNS
		-------
			state with its cols and rows changed.
	"""
	result = [0x0 for _ in range(16)]
	j = 0
	for i in range(4):
		result[j] = state[i]; j+=1
		result[j] = state[i + (1 * 4)]; j+=1
		result[j] = state[i + (2 * 4)]; j+=1
		result[j] = state[i + (3 * 4)]; j+=1
	return bytearray(result)


def aes_decipher(block,  expanded_key):
	""" Apply AES decipher to a block

		PARAMS
		------
			block: bytearray of 16 bytes.
			expanded_key: key expanded in 176 bytes.

		RETURNS
		-------
			block encrypted with AES.
	"""
	state = block
	state = inv_add_round_key(state, expanded_key[160:176])

	for aes_round in range(9, 0, -1):	
		state = inv_shift_rows(state)
		state = inv_sub_bytes(state)
		state = inv_add_round_key(state, expanded_key[aes_round*16: aes_round*16+16])
		state = inv_mix_columns(state)
		

	state = inv_shift_rows(state)
	state = inv_sub_bytes(state)
	state = inv_add_round_key(state, expanded_key[0: 16])

	return state


def decipher_document_cbc(blocks, expanded_key):
	""" Apply AES cipher to decrypt the blocks obtained in the document.
		Uses Cipher Block Chaining

		PARAMS
		------
			blocks: List of blocks made of 16 bytes.

		RETURNS
		-------
			AES cipher.
	"""
	v = bytearray([0x0 for _ in range(16)])
	for i in range(len(blocks)):
		if i > 0:
			v = past_block
		past_block = [x for x in blocks[i]]	
		blocks[i] = aes_decipher(blocks[i], expanded_key)
		blocks[i] = bytearray([blocks[i][j]^v[j] for j in range(16)])
	return blocks


def print_hex(test):
	for t in test:
		print(hex(t), end=' ')
	print()


def write_blocks_in_file(blocks, ext, last_valid_index):
	""" Write ciphered blocks in a new file.
		PARAMS		
		------
			blocks: ciphered blocks of 16 bytes each.			
	"""
	file_blocks = open('result.' + ext, 'wb')
	for i in range(len(blocks)):
		if i < len(blocks) - 1:
			file_blocks.write(blocks[i])
		else:
			file_blocks.write(blocks[i][:last_valid_index])
	file_blocks.close()


def get_last_valid_byte_index(block):
	""" Get the index of the last byte 01
		RETURNS
		-------
			index of last byte 01.
	"""
	for i in range(BLOCK_SIZE):
		if block[i] == 0x01:
			return i
	return 0


def main(filename):
	"""file_content = open(filename, 'rb')
	data = file_content.read()
	print_hex(data)"""
	ext = get_file_ext_from_file()
	blocks = get_blocks_from_file()
	for b in blocks:
		print_hex(b)
	print()
	expanded_key = get_expanded_key_from_file()
	blocks = decipher_document_cbc(blocks, expanded_key)
	write_blocks_in_file(blocks, ext, get_last_valid_byte_index(blocks[-1]))

	

if __name__ == '__main__':
	if len(sys.argv) < 2:
		sys.exit('Usage: %s: [filename]' % sys.argv[0])
	else:
		main(sys.argv[1])