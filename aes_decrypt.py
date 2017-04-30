import sys
import collections


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


def print_hex(test):
	for t in test:
		print(hex(t), end=' ')
	print()


def main(filename):
	"""file_content = open(filename, 'rb')
	data = file_content.read()
	print_hex(data)"""
	test = bytearray([0xe2, 0x57, 0x0f, 0x00, 0x41, 0xb4, 0x15, 0x04, 0xd0, 0x0e, 0x94, 0x6a, 0x56, 0x54, 0x0b, 0x92])
	print('TEXT')
	print_hex(test)
	print('After inv shift rows')
	test = inv_shift_rows(test)
	print_hex(test)

if __name__ == '__main__':
	if len(sys.argv) < 2:
		sys.exit('Usage: %s: [filename]' % sys.argv[0])
	else:
		main(sys.argv[1])