"""
AES Cipher implementation
Eduardo Vaca
A01207563
Fernando Lobato
Course: Information Security
"""
import sys

BLOCK_SIZE = 16 # This is bytes

def read_file(filename):
	file_content = open(filename, 'rb')
	while True:
		data = file_content.read(BLOCK_SIZE)
		if not data:
			break
		print(len(data))
			

def main(filename):
	read_file(filename)

if __name__ == '__main__':
	if len(sys.argv) < 2:
		sys.exit('Usage: %s: [filename]' % sys.argv[0])
	else:
		main(sys.argv[1])