import sys


def print_hex(test):
	for t in test:
		print(hex(t), end=' ')
	print()

def main(filename):
	file_content = open(filename, 'rb')
	data = file_content.read()
	print_hex(data)

if __name__ == '__main__':
	if len(sys.argv) < 2:
		sys.exit('Usage: %s: [filename]' % sys.argv[0])
	else:
		main(sys.argv[1])