# bufferoverflow.py
A Python script used to assist with the binary exploitation of stack-based Buffer Overflow vulnerabilities in network-based applications.

## Description
```
usage: bufferoverflow.py [-h] mode ...

A Python script used to assist with the binary exploitation of stack-based Buffer Overflow vulnerabilities in network-based applications.

positional arguments:
  mode        Use <mode> -h to list addtional required and optional arguments for the selected mode.
    spiking   Spike arguments to parameters to identify vulnerable inputs.
    offset    Identify the offset of the EIP by injecting a unique payload into a vulnerable parameter.
    eip       Validate that you control EIP by overwritting the EIP to an expected value.
    badchars  Submit a string of hexadecimal characters against the application to identify 'Bad Characters'.
    exploit   Exploit a vulnerable application with a stack-based Buffer Overflow to execute shellcode.

options:
  -h, --help  show this help message and exit
```
