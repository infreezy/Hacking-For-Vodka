#!/usr/bin/python3

from pwn import *
import re
flagP= re.compile(r'watevr{.*}')

alnum = ''

for i in range(90):
	p = process(f'echo {letter} | ltrace ./vodka',shell=True)
	result = p.recvall().decode()
	match = re.findall(r'(strcmp\([\"\\n]*, "(.+)"\))',result) 
	try : 
		# Regex sucks so I had to adapt ¯\_(ツ)_/¯
		if len(match)>1:
			case=len(match)-1
		else:
			case=0
		alnum += match[case][1]
	except Exception:
		print('why the fuck is this happening bruv')

flag = flagP.findall(alnum)[0]
process(f'echo {flag} >> flag.txt',shell=True)
