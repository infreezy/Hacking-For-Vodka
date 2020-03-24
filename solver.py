#!/usr/bin/python3

from pwn import *
import re
flagP= re.compile(r'watevr{.*}')

alnum = ''

for i in range(90):
	p = process(f'echo {letter} | ltrace ./vodka',shell=True)
	result = p.recvall().decode()
	match = re.findall(r'(strcmp\([\"\\n]*, "(.+)"\))',result) 

	# Regex sucks so I had to adapt ¯\_(ツ)_/¯
	if len(match)>1:case=len(match)-1
	else:case=0
	alnum += match[case][1]


flag = flagP.findall(alnum)[0]
print(flag)
p = process(f'echo {flag} >> flag.txt',shell=True)
