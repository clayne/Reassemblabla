#!/usr/bin/python
#-*- coding: utf-8 -*-

f = open('z','r+')
funcset = set()

while True:
	line = f.readline()
	if not line:
		break
	if '#' in line:
		line = line[:line.index('#')]
	line = line.strip()
	if 'MYSYM' not in line:
		l = line.split(' ')
		if len(l) >= 2:
			funcset.add(l[1])

for _ in funcset:
	print _
f.close()