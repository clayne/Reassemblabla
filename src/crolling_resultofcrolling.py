#!/usr/bin/python
#-*- coding: utf-8 -*-
import requests
import re

f = open('remove.txt')

while True:
	line = f.readline()
	if not line: break
	if '[O]' in line:
		"do nothing"
	else:
		print str(line[:-1]).lower()