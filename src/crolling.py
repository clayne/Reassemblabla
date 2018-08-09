#!/usr/bin/python
#-*- coding: utf-8 -*-
import requests
import re
# https://c9x.me/x86/html/file_module_x86_id_15.html
def find_nth(haystack, needle, n):
    start = haystack.find(needle)
    while start >= 0 and n > 1:
        start = haystack.find(needle, start+len(needle))
        n -= 1
    return start

def get_html(url):
   _html = ""
   resp = requests.get(url)
   if resp.status_code == 200:
      _html = resp.text
      i1 = find_nth(_html,'<h1>',2)
      i2 = find_nth(_html,'</h1>',2)
      name = _html[i1 + len('<h1>'):i2]
   return _html, name


# case 2. regex
'''
p = re.compile('/'+'[0-7]') # /digit

exist = []
for i in range(1,333): 
	url = 'https://c9x.me/x86/html/file_module_x86_id_{}.html'.format(i)
	text, name = get_html(url)
	if len(p.findall(text)) > 0: 
		print name + ' [O]'
		exist.append(i)
		count = text.count('<code>')
		for i in xrange(count):
			start = text.index('<code>') + len('<code>')
			end   = text.index('</code>')
			line = text[start:end]
			text = text[end + len('</code>'):]
			if len(p.findall(line)) > 0:
				print " "+line
	else:
		"no" 
print exist
'''

# case 1. simple string 
exist = []
for i in range(1,333): 
	url = 'https://c9x.me/x86/html/file_module_x86_id_{}.html'.format(i)
	text, name = get_html(url)
	if '/r' in text:
		print name + ' [O]'
		exist.append(i)
		count = text.count('<code>')
		for i in xrange(count):
			start = text.index('<code>') + len('<code>')
			end   = text.index('</code>')
			line = text[start:end]
			text = text[end + len('</code>'):]
			if '/r' in line:
				print " "+line
	else:
		"no" 
print exist