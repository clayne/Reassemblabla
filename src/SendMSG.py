#!/usr/bin/python
#-*- coding: utf-8 -*-
from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection
import sys
import os
import subprocess
import re
from optparse import OptionParser
import binascii 
from global_variables import *
import requests
import telegram

def SendMessage(msgstr):
	target_url = 'https://maker.ifttt.com/trigger/TestDone/with/key/cBDnuINFgFT0GIw6ajAAwB'
	r = requests.post(target_url, data={"value1" : msgstr})

def SendTelegram(msgstr):
	my_token = '686723033:AAGcsOMwDZAjsRwrsSK2gQRUNiHpn3hZQSw' # BotFather가 준 HTTP API입력
	bot = telegram.Bot(token = my_token)   # bot 선언.
	updates = bot.getUpdates()  # 업데이트
	chat_id = bot.getUpdates()[-1].message.chat.id
	bot.sendMessage(chat_id = chat_id, text=msgstr)

SendTelegram("잘되냐?")