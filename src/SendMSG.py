#!/usr/bin/python
#-*- coding: utf-8 -*-
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
	bot.sendMessage(chat_id = chat_id, text="[지원봇] " + msgstr)
 

try:
	SendTelegram("Telegram library loaded")
except:
	print "telegram error"