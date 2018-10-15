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

target_url = 'https://maker.ifttt.com/trigger/TestDone/with/key/cBDnuINFgFT0GIw6ajAAwB'
r = requests.post(target_url, data={"value1" : "[Coreutils Performance Test]"})