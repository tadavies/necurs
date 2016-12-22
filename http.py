import json
import base64
import struct
import socket
import datetime
from binascii import hexlify

ENUM_LIST = {
	0x4008cdaf91d42640 : "p2plist",
	0xf7485554ea9dfc44 : "commandBlock",
	0x49340b1574c451a4 : "c2List",
	0xd2b3cb6d2757a62c : "sleepTime",
	0x3cae696275cd12c4 : "sha",
	0x2e9bca0a3ef0dd18 : "version",
	0x4768130ffd8b1660 : "dgaSeed",
	0x50a29bce1ea74ddc : "timeDif",
	0x72d605c1bc4beb60 : "rand_mwc2",
	0x2b007dfb08e94360 : "unkVar",
	0xb2d7bf31e16a4860 : "rand_mwc",
	0x5b4ab05e9748dd18 : "osVersion",
	0x5774f028d11237ac : "langID",
	0xa6f73a722b8d2144 : "pipeSatus",
	0x9924541302c75f90 : "p2pPortNo",
	0x543591d7e21cfc94 : "ipCrc32",
	0x4cb5823b4ecfd1dc : "time",
	0xc3759a8411bcfb90 : "ip",
	0xedf5644920ade5d4 : "service",
	0xd8cc549b8fb48978 : "admin",
	0x0a8aa0eec8402790 : "is64bit"
}


rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))
ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

class commandBlock():
	def __init__(self, data=None):
		if data != None:
			self.parse(data)
	def parse(self, data):
		if data[0] != 0x2b:
			x = 0
			while x < len(data)-4:
				length = struct.unpack('<I', data[x:x+4])[0]
				if length > 0:
					block = data[x:x+length]
					blockHeader = block[4:0x2a]
					blockData = block[0x2a:]
					print base64.b64encode(blockHeader)
					x = x + length
				else:
					x = x + 4

class header():
	def __init__(self, data=None):
		self.dict = None
		if data != None:
			self.raw = data
			self.dict = self.parse(data)

	def parse(self, data):
		if len(data) == 0x1a:
			header = struct.unpack('<QQQBB', data)
			return {
				"rand": header[0],
				"botid": header[1],
				"time": header[2],
				"command": header[3],
				"flag": header[4]
			}

	def convertTime(self, time):
		return datetime.datetime.fromtimestamp(time/1000-2208988800).strftime('%Y/%m/%d %H:%M:%S')

class payload():
	def __init__(self, data=None):
		self.dict = None
		if data != None:
			self.raw = data
			self.dict = self.parsePayload(data)

	def parsePayload(self, data):
		payload = {}
		x = 0
		while x < len(data)-9:
			content = None
			s = struct.unpack('<BQ', data[x:x+9])

			if s[0] == 0:
				length = struct.unpack('<I', data[x+9:x+13])[0]
				content = base64.b64encode(data[x+13:x+13+length])
				x = x + 13 + length
			elif s[0] == 1:
				content = struct.unpack('<I', data[x+9:x+13])[0]
				x = x + 13
			elif s[0] == 2:
				content = struct.unpack('<Q', data[x+9:x+17])[0]
				x = x + 17
			elif s[0] == 4:
				length = struct.unpack('<H', data[x+9:x+11])[0]
				content = data[x+11:x+11+length+1]
				x = x + 11 + length + 1
			elif s[0] == 5:
				content = base64.b64encode(data[x+9:x+29])
				x = x + 29
			else:
				print "Unhandled Type", s, "data remaining = ", len(data) - x
				break

			if s[1] in ENUM_LIST:
				payload[ENUM_LIST[s[1]]] = content
			else:
				print "Unhandled Enum = ", hex(s[1]), "data remaining = ", len(data) - x
				continue
		return payload

class httpMsg():
	def __init__(self):
		self.header = None
		self.payload = None
		self.baseSeed = 0x5ba4fa79

	def setBaseSeed(self, seed):
		self.baseSeed = seed

	def decode(self, data, key): 
		ret = ""
		for byte in data:
			ret += chr(ord(byte) ^ (key & 0xff))
			key = key + ((ror(key,13,32)) ^ ((key+ord(byte)*4)*2)) & 0xffffffff
		return ret, key

	def encode(self, data, key):
		ret = ''
		for x in range(0, len(data)):
			b = (ord(data[x]) ^ (key & 0xff))
			key = key + ((ror(key,13,32)) ^ ((key+b*4)*2)) & 0xffffffff
			ret += chr(b)
		return ret, key

	def dump(self):
		if self.header != None:
			h = self.header.dict
		else:
			h = None
		if self.payload != None:
			p = self.payload
		else:
			p = None
		return {
			"header" : h,
			"payload" : p
		}

class clientMsg(httpMsg):
	def parse(self, data):
		if data != None and len(data) > 0x1a:
			# Key = first 4 bytes
			self.key = (struct.unpack('<I', data[0:4])[0] + self.baseSeed) & 0xffffffff

			# ResponseKey = last 4 bytes
			self.responseKey = struct.unpack('<I', data[-4:])[0]

			# Decode data
			data, k = self.decode(data[4:], self.key)
			
			# Get header
			self.header = header(data[:0x1a])

			# Check command and parse accordingly
			if self.header.dict["command"] == 0:
				p = payload(data[0x1a:-4])
				self.payload = p.dict
			elif self.header.dict["command"] == 1:
				self.payload ={
					"fileRequest" : hexlify(data[0x1a:-4])
				}
			else:
				print "[-]Unknown command", self.header.dict["command"]

class serverMsg(httpMsg):
	def parse(self, data, key):
		if data != None and len(data) > 0x1a:
			keyValidation = (struct.unpack('<I', data[-4:])[0])
			data, key = self.decode(data[:-4],key)
			if key == keyValidation:
				self.header = header(data[4:0x1e])
				if self.header.dict['command'] == 0:
					payload  = data[0x1e:-128]
					sigBlock = data[-128:-4]
					p = payload(payload)
					self.payload = p.dict

			else:
				print "Failed key validation"
				
