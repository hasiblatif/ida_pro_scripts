'''
----- IDA Pro script for mailto(netwalker) ransomware ---

Author: Muhammad Hasib Latif

md5: 1c92e5e1131ad8ac0891eb30a3fde73e

Purpose: To decode native api calls used in this sample. This sample has created an automated procedure to call APIs from a custom IAT table which is created  
at the start of sample execution. IAT is created by matching a CRC32 value of APIs against dynamically retrieved DLL names and creating their CRC32 from TEB/PEB. 
This script will create that custom IAT and will comment on the call address.

Note: I have created a dictionary of known/undocumented Windows APIs and utilizing that file to get API names instead of 
reading TEB/PEB as sample is doing.

Bugs: Some APIs could not be decoded due to missing CRC32. Such APIs will have UNKNOWN_API comment
Date: 24 Feb 2020

'''
import idc
from idaapi import *
from idautils import *
import json,traceback
import binascii
crc32_dict_ = {}
def crc2hex(crc):
    res=''
    for i in range(4):
        t=crc & 0xFF
        crc >>= 8
        res='%02X%s' % (t, res)
    return res
def calc_crc32(str):
	return crc2hex(binascii.crc32(str)).upper()
def get_api(crc32,crc32_dict):
	try:
		return crc32_dict[crc32]
	except Exception as e:
		print e
		return None
def put_comments_on_call(iat):
	for addr in XrefsTo(0x004025C0, flags=0): # please adjust base, should be base+0x25c0
		addr = idc.NextHead(addr.frm)
		iat_addr = GetOperandValue(addr, 1)
		addr_to_comment = idc.NextHead(addr)
		if GetMnem(addr_to_comment) == "call":
			try:
				idc.MakeComm(addr_to_comment,  str(iat[iat_addr]))
			except Exception as e:
				print traceback.print_exc()
				pass
def get_names(crc32_dict):
	iat = {}
	for addr in XrefsTo(0x00401000, flags=0): # please adjust base, should be base+0x1000
		call_addr = addr
		addr = idc.PrevHead(addr.frm)
		addr = idc.PrevHead(addr)
		push_addr = idc.PrevHead(addr)
		push_nem = GetMnem(push_addr)
		
		next_addr = idc.NextHead(call_addr.frm)
		next_addr = idc.NextHead(next_addr)
		next_addr = idc.NextHead(next_addr)
		iat_addr = GetOperandValue(next_addr, 0)
		if push_nem == "push":
			val = crc2hex(GetOperandValue(push_addr, 0))
			api = get_api(val.upper(),crc32_dict)
			if api is not None:
				iat.update({iat_addr: api})
			else:
				iat.update({iat_addr: "UNKNOWN_API"})
	
	return iat
	

# predefined crc32 of Windows APIs
with open("win_apis_crc32.json") as f:
	crc32_dict_ = json.load(f)
# find decoding function calls and create custom IAT 
iat = get_names(crc32_dict_)
# find all call instructions and comment decoded APIs 
put_comments_on_call(iat)