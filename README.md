Man in the Middle SOCKS Proxy for JAVA
===========

An interceptor for SOCKS Proxy protocol to allow user to dump any connections' content even if it is secured with SSL.

Please note that this is not a general purpose proxy server (performance issues and lack of capabilities). I actually developed it for my needs about examining connections of mobile applications.

I only tested it over connections of applications on my Android phone. So it is a very restricted cluster for a test. If you encounter an misfunction, you are always welcome to open an issue explaining it.

## Usage

	java -jar mitmsocks4j.jar -h
	usage: mitmsocks4j [-h] [-l [{ALL,TRACE,DEBUG,INFO,WARN,ERROR,OFF}]]
                   [-x [PROXYPORT]] [-d [DELEGATORPORT]]
                   [-s [SECUREDPORTS [SECUREDPORTS ...]]] [-k KEYSTORE]
                   [-p PASSWORD]

	Strips SSL/TLS layer from SOCKS proxy connection to dump plain data!

	optional arguments:
		-h, --help          show this help message and exit
		-l [{ALL,TRACE,DEBUG,INFO,WARN,ERROR,OFF}], --loglevel [{ALL,TRACE,DEBUG,INFO,WARN,ERROR,OFF}]
							Sets logging level!
	-x [PROXYPORT], --proxyport [PROXYPORT]
							Proxy port that proxy listens.(default:1080)
	-d [DELEGATORPORT], --delegatorport [DELEGATORPORT]
							Delegator port that mitm takes place.(default:1081)
	-s [SECUREDPORTS [SECUREDPORTS ...]], --securedports [SECUREDPORTS [SECUREDPORTS ...]]
							Secured ports that will be ssl-stripped
	-k KEYSTORE, --keystore KEYSTORE
							Keystore that will be used to imitate actual
							server certificates for clients(default:mitmsocks4j.jks)
	-p PASSWORD, --password PASSWORD
							Keystore password.(default:123456)

**Sample usage:**

	java -jar mitmsocks4j.jar -l ERROR -s 5228 443 8883
	
## About CA Certificate
``mitmsocks4j`` needs a CA certificate to forge remote server's certificate and signs it. So user should add this CA certificate to its trust store. Otherwise most of applications will drop the connection.(Browser may have an option to ask user to accept that certificate.)

## About SOCKS Protocol
To be able to use this tool, user should be able to redirect his program's traffic to a SOCKS proxy. Most of the browsers have an option to configure SOCKS proxy settings.
In my case; Android does not have such an option(only supports HTTP proxy). So I rooted my phone and use [ProxyDroid](https://play.google.com/store/apps/details?id=org.proxydroid) 

TODO
----
Not fully tested. Test it!

Add BIND command support.

License
----
    Copyright (c) 2012, Akdeniz
    All rights reserved.
    
    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met: 
    
    1. Redistributions of source code must retain the above copyright notice, this
    list of conditions and the following disclaimer. 
    2. Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution. 

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
    ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
    WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
    ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
    (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
    ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
    
    The views and conclusions contained in the software and documentation are those
    of the authors and should not be interpreted as representing official policies, 
    either expressed or implied, of the FreeBSD Project.
