from scapy.all import *

http_methods = {
	0: "GET",
	1: "POST",
	2: "PUT",
	3: "DELETE",
	4: "HEAD"
}

http_protocol = {
	10: 'HTTP/1.0',
	11: 'HTTP/1.1',
}

class HTTPHeadersField(StrField):
    #islist=1
    def __init__(self, name, default):
        StrField.__init__(self, name, default)

    # will be specified as a python expression - array of tuples
    #internal value: [("Host", "example.com")]
    def i2m(self, pkt, x):
        res = ""
	for header in eval(x):
            res += "{0}: {1}\n".format(*header)
        return bytes(res + "\n")

class ExStrEnumField(StrField):
    isenum=1 
    def __init__(self, name, default, enum,  postfix="", prefix=""):
        self.i2s = enum
        self.s2i = {v: k for k, v in enum.items()}
	StrField.__init__(self, name, default, "s")
	self.prefix = prefix
	self.postfix = postfix

    def i2repr(self, pkt, x):
        return self.i2h(pkt, x)

    def any2i(self, pkt, x):
        try:
            return self.i2s[int(x)]
        except:
            return x

    def h2i(self, pkt, x):
        return x.strip()

    def i2m(self, pkt, x):
        return bytes(self.prefix + x.strip() + self.postfix)

class HTTP(Packet):
    name = "HTTP"
    fields_desc = [
            ExStrEnumField("method", "GET", http_methods, postfix=" "),
            StrField("url", "/"),
            ExStrEnumField("protocol", "HTTP/1.1", http_protocol, postfix="\n", prefix=" "),
            HTTPHeadersField("headers", '[("Host", "example.com")]'),
            StrField("data", ""),
    ]

    def mysummary(self):
        return self.sprintf("HTTP %HTTP.method%")
   
    #def post_build(self, p, pay):
        # here we can perform header auto-calculation and calculate proper
        # content-length, and lengths/offsets for variable length fields.
        # btw, to do this properly, we may need to change
	# def get_size_bytes (self) to
        # def get_size_bytes (self, pkt, x):
        # (see Field.i2h, Field.h2i, ...
