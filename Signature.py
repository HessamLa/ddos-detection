class Signature(object):
	def __init__(self,
		OXM_OF_IN_PORT=None,
		OXM_OF_ETH_DST=None,
		OXM_OF_ETH_SRC=None,
		OXM_OF_ETH_TYPE=None,
		OXM_OF_IP_PROTO=None,
		OXM_OF_IPV4_SRC=None,
		OXM_OF_IPV4_DST=None,
		OXM_OF_IPV6_SRC=None,
		OXM_OF_IPV6_DST=None,
		OXM_OF_TCP_SRC=None,
		OXM_OF_TCP_DST=None,
		OXM_OF_UDP_SRC=None,
		OXM_OF_UDP_DST=None):
		
		self.OXM_OF_IN_PORT = OXM_OF_IN_PORT
		self.OXM_OF_ETH_DST = OXM_OF_ETH_DST
		self.OXM_OF_ETH_SRC = OXM_OF_ETH_SRC
		self.OXM_OF_ETH_TYPE = OXM_OF_ETH_TYPE
		self.OXM_OF_IP_PROTO = OXM_OF_IP_PROTO
		self.OXM_OF_IPV4_SRC = OXM_OF_IPV4_SRC
		self.OXM_OF_IPV4_DST = OXM_OF_IPV4_DST
		self.OXM_OF_IPV6_SRC = OXM_OF_IPV6_SRC
		self.OXM_OF_IPV6_DST = OXM_OF_IPV6_DST
		self.OXM_OF_TCP_SRC = OXM_OF_TCP_SRC
		self.OXM_OF_TCP_DST = OXM_OF_TCP_DST
		self.OXM_OF_UDP_SRC = OXM_OF_UDP_SRC
		self.OXM_OF_UDP_DST = OXM_OF_UDP_DST

	def ADD_OXM_OF_IN_PORT(self,data):
		self.OXM_OF_IN_PORT = data

	def ADD_OXM_OF_ETH_DST(self,data):
		self.OXM_OF_ETH_DST = data

	def ADD_OXM_OF_ETH_SRC(self,data):
		self.OXM_OF_ETH_SRC = data

	def ADD_OXM_OF_ETH_TYPE(self,data):
		self.OXM_OF_ETH_TYPE = data

	def ADD_OXM_OF_IP_PROTO(self,data):
		self.OXM_OF_IP_PROTO = data

	def ADD_OXM_OF_IPV4_SRC(self,data):
		self.OXM_OF_IPV4_SRC = data

	def ADD_OXM_OF_IPV4_DST(self,data):
		self.OXM_OF_IPV4_DST = data

	def ADD_OXM_OF_IPV6_SRC(self,data):
		self.OXM_OF_IPV6_SRC = data

	def ADD_OXM_OF_IPV6_DST(self,data):
		self.OXM_OF_IPV6_DST = data

	def ADD_OXM_OF_TCP_SRC(self,data):
		self.OXM_OF_TCP_SRC = data

	def ADD_OXM_OF_TCP_DST(self,data):
		self.OXM_OF_TCP_DST = data

	def ADD_OXM_OF_UDP_SRC(self,data):
		self.OXM_OF_UDP_SRC = data

	def ADD_OXM_OF_UDP_DST(self,data):
		self.OXM_OF_UDP_DST = data

	def GET_OXM_OF_IPV4_SRC(self):
		return self.OXM_OF_IPV4_SRC

	def GET_OXM_OF_IPV4_DST(self):
		return self.OXM_OF_IPV4_DST

	def GET(self):
		data = {}
		if self.OXM_OF_IN_PORT:
			data['OXM_OF_IN_PORT'] = self.OXM_OF_IN_PORT
		if self.OXM_OF_ETH_DST:
			data['OXM_OF_ETH_DST'] = self.OXM_OF_ETH_DST
		if self.OXM_OF_ETH_SRC:
			data['OXM_OF_ETH_SRC'] = self.OXM_OF_ETH_SRC
		if self.OXM_OF_ETH_TYPE:
			data['OXM_OF_ETH_TYPE'] = self.OXM_OF_ETH_TYPE
		if self.OXM_OF_IP_PROTO:
			data['OXM_OF_IP_PROTO'] = self.OXM_OF_IP_PROTO
		if self.OXM_OF_IPV4_SRC:
			data['OXM_OF_IPV4_SRC'] = self.OXM_OF_IPV4_SRC
		if self.OXM_OF_IPV4_DST:
			data['OXM_OF_IPV4_DST'] = self.OXM_OF_IPV4_DST
		if self.OXM_OF_IPV6_SRC:
			data['OXM_OF_IPV6_SRC'] = self.OXM_OF_IPV6_SRC
		if self.OXM_OF_IPV6_DST:
			data['OXM_OF_IPV6_DST'] = self.OXM_OF_IPV6_DST
		if self.OXM_OF_TCP_SRC:
			data['OXM_OF_TCP_SRC'] = self.OXM_OF_TCP_SRC
		if self.OXM_OF_TCP_DST:
			data['OXM_OF_TCP_DST'] = self.OXM_OF_TCP_DST
		if self.OXM_OF_UDP_SRC:
			data['OXM_OF_UDP_SRC'] = self.OXM_OF_UDP_SRC
		if self.OXM_OF_UDP_DST:
			data['OXM_OF_UDP_DST'] = self.OXM_OF_UDP_DST
		return data
