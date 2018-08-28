'''
if you want to save semanticnet, query save.com to server
than 'log.json' will savee
'''

import threading
import sys
import socket
import dns.resolver
import json
import pickle
import os
import semanticnet as sn
from requests import *
from trust_domain import *
from pprint import pprint

cache_dns = {}


def error_msg(message):
	sys.stderr.write(message + '\n')



def open_dns(append_url, datas='', types='GET', key='Bearer 2f7a360b-7d77-4ac8-980a-23a28b315367', url='https://investigate.api.opendns.com'):
	if types == 'GET':
		try:
			s = Session()
			s.headers['Authorization'] = key
			r = s.get(url + append_url)
			j = json.loads(r.text.decode('utf-8'))
			return j
		except KeyboardInterrupt:
			global db
			print '[+] saving...'
			db.save_cache()
			print '[+] saved!'
			sys.exit()
		except:
			error_msg('[-] open_dns GET error...')

	elif types == 'POST':
		try:
			s = Session()
			s.headers['Authorization'] = key
			r = s.post(url + append_url, data=datas)
			j = json.loads(r.text.decode('utf-8'))
			return j
		except KeyboardInterrupt:
			global db
			print '[+] saving...'
			db.save_cache()
			print '[+] saved!'
			sys.exit()
		except:
			error_msg('[-] open_dns POST error...')

	else:
		return False



def DNStoIP(domain):
	global cache_dns
	if cache_dns.get(domain) != None:
		return cache_dns.get(domain)
	
	try:
		answers = resolver.query(domain, 'A')
		cache_dns[domain] = answers[0].address
		return str(answers[0].address)
	except:
		pass



class DB():	
	def __init__(self):
		try:
			self.graph = sn.Graph()
			self.trust_domain = trust_domain   # defined trust domain list by ip
			self.categories = open_dns('/domains/categories/', types='GET') # categories
			self.db_category = {}              # category score sum to calculate similarity
			self.node_ids = {}                 # node's id
	
			if os.path.isfile('cache.pickle'): # load cache
				global cache_dns
				with open('cache.pickle', 'rb') as pFile:
					self.cache_category = pickle.load(pFile)
					self.cache_security = pickle.load(pFile)
					self.cache_links = pickle.load(pFile)
					cache_dns = pickle.load(pFile)
			else:
				self.cache_category = {}      # category cache
				self.cache_security = {}      # security cache
				self.cache_links = {}         # links cache

			self.domain_sum = {}          # domain category count sum
			
			idx = 0
			for ip in trust_domain.viewkeys():
				idx += 1
				print '[+] %.2f...%%'%((idx/float(len(trust_domain.viewkeys())))*100)
				self.make_ip(ip)
				if trust_domain[ip] == '*':
					continue
				cate = open_dns('/domains/categorization/', types='POST', datas=str(trust_domain[ip]).replace('\'','\"'))
				for u in cate.viewkeys():
					self.domain_sum[ip] += len(cate[u]['content_categories'])
					for c in cate[u]['content_categories']:
						self.db_category[ip][c] += 1
		except:
			error_msg('[-] DB.__init__ error...')

	def add_graph(self, src, dst, src_attr, dst_attr, edge_attr):
		if self.node_ids.get(src) == None:
			self.node_ids[src] = self.graph.add_node(src_attr)
		if self.node_ids.get(dst) == None:
			self.node_ids[dst] = self.graph.add_node(dst_attr)
		self.graph.add_edge(self.node_ids[src], self.node_ids[dst], edge_attr)

		
	def make_ip(self, ip): # if first, add ip to db_category
		try:
			self.db_category[ip] = {}
			self.domain_sum[ip] = 0
			for k in self.categories.viewkeys():
				self.db_category[ip][k] = 0
		except KeyboardInterrupt:
			global db
			print '[+] saving...'
			db.save_cache()
			print '[+] saved!'
			sys.exit()
		except:
			error_msg('[-] DB.make_ip error...')


	def add_category(self, domain, ip):
		try:
			if self.cache_category.get(domain) != None:
				cate = self.cache_category.get(domain)
			else:
				cate = open_dns('/domains/categorization/%s'%(domain))[domain]
				self.cache_category[domain] = cate
			self.domain_sum[ip] += len(cate['content_categories'])
			for c in cate['content_categories']:
				self.db_category[ip][c] += 1
				self.domain_sum[ip] += 1
		except KeyboardInterrupt:
			global db
			print '[+] saving...'
			db.save_cache()
			print '[+] saved!'
			sys.exit()
		except:
			error_msg('[-] DB.add_category error...')


	def similarity(self, ip, blocked_domain):
		score = 0.0
		simi_sum = 0 # step1
		b = blocked_domain[:-1]# step2

		#Step1 category similarity
		try:
			if self.cache_category.get(blocked_domain) != False:
				if self.cache_category.get(blocked_domain) != None:
					category = self.cache_category.get(blocked_domain)
				else:
					category = open_dns('/domains/categorization/%s'%(blocked_domain), types='GET')[blocked_domain]
					self.cache_category[blocked_domain] = category
				score += int(category['status']) * 30                           # -30 ~ 30
				simi_sum = 0
				for c in category['content_categories']:
					simi_sum += self.db_category[ip][c]
				score += (simi_sum/float(self.domain_sum[ip])) * 20                    # 0 ~ 20
		except:
			self.cache_category[blocked_domain] = False

		#Step2 links correlation
		try:
			if self.cache_links.get(blocked_domain) != False:
				if self.cache_links.get(blocked_domain) != None:
					links_response = self.cache_links.get(blocked_domain)
				else:
					links_response = open_dns('/links/name/%s.json'%(blocked_domain), types='GET')
					self.cache_links[blocked_domain] = links_response
				if links_response != None and links_response.get('found') == True:
					for l in links_response['tb1']:
						if l[0] == b:
							score += l[1]/links_response['tb1'][0][1]
							#todo make viz
		except:
			self.cache_links[blocked_domain] = False

		#Step3 Domain similarity
		try:
			if self.cache_security.get(blocked_domain) != False:	
				if self.cache_security.get(blocked_domain) != None:
					security_response = self.cache_security.get(blocked_domain)
				else:
					security_response = open_dns('/security/name/%s.json'%(blocked_domain))
					self.cache_security[blocked_domain] = security_response
				score += float(security_response.get('dga_score')) * 0.5         if security_response.get('dga_score') else -2      # -50 ~ 0
				score += float(security_response.get('securerank2')) * -1 * 0.2  if security_response.get('securerank2') else -2    # -20 ~ 20
				score += float(security_response.get('asn_score')) * 0.5         if security_response.get('asn_score') else -2      # ~50 ~ 0
				score += float(security_response.get('prefix_score')) * 0.5      if security_response.get('prefix_score') else -2   # ~50 ~ 0
		except:
			self.cache_security[blocked_domain] = False

		return score


	def save_cache(self):
		#try:
		if True:
			global cache_dns
			with open('cache.pickle','wb') as pFile:
				pickle.dump(self.cache_category, pFile)
				pickle.dump(self.cache_security, pFile)
				pickle.dump(self.cache_links, pFile)
				pickle.dump(cache_dns, pFile)
			self.graph.save_json('log.json')
		#except:
		#	print 'undefined error...'
		#	sys.exit()


class DNSQuery:
	def __init__(self, data):
		self.data=data
		self.dominio=''

		tipo = (ord(data[2]) >> 3) & 15   # Opcode bits
		if tipo == 0:          # Standard query
			ini=12
			lon=ord(data[ini])
			while lon != 0:
				self.dominio+=data[ini+1:ini+lon+1]+'.'
				ini+=lon+1
				lon=ord(data[ini])

	def respuesta(self, ip, block=False, hidden=False):
		try:
			packet=''
			if self.dominio:
				if block == True:
					packet+=self.data[:2] + '\x81\x83'
					packet+=self.data[4:6] + '\x00\x00\x00\x00\x00\x00'
					packet+=self.data[12:]
				elif hidden == True:
					packet+=self.data[:2] + '\x85\x83'
					packet+=self.data[4:6] + '\x00\x00\x00\x00\x00\x00'
					packet+=self.data[12:]	
				else:
					packet+=self.data[:2] + '\x81\x80'
					packet+=self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00'   # Questions and Answers Counts
					packet+=self.data[12:]                     # Original Domain Name Question
					packet+='\xc0\x0c'                       # Pointer to domain name
					packet+='\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'       # Response type, ttl and resource data length -> 4 bytes
					packet+=str.join('',map(lambda x: chr(int(x)), ip.split('.'))) # 4bytes of IP
			return packet
		except:
			return False


def processing(data, addr):
	p = DNSQuery(data)
	if p.dominio == 'save.com.':
		global db
		db.save_cache()
		print '[+] log saved'
		udps.sendto(p.respuesta('0.0.0.0', hidden=True), addr)
		return
	if p.dominio.find('._dns-sd._udp.') != -1:
		udps.sendto(p.respuesta('0.0.0.0', hidden=True), addr)
		return
	score = 99
	if trust_domain.get(addr[0]) == None:
		db.add_graph(addr[0], p.dominio, src_attr={'label':addr[0],'space:icon':'shapes/forbidden','og:space:color':[1.0,0.0,0.0,1.0]}, dst_attr={'label':p.dominio}, edge_attr={'space:icon':'styles/zigzag','og:space:color':[1.0,0.0,0.0,1.0]})
		print '[-] undefined ip - %s'%addr[0]
		return

	elif trust_domain.get(addr[0]) != '*': # pass all
		try:
			trust_domain[addr[0]].index(p.dominio)
		except ValueError:
			score = db.similarity(addr[0],p.dominio)
			if score < 0:
				db.add_graph(addr[0], p.dominio, src_attr={'label':addr[0],'space:icon':'shapes/star'}, dst_attr={'label':p.dominio}, edge_attr={'space:icon':'styles/dots','og:space:color':[1.0,0.0,0.0,1.0]})
				udps.sendto(p.respuesta('0.0.0.0', block=True), addr)
				print '[-] %s - %s -X %s ' % (score, addr[0], p.dominio)
				return
	
	origin_ip = DNStoIP(p.dominio)
	if origin_ip == None:
		print '[-] Can\'t find host: %s' % (p.dominio)
		return

	a = p.respuesta(origin_ip)
	if a == False:
		return 

	udps.sendto(a, addr) # addr[0] is request user  addr[1] is port
	db.add_graph(addr[0], p.dominio, src_attr={'label':addr[0],'space:icon':'shapes/star','og:space:color':[1.0,1.0,0.0,1.0]}, dst_attr={'label':p.dominio}, edge_attr={'og:space:color':[0.0,1.0,0.0,1.0]})
	print '[+] %s - %s -> %s - %s' % (score, addr[0], p.dominio, origin_ip)
	db.add_category(p.dominio,addr[0])


if __name__ == '__main__':
	print('[+] server loading...')
	udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	udps.bind(('0.0.0.0', 53))
	resolver = dns.resolver.Resolver()
	resolver.nameservers = ['8.8.8.8']
	db = DB()
	print('[+] server loaded!')

	if True:
		while True:
			try:
				data, addr = udps.recvfrom(1024)
				processing(data, addr)
			except KeyboardInterrupt:
				global db
				print '[+] saving...'
				db.save_cache()
				print '[+] saved!'
				sys.exit()
