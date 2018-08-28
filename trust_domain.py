trust_domain = {
	'192.168.43.25':['naver.com.','daum.net'],
	'192.168.43.230':['naver.com'],
	'172.30.1.21':'*',
	'192.168.43.112':'*',
	'192.168.219.116':['naver.com','www.naver.com'],
	'192.168.219.117':['naver.com','www.naver.com'],
	'192.168.219.118':['naver.com','www.naver.com'],
	'192.168.219.119':['naver.com','www.naver.com'],
	'192.168.219.120':['naver.com','www.naver.com'],
	'192.168.219.121':['naver.com','www.naver.com'],
	'192.168.219.122':['naver.com','www.naver.com'],
	'192.168.219.123':['naver.com','www.naver.com'],
	'192.168.219.124':['naver.com','www.naver.com'],
	'192.168.219.125':['naver.com','www.naver.com'],
	'192.168.219.126':['naver.com','www.naver.com'],
	'192.168.219.127':['naver.com','www.naver.com'],
	'192.168.219.128':['naver.com','www.naver.com'],
	'192.168.219.129':['naver.com','www.naver.com'],
	'192.168.219.130':['naver.com','www.naver.com'],
	'192.168.219.131':['naver.com','www.naver.com'],
	'192.168.219.132':['naver.com','www.naver.com'],
	'192.168.219.133':['naver.com','www.naver.com'],
	'192.168.219.134':['naver.com','www.naver.com'],
	'192.168.219.135':['naver.com','www.naver.com'],
	'192.168.219.136':['naver.com','www.naver.com'],
	'192.168.219.137':['naver.com','www.naver.com'],
	'192.168.219.138':['naver.com','www.naver.com'],
	'192.168.219.139':['naver.com','www.naver.com'],
	'192.168.219.140':['naver.com','www.naver.com']
}

for t in trust_domain:
	if type(trust_domain[t]) == type([]):
		for d in trust_domain[t]:
			if d[-1] != '.':
				trust_domain[t][trust_domain[t].index(d)] = d + '.'
