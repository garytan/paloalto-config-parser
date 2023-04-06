import xml.etree.ElementTree as ET
import argparse
import csv
import requests
from socket import getservbyname

parser = argparse.ArgumentParser(description='Parsing security rules from palauto.')
parser.add_argument('-f', action='store',
					metavar='<configuration-file>',
                    help='path to configuration file',
                    required=True)
parser.add_argument('-o', action='store',
					metavar='<output-file>',
                    help='path to output file',
                    required=True)

args = parser.parse_args()

CONFIGFILE = vars(args)['f']
OUTPUTFILE = vars(args)['o']

print('Parsing: {}'.format(CONFIGFILE))

tree = ET.parse(CONFIGFILE)
root = tree.getroot()

outdata = open(OUTPUTFILE, 'w')
csvwriter = csv.writer(outdata)
csvwriter.writerow(['Name', 'Description', 'Action', 'To', 'From', 'Source (Alias)','Source (Addresses)', 'Destination (Alias)', 'Destination (Addresses)', 'Source-User', 'Category', 'Application', 'Service', 'Ports', 'Hip-Profiles'])

#pretty sure that's not how you spell it
aliases = {'any':'0.0.0.0/0'}

#This deals with the alias' (and yeah it's messy)
for alias in root.find('.//devices/entry/vsys/entry/address'):
	try: 
		aliases[alias.attrib['name']] = "%s (%s)"%(alias.find('ip-netmask').text,alias.attrib['name'])
	except AttributeError:
		try:
			aliases[alias.attrib['name']] = "%s (%s)"%(alias.find('fqdn').text,alias.attrib['name'])
		except AttributeError:
			try:
				aliases[alias.attrib['name']] = "%s (%s)"%(alias.find('ip-range').text,alias.attrib['name'])
			except AttributeError:
				try:
					aliases[alias.attrib['name']] = "Null (%s)"%alias.attrib['name']
				except KeyError:
					continue

#and this with URL lists
for alias in root.find('.//devices/entry/vsys/entry/profiles/custom-url-category'):
	name = alias.attrib['name']
	aliases[name] = '\n'.join(["%s (%s)"%(i.text,name) for i in alias.find('list')])
	
#and this for the groups thereof
for alias in root.find('.//devices/entry/vsys/entry/address-group'):
	name = alias.attrib['name']
	aliases[name] = '\n'.join(["%s (%s)"%(aliases[i.text],name) for i in alias.find('static')])

#and this for dynamic lists!
for alias in root.find('.//devices/entry/vsys/entry/external-list'):
	try:
		name = alias.attrib['name']
		url = alias.find('./type/*/url').text.strip()
		print('Requesting: %s'%url)
		#resp = requests.get(url)
		aliases[name] = 'placeholder'#'\n'.join(["%s (%s)"%(i,name) for i in resp.text.strip().split('\n')])
	except AttributeError:
		print("Error discovered for dynamic group %s"%name)
		continue

ports = {'any':'0-65535 (any)',
'service-https':'443/tcp (service-https)',
'service-http':'80/tcp (service-http)',
'ssl':'443/tcp (ssl)',
'rtp':'16384-32767/udp (rtp)',
'sip':'5060/tcp (sip)\n5061/tcp (sip)\n5060/udp (sip)\n5061/udp (sip)',
'web-browsing':'80/tcp (web-browsing)\n443/tcp (web-browsing)',
'dns':'53/tcp (dns)'}

for proto in root.find('.//devices/entry/vsys/entry/service'):
	name = proto.attrib['name']
	placeholder = []
	try:
		placeholder.append("%s/tcp (%s)"%(proto.find('protocol/tcp/port').text,name))
	except AttributeError:
		pass

	try:
		placeholder.append("%s/udp (%s)"%(proto.find('protocol/udp/port').text,name))
	except AttributeError:
		pass

	ports[name] = '\n'.join(placeholder)

#now dealing with application

for app in root.find('.//devices/entry/vsys/entry/application'):
	name = app.attrib['name']
	placeholder = []
	for member in app.find('default/port').findall('member'):
		prt = member.text.split('/')
		placeholder.append("%s/%s (%s)"%(prt[1],prt[0],name))

	ports[name] = '\n'.join(placeholder)

#this deals with service groups
for group in root.find('.//devices/entry/vsys/entry/service-group'):
	name = group.attrib['name']
	placeholder = []
	for member in group.find('members').findall('member'):
		placeholder.append("%s (%s)"%(ports[member.text],member.text))

	ports[name] = '\n'.join(placeholder)


#this is the actual rules bit
for entry in root.find('.//devices/entry/vsys/entry/rulebase/security/rules'):
	out = []

	# name
	out.append(entry.attrib['name'])
	try:
		out.append(entry.find('description').text)
	except AttributeError:
		out.append('N/A')
	#action
	out.append(entry.find('action').text)

	# rule format 'to', 'from', 'source', 'destination', 'source-user', 'category', 'application', 'service', 'hip-profiles'
	for i in ['to', 'from', 'source', 'destination', 'source-user', 'category', 'application', 'service', 'hip-profiles']:
		temp = []
		alias_decoded = []
		protos = []
		try:
			for t in entry.find(i).findall('member'):
				temp.append(t.text)
				if i == 'source' or i == 'destination':
					try:
						alias_decoded.append("%s\n"%aliases[t.text]) 
					except KeyError:
						print('Rule %s has not aliased their %s'%(entry.attrib['name'],i))
						alias_decoded.append(t.text)
				elif i == 'service':
					if t.text == 'application-default':
						for protocol in out[-1].split('\n'):
							try:
								protos.append("%s\n"%ports[protocol])
							except KeyError:
								try: 
									protos.append("%s (%s)\n"%(str(getservbyname(protocol)),protocol))
								except OSError:
									protos.append("Undefined (%s)\n"%protocol)
					else:
						protos.append("%s\n"%ports[t.text])


			out.append('\n'.join(temp))

			if alias_decoded != []:

				out.append('\n'.join(alias_decoded))
			elif protos != []:
				out.append('\n'.join(protos))

		except AttributeError as e:
			print("AttributeError noted: %s\nContinuing"%e)
			continue
		

	


	csvwriter.writerow(out)

print("COMPLETE!")