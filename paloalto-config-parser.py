import xml.etree.ElementTree as ET
import argparse
import csv

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
csvwriter.writerow(['Name', 'to', 'from', 'source', 'destination', 'source-user', 'category', 'application', 'service', 'hip-profiles', 'action'])


for entry in root.find('.//devices/entry/vsys/entry/rulebase/security/rules'):
	out = []

	# name
	out.append(entry.attrib['name'])

	# rule format 'to', 'from', 'source', 'destination', 'source-user', 'category', 'application', 'service', 'hip-profiles'
	for i in ['to', 'from', 'source', 'destination', 'source-user', 'category', 'application', 'service', 'hip-profiles']:
		temp = []
		try:
			for t in entry.find(i).findall('member'):
				temp.append(t.text)
			out.append('\n'.join(temp))
		except AttributeError as e:
			print("AttributeError noted: %s\nContinuing"%e)
			continue
		


	#action
	out.append(entry.find('action').text)

	csvwriter.writerow(out)

print("COMPLETE!")
