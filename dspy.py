import psutil
import vt2public
from tabulate import tabulate
import argparse
import os

"""
dspy.py - fetches VirusTotal Domain Reports for a list of domains

	Author: 	Paul Dicovitsky
	Copyright 2014 Paul Dicovitsky 
	License: 	GNU General Public License Version 3 or later


"""

TITLE = "Domain Spy"
DESCRIPTION = "Fetch VirusTotal Domain Report for domain or domains."
VERSION = 0.001


def getAPIKEY(key):
	# read Virus Total Public API 2.0 Key from APIKEY env variable
	if key is None: 
		APIKEY = os.getenv('APIKEY')
	else:
		APIKEY = key
	if APIKEY is None:
		print("Please specify a VirusTotal 2 Public API key via either the -k (--key) switch or the APIKEY environment variable.")
		exit()
	return APIKEY

def outputTable(reports):

	""" output module - Tabulate table format """

	table = []
	for k in reports.keys():
		r = reports[k]
		row = [k, r.response_code, r.status, r.numberof_urls, r.categories, r.numberof_subdomains, r.numberof_detected_downloaded_samples, r.numberof_undetected_downloaded_samples]
		table.append(row)

	headers = ['domain','code','status','urls', 'categories', 'subdomains', 'detected_samples', 'undetected_samples']

	print tabulate(table,headers)	


def outputCSV(reports):

	""" output module - CSV format """

	table = []
	for k in reports.keys():
		r = reports[k]
		row = [k, r.response_code, r.status, r.numberof_urls, r.categories, r.numberof_subdomains, r.numberof_detected_downloaded_samples, r.numberof_undetected_downloaded_samples]
		table.append(row)

	headers = ['domain','code','status','urls', 'categories', 'subdomains', 'detected_samples', 'undetected_samples']

	print(",".join(headers))
 	for row in table: 
 		s = row[0]
 		for i in xrange(1,len(row)):
 			s += ',' 
 			s += str(row[i])
 		print s
 		# .join is not working, perhaps because of the occasional None list entry?
 		# print ",".join(row)


def parseCommandLine():
	""" parse command-line options """

	parser = argparse.ArgumentParser(prog=TITLE, description=DESCRIPTION)
	parser.add_argument("-v", "--verbose", help="verbose mode (-vv for debug mode)", action="count")
	parser.add_argument("-t", "--test", help="test mode", action="store_true")
	parser.add_argument("filename", help="file of domain names to lookup")
	parser.add_argument("-k", "--key", help="VirusTotal 2 Public API key")
	parser.add_argument('-o','--output', help="output formating", choices=('csv','table'), default='table')
	parser.add_argument('--version', action='version', version='%(prog)s {0}'.format(VERSION))
	args = parser.parse_args()

	return args


"""
MAIN
"""

print ("{0} {1}".format(TITLE,VERSION))

args = parseCommandLine()

VERBOSE = (args.verbose >= 1)
DEBUG = (args.verbose > 1)
TEST = args.test
FILENAME = args.filename
APIKEY = getAPIKEY(args.key)
OUTPUT = args.output
vt2public.Flags.VERBOSE = VERBOSE
vt2public.Flags.DEBUG = DEBUG
vt2public.Flags.TEST = TEST

if VERBOSE: print("Verbose mode")
if DEBUG: print("Debug mode")
if TEST: print("Test mode")

""" read domains from input file, one domain name per line """
lines = open(FILENAME).read().splitlines()

if DEBUG: print("found {0} domains in file {1}".format(len(lines),args.filename))

""" Query VirusTotal for Domain Repors """

VirusTotal = vt2public.DomainGofer(APIKEY)
VirusTotal.resource = lines
VirusTotal.fetch()
reports = VirusTotal.reports

if VERBOSE: print("{0} reports found".format(len(reports.keys())))

if args.output == "table":
	outputTable(reports)
elif args.output == "csv":
	outputCSV(reports)

