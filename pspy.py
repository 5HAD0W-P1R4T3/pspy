import psutil
from pshash import ProcHash
import vt2public
from tabulate import tabulate
import argparse
import os

"""
ps + virus total = pspy.py  - a python script to check running processes against VirusTotal (like SysInternals Process Explorer)

	Author: 	Paul Dicovitsky
	Copyright 2014 Paul Dicovitsky 
	License: 	GNU General Public License Version 3 or later


"""

TITLE = "Process Spy"
DESCRIPTION = "Fetch VirusTotal File Scans Reports for running processes."
VERSION = 0.001
EPILOG = "The APIKEY environment variable can used instead of --key KEY."

def SpyOnOne(pid):
	""" spy on process pid """

	table = []

	if psutil.pid_exists(pid):
		p = ProcHash(pid)
		print p.pid
		print p.name
		print p.exe
		print p.sha256

		gofer = vt2public.FileScanGofer(APIKEY)
		gofer.resource = p.sha256 
		gofer.fetch()
		
		r = gofer.reports[p.sha256]
		row = [pid,p.name,r.status,r.positives,r.total,r.permalink]
		table.append(row)
		header = ["pid","name","status","positives","total","permalink"]
		print(tabulate(table,header))

	else:
		print("PID {0} not found".format(pid))


def SpyOnAll():

	""" enumerate all processes and caculate thier hashes """


	pd = {}				# dictionary of processes, keyed by pid
	hashlist = []		# list of every hash found

	for pid in psutil.pids():

		try:
			pd[pid] = ProcHash(pid)								# build dictionary of processes, keyed by pid	
			hashlist.append(pd[pid].sha256)						# save each hash to a list
		except psutil.AccessDenied:
			if VERBOSE: print("psutil.AccessDenied for process pid={0}".format(pid))

	hashset = set(hashlist)					# save unique hashes in a set
	uniquehashes = list(hashset)			# list of unique hashes

	if VERBOSE:
		print("{0} processes found".format(len(pd)))
		print("{0} unique hashes found".format(len(hashset)))

	# initialize VirusTotal gofer object to fetch reports
	# set gofer 'resource' to sorted list of unique hashes
	# request reports

	gofer = vt2public.FileScanGofer(APIKEY)
	gofer.resource = uniquehashes 
	gofer.fetch()

	if VERBOSE: print("Found {0} Reports".format(len(gofer.reports)))
	if DEBUG: print("found {0} PIDs".format(len(pd.keys())))

	header = ["pid","name","status","positives","total","permalink"]

	# merge process and reports list
	row = []
	table = []

	for pid in sorted(pd.keys()):
		p = pd[pid]

		try:
			r = gofer.reports[p.sha256]
			row = [pid,p.name,r.status,r.positives,r.total,r.permalink]
			table.append(row)

		except KeyError as e:
			# surpress records with out matches in Test Mode
			if not TEST:	
				row = [pid,"None","None","None","None","None"]

			if DEBUG: 
				print("KeyError:")
				print("\tHash {0} not found in gofer.reports".format(e))
				print("\tReport not found for {0} {1}".format(pid,p.name))

		except Exception as e:
			# surpress records with out matches in Test Mode
			if not TEST:	
				row = [pid,"None","None","None","None","None"]

			if DEBUG:
				print("Exception occured trying to access FileScanReports[{0}] for process {1}/{2}".format(p.sha256,p.pid,p.name))
				print("\t{0}".format(e))
				# row = [pid,"None","None","None","None","None"]
				

	if TEST: print("*** Test Mode: result limited to the first chunk fetched from VirusTotal.")
	if TEST: print("printing {0} records".format(len(table)))
	print(tabulate(table,header))



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


def parseCommandLine():
	# parse command-line optons
	parser = argparse.ArgumentParser(prog=TITLE, description=DESCRIPTION, epilog=EPILOG)
	parser.add_argument("-v", "--verbose", help="increase verbosity (use --vv for greater effect)", action="count")
	parser.add_argument("-t", "--test", help="test mode", action="store_true")
	parser.add_argument("-k", "--key", help="VirusTotal 2 Public API key")
	parser.add_argument("pid", nargs='?', type=int, help="process ID", default=None)
	parser.add_argument('-V', '--version', action='version', version='%(prog)s {0}'.format(VERSION))
	args = parser.parse_args()
	return args


""" MAIN """

print ("{0} {1}".format(TITLE,VERSION))

args = parseCommandLine()

print args

VERBOSE = (args.verbose >= 1)
DEBUG = (args.verbose > 1)
TEST = args.test
PID = args.pid
APIKEY = getAPIKEY(args.key)

vt2public.Flags.VERBOSE = VERBOSE
vt2public.Flags.DEBUG = DEBUG
vt2public.Flags.TEST = TEST

if VERBOSE: print("Verbose mode")
if DEBUG: print("Debug mode")
if TEST: print("Test mode")

if args.pid > 0:
	SpyOnOne(args.pid)
else:
	SpyOnAll()