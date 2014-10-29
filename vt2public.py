import hashlib
import simplejson
import urllib
import urllib2
import time
import traceback
import sys

""" 
v2tpublic.pys - VirusTotal 2.0 Public API Interface module

	Author: 	Paul Dicovitsky
	Copyright 2014 Paul Dicovitsky 
	License: 	GNU General Public License Version 3 or later

Classes:
	
	Report:				base VirusTotal Report object
	DomainReport:		VirusTotal Domain Report
	FileReport:			VirusTotal File Scan Report
	Gopher:				base fetch object: retrieves reports from VirusTotal
	DomainGopher:		fetches one or more domain reports from VirusTotal
	FileGopher:			fetches one or more file scan reports from VirusTotal

"""

""" vt2public.flags """

class Flags(object):
	VERBOSE = False
	DEBUG = False
	TEST = False

	def __str__(self):
		return "VERBOSE {0} DEBUG {1} TEST {2}".format(VERBOSE,DEBUG,TEST)

""" VTScanReport """

class Report(object):
	""" Base VirusTotal Report object """
	
	# class constants
	_VT_RESPONSE_CODE = 'response_code'		# VirusTotal
	_VT_VERBOSE_MSG = 'verbose_msg'			# VirusTotal
	_VT_STATUS = "status"													# extension: Wouldn't it be nice if VT included a brief status message
	_VT_STATUS_CODE = { -1 : 'Invalid', 0 : 'Not Found', 1: 'Found'}		# extension: shorter version of verbose_msg

	def __init__(self,rd):

		""" initialize VirusTotal object with single dictionary returned from VT query """

		# dict.get() returns None if a matching key is not found

		try:		
			self._response_code = rd.get(self._VT_RESPONSE_CODE)
			self._verbose_msg = rd.get(self._VT_VERBOSE_MSG)
			self._status = Report._VT_STATUS_CODE[self._response_code]
	
		except KeyError as e:
			self._status = "Error"
			if Flags.DEBUG: print("KeyError: response_code {0} invalid".format(self._response_code))
			
		except AttributeError as e:
			if Flags.DEBUG: 
				print("Report.__init__(self,rd): AttributeError")
				print("\t{0}".format(e))
				print("rd:")
				print("\t{0}".format(rd))
			pass


	@property
	def response_code(self):
		return self._response_code
    
	@property
	def verbose_msg(self):
		return self._verbose_msg

	@property
	def status(self):
	    return self._status


class DomainReport(Report):
	""" VirusTotal Domain Report.  Result of a VirusTotal Report request """				

	# class specific constants
	_VT_POSITIVES = 'positives'												# VirusTotal
	_VT_TOTAL = 'total'														# VirusTotal
	_VT_PERMALINK = 'permalink'												# VirusTotal
	_VT_SHA256 = 'sha256'													# VirusTotal
	_VT_SCAN_DATE = 'scan_date'												# VirusTotal
	_VT_RESOURCE = "resource"												# VirusTotal
	_VT_DETECTED_URLS = "detected_urls"
	_VT_RESOLUTIONS = "resolutions"
	_VT_CATEGORIES = "categories"
	_VT_undetected_downloaded_samples = "undetected_downloaded_samples"
	_VT_detected_downloaded_samples = "detected_downloaded_samples"
	_VT_subdomains = "subdomains"

	def __init__(self,rdict):
		""" initialize VirusTotal object with single dictionary returned from VT query """

		# Instance specific variables
		# dict.get() returns None if a matching key is not found

		try:

			Report.__init__(self,rdict)		
			
			self._detectedURLs = rdict.get(self._VT_DETECTED_URLS)
			self._resolutions = rdict.get(self._VT_RESOLUTIONS)
			
			
			self._subdomains = rdict.get(self._VT_subdomains)
			self._undetected_downloaded_samples = rdict.get(self._VT_undetected_downloaded_samples)			
			self._detected_downloaded_samples = rdict.get(self._VT_detected_downloaded_samples)

			self._categories = rdict.get(self._VT_CATEGORIES)
			if type(self._categories) is list:
				self._categories = "(" + (",".join(self._categories)) + ")"

			# calculate some handy counters
			self._numberof_URLs = -1
			self._numberof_subdomains = -1
			self._numberof_undetected_downloaded_samples = -1
			self._numberof_detected_downloaded_samples = -1

			if self._response_code == 1:
				try:
					self._numberof_URLs = len(self._detectedURLs)
					self._numberof_subdomains = len(self._subdomains)
					self._numberof_undetected_downloaded_samples = len(self._undetected_downloaded_samples)
					self._numberof_detected_downloaded_samples = len(self._detected_downloaded_samples)

				except TypeError as e:
					if Flags.DEBUG: print("\t\t\tTypeError {0}".format(e))

			if Flags.DEBUG:	
				print("\t\tresponse_code: {0}, status: {1}, URLs detected: {2}".format(self._response_code,self._status, self._numberof_URLs))

		except AttributeError as e:
			if Flags.DEBUG: 
				print("DomainReport.__init__(self,rdict): AttributeError")
				print("\t{0}".format(e))
				print("rdict:")
				print("\t{0}".format(rd))


    
	@property
	def detected_urls(self):
	    return self._detected_urls

	@property
	def numberof_urls(self):
	    return self._numberof_URLs

	@property
	def resolutions(self):
	    return self._resolutions

	@property
	def categories(self):
	    return self._categories

	@property
	def subdomains(self):
	    return self._subdomains

	@property
	def numberof_subdomains(self):
	    return self._numberof_subdomains
	
	@property
	def undetected_downloaded_samples(self):
	    return self._undetected_downloaded_samples

	@property
	def numberof_undetected_downloaded_samples(self):
	    return self._numberof_undetected_downloaded_samples

	@property
	def detected_downloaded_samples(self):
	    return self._detected_downloaded_samples

	@property
	def numberof_detected_downloaded_samples(self):
	    return self._numberof_detected_downloaded_samples
	
	def __str__(self):
		return "{0} {1} {2}".format(self._response_code,self._status,self._verbose_msg, self._numberofURLs, self._numberof_subdomains, self._resolutions, self._categories, self._numberof_detected_downloaded_samples, self._numberof_undetected_downloaded_samples)
		# return "{0} {1} {2}".format(self._response_code,self._status,self._verbose_msg)


class FileScanReport(Report):
	""" VirusTotal File Scan Report.  Result of a VirusTotal Report request """				

	# class specific constants
	_VT_POSITIVES = 'positives'				# VirusTotal
	_VT_TOTAL = 'total'						# VirusTotal
	_VT_PERMALINK = 'permalink'				# VirusTotal
	_VT_SHA256 = 'sha256'					# VirusTotal
	_VT_SCAN_DATE = 'scan_date'				# VirusTotal
	_VT_RESOURCE = 'resource'				# VirusTotal
	_VT_STATUS = 'status'						# Wouldn't it be nice if VT included a brief status message
	_VT_STATUS_CODE = ['Not Found','Found']		# shorter version of verbose_msg

	def __init__(self,rd):
		""" initialize VTReport object with single dictionary returned from VT query """

		Report.__init__(self,rd)	

		# Instance specific variables
		# dict.get() returns None if a matching key is not found

		try:		

			self._positives = rd.get(FileScanReport._VT_POSITIVES)
			self._total = rd.get(FileScanReport._VT_TOTAL)
			self._sha256 = rd.get(FileScanReport._VT_SHA256)
			self._scan_date = rd.get(FileScanReport._VT_SCAN_DATE)
			self._resource = rd.get(FileScanReport._VT_RESOURCE)
			self._permalink = rd.get(FileScanReport._VT_PERMALINK)
			self._resource = rd.get(FileScanReport._VT_RESOURCE)

		except AttributeError as e:
			if Flags.DEBUG: 
				print("AttributeError: FileScanReport.__init__(self,rd): AttributeError")
				print("\t{0}".format(e))
				print("rd:")
				print("\t{0}".format(rd))
				# print("rd.help() : {0}".format(rd.help()))

	@property
	def positives(self):
	    return self._positives

	@property
	def total(self):
		return self._total
    
	@property
	def permalink(self):
		return self._permalink
    
	@property
	def resource(self):
		return self._resource

	@property
	def sha256(self):
		return self._sha256

	def __str__(self):
		return "{0} {1} {2} {3} {4}".format(self._resource,self._status,self._positives,self._total,self._permalink)



class Gofer(object):
	""" VirusTotal Public API version 2 - VirusTotal2 Report Gofer """

	# VirusTotal API service constants - fields/table headers

	_VT_MAX_QUERIES_PER_POST = 25
	_VT_MAX_QUERIES_PER_MINUTE = 4

	_HTTPGET = "get"
	_HTTPPOST = "post"

	_TOOBIG = "resource lists is longer than {0}, the maximum allowable queries per post".format(_VT_MAX_QUERIES_PER_POST)

	def __init__(self,APIKEY):
		""" Initialize VirusTotal Public API 2.0 Supplicant with valid VirusTotal Public API 2.0 KEY """
	
		self._apikey = APIKEY 					# VirusTotal 2 Public API Key
		self._querycounter = 0					# we can only submit _VT_MAX_QUERIES_PER_MINUTE per minute
		self._first_query = 0					# time of first query in a set of _VT_MAX_QUERIES_PER_MINUTE
		self._totalqueries = 0					# count 'em all, just for fun
		self._resource = []						# list of hashes, or domains, or IP addresses to fetch from Virus Total
		self._resourcecount = 0					# length the resource list
		self._reports = {}						# dictionary of reports retrieved from Virus Total


	class RateLimitExceeded(Exception):
		""" VirusTotal2 Public API Request Rate Limit Exceeded (HTTP 204) """
		def __init__(self, httpstatus):
			self._httpstatus = httpstatus
		def __str__(self):
			return repr(self._httpstatus)		
		@property
		def httpstatus(self):
		    return self._httpstatus


	class PrivilegeError(Exception):
		""" VirusTotal2 Public API Insufficient Privileges to perform requested operation (HTTP 403) """
		def __init__(self, value):
			self.value = value
		def __str__(self):
			return repr(self.value)		

	def _rate_limiter(self):
		""" 
			VirusTotal Public API only allows 4 queries per minute 
			call _rate_limiter one time for every request to VirusTotal
		"""

		# start timer
		if self._querycounter == 1:
			self._first_query = time.time()

		# increment query counter
		self._querycounter += 1
		self._totalqueries += 1 								# count 'em all, just for fun

		# check to see if we've exceeded the maximum number queries per minute
		if self._querycounter > self._VT_MAX_QUERIES_PER_MINUTE:
			elapsedtime = time.time() - self._first_query
			if elapsedtime < 60:
				self._querycounter = 1
				time2wait = 60 - elapsedtime
				if Flags.VERBOSE: 								# an now for something completely different
					hourglass = u"\u231B"				
					print(u"{0} VirusTotal Public API rate limit, please wait {1:.2f} seconds".format(hourglass, time2wait))
				time.sleep(time2wait)

	def _timeout(self):
		""" take a timeout due to an unexcepted RateLimitExceeded exception """
		_TIMEOUT = 15
		if Flags.VERBOSE: print("\tTaking a {0} second timeout".format(_TIMEOUT))
		time.sleep(_TIMEOUT)

	def _get(self,url,resource):
		""" certain VirusTotal 2 requests require an HTTP GET """

		parameters = {"domain": resource,"apikey": self._apikey}
		data = urllib.urlencode(parameters)
		full_url = url + "?" + data
		if Flags.DEBUG: print("\trequest url = {0}".format(full_url))
		req = urllib2.Request(full_url)
		
		while True:												# keep trying to beat the rate limiter

			try:
				response = urllib2.urlopen(req)
				httpstatus = response.code
				if httpstatus == 204:
					raise self.RateLimitExceeded(httpstatus)
				break	

			except self.RateLimitExceeded as e:
				police = u"\u2301"	
				if Flags.VERBOSE: print(u"{0} VirusTotal Public API Rate Limit Exceeded (HTTP Status {1})".format(police,e.httpstatus))
				self._timeout()
				continue
			
			except urllib2.URLError as e:
				if Flags.DEBUG:
					print("URLError:")
					print("\tUnable to reach server.")
					print("\tREASON {0}".format(e.reason))
					print("\tHOST {0}".format(req.host))
					print("\tDATA {0}".format(req.data))
					print("\tURL {0}".format(req.get_full_url()))
					break

			except urllib2.HTTPError as e:
				if Flags.DEBUG:
					print("HTTPError:")
					print("\treq:{0}".format(req))
					print("\t{0} {1}".format(e.code,e.read()))
					break

		if Flags.DEBUG: print("\t\tHTTP Status Code: {0}".format(httpstatus))

		return response


	def _post(self,url,resource):
		""" 
			certain VirusTotal 2 requests require an HTTP POST 
			source: https://www.virustotal.com/en/documentation/public-api/#getting-file-scans 
		"""

		parameters = {"resource": resource,"apikey": self._apikey}
		data = urllib.urlencode(parameters)
		req = urllib2.Request(url, data)

		while True:										# keep trying to beat the rate limiter

			try:
				response = urllib2.urlopen(req)
				httpstatus = response.code
				if httpstatus == 204:
					raise self.RateLimitExceeded(httpstatus)
				break

			except self.RateLimitExceeded as e:
				police = u"\u2301"
				print(u"{0}VirusTotal Public API Rate Limit Exceeded (HTTP Status {1})".format(police,e))
				self._timeout()
				continue

			except urllib2.URLError as e:
				# if Flags.DEBUG:
				police = u"\u2300"
				print(u"{0} Network Error: Unable to reach server {1} ({2})".format(police,req.host,e.reason))
				raise
					# print("URLError:")
					# print("\tREASON {0}".format(e.reason))
					# print("\tHOST {0}".format(req.host))
					# print("\tDATA {0}".format(req.data))
					# print("\tURL {0}".format(req.get_full_url()))
				break

			except urllib2.HTTPError as e:
				if Flags.DEBUG:
					print("HTTPError:")
					print("\treq:{0}".format(req))
					print("\t{0} {1}".format(e.code,e.read()))
				break

			if Flags.DEBUG: print("\t\tHTTP Status Code: {0}".format(httpstatus))

		return response
	

	def _fetch_report(self,method,url,resource):
		""" submit HTTP request to VirusTotal for a class of report """

		# don't get a speeding ticket - Virus Total only allows 4 requests per minute with the Public API
		self._rate_limiter()
		
		try:

			if method == self._HTTPGET:
				response = self._get(url,resource)

			elif method == self._HTTPPOST:
				response = self._post(url,resource)
	
			response_dict = {}
		
			try:
				json = response.read()			
				response_dict = simplejson.loads(json)

			except simplejson.scanner.JSONDecodeError as e:
				if Flags.DEBUG:
					print("JSONDecodeError:")
					print("\t{0}".format(e))
					print("\tresponse.code: {0}".format(response.code))
					print("\tresponse.msg: {0}".format(response.msg))
					print("\tjson: {0}".format(repr(json)))

			# for consistency's sake, always return a list
			if isinstance(response_dict,list):
				return response_dict
			else:												
				return [response_dict]

		except urllib2.URLError as e:
			return []

	@property
	def resource(self):
	    return self._resource

	@resource.setter
	def resource(self,resource):

		# we can accept a single hash as a string, or alist of hash strings
		if isinstance(resource,str):
			self._resource.append(resource)

		if isinstance(resource,list):
			self._resource = resource
		
		self._resourcecount = len(self._resource)

	@property
	def reports(self):
	    return self._reports


class DomainGofer(Gofer):

	""" DomainGofer: Fetches VirusTotal Domain Reports """

	# VirusTotal Domain Report URL, method
	
	_URL = "https://www.virustotal.com/vtapi/v2/domain/report"
	_METHOD = Gofer._HTTPGET			# Domain Reports require an HTTP GET

	def __init__(self,APIKEY):		
		""" Initialize VirusTotal with valid VirusTotal Public API 2.0 KEY """
		Gofer.__init__(self,APIKEY)		
	
	def fetch(self):
	
		""" query VirusTotal for each domain stored in resource """

		# query VirusTotal, one domain at a time

		if Flags.VERBOSE: print("Requesting Domain Reports {0} domains".format(len(self._resource))) 

		y = 0
		for domain in self._resource:								# resource is a list of domains to query
			y += 1
			if Flags.VERBOSE: print("\n{0} of {1}: Querying VirusTotal for domain {2}".format(y, self._resourcecount,domain))

			# submit a Domain Report request to VirusTotal
			response = self._fetch_report(self._METHOD,self._URL,domain)

			# create a Domain Report object
			report = DomainReport(response[0])															

			if Flags.DEBUG: 
				print("\tadding report for {0} to _DomainReports".format(domain))

			self._reports[domain] = report 		   		# safe the reports to the Domain Report dictionary, keyed by domain


			if Flags.VERBOSE: print("\tdomain: {0}, status: {1}, {2} URLs, categories: {3}".format(domain, report.status, report.numberof_urls, report.categories))
			# **** BREAK to speed up testing **** 
			if Flags.TEST and self._totalqueries == Gofer._VT_MAX_QUERIES_PER_MINUTE: break


class FileScanGofer(Gofer):
	""" fetches VirusTotal File Scan Reports using the VirusTotal Public API """

	# VirusTotal File Scan Report URL, method
	_URL = "https://www.virustotal.com/vtapi/v2/file/report"
	_METHOD = Gofer._HTTPPOST

	def __init__(self,APIKEY):
		""" Initialize VirusTotal with valid VirusTotal Public API 2.0 KEY """

		Gofer.__init__(self,APIKEY)		

		self._hashlist = [] 
		self._hashcount = 0

		self._chunks = []
		self._chunkcount = 0

	@property
	def resource(self):
	    return self._resource

	@resource.setter
	def resource(self,resource):

		self._resource = resource

		# we can accept a single hash as a string, or alist of hash strings
		if isinstance(resource,str):
			self._hashlist.append(resource)

		if isinstance(resource,list):
			self._hashlist = resource
			self._hashcount = len(self._hashlist)

		# resource can be a long list of hashes, but we can only process so many at once
		# so we split the list up into smaller chunks		
		self._chunks = self._chunklist(self._hashlist,self._VT_MAX_QUERIES_PER_POST)
		self._chunkcount = len(self._chunks)

	@property
	def report_count(self):
	    return len(self._reports)

	@property
	def hashcount(self):
	    return self._hashcount
	
	@property
	def chunkcount(self):
	    return self._chunkcount

	def _chunklist(self,lst,size):
		""" splits a list into smaller lists with a maximum size 
			employs a list comprehension to iterate over the input list in increments of step size
			Example:
			 	chunklist([0,1,2,3,4,5,6,7,8,9,0],3) = [[0,1,2],[3,4,5],[6,7,8],[9]]
		"""
		return [lst[x:x+size] for x in xrange(0, len(lst), size)]

	def fetch(self):
		""" query VirusTotal for File Scan Reports for every hash in hashlist """

		# query VirusTotal, one chunk at a time
		y = 0

		for chunk in self._chunks:									# resource is already cut up into bite size chunks

			y += 1

			if Flags.VERBOSE: print("Querying VirusTotal for chunk {0} of {1}: {2} hashes".format(y, self._chunkcount, len(chunk)))

			resource = ", ".join(chunk)							    # convert list to comma seperated string resource
	
			response = self._fetch_report(self._METHOD,self._URL,resource)

			for r in response:
				report = FileScanReport(r)
				self._reports[report.resource] = report

			# **** insert BREAK to speed up testing **** 
			if Flags.TEST: break
