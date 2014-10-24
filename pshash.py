import psutil
import hashlib

""" 
	
	pshash.py - xtension of psUtil.Process to calculates a hash for a process' executable

	Author: 	Paul Dicovitsky
	Copyright 2014 Paul Dicovitsky 
	License: 	GNU General Public License Version 3 or later

	Class Definitions:
	
		ProcHash = extension of psUtil.Process that calculates a hash of process executable

"""

class ProcHash (psutil.Process):

	""" Extension of psUtil.Process that calculates SHA256 hashes for a given process

	Attributes:
		pid (str): process ID
		name (str): process name
		exe (str): process exe (fully qualified)
		sha256 (str): SHA256 hash of process exe

	"""

	# class specific constants
	_SHA_BLOCKSIZE = 65536
	_READBINARY = 'rb'			# Python file open mode (read/binary)
	_IOERROR_MSG = 'IOError'	# value to substitue for hash when an IOError occurs

	def __init__(self, pid):
		psutil.Process.__init__(self,pid)
		self._pid = super(ProcHash,self).pid
		self._name = super(ProcHash,self).name()
		self._exe = super(ProcHash,self).exe()
		self._sha256 = self.__sha256()


 	def __sha256(self):
		try:
			pexe = super(ProcHash,self).exe()
			with open(pexe, ProcHash._READBINARY) as f:		
				h = hashlib.sha256()
				while True:
					data = f.read(ProcHash._SHA_BLOCKSIZE)		
					if not data:
						break
					h.update(data)
			return h.hexdigest()
		except IOError:
			return ProcHash._IOERROR_MSG


	# properties for pid, name, and exe make calls consist
	# p.name works, p.name() is not required.

	@property
	def pid(self):
	    return self._pid
	
	@property
	def name(self):
		return self._name
	
	@property
	def exe(self):
		return self._exe

	@property
	def sha256(self):
		return self._sha256

	def __str__(self):
		return "{0} {1} {2} {3}".format(self._pid, self._name, self._exe, self._sha256)

