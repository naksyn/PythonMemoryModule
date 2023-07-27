#!/usr/bin/env python
# encoding: utf-8
"""
Author: @naksyn (c) 2023
Description: Python porting of MemoryModule technique
Instructions: See README on https://github.com/naksyn/PythonMemoryModule
Credits:
  - C language code and original technique by Joachim Bauch https://github.com/fancycode/MemoryModule
  - https://github.com/juntalis/memmodule

Copyright 2023
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""
import sys
from ctypes import *
from ctypes.wintypes import *
import pythonmemorymodule.pefile as pe
import windows
import threading
import time

kernel32 = windll.kernel32


# debug flag
debug_output = __debug__

# system DLLs
_kernel32 = WinDLL('kernel32')
_msvcrt = CDLL('msvcrt')

# Check if the current machine is x64 or x86
isx64 = sizeof(c_void_p) == sizeof(c_ulonglong)

# type declarations
PWORD = POINTER(WORD)
PDWORD = POINTER(DWORD)
PHMODULE = POINTER(HMODULE)

LONG_PTR = c_longlong if isx64 else LONG
ULONG_PTR2 = c_ulong
ULONG_PTR = c_ulonglong if isx64 else DWORD
UINT_PTR = c_ulonglong if isx64 else c_uint
SIZE_T = ULONG_PTR
POINTER_TYPE = ULONG_PTR
POINTER_TYPE2 = ULONG_PTR2
LP_POINTER_TYPE = POINTER(POINTER_TYPE)
FARPROC = CFUNCTYPE(None)
PFARPROC = POINTER(FARPROC)
c_uchar_p = POINTER(c_ubyte)
c_ushort_p = POINTER(c_ushort)

# Generic Constants
NULL = 0

# Win32/Module-specific constants
IMAGE_SIZEOF_SHORT_NAME = 8
IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
IMAGE_SIZEOF_SECTION_HEADER = 40

# Struct declarations
class IMAGE_SECTION_HEADER_MISC(Union):
	_fields_ = [
		('PhysicalAddress', DWORD),
		('VirtualSize', DWORD),
	]


class IMAGE_SECTION_HEADER(Structure):
	_anonymous_ = ('Misc',)
	_fields_ = [
		('Name', BYTE * IMAGE_SIZEOF_SHORT_NAME),
		('Misc', IMAGE_SECTION_HEADER_MISC),
		('VirtualAddress', DWORD),
		('SizeOfRawData', DWORD),
		('PointerToRawData', DWORD),
		('PointerToRelocations', DWORD),
		('PointerToLinenumbers', DWORD),
		('NumberOfRelocations', WORD),
		('NumberOfLinenumbers', WORD),
		('Characteristics', DWORD),
	]

PIMAGE_SECTION_HEADER = POINTER(IMAGE_SECTION_HEADER)


class IMAGE_DOS_HEADER(Structure):
	_fields_ = [
		('e_magic', WORD),
		('e_cblp', WORD),
		('e_cp', WORD),
		('e_crlc', WORD),
		('e_cparhdr', WORD),
		('e_minalloc', WORD),
		('e_maxalloc', WORD),
		('e_ss', WORD),
		('e_sp', WORD),
		('e_csum', WORD),
		('e_ip', WORD),
		('e_cs', WORD),
		('e_lfarlc', WORD),
		('e_ovno', WORD),
		('e_res', WORD * 4),
		('e_oemid', WORD),
		('e_oeminfo', WORD),
		('e_res2', WORD * 10),
		('e_lfanew', LONG),
	]

PIMAGE_DOS_HEADER = POINTER(IMAGE_DOS_HEADER)

''' ref: https://github.com/wine-mirror/wine/blob/master/include/winnt.h

typedef struct _IMAGE_TLS_DIRECTORY64 {
	ULONGLONG   StartAddressOfRawData;
	ULONGLONG   EndAddressOfRawData;
	ULONGLONG   AddressOfIndex;
	ULONGLONG   AddressOfCallBacks;
	DWORD	   SizeOfZeroFill;
	DWORD	   Characteristics;
} IMAGE_TLS_DIRECTORY64, *PIMAGE_TLS_DIRECTORY64;


typedef VOID (CALLBACK *PIMAGE_TLS_CALLBACK)(
	LPVOID DllHandle,DWORD Reason,LPVOID Reserved
);
'''

#ref: https://github.com/arizvisa/syringe/blob/1f0ea1f514426fd774903c70d03638ecd40a97c3/lib/pecoff/portable/tls.py

class IMAGE_TLS_CALLBACK(c_void_p):
	'''
	void NTAPI IMAGE_TLS_CALLBACK(PVOID DllHandle, DWORD Reason, PVOID Reserved)
	'''

PIMAGE_TLS_CALLBACK = POINTER(IMAGE_TLS_CALLBACK)

class IMAGE_TLS_DIRECTORY(Structure):
	_fields_ = [
		('StartAddressOfRawData', c_ulonglong),
		('EndAddressOfRawData', c_ulonglong),
		('AddressOfIndex', c_ulonglong),
		('AddressOfCallBacks', c_ulonglong),
		('SizeOfZeroFill', DWORD),
		('Characteristics', DWORD),
	]
	
PIMAGE_TLS_DIRECTORY = POINTER(IMAGE_TLS_DIRECTORY)



class IMAGE_DATA_DIRECTORY(Structure):
	_fields_ = [
		('VirtualAddress', DWORD),
		('Size', DWORD),
	]

PIMAGE_DATA_DIRECTORY = POINTER(IMAGE_DATA_DIRECTORY)


class IMAGE_BASE_RELOCATION(Structure):
	_fields_ = [
		('VirtualAddress', DWORD),
		('SizeOfBlock', DWORD),
	]

PIMAGE_BASE_RELOCATION = POINTER(IMAGE_BASE_RELOCATION)


class IMAGE_EXPORT_DIRECTORY(Structure):
	_fields_ = [
		('Characteristics', DWORD),
		('TimeDateStamp', DWORD),
		('MajorVersion', WORD),
		('MinorVersion', WORD),
		('Name', DWORD),
		('Base', DWORD),
		('NumberOfFunctions', DWORD),
		('NumberOfNames', DWORD),
		('AddressOfFunctions', DWORD),
		('AddressOfNames', DWORD),
		('AddressOfNamesOrdinals', DWORD),
	]

PIMAGE_EXPORT_DIRECTORY = POINTER(IMAGE_EXPORT_DIRECTORY)


class IMAGE_IMPORT_DESCRIPTOR_START(Union):
	_fields_ = [
		('Characteristics', DWORD),
		('OriginalFirstThunk', DWORD),
	]


class IMAGE_IMPORT_DESCRIPTOR(Structure):
	_anonymous_ = ('DUMMY',)
	_fields_ = [
		('DUMMY', IMAGE_IMPORT_DESCRIPTOR_START),
		('TimeDateStamp', DWORD),
		('ForwarderChain',DWORD),
		('Name', DWORD),
		('FirstThunk', DWORD),
	]

PIMAGE_IMPORT_DESCRIPTOR = POINTER(IMAGE_IMPORT_DESCRIPTOR)


class IMAGE_IMPORT_BY_NAME(Structure):
	_fields_ = [
		('Hint', WORD),
		('Name', ARRAY(BYTE, 1)),
	]

PIMAGE_IMPORT_BY_NAME = POINTER(IMAGE_IMPORT_BY_NAME)

class IMAGE_OPTIONAL_HEADER(Structure):
	_fields_ = [
		('Magic', WORD),
		('MajorLinkerVersion', BYTE),
		('MinorLinkerVersion', BYTE),
		('SizeOfCode', DWORD),
		('SizeOfInitializedData', DWORD),
		('SizeOfUninitializedData', DWORD),
		('AddressOfEntryPoint', DWORD),
		('BaseOfCode', DWORD),
		('BaseOfData', DWORD),
		('ImageBase', POINTER_TYPE),
		('SectionAlignment', DWORD),
		('FileAlignment', DWORD),
		('MajorOperatingSystemVersion', WORD),
		('MinorOperatingSystemVersion', WORD),
		('MajorImageVersion', WORD),
		('MinorImageVersion', WORD),
		('MajorSubsystemVersion', WORD),
		('MinorSubsystemVersion', WORD),
		('Reserved1', DWORD),
		('SizeOfImage', DWORD),
		('SizeOfHeaders', DWORD),
		('CheckSum', DWORD),
		('Subsystem', WORD),
		('DllCharacteristics', WORD),
		('SizeOfStackReserve', POINTER_TYPE),
		('SizeOfStackCommit', POINTER_TYPE),
		('SizeOfHeapReserve', POINTER_TYPE),
		('SizeOfHeapCommit', POINTER_TYPE),
		('LoaderFlags', DWORD),
		('NumberOfRvaAndSizes', DWORD),
		('DataDirectory', IMAGE_DATA_DIRECTORY * IMAGE_NUMBEROF_DIRECTORY_ENTRIES),
	]

PIMAGE_OPTIONAL_HEADER = POINTER(IMAGE_OPTIONAL_HEADER)


class IMAGE_FILE_HEADER(Structure):
	_fields_ = [
		('Machine', WORD),
		('NumberOfSections', WORD),
		('TimeDateStamp', DWORD),
		('PointerToSymbolTable', DWORD),
		('NumberOfSymbols', DWORD),
		('SizeOfOptionalHeader', WORD),
		('Characteristics', WORD),
	]

PIMAGE_FILE_HEADER = POINTER(IMAGE_FILE_HEADER)


class IMAGE_NT_HEADERS(Structure):
	_fields_ = [
		('Signature', DWORD),
		('FileHeader', IMAGE_FILE_HEADER),
		('OptionalHeader', IMAGE_OPTIONAL_HEADER),
	]

PIMAGE_NT_HEADERS = POINTER(IMAGE_NT_HEADERS)

# Win32 API Function Prototypes
VirtualAlloc = _kernel32.VirtualAlloc
VirtualAlloc.restype = LPVOID
VirtualAlloc.argtypes = [LPVOID, SIZE_T, DWORD, DWORD]

VirtualFree = _kernel32.VirtualFree
VirtualFree.restype = BOOL
VirtualFree.argtypes = [ LPVOID, SIZE_T, DWORD ]

VirtualProtect = _kernel32.VirtualProtect
VirtualProtect.restype = BOOL
VirtualProtect.argtypes = [ LPVOID, SIZE_T, DWORD, PDWORD ]

HeapAlloc = _kernel32.HeapAlloc
HeapAlloc.restype = LPVOID
HeapAlloc.argtypes = [ HANDLE, DWORD, SIZE_T ]

GetProcessHeap = _kernel32.GetProcessHeap
GetProcessHeap.restype = HANDLE
GetProcessHeap.argtypes = []

HeapFree = _kernel32.HeapFree
HeapFree.restype = BOOL
HeapFree.argtypes = [ HANDLE, DWORD, LPVOID ]

GetProcAddress = _kernel32.GetProcAddress
GetProcAddress.restype = FARPROC
GetProcAddress.argtypes = [HMODULE, LPCSTR]

LoadLibraryA = _kernel32.LoadLibraryA
LoadLibraryA.restype = HMODULE
LoadLibraryA.argtypes = [ LPCSTR ]

LoadLibraryW = _kernel32.LoadLibraryW
LoadLibraryW.restype = HMODULE
LoadLibraryW.argtypes = [ LPCWSTR ]

FreeLibrary = _kernel32.FreeLibrary
FreeLibrary.restype = BOOL
FreeLibrary.argtypes = [ HMODULE ]

IsBadReadPtr = _kernel32.IsBadReadPtr
IsBadReadPtr.restype = BOOL
IsBadReadPtr.argtypes = [ LPCVOID, UINT_PTR ]

realloc = _msvcrt.realloc
realloc.restype = c_void_p
realloc.argtypes = [ c_void_p, c_size_t ]

# Type declarations 
DllEntryProc = WINFUNCTYPE(BOOL, HINSTANCE, DWORD, LPVOID)
PDllEntryProc = POINTER(DllEntryProc)
TLSexecProc = WINFUNCTYPE(BOOL, HINSTANCE, DWORD, LPVOID)
PTLSExecProc = POINTER(TLSexecProc)
HMEMORYMODULE = HMODULE

ExeEntryProc = WINFUNCTYPE(BOOL, LPVOID)
PExeEntryProc = POINTER(ExeEntryProc)

# Constants
MEM_COMMIT = 0x00001000
MEM_DECOMMIT = 0x4000
MEM_RELEASE = 0x8000
MEM_RESERVE = 0x00002000
MEM_FREE = 0x10000
MEM_MAPPED = 0x40000
MEM_RESET = 0x00080000

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_NOCACHE = 0x200

ProtectionFlags = ARRAY(ARRAY(ARRAY(c_int, 2), 2), 2)(
	(
		(PAGE_NOACCESS, PAGE_WRITECOPY),
		(PAGE_READONLY, PAGE_READWRITE),
	), (
		(PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY),
		(PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE),
	),
)


IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
IMAGE_SCN_MEM_NOT_CACHED = 0x04000000
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080

IMAGE_DIRECTORY_ENTRY_EXPORT = 0
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_RESOURCE = 2
IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3
IMAGE_DIRECTORY_ENTRY_SECURITY = 4
IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
IMAGE_DIRECTORY_ENTRY_DEBUG = 6
# IMAGE_DIRECTORY_ENTRY_COPYRIGHT = 7
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7
IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8
IMAGE_DIRECTORY_ENTRY_TLS = 9
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11
IMAGE_DIRECTORY_ENTRY_IAT = 12
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14

DLL_PROCESS_ATTACH = 1
DLL_THREAD_ATTACH = 2
DLL_THREAD_DETACH = 3
DLL_PROCESS_DETACH = 0

INVALID_HANDLE_VALUE = -1

IMAGE_SIZEOF_BASE_RELOCATION = sizeof(IMAGE_BASE_RELOCATION)
IMAGE_REL_BASED_ABSOLUTE = 0
IMAGE_REL_BASED_HIGH = 1
IMAGE_REL_BASED_LOW = 2
IMAGE_REL_BASED_HIGHLOW = 3
IMAGE_REL_BASED_HIGHADJ = 4
IMAGE_REL_BASED_MIPS_JMPADDR = 5
IMAGE_REL_BASED_MIPS_JMPADDR16 = 9
IMAGE_REL_BASED_IA64_IMM64 = 9
IMAGE_REL_BASED_DIR64 = 10

_IMAGE_ORDINAL_FLAG64 = 0x8000000000000000
_IMAGE_ORDINAL_FLAG32 = 0x80000000
_IMAGE_ORDINAL64 = lambda o: (o & 0xffff)
_IMAGE_ORDINAL32 = lambda o: (o & 0xffff)
_IMAGE_SNAP_BY_ORDINAL64 = lambda o: ((o & _IMAGE_ORDINAL_FLAG64) != 0)
_IMAGE_SNAP_BY_ORDINAL32 = lambda o: ((o & _IMAGE_ORDINAL_FLAG32) != 0)
IMAGE_ORDINAL = _IMAGE_ORDINAL64 if isx64 else _IMAGE_ORDINAL32
IMAGE_SNAP_BY_ORDINAL = _IMAGE_SNAP_BY_ORDINAL64 if isx64 else _IMAGE_SNAP_BY_ORDINAL32
IMAGE_ORDINAL_FLAG = _IMAGE_ORDINAL_FLAG64 if isx64 else _IMAGE_ORDINAL_FLAG32

IMAGE_DOS_SIGNATURE = 0x5A4D # MZ
IMAGE_OS2_SIGNATURE = 0x454E # NE
IMAGE_OS2_SIGNATURE_LE = 0x454C # LE
IMAGE_VXD_SIGNATURE = 0x454C # LE
IMAGE_NT_SIGNATURE = 0x00004550 # PE00

class MEMORYMODULE(Structure):
	_fields_ = [
		('headers', PIMAGE_NT_HEADERS),
		('codeBase', c_void_p),
		('modules', PHMODULE),
		('numModules', c_int),
		('initialized', c_int),
	]
PMEMORYMODULE = POINTER(MEMORYMODULE)

def as_unsigned_buffer(sz=None, indata=None):
	if sz is None:
		if indata is None:
			raise Exception('Must specify initial data or a buffer size.')
		sz = len(indata)
	rtype = (c_ubyte * sz)
	if indata is None:
		return rtype
	else:
		tindata = type(indata)
		if tindata in [ int, int ]:
			return rtype.from_address(indata)
		elif tindata in [ c_void_p, DWORD, POINTER_TYPE ] or hasattr(indata, 'value') and type(indata.value) in [ int, int ]:
			return rtype.from_address(indata.value)
		else:
			return rtype.from_address(addressof(indata))

def create_unsigned_buffer(sz, indata):
	res = as_unsigned_buffer(sz)()
	for i, c in enumerate(indata):
		if type(c) in [ str, str, str ]:
			c = ord(c)
		res[i] = c
	return res

def getprocaddr(handle,func):
	kernel32.GetProcAddress.argtypes = [c_void_p, c_char_p]
	kernel32.GetProcAddress.restype = c_void_p
	address = kernel32.GetProcAddress(handle, func)
	return address

class MemoryModule(pe.PE):

	_foffsets_ = {}

	def __init__(self, name = None, data = None, debug=False, command=None):
		self._debug_ = debug or debug_output
		self.new_command=command
		pe.PE.__init__(self, name, data)
		self.load_module()

	def dbg(self, msg, *args):
		if not self._debug_: return
		if len(args) > 0:
			msg = msg % tuple(args)
		print('DEBUG: %s' % msg)

	def cmdline_check(self):
		cp=windows.current_process
		peb = windows.current_process.peb
		
		commandline = peb.commandline
		self.dbg("Original PEB commamdline length: {}".format(commandline.Length))
		self.dbg("New command ommand length: {}".format(len(self.new_command)))

		if len(self.new_command) > commandline.Length:
			print("[!] Error - Not enough space on PEB commandline for stomping. Try increasing the commandline (e.g. by placing python binary in a nested folder) - Exiting")
			sys.exit()

	def stomp_PEB(self):
		self.cp=windows.current_process
		peb = windows.current_process.peb
		self.dbg("Current process PEB is <{0}>".format(peb))
		
		self.commandline = peb.commandline  
		self.cmdlineaddr= self.commandline.Buffer
		self.cmdlinetext=self.cp.read_memory(self.cmdlineaddr, self.commandline.Length).decode("utf-16")

		self.dbg("Original commandline: {}".format(self.cmdlinetext))  
		newcmd=self.new_command + " \x00"
		encnewcmd=newcmd.encode("utf-16")

		self.cp.write_memory(self.cmdlineaddr,encnewcmd)
 
		self.dbg("Stomped commandline: {}".format(self.cp.read_memory(self.cmdlineaddr, self.commandline.Length).decode("utf-16")))

	
	def unstomp_PEB(self):
		time.sleep(2)
		self.dbg("Restoring original commandline: {}".format(self.cmdlinetext))
		self.cp.write_memory(self.cmdlineaddr,self.cmdlinetext.encode("utf-16"))


	def execPE(self):
			codebase = self._codebaseaddr
			entryaddr = self.pythonmemorymodule.contents.headers.contents.OptionalHeader.AddressOfEntryPoint		
		
			self.dbg('Checking for entry point.')
			if entryaddr != 0:
				entryaddr += codebase		 
				
				if self.is_exe():
					ExeEntry = ExeEntryProc(entryaddr)
					if not bool(ExeEntry):
						self.free_library()
						raise WindowsError('exe has no entry point.\n')
					try:
						self.dbg("Calling exe entrypoint 0x%x", entryaddr)					
						success = ExeEntry(entryaddr)
					except Exception as e:
						print(e)
						
				elif self.is_dll():
					DllEntry = DllEntryProc(entryaddr)
					if not bool(DllEntry):
						self.free_library()
						raise WindowsError('dll has no entry point.\n')
						
					try:
						self.dbg("Calling dll entrypoint 0x%x with DLL_PROCESS_ATTACH", entryaddr)
						success = DllEntry(codebase, DLL_PROCESS_ATTACH, 0)
					except Exception as e:
						print(e)
						
				if not bool(success):
					if self.is_dll():
						self.free_library()
						raise WindowsError('dll could not be loaded.')
					else:
						self.free_exe()
						raise WindowsError('exe could not be loaded')
				self.pythonmemorymodule.contents.initialized = 1
	
	def load_module(self):
		if self.new_command:
			self.cmdline_check()

		if not self.is_exe() and not self.is_dll():
			raise WindowsError('The specified module does not appear to be an exe nor a dll.')
		if self.PE_TYPE == pe.OPTIONAL_HEADER_MAGIC_PE and isx64:
			raise WindowsError('The exe you attempted to load appears to be an 32-bit exe, but you are using a 64-bit version of Python.')
		elif self.PE_TYPE == pe.OPTIONAL_HEADER_MAGIC_PE_PLUS and not isx64:
			raise WindowsError('The exe you attempted to load appears to be an 64-bit exe, but you are using a 32-bit version of Python.')
		
		self._codebaseaddr = VirtualAlloc(
			self.OPTIONAL_HEADER.ImageBase, # To test relocations, add some values here i.e. +int(0x030000000)
			self.OPTIONAL_HEADER.SizeOfImage,
			MEM_RESERVE,
			PAGE_READWRITE
		)

		if not bool(self._codebaseaddr):
			self._codebaseaddr = VirtualAlloc(
				NULL,
				self.OPTIONAL_HEADER.SizeOfImage,
				MEM_RESERVE,
				PAGE_READWRITE
			)
			if not bool(self._codebaseaddr):
				raise WindowsError('Cannot reserve memory')

		codebase = self._codebaseaddr
		self.dbg('Reserved %d bytes for dll at address: 0x%x', self.OPTIONAL_HEADER.SizeOfImage, codebase)
		self.pythonmemorymodule = cast(HeapAlloc(GetProcessHeap(), 0, sizeof(MEMORYMODULE)), PMEMORYMODULE)
		self.pythonmemorymodule.contents.codeBase = codebase
		self.pythonmemorymodule.contents.numModules = 0
		self.pythonmemorymodule.contents.modules = cast(NULL, PHMODULE)
		self.pythonmemorymodule.contents.initialized = 0

		# Committing memory.
		VirtualAlloc(
			codebase,
			self.OPTIONAL_HEADER.SizeOfImage,
			MEM_COMMIT,
			PAGE_READWRITE
		)
		self._headersaddr = VirtualAlloc(
			codebase,
			self.OPTIONAL_HEADER.SizeOfHeaders,
			MEM_COMMIT,
			PAGE_READWRITE
		)
		if not bool(self._headersaddr):
			raise WindowsError('Could not commit memory for PE Headers!')

		szheaders = self.DOS_HEADER.e_lfanew + self.OPTIONAL_HEADER.SizeOfHeaders
		tmpheaders = create_unsigned_buffer(szheaders, self.__data__[:szheaders])
		if not memmove(self._headersaddr, cast(tmpheaders, c_void_p), szheaders):
			 raise RuntimeError('memmove failed')
		del tmpheaders

		self._headersaddr += self.DOS_HEADER.e_lfanew
		self.pythonmemorymodule.contents.headers = cast(self._headersaddr, PIMAGE_NT_HEADERS)
		self.pythonmemorymodule.contents.headers.contents.OptionalHeader.ImageBase = POINTER_TYPE(self._codebaseaddr)
		self.dbg('Copying sections to reserved memory block.')
		self.copy_sections()

		
		self.dbg('Checking for base relocations.')
		locationDelta = codebase - self.OPTIONAL_HEADER.ImageBase
		if locationDelta != 0:
			self.dbg('Detected relocations - Performing base relocations..')
			self.perform_base_relocations(locationDelta)

		self.dbg('Building import table.')
		self.build_import_table()
		self.dbg('Finalizing sections.')
		self.finalize_sections()
		self.dbg('Executing TLS.')
		self.ExecuteTLS()
		self.dbg('Stomping PEB')
		self.stomp_PEB()
		
		
		
		self.dbg('Starting new thread to execute PE')
		my_thread = threading.Thread(target=self.execPE)
		my_thread.start()
		self.unstomp_PEB()
			
	   
	def IMAGE_FIRST_SECTION(self):
		return self._headersaddr + IMAGE_NT_HEADERS.OptionalHeader.offset + self.FILE_HEADER.SizeOfOptionalHeader
	
	def copy_sections(self):
		codebase = self._codebaseaddr
		sectionaddr = self.IMAGE_FIRST_SECTION()
		numSections = self.pythonmemorymodule.contents.headers.contents.FileHeader.NumberOfSections
		
		for i in range(0, numSections):	
			if self.sections[i].SizeOfRawData == 0:
				size = self.OPTIONAL_HEADER.SectionAlignment
				if size > 0:
					destBaseAddr = codebase + self.sections[i].VirtualAddress
					dest = VirtualAlloc(destBaseAddr, size, MEM_COMMIT, PAGE_READWRITE )
					self.sections[i].Misc_PhysicalAddress = dest 
					memset(dest, 0, size)
				continue
			size = self.sections[i].SizeOfRawData
			dest = VirtualAlloc(codebase + self.sections[i].VirtualAddress, size, MEM_COMMIT, PAGE_READWRITE )
			if dest <=0:
				raise WindowsError('Error copying section no. %s to address: 0x%x',self.sections[i].Name.decode('utf-8'),dest)
			self.sections[i].Misc_PhysicalAddress = dest
			tmpdata = create_unsigned_buffer(size, self.__data__[self.sections[i].PointerToRawData:(self.sections[i].PointerToRawData+size)])
			if not memmove(dest, tmpdata, size):
				raise RuntimeError('memmove failed')
			del tmpdata
			self.dbg('Copied section no. %s to address: 0x%x', self.sections[i].Name.decode('utf-8'), dest)
			i += 1
			

	def ExecuteTLS(self):
		codebase = self._codebaseaddr
		
		directory = self.OPTIONAL_HEADER.DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_TLS] 
		if directory.VirtualAddress <= 0: 
			self.dbg("no TLS address found")
			return True
	
		tlsaddr = codebase + directory.VirtualAddress
		tls = IMAGE_TLS_DIRECTORY.from_address(tlsaddr)
		callback = IMAGE_TLS_CALLBACK.from_address(tls.AddressOfCallBacks)
		callbackaddr=tls.AddressOfCallBacks
		
		while(callback):
			TLSexec=TLSexecProc(callback.value)
			tlsres= TLSexec( cast(codebase,LPVOID), DLL_PROCESS_ATTACH, 0)
			if not bool(tlsres):
				raise WindowsError('TLS could not be executed.')
			else:
				# 8 bytes step - this is the size of the callback field in the TLS callbacks table. Need to initialize callback to IMAGE_TLS_CALLBACK with
				# the updated address, otherwise callback.value won't be null when the callback table is finished and the while won't exit
				self.dbg("TLS callback executed")
				callbackaddr+=sizeof(c_ulonglong)
				callback= IMAGE_TLS_CALLBACK.from_address(callbackaddr)				

	def finalize_sections(self):
		sectionaddr = self.IMAGE_FIRST_SECTION()
		numSections = self.pythonmemorymodule.contents.headers.contents.FileHeader.NumberOfSections
		imageOffset = POINTER_TYPE(self.pythonmemorymodule.contents.headers.contents.OptionalHeader.ImageBase & 0xffffffff00000000) if isx64 else POINTER_TYPE(0)
		checkCharacteristic = lambda sect, flag: 1 if (sect.contents.Characteristics & flag) != 0 else 0
		getPhysAddr = lambda sect: section.contents.PhysicalAddress | imageOffset.value
		
		self.dbg("Found %d total sections.",numSections)
		for i in range(0, numSections):
			self.dbg("Section n. %d",i)
			
			section = cast(sectionaddr, PIMAGE_SECTION_HEADER)
			size = section.contents.SizeOfRawData
			if size == 0:
				if checkCharacteristic(section, IMAGE_SCN_CNT_INITIALIZED_DATA):
					self.dbg("Zero size rawdata section")
					size = self.pythonmemorymodule.contents.headers.contents.OptionalHeader.SizeOfInitializedData
				elif checkCharacteristic(section, IMAGE_SCN_CNT_UNINITIALIZED_DATA):
					size = self.pythonmemorymodule.contents.headers.contents.OptionalHeader.SizeOfUninitializedData
					self.dbg("Uninitialized data, return")
					continue
			if size == 0:
				self.dbg("zero size section")
				continue
			self.dbg("size=%d",size)	
			oldProtect = DWORD(0)
			self.dbg("execute %d",checkCharacteristic(section, IMAGE_SCN_MEM_EXECUTE))
			executable = checkCharacteristic(section, IMAGE_SCN_MEM_EXECUTE)
			self.dbg("read %d",checkCharacteristic(section, IMAGE_SCN_MEM_READ))
			readable = checkCharacteristic(section, IMAGE_SCN_MEM_READ)
			writeable = checkCharacteristic(section, IMAGE_SCN_MEM_WRITE)
			self.dbg("write %d",checkCharacteristic(section, IMAGE_SCN_MEM_WRITE))

			if checkCharacteristic(section, IMAGE_SCN_MEM_DISCARDABLE):
				addr = self.sections[i].Misc_PhysicalAddress #getPhysAddr(section)
				self.dbg("physaddr:0x%x", addr)
				VirtualFree(addr, section.contents.SizeOfRawData, MEM_DECOMMIT)
				continue

			protect = ProtectionFlags[executable][readable][writeable]
			self.dbg("Protection flag:%d",protect)
			if checkCharacteristic(section, IMAGE_SCN_MEM_NOT_CACHED):
				print("not cached")			
				protect |= PAGE_NOCACHE
			

			size = section.contents.SizeOfRawData
			if size == 0:
				if checkCharacteristic(section, IMAGE_SCN_CNT_INITIALIZED_DATA):
					size = self.pythonmemorymodule.contents.headers.contents.OptionalHeader.SizeOfInitializedData
				elif checkCharacteristic(section, IMAGE_SCN_CNT_UNINITIALIZED_DATA):
					size = self.pythonmemorymodule.contents.headers.contents.OptionalHeader.SizeOfUninitializedData
			if size > 0:
				addr = self.sections[i].Misc_PhysicalAddress #getPhysAddr(section)
				self.dbg("physaddr:0x%x", addr)
				if VirtualProtect(addr, size, protect, byref(oldProtect)) == 0:
					raise WindowsError("Error protecting memory page")
			sectionaddr += sizeof(IMAGE_SECTION_HEADER)
			i += 1

	
	def perform_base_relocations(self, delta):
		codeBaseAddr = self._codebaseaddr
		directory = self.OPTIONAL_HEADER.DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_BASERELOC]
		if directory.Size <= 0: return
		relocaddr=codeBaseAddr + directory.VirtualAddress
		relocation = IMAGE_BASE_RELOCATION.from_address(relocaddr)

		maxreloc = lambda r: (relocation.SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION) / 2
		while relocation.VirtualAddress > 0:
			i = 0
			dest = codeBaseAddr + relocation.VirtualAddress
			relinfoaddr = relocaddr + IMAGE_SIZEOF_BASE_RELOCATION
			while i < maxreloc(relocaddr):
				relinfo = c_ushort.from_address(relinfoaddr)
				type = relinfo.value >> 12
				offset = relinfo.value & 0xfff
				if type == IMAGE_REL_BASED_ABSOLUTE:
					self.dbg("Skipping relocation")
				elif type == IMAGE_REL_BASED_HIGHLOW or (type == IMAGE_REL_BASED_DIR64 and isx64):
					self.dbg("Relocating offset: 0x%x", offset)
					patchAddrHL = cast(dest + offset, LP_POINTER_TYPE)
					patchAddrHL.contents.value += delta
				else:
					self.dbg("Unknown relocation at address: 0x%x", relocation)
					break
				# advancing two bytes at a time in the relocation table
				relinfoaddr += 2
				i += 1
			relocaddr += relocation.SizeOfBlock
			relocation = IMAGE_BASE_RELOCATION.from_address(relocaddr)
	
	
	def build_import_table(self, dlopen = LoadLibraryW):
		codebase = self._codebaseaddr
		self.dbg("codebase:0x%x", codebase)
		directory = self.OPTIONAL_HEADER.DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_IMPORT]
		
		if directory.Size <= 0:
			self.dbg('Import directory\'s size appears to be zero or less. Skipping.. (Probably not good)')
			return
		importdescaddr = codebase + directory.VirtualAddress
		check = not bool(IsBadReadPtr(importdescaddr, sizeof(IMAGE_IMPORT_DESCRIPTOR)))
		if not check:
			self.dbg('IsBadReadPtr(address) at address: 0x%x returned true', importdescaddr)
		i=0 # index for entry import struct
		for i in range(0, len(self.DIRECTORY_ENTRY_IMPORT)):
			self.dbg('Found importdesc at address: 0x%x', importdescaddr)
			importdesc = directory.VirtualAddress 
			
			# ref: https://sites.google.com/site/peofcns/win32forth/pe-header-f/02-image_directory/02-import_descriptor
			entry_struct=self.DIRECTORY_ENTRY_IMPORT[i].struct
			entry_imports=self.DIRECTORY_ENTRY_IMPORT[i].imports
			dll = self.DIRECTORY_ENTRY_IMPORT[i].dll.decode('utf-8')
			if not bool(dll):
				self.dbg('Importdesc at address 0x%x name is NULL. Skipping load library', importdescaddr)
				hmod = dll
			else:
				self.dbg('Found imported DLL, %s. Loading..', dll)
				hmod = dlopen(dll)
				if not bool(hmod): raise WindowsError('Failed to load library, %s' % dll)
				result_realloc= realloc(
					self.pythonmemorymodule.contents.modules,
					(self.pythonmemorymodule.contents.modules._b_base_.numModules + 1) * sizeof(HMODULE)
				)
				if not bool(result_realloc):
					raise WindowsError('Failed to allocate additional room for our new import.')
				self.pythonmemorymodule.contents.modules = cast(result_realloc, type(self.pythonmemorymodule.contents.modules))
				self.pythonmemorymodule.contents.modules[self.pythonmemorymodule.contents.modules._b_base_.numModules] = hmod
				self.pythonmemorymodule.contents.modules._b_base_.numModules += 1


			thunkrefaddr = funcrefaddr = codebase + entry_struct.FirstThunk
			if entry_struct.OriginalFirstThunk > 0:
				thunkrefaddr = codebase + entry_struct.OriginalFirstThunk
			
			for j in range(0, len(entry_imports)):
			
				funcref = cast(funcrefaddr, PFARPROC)
				if entry_imports[j].import_by_ordinal == True: 
					if 'decode' in dir(entry_imports[j].ordinal):
						importordinal= entry_imports[j].ordinal.decode('utf-8')
					else:
						importordinal= entry_imports[j].ordinal
					self.dbg('Found import ordinal entry, %s', cast(importordinal, LPCSTR))
					funcref.contents = GetProcAddress(hmod, cast(importordinal, LPCSTR))
					address = funcref.contents
				else:
					importname= entry_imports[j].name.decode('utf-8') 
					self.dbg('Found import by name entry %s , at address 0x%x', importname, entry_imports[j].address)
					address= getprocaddr(hmod, importname.encode())
					if not memmove(funcrefaddr,address.to_bytes(sizeof(LONG_PTR),'little'),sizeof(LONG_PTR)):
						raise WindowsError('memmove failed')
					self.dbg('Resolved import %s at address 0x%x', importname, address)
				if not bool(address):
					raise WindowsError('Could not locate function for thunkref %s', importname)
				funcrefaddr += sizeof(PFARPROC)
				j +=1
			i +=1 
			

	def free_library(self):
		self.dbg("Freeing dll")
		if not bool(self.pythonmemorymodule): return
		pmodule = pointer(self.pythonmemorymodule)
		if self.pythonmemorymodule.contents.initialized != 0:
			DllEntry = DllEntryProc(self.pythonmemorymodule.contents.codeBase + self.pythonmemorymodule.contents.headers.contents.OptionalHeader.AddressOfEntryPoint)
			DllEntry(cast(self.pythonmemorymodule.contents.codeBase, HINSTANCE), DLL_PROCESS_DETACH, 0)
			pmodule.contents.initialized = 0
		if bool(self.pythonmemorymodule.contents.modules) and self.pythonmemorymodule.contents.numModules > 0:
			for i in range(1, self.pythonmemorymodule.contents.numModules):
				if self.pythonmemorymodule.contents.modules[i] != HANDLE(INVALID_HANDLE_VALUE):
					FreeLibrary(self.pythonmemorymodule.contents.modules[i])

		if bool(self._codebaseaddr):
			VirtualFree(self._codebaseaddr, 0, MEM_RELEASE)

		HeapFree(GetProcessHeap(), 0, self.pythonmemorymodule)
		self.close()
		
	def free_exe(self):
		self.dbg("Freeing exe")
		if not bool(self.pythonmemorymodule): return
		pmodule = pointer(self.pythonmemorymodule)
		if bool(self._codebaseaddr):
			VirtualFree(self._codebaseaddr, 0, MEM_RELEASE)

		HeapFree(GetProcessHeap(), 0, self.pythonmemorymodule)
		self.close()

	
	def _proc_addr_by_ordinal(self, idx):
		codebase = self._codebaseaddr
		if idx == -1:
			raise WindowsError('Could not find the function specified')
		elif idx > self._exports_.NumberOfFunctions:
			raise WindowsError('Ordinal number higher than our actual count.')
		funcoffset = DWORD.from_address(codebase + self._exports_.AddressOfFunctions + (idx * 4))
		return funcoffset.value

	
	def _proc_addr_by_name(self, name):
		codebase = self._codebaseaddr
		exports = self._exports_
		if exports.NumberOfNames == 0:
			raise WindowsError('DLL doesn\'t export anything.')

		ordinal = -1
		name = name.lower()
		namerefaddr = codebase + exports.AddressOfNames
		ordinaladdr = codebase + exports.AddressOfNamesOrdinals
		i = 0
		while i < exports.NumberOfNames:
			nameref = DWORD.from_address(namerefaddr)
			funcname = string_at(codebase + nameref.value).lower()
			if funcname.decode() == name:
				ordinal = WORD.from_address(ordinaladdr).value
			i += 1
			namerefaddr += sizeof(DWORD)
			ordinaladdr += sizeof(WORD)
		return self._proc_addr_by_ordinal(ordinal)
	
	def get_proc_addr(self, name_or_ordinal):
		codebase = self._codebaseaddr
		if not hasattr(self, '_exports_'):
			directory = self.OPTIONAL_HEADER.DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_EXPORT]
			# No export table found
			if directory.Size <= 0: raise WindowsError('No export table found.')
			self._exports_ = IMAGE_EXPORT_DIRECTORY.from_address(codebase + directory.VirtualAddress)
			if self._exports_.NumberOfFunctions == 0:
				# DLL doesn't export anything
				raise WindowsError('DLL doesn\'t export anything.')
		targ = type(name_or_ordinal)
		if targ in [ str, str, str ]:
			name_or_ordinal = str(name_or_ordinal)
			procaddr_func = self._proc_addr_by_name
		elif targ in [ int, int ]:
			name_or_ordinal = int(name_or_ordinal)
			procaddr_func = self._proc_addr_by_ordinal
		else:
			raise TypeError('Don\'t know what to do with name/ordinal of type: %s!' % targ)

		if not name_or_ordinal in self._foffsets_:
			self._foffsets_[name_or_ordinal] = procaddr_func(name_or_ordinal)
		return FARPROC(codebase + self._foffsets_[name_or_ordinal])

