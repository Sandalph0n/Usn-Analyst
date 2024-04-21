#The tool is referenced from several other projects on GitHub.
#https://github.com/PoorBillionaire/USN-Journal-Parser
#https://github.com/siddontang/usn



import ctypes
# from GlobObj import drives,BOOT_TIME,PREFETCH_FOLDER,RECYCLE_BIN_FOLDER,ToHumanReadable
from win32kernel import *
import os
import win32file 
from datetime import datetime
from psutil import disk_partitions
import collections
from pprint import pprint
import win32timezone

MAX_PATH = 256
drives_latter = [i.mountpoint[0] for i in disk_partitions()]



reasons = collections.OrderedDict()
reasons[0x1] = u'DATA_OVERWRITE'
reasons[0x2] = u'DATA_EXTEND'
reasons[0x4] = u'DATA_TRUNCATION'
reasons[0x10] = u'NAMED_DATA_OVERWRITE'
reasons[0x20] = u'NAMED_DATA_EXTEND'
reasons[0x40] = u'NAMED_DATA_TRUNCATION'
reasons[0x100] = u'FILE_CREATE'
reasons[0x200] = u'FILE_DELETE'
reasons[0x400] = u'EA_CHANGE'
reasons[0x800] = u'SECURITY_CHANGE'
reasons[0x1000] = u'RENAME_OLD_NAME'
reasons[0x2000] = u'RENAME_NEW_NAME'
reasons[0x4000] = u'INDEXABLE_CHANGE'
reasons[0x8000] = u'BASIC_INFO_CHANGE'
reasons[0x10000] = u'HARD_LINK_CHANGE'
reasons[0x20000] = u'COMPRESSION_CHANGE'
reasons[0x40000] = u'ENCRYPTION_CHANGE'
reasons[0x80000] = u'OBJECT_ID_CHANGE'
reasons[0x100000] = u'REPARSE_POINT_CHANGE'
reasons[0x200000] = u'STREAM_CHANGE'
reasons[0x80000000] = u'CLOSE'



attributes = collections.OrderedDict()
attributes[0x1] = u'READONLY'
attributes[0x2] = u'HIDDEN'
attributes[0x4] = u'SYSTEM'
attributes[0x10] = u'DIRECTORY'
attributes[0x20] = u'ARCHIVE'
attributes[0x40] = u'DEVICE'
attributes[0x80] = u'NORMAL'
attributes[0x100] = u'TEMPORARY'
attributes[0x200] = u'SPARSE_FILE'
attributes[0x400] = u'REPARSE_POINT'
attributes[0x800] = u'COMPRESSED'
attributes[0x1000] = u'OFFLINE'
attributes[0x2000] = u'NOT_CONTENT_INDEXED'
attributes[0x4000] = u'ENCRYPTED'
attributes[0x8000] = u'INTEGRITY_STREAM'
attributes[0x10000] = u'VIRTUAL'
attributes[0x20000] = u'NO_SCRUB_DATA'


sourceInfo = collections.OrderedDict()
sourceInfo[0x1] = u'DATA_MANAGEMENT'
sourceInfo[0x2] = u'AUXILIARY_DATA'
sourceInfo[0x4] = u'REPLICATION_MANAGEMENT'

def ToRelativeTime(past_time:int,current_time = int(datetime.now().timestamp()), exactly = False):
	try:
		time_string = ""
		dif_time =  current_time - int(past_time)
		if dif_time <= 0:
			return "1s "
		days,sec_remainder = divmod(dif_time,86400)
		if days > 0:
			time_string += f"{days}d "
		hours,sec_remainder = divmod(sec_remainder,3600)
		if hours > 0:
			time_string += f"{hours}h "
		minutes,sec_remainder = divmod(sec_remainder,60)
		if minutes > 0:
			time_string += f"{minutes}m "
		if (sec_remainder > 0 and exactly) or (days ==0 and hours == 0 and minutes == 0):
			# print(exactly)
			time_string += f"{sec_remainder}s "

		return time_string 
	except:
		return "Unknown "

def ToHumanReadable(time_stamp:int):
	try:
		return datetime.fromtimestamp(time_stamp).strftime("%d/%m/%Y %H:%M:%S")
	except:
		return "Unknown"



def convertAttributes(attributeType, data):
	attributeList = [attributeType[i] for i in attributeType if i & data]
	return u' '.join(attributeList)

def convertFileReference(buf):
	sequenceNumber = (buf >> 48) & 0xFFFF
	entryNumber = buf & 0xFFFFFFFFFFFF
	return sequenceNumber, entryNumber

def getFileSystemName(volumeName):    
	sysNameBuf = ctypes.create_unicode_buffer(MAX_PATH + 1)

	volName = volumeName.upper() + ":\\"
	ret = GetVolumeInformationW(
		ctypes.c_wchar_p(volName),
		None,
		0,
		None,
		None,
		None,
		sysNameBuf,
		len(sysNameBuf))

	if ret != 0:
		print(sysNameBuf.value)
		return sysNameBuf.value
	else:
		return ''
	
def checkNtfs(path):
	name = getFileSystemName(path)
	if name == 'NTFS':
		return True

	return False

def getVolumeHandle(volumeName):
	volumeName = volumeName.upper()
	name = "\\\\.\\" + volumeName + ":"
	hHandle = CreateFileW(ctypes.c_wchar_p(name),
							  FILE_GENERIC_READ,
							  FILE_SHARE_READ | FILE_SHARE_WRITE,
							  None,
							  OPEN_EXISTING,
							  FILE_ATTRIBUTE_READONLY,
							  None)
	return hHandle

def initUsnJournal(hVolHandle):
	br = DWORD()
	cujd = CREATE_USN_JOURNAL_DATA()
	cujd.MaximumSize = 0
	cujd.AllocationDelta = 0

	
	status = DeviceIoControl(hVolHandle,
							 FSCTL_CREATE_USN_JOURNAL,
							 ctypes.byref(cujd),
							 ctypes.sizeof(cujd),
							 None,
							 0,
							 ctypes.byref(br),
							 None)

	if status != 0:
		return True
	else:
		return GetLastError()

def getUsnJournal(hVolHandle):
	br = DWORD()
	usnData = USN_JOURNAL_DATA()
	ret = DeviceIoControl(hVolHandle,
						  FSCTL_QUERY_USN_JOURNAL,
						  None,
						  0,
						  ctypes.byref(usnData),
						  ctypes.sizeof(usnData),
						  ctypes.byref(br),
						  None)
	return usnData if ret == True else None

def enumUsnJournal(hVolHandle, usnData, callback):
	med = MFT_ENUM_DATA()
	med.StartFileReferenceNumber = 0
	med.LowUsn = 0
	med.HighUsn = usnData.NextUsn

	bufLen = 4096
	buf = ctypes.create_string_buffer(bufLen)
	usnDataSize = DWORD()
	while True:
		ret = DeviceIoControl(hVolHandle,
							   FSCTL_ENUM_USN_DATA,
							   ctypes.byref(med),
							   ctypes.sizeof(med),
							   buf,
							   bufLen,
							   ctypes.byref(usnDataSize),
							   None)
		if ret != True:
			print('FALSE')
			break

		dwRetBytes = usnDataSize.value - ctypes.sizeof(USN)
		offset = 0

		while dwRetBytes > 0:
			usnRecord = ctypes.cast(ctypes.byref(buf, ctypes.sizeof(USN) + offset), LPUSN_RECORD)[0]
			
			_dealUsnRecord(usnRecord, callback)
			
			recordLen = usnRecord.RecordLength
			dwRetBytes -= recordLen
			offset += recordLen

		med.StartFileReferenceNumber = ctypes.cast(ctypes.byref(buf), LPUSN)[0]

def readUsnJournal(hVolHandle, usnData, startUsn, callback):
	readData = READ_USN_JOURNAL_DATA()
	readData.StartUsn = startUsn
	readData.ReasonMask = 0xFFFFFFFF
	readData.ReturnOnlyOnClose = 0
	readData.Timeout = 0
	readData.BytesToWaitFor = 0
	readData.UsnJournalID = usnData.UsnJournalID

	bufLen = 4096
	buf = ctypes.create_string_buffer(bufLen)
	usnDataSize = DWORD()
	while True:
		ret = DeviceIoControl(hVolHandle,
							   FSCTL_READ_USN_JOURNAL,
							   ctypes.byref(readData),
							   ctypes.sizeof(readData),
							   buf,
							   bufLen,
							   ctypes.byref(usnDataSize),
							   None)
		if ret != True:
			break

		dwRetBytes = usnDataSize.value - ctypes.sizeof(USN)
		offset = 0

		if dwRetBytes == 0:
			break
		
		while dwRetBytes > 0:
			usnRecord = ctypes.cast(ctypes.byref(buf, ctypes.sizeof(USN) + offset), LPUSN_RECORD)[0]
			
			_dealUsnRecord(usnRecord, callback)
			
			recordLen = usnRecord.RecordLength
			dwRetBytes -= recordLen
			offset += recordLen

		readData.StartUsn  = ctypes.cast(ctypes.byref(buf), LPUSN)[0]
		
def _dealUsnRecord(usnRecord, callback):
	ptr = ctypes.addressof(usnRecord) + usnRecord.FileNameOffset
	fileName = ctypes.wstring_at(ptr, usnRecord.FileNameLength // 2)
	#fileName = fileName.encode('utf8')
		
	callback(fileName, usnRecord)

def queryFileNameById(File_id:int,mountpoint = None):
	global drives_latter
	FILE_NAME_NORMALIZED = 0x0
	def callback(hVol):
		try:
			file_h = win32file.OpenFileById(
				hVol  ,
				File_id,
				FILE_GENERIC_READ,
				FILE_SHARE_READ,
				win32file.FILE_FLAG_OVERLAPPED,
				None	
			)
			
			return win32file.GetFinalPathNameByHandle(file_h,FILE_NAME_NORMALIZED).replace("\\\\?\\","")
		except:
			
			return False
	
	
	if mountpoint != None:
		hVol = win32file.CreateFile(
		f"\\\\.\\{mountpoint}:",
		win32file.GENERIC_READ|win32file.GENERIC_EXECUTE ,
		FILE_SHARE_READ|FILE_SHARE_WRITE,
		None,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_READONLY|win32file.FILE_FLAG_BACKUP_SEMANTICS,
		win32file.GENERIC_READ
		)
		result = callback(hVol)
		
		hVol.close()
		if not result:
			return File_id
		else:
			return result

	for char in drives_latter:
		hVol = win32file.CreateFile(
		f"\\\\.\\{char}:",
		win32file.GENERIC_READ|win32file.GENERIC_EXECUTE ,
		FILE_SHARE_READ|FILE_SHARE_WRITE,
		None,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_READONLY|win32file.FILE_FLAG_BACKUP_SEMANTICS,
		win32file.GENERIC_READ
		)

		result = callback(hVol)
		if result != False:
			return result
		else:
			hVol.close()
			continue
	return File_id

def queryFileId(path:str):
	path = "\\\\?\\" +  path.replace("/","\\")
	if os.path.exists(path):
		filename = "."
		if not os.path.isdir(path):
			path, filename = "\\".join(path.split("\\")[0:-1]), path.split("\\")[-1]
			
		
		file_h = win32file.CreateFile(
			path,
			win32file.GENERIC_READ,
			FILE_SHARE_READ,
			None,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_READONLY|win32file.FILE_FLAG_BACKUP_SEMANTICS,
			win32file.GENERIC_READ
		)
		
		info =  win32file.GetFileInformationByHandleEx(file_h,win32file.FileIdBothDirectoryInfo)
		for file in info:
			if file['FileName'].lower() == filename.lower():
				return file['FileId']
				
		file_h.close()
		return info
	else:
		return False

def filetimeToTimeStamp(filetime):
	try:
		return (datetime.fromtimestamp((float(filetime) * 1e-7 - 11644473600)).timestamp())
	except:
		pass

def query_usn_data(volName):
	disk_records = []
	if not checkNtfs(volName):
		print("return")
		# return
	handle = getVolumeHandle(volName)
	initUsnJournal(handle)
	data =  getUsnJournal(handle)
	
	if data:
		def callback(fileName, usnRecord):
			nonlocal disk_records
			timestamp = filetimeToTimeStamp(usnRecord.TimeStamp)
			if timestamp > BOOT_TIME:
				disk_records.append((fileName, convertAttributes(reasons,usnRecord.Reason), timestamp, usnRecord.FileReferenceNumber, usnRecord.ParentFileReferenceNumber))
			
		readUsnJournal(handle, data, 0, callback)
	
	CloseHandle(handle)
	return disk_records


def usn_parser(shared_result:dict = None):
	records = []
	first_record = {}
	# RECYCLE_BIN_FILEID = queryFileId(RECYCLE_BIN_FOLDER)
	# PREFETCH_FOLDER_FILEID = queryFileId(PREFETCH_FOLDER)
	file_renamed = []
	file_move_to_recycle_bin = []
	file_deleted = []
	file_replaced = []

	for mountpoint in drives_latter:
		records = (query_usn_data(mountpoint))
		
		if len(records) > 0:
			first_record[mountpoint] = records[0][2]
		else:
			first_record[mountpoint] = float("inf")
		
	
		fileids = [x[3] for x in records if x[0].lower().endswith(".pf") or x[0].lower().endswith(".exe") or x[0].lower().endswith(".jar")]   
		fileids = list(set(fileids))    
		
		records = [x for x in records if x[3] in fileids]
		records.sort(key = lambda x:x[2])
	

		i = 0
		while i < len(records):
			record1 = records[i]
			
			directory = queryFileNameById(record1[4],mountpoint)
			if type(directory) == int:
				directory = mountpoint + ":\\ | " + str(directory)
			
			if record1[1] == "RENAME_OLD_NAME": # nếu reason của record đầu tiên là rename old name
				for j in range(i+1,len(records)): # tìm các record tiếp theo xem cái nào có thuộc tính rename new name
					record2 = records[j]
					if record1[3] == record2[3] and "RENAME_NEW_NAME" == record2[1]:
						
						

						if "$RECYCLE.BIN".lower() == str(queryFileNameById(record2[4])).lower()[3:15] :
							file_move_to_recycle_bin.append((record1[0],record1[2],directory))   
						
						elif "$RECYCLE.BIN".lower() != directory.lower()[3:15]:
							file_renamed.append((record1[0],record2[0],record1[2],directory))
						break
			
			if 'FILE_DELETE' in record1[1] and "$RECYCLE.BIN".lower() != directory.lower()[3:15]:
				

				file_deleted.append((record1[0],record1[2],directory))

			if "DATA_OVERWRITE" in record1[1] and "DATA_TRUNCATION" in record1[1] and "DATA_EXTEND" in record1[1]:
				file_replaced.append((record1[0],record1[2],directory))

			i+=1


	file_replaced = list(set(file_replaced))

	result = {
		"First record" : first_record,
		"File renamed" : file_renamed,
		"File deleted" : file_deleted,
		"RecycleBin" : file_move_to_recycle_bin,
		"File replaced" : file_replaced

	}
	
	if shared_result != None:
		shared_result.update(result)
	else:
		return result

if __name__ == '__main__':
	from psutil import boot_time
	usn_journal =  usn_parser()
	BOOT_TIME = boot_time()



	file_path = os.environ["TMP"] + "\\Usn_Journal.txt"
	with open(file_path,"w" ,encoding="UTF") as f:
		f.write("Tool was created by AoiKanariya\nDiscord: aoikanariya\n")
		f.write("Work only on some specific types of file\n\n")


		f.write( "\n=============================================  File rename  =============================================\n")
		for item in sorted(usn_journal["File renamed"],key = lambda x:x[2]):
			f.write(f"\"{item[0]}\" -> \"{item[1]}\"  | {ToHumanReadable(item[2])} ({ToRelativeTime(item[2])}ago) | {item[3]}\n")

		f.write("\n\n======================================  File moved to recyle bin  ======================================\n")
		for item in sorted(usn_journal["RecycleBin"],key = lambda x:x[1]):
			f.write(f"\"{item[0]}\"   | {ToHumanReadable(item[1])} ({ToRelativeTime(item[1])}ago) | {item[2]}\n")

		f.write("\n\n============================================  File deleted  ============================================\n")
		for item in sorted(usn_journal["File deleted"],key = lambda x:x[1]):
			f.write(f"\"{item[0]}\"   | {ToHumanReadable(item[1])} ({ToRelativeTime(item[1])}ago) | {item[2]}\n")

		f.write("\n\n===========================================  File replaced  ============================================\n")
		for item in sorted(usn_journal["File replaced"],key = lambda x:x[1]):
			f.write(f"\"{item[0]}\"   | {ToHumanReadable(item[1])} ({ToRelativeTime(item[1])}ago) | {item[2]}\n")


	os.startfile(file_path)
   

	

