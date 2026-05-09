#cython: language_level=3
#distutils: language=c++

import re
import pefile
import traceback
import binascii

from dotnetutils.net_structs import DotNetResourceSet
from dotnetutils import net_exceptions
from logging import getLogger

from dotnetutils cimport net_tokens, net_metadata
from dotnetutils cimport net_row_objects, net_table_objects, net_patch
from dotnetutils cimport net_structs, net_processing, net_cil_disas
from libc.stdint cimport uintptr_t, uint64_t, uint32_t
from dotnetutils.net_structs cimport IMAGE_DOS_HEADER, IMAGE_RESOURCE_DATA_ENTRY, IMAGE_RESOURCE_DIRECTORY, IMAGE_RESOURCE_DIRECTORY_ENTRY, VS_VERSIONINFO, IMAGE_DIRECTORY_ENTRY_RESOURCE, IMAGE_DATA_DIRECTORY, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, IMAGE_SECTION_HEADER, IMAGE_FILE_HEADER, IMAGE_COR20_HEADER, IMAGE_NT_OPTIONAL_HDR64_MAGIC
from dotnetutils.net_structs cimport IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_CNT_UNINITIALIZED_DATA, COMIMAGE_FLAGS_NATIVE_ENTRYPOINT, IMAGE_OPTIONAL_HEADER32, IMAGE_OPTIONAL_HEADER64, IMAGE_BASE_RELOCATION, IMAGE_DEBUG_DIRECTORY, IMAGE_IMPORT_DESCRIPTOR, IMAGE_THUNK_DATA32, IMAGE_THUNK_DATA64
from dotnetutils.net_structs cimport IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_FILE_DLL, IMAGE_DIRECTORY_ENTRY_DEBUG, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_ORDINAL_FLAG32, IMAGE_DEBUG_DIRECTORY, IMAGE_ORDINAL_FLAG64, IMAGE_NT_OPTIONAL_HDR32_MAGIC
from cpython.buffer cimport PyObject_GetBuffer, PyBuffer_Release, PyBUF_ANY_CONTIGUOUS, PyBUF_WRITABLE
from cpython.bytes cimport PyBytes_FromStringAndSize
from cpython.ref cimport PyObject

logger = getLogger(__name__)

def method_rva_sort(method):
    return method.get_column('RVA').get_value()

cdef class PeFile:
    """Small custom PeFile implementation.
    Designed to ensure less python dependencies.
    
    Notes:
        __file_data (bytearray): Byte representation of the PE file.
        __sections (list[dict]): A list of IMAGE_SECTION_HEADER items in python dict format.
    """
    def __cinit__(self, bytes file_data):
        """Constructor method for PeFile.  Takes the PE file's byte data as an argument.
        
        Args:
            file_data (bytes): Byte data of the PE file.
        
        Returns:
            PeFile: A PeFile object created from file_data.
        """
        self.__file_data = bytearray(file_data)
        self.__sections = list()
        PyObject_GetBuffer(self.__file_data, &self.__file_view, PyBUF_ANY_CONTIGUOUS)
        self.__parse()

    def __dealloc__(self):
        PyBuffer_Release(&self.__file_view)

    cpdef bint is_dll(self):
        cdef IMAGE_FILE_HEADER *file_header = <IMAGE_FILE_HEADER*>((<char*>self.get_data_view()) + self.__nt_headers_offset + 4)
        return file_header.Characteristics & IMAGE_FILE_DLL != 0

    cdef void __add_section(self, IMAGE_SECTION_HEADER * sec_hdr):
        """Internal method used to add an IMAGE_SECTION_HEADER to the internal python list of sections.
        
        Args:
            sec_hdr (IMAGE_SECTION_HEADER*): A pointer to the section header object to add.
        """
        cdef dict actually_added = sec_hdr[0]
        if 'PhysicalAddress' in actually_added['Misc']:
            #Strip out PhysicalAddress since we arent dealing with object files here.
            #Allows for proper transitions between cython IMAGE_SECTION_HEADER and dict.
            del actually_added['Misc']['PhysicalAddress']
        if len(actually_added['Name']) != 8:
            actually_added['Name'] = actually_added['Name'] + (b'\x00' * (8 - len(actually_added['Name'])))
        if len(actually_added['Name']) != 8:
            actually_added['Name'] = actually_added['Name'][:8]
        self.__sections.append(actually_added)

    cdef void __parse(self) except *:
        """Internal method to parse the PE File.
        """
        cdef IMAGE_DOS_HEADER * dos_header = <IMAGE_DOS_HEADER*>self.get_data_view()
        cdef IMAGE_NT_HEADERS32 * nt_headers = NULL
        if dos_header.e_magic != 0x5A4D:
            raise ValueError('dos_header.e_magic != MZ')
        if len(self.__file_data) <= dos_header.e_lfanew:
            raise ValueError("e_lfanew >= len(file_data)")

        self.__nt_headers_offset = dos_header.e_lfanew
        nt_headers = <IMAGE_NT_HEADERS32*> (<uintptr_t>self.get_data_view() + self.__nt_headers_offset)
        if nt_headers.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            self.__parse_64()
        else:
            self.__parse_32()

    cdef void __parse_64(self):
        """Internal method to parse a 64 bit PE file.
        """
        cdef IMAGE_NT_HEADERS64 *nt_headers = <IMAGE_NT_HEADERS64*> (<uintptr_t>self.get_data_view() + self.__nt_headers_offset)
        cdef IMAGE_SECTION_HEADER * sec_hdr = NULL
        cdef unsigned int sechdr_offset
        self.__image_base = nt_headers.OptionalHeader.ImageBase
        self.__is_64bit = True
        sechdr_offset = self.__nt_headers_offset + 4 + sizeof(IMAGE_FILE_HEADER) + nt_headers.FileHeader.SizeOfOptionalHeader
        for x in range(nt_headers.FileHeader.NumberOfSections):
            sec_hdr = <IMAGE_SECTION_HEADER*> (self.get_data_view() + sechdr_offset)
            self.__add_section(sec_hdr)
            sechdr_offset += sizeof(IMAGE_SECTION_HEADER)

    cdef void __parse_32(self):
        """Internal method to parse a 32 bit PE file.
        """
        cdef IMAGE_NT_HEADERS32 *nt_headers = <IMAGE_NT_HEADERS32*> (<uintptr_t>self.get_data_view() + self.__nt_headers_offset)
        cdef IMAGE_SECTION_HEADER * sec_hdr = NULL
        cdef unsigned int sechdr_offset
        self.__is_64bit = False
        self.__image_base = nt_headers.OptionalHeader.ImageBase
        sechdr_offset = self.__nt_headers_offset + 4 + sizeof(IMAGE_FILE_HEADER) + nt_headers.FileHeader.SizeOfOptionalHeader
        for x in range(nt_headers.FileHeader.NumberOfSections):
            sec_hdr = <IMAGE_SECTION_HEADER*> (self.get_data_view() + sechdr_offset)
            self.__add_section(sec_hdr)
            sechdr_offset += sizeof(IMAGE_SECTION_HEADER)

    cpdef uint32_t get_offset_from_rva(self, uint32_t rva):
        """Obtain a PE file offset from a RVA.
        
        Args:
            rva (uint32_t): The RVA to obtain the offset for.
        
        Returns:
            uint32_t: <uint32_t>-1 if not found, the file offset for the RVA otherwise.
        """
        cdef IMAGE_SECTION_HEADER sec_hdr
        cdef int sec_size
        cdef dict sec_hdr_dict
        for x in range(len(self.__sections)):
            sec_hdr_dict = self.__sections[x]
            sec_hdr = sec_hdr_dict
            sec_size = max(sec_hdr.SizeOfRawData, sec_hdr.Misc.VirtualSize)
            if sec_hdr.VirtualAddress <= rva < (sec_hdr.VirtualAddress + sec_size):
                return sec_hdr.PointerToRawData + (rva - sec_hdr.VirtualAddress)
        return <uint32_t>-1

    cpdef uint32_t get_rva_from_offset(self, uint32_t offset):
        """Obtain a PE RVA from a file offset.
        
        Args:
            rva (uint32_t): The file offset to obtain the RVA for.
        
        Returns:
            uint32_t: <uint32_t>-1 if not found, the file RVA for the file offset otherwise.
        """
        cdef IMAGE_SECTION_HEADER sec_hdr
        cdef dict sec_hdr_dict
        for x in range(len(self.__sections)):
            sec_hdr_dict = self.__sections[x]
            sec_hdr = sec_hdr_dict
            if sec_hdr.PointerToRawData <= offset < (sec_hdr.PointerToRawData + sec_hdr.SizeOfRawData):
                return sec_hdr.VirtualAddress + (offset - sec_hdr.PointerToRawData)
        return <uint32_t>-1

    cpdef IMAGE_DATA_DIRECTORY get_directory_by_idx(self, unsigned int idx):
        """Obtain an IMAGE_DATA_DIRECTORY by its index within the PE file's optional header.
        
        Args:
            idx (unsigned int): The index of the data directory within the PE Optional header.
        
        Returns:
            IMAGE_DATA_DIRECTORY: A blank data directory if not found, otherwise the data directory at idx.
        """
        cdef IMAGE_NT_HEADERS32 * nt_headers32 = NULL
        cdef IMAGE_NT_HEADERS64 * nt_headers64 = NULL
        cdef IMAGE_DATA_DIRECTORY blank
        blank.VirtualAddress = 0
        blank.Size = 0
        if self.__is_64bit:
            nt_headers64 = <IMAGE_NT_HEADERS64*>(<uintptr_t>self.__file_view.buf + self.__nt_headers_offset)
            if idx >= nt_headers64.OptionalHeader.NumberOfRvaAndSizes:
                return blank
            return nt_headers64.OptionalHeader.DataDirectory[idx]
        else:
            nt_headers32 = <IMAGE_NT_HEADERS32*>(<uintptr_t>self.__file_view.buf + self.__nt_headers_offset)
            if idx >= nt_headers32.OptionalHeader.NumberOfRvaAndSizes:
                return blank
            return nt_headers32.OptionalHeader.DataDirectory[idx]

    cpdef bint is_64bit(self):
        """Is the PE File 64 bit?

        Returns:
            bool: True if the PE file is 64-bit, False otherwise.
        """
        return self.__is_64bit

    cpdef list get_sections(self):
        """Obtain a list of python objects (dicts) representing the sections.

        Returns:
            list: A list of sections represented by python objects.
        """
        return self.__sections

    cpdef int get_elfanew(self):
        """Obtain the value of IMAGE_DOS_HEADER.e_lfanew.

        Returns:
            int: The value of IMAGE_DOS_HEADER.e_lfanew
        """
        return self.__nt_headers_offset

    cdef uintptr_t get_data_view(self):
        """Obtain a uintptr_t representing the data view for the PE file's data.

        Returns:
            uintptr_t: A READ ONLY poitner to the file's data.
        """
        return <uintptr_t>self.__file_view.buf

    cpdef bytes get_file_data(self):
        """Obtain a byte representation of the PE file's data.
        Returns:
            bytes: A Byte representation of the PE file's data.
        """
        return bytes(self.__file_data)

    cpdef uint32_t get_physical_by_rva(self, uint32_t rva):
        """See PeFile.get_offset_from_rva()

        Args:
            rva (uint32_t): See PeFile.get_offset_from_rva()
    
        Returns:
            uint32_t: See PeFile.get_offset_from_rva()
        """
        return self.get_offset_from_rva(rva)

    cdef int get_sec_index_va(self, uint32_t va_addr):
        """OObtain the section header index that corresponds to a RVA.

        Args:
            va_addr (uint32_t): The VA to obtain the section header index for.

        Returns:
            int: -1 if not found, the index of the section header corresponding to va_addr otherwise.
        """
        cdef dict sec_hdr = None
        cdef int x = 0
        for sec_hdr in self.get_sections():
            if sec_hdr['VirtualAddress'] <= va_addr < (sec_hdr['VirtualAddress'] + sec_hdr['Misc']['VirtualSize']):
                return x
            x += 1
        return -1

    cdef int get_sec_index_phys(self, uint32_t offset):
        """OObtain the section header index that corresponds to a offset.

        Args:
            offset (uint32_t): The VA to obtain the section header index for.

        Returns:
            int: -1 if not found, the index of the section header corresponding to offset otherwise.
        """
        cdef dict sec_hdr = None
        cdef int x = 0
        for sec_hdr in self.get_sections():
            if sec_hdr['PointerToRawData'] <= offset < (sec_hdr['PointerToRawData'] + sec_hdr['SizeOfRawData']):
                return x
            x += 1
        return -1

    cpdef IMAGE_COR20_HEADER get_net_header(self):
        """ Obtain the IMAGE_COR20_HEADER associated with the executable.

        Returns:
            IMAGE_COR20_HEADER: the IMAGE_COR20_HEADER associated with the executable.
        """
        cdef IMAGE_DATA_DIRECTORY datadir = self.get_directory_by_idx(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
        cdef uint32_t offset = 0
        cdef IMAGE_COR20_HEADER * ptr = NULL
        if datadir.VirtualAddress == 0 or datadir.Size == 0:
            raise net_exceptions.NotADotNetFile

        offset = self.get_offset_from_rva(datadir.VirtualAddress)
        ptr = <IMAGE_COR20_HEADER*>(<uint64_t>self.__file_view.buf + offset)
        return ptr[0]

cdef class DotNetPeFile:
    """Represents a DotNetPeFile.  Contains all methods used to access other parts of the .NET metadata structure.

    Notes:
        file_path (str): The file path of the executable, if set.
        exe_data (bytes): A byte representation of the current exe data.
        pe (PeFile): A PeFile object representing the executable.
        metadata_dir (MetadataDirectory): A metadata directory object representing the executable's Metadata.
        original_exe_data (bytes): A holder for the unmodified exe data.
        __versioninfo_str (str): Used to hold the version info string obtained by DotNetPeFile.get_product_version().
    """
    def __init__(self, str file_path='', bytes pe_data=bytes(), bint no_processing=False, bint raise_exc=False):
        """ Create a new DotNetPeFile

        Args:
            file_path (str): The file path of the PE file.  Optional if pe_data is provided.
            pe_data (bytes): Bytes representing the PE file.  Optional if file_path is provided.
            no_processing (bool): Should DotNetUtils run processing on the metadata or just read it?  If processing is disabled, some functions may not return correct values.
        
        Raises:
            net_exceptions.InvalidArgumentsException: If no data is supplied.
            net_exceptions.NotADotNetFile: On pe parsing or other .NET signature related errors.

        """

        if  len(file_path) == 0 and len(pe_data) == 0:
            raise net_exceptions.InvalidArgumentsException

        self.file_path = file_path

        if len(pe_data):
            self.exe_data = bytes(pe_data)
        else:
            fd = open(file_path, 'rb')
            self.exe_data = fd.read()
            fd.close()
        try:
            self.pe = PeFile(self.exe_data)
        except ValueError as e:
            raise net_exceptions.NotADotNetFile

        self.reinit_dpe(no_processing)
        self.raise_exc_on_invalid_method = raise_exc

    cdef bint should_raise_exc_on_invalid_method(self):
        """ Obtains the value which determines whether or not malformed methods will raise an exception or a warning.
            Returning exceptions on invalid methods can be a bad thing - some obfuscators can add invalid metadata and also code
            can be encrypted on disk.
        Returns:
            bint: True if invalid methods will return an exception, False if they will return a warning.
        """
        return self.raise_exc_on_invalid_method

    cdef uint32_t __get_offset_from_memview(self, Py_buffer view_obj, uint32_t rva):
        cdef IMAGE_DOS_HEADER * dos = <IMAGE_DOS_HEADER*>view_obj.buf
        cdef IMAGE_NT_HEADERS32 * nt = <IMAGE_NT_HEADERS32*>(<char*>view_obj.buf + dos.e_lfanew)
        cdef IMAGE_SECTION_HEADER * array = <IMAGE_SECTION_HEADER*>(<char*>view_obj.buf + dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + nt.FileHeader.SizeOfOptionalHeader)
        cdef int x = 0
        cdef IMAGE_SECTION_HEADER hdr
        for x in range(nt.FileHeader.NumberOfSections):
            hdr = array[x]
            if hdr.VirtualAddress <= rva < (hdr.VirtualAddress + max(hdr.Misc.VirtualSize, hdr.SizeOfRawData)):
                return hdr.PointerToRawData + (rva - hdr.VirtualAddress)
        return 0

    cdef uint32_t __get_rva_from_memview(self, Py_buffer view_obj, uint32_t offset):
        cdef IMAGE_DOS_HEADER * dos = <IMAGE_DOS_HEADER*>view_obj.buf
        cdef IMAGE_NT_HEADERS32 * nt = <IMAGE_NT_HEADERS32*>(<char*>view_obj.buf + dos.e_lfanew)
        cdef IMAGE_SECTION_HEADER * array = <IMAGE_SECTION_HEADER*>(<char*>view_obj.buf + dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + nt.FileHeader.SizeOfOptionalHeader)
        cdef int x = 0
        cdef IMAGE_SECTION_HEADER hdr
        for x in range(nt.FileHeader.NumberOfSections):
            hdr = array[x]
            if hdr.PointerToRawData <= offset < (hdr.PointerToRawData + hdr.SizeOfRawData):
                return hdr.VirtualAddress + (offset - hdr.PointerToRawData)
        return 0

    cpdef void update_streams(self):
        """Used for updating the data in the .NET metadata heaps for get_exe_data() 
        """
        cdef net_processing.HeapObject heap_obj = None
        cdef bytes exe_data = self.get_exe_data()
        for heap_obj in self.get_heaps().values():
            exe_data = exe_data[:heap_obj.get_offset()] + heap_obj.to_bytes() + exe_data[heap_obj.get_offset() + heap_obj.get_size():]
        self.set_exe_data(exe_data)

    cpdef void reinit_dpe(self, bint no_processing):
        """ Reparse the dotnet file.  Eventually likely to remove this in favor of removing state variables that cause issues requiring this.
        """
        self.original_exe_data = bytes(self.exe_data)
        self.metadata_dir = net_metadata.MetaDataDirectory(self)
        self.__versioninfo_str = None
        if not self.metadata_dir.is_valid_directory:
            return
        self.process_metadata_heap(no_processing)

    cdef void process_metadata_heap(self, bint dont_process):
        """ Process the metadata heaps
        """
        cdef net_processing.MetadataTableHeapObject mheap = None
        cdef net_processing.UserStringsHeapObject usheap = None
        self.metadata_dir.metadata_table_header = net_table_objects.MetadataTableHeader(self, self.metadata_dir.metadata_file_offset)
        mheap = net_processing.MetadataTableHeapObject(self.metadata_dir.metadata_file_offset, self.metadata_dir.metadata_file_size, b'#~', self)
        self.metadata_dir.heaps['#~'] = mheap
        self.metadata_dir.heaps = dict(sorted(self.metadata_dir.heaps.items(), key=lambda item: item[1].get_offset()))
        self.metadata_dir.metadata_heap_size = self.metadata_dir.metadata_file_size
        if not dont_process:
            mheap.process_tables()
            if '#US' in self.metadata_dir.heaps:
                usheap = self.metadata_dir.heaps['#US']
                usheap._fill_methods() #Fill methods after processing for #US updates.  Patching wont work if processing isnt done.

    cpdef uint32_t get_cor_header_offset(self):
        """ Obtain the file offset of the IMAGE_COR20_HEADER structure.

        Returns:
            uint32_t: The offset of the IMAGE_COR20_HEADER structure.
        """
        cdef IMAGE_DATA_DIRECTORY com_table_directory
        try:
            com_table_directory = self.pe.get_directory_by_idx(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
            if com_table_directory.VirtualAddress == 0 or com_table_directory.Size == 0:
                raise net_exceptions.NotADotNetFile
        except IndexError:
            raise net_exceptions.NotADotNetFile
        return self.pe.get_offset_from_rva(com_table_directory.VirtualAddress)

    cpdef bytes get_original_exe_data(self):
        """ Obtain the original exe's data before any patching etc.

        Returns:
            bytes: The original data representing the PE file.
        """
        return self.original_exe_data

    cpdef bytes get_exe_data(self):
        """ Obtain the current exe's data.

        Returns:
            bytes: The current exe's data, including any patched bytes strings etc.
        """
        return self.exe_data

    cpdef net_metadata.MetaDataDirectory get_metadata_dir(self):
        """ Obtain the metadata directory.

        Returns:
            net_metadata.MetadataDirectory: The metadata directory object for the executable.
        """
        return self.metadata_dir

    cpdef void add_string(self, str string) except *:
        """ Appends a string onto the executable's Strings heap.

        Args:
            string (str): The string to add.  Must be able to be encoded in UTF-8.
        """
        self.get_heap('#Strings').append_item(string.encode('utf-8'))

    cpdef void set_exe_data(self, bytes exe_data):
        """ Used internally to update the exe_data attribute as well as the PeFile.
            Can be used externally but you MUST update call update_va, etc etc.

        Args:
            exe_data (bytes): The new exe's bytes.
        """
        self.exe_data = bytes(exe_data)
        self.pe = PeFile(exe_data)

    cpdef PeFile get_pe(self):
        """ Obtain an object representing the current exe's PeFile structure.

        Returns:
            PeFile: A PeFile object representing the current executable.
        """
        return self.pe

    cpdef int get_processor_bits(self):
        """Determines what procesor bits (32 or 64) the .NET Assembly actually runs as.
        see dnSpy's dnSpy.Decompiler.TargetFrameworkUtils.GetArchString
        
        Returns:
            int: 0 if an error occurred, otherwise 32 if the file runs on 32-bit and 64 if it runs on 64-bit.
        """
        cdef int c
        cdef IMAGE_COR20_HEADER cor_header
        c = 0
        cor_header = self.get_pe().get_net_header()
        if cor_header.Flags & net_structs.COMIMAGE_FLAGS_32BITREQUIRED != 0:
            c += 2
        
        if cor_header.Flags & net_structs.COMIMAGE_FLAGS_32BITPREFERRED != 0:
            c += 1

        if c == 0:
            return 64
        elif c == 1:
            return 0
        elif c == 2:
            return 32
        elif c == 3:
            return 32
        return 0

    cpdef list get_methods_by_name(self, bytes name):
        """ Obtains a list of MethodDef objects matching a provided name.

        Args:
            name (bytes): The name of the method(s) to search for.
        
        Returns:
            list[MethodDef]: a list of MethodDef objects corresponding to name
        """
        cdef net_table_objects.MethodDefTable mtable
        mtable = <net_table_objects.MethodDefTable>self.get_metadata_table('MethodDef')
        if mtable is not None:
            return mtable.get_methods_by_name(name)
        return list()

    cpdef net_row_objects.MethodDef get_method_by_rid(self, int rid):
        """ Obtains a MethodDef matching a particular RID.

        Args:
            rid (int): The Method RID to obtain.
        
        Returns:
            MethodDef: the MethodDef object representing the Method at table RID rid.
        """
        return self.get_metadata_table('MethodDef').get(rid)

    cpdef list get_methods_by_full_name(self, bytes full_name):
        """ Obtains a list of MethodDef objects matching a provided full name. The full name must include the namespace.

        Args:
            full_name (bytes): The full name, including namespace, of the method(s) to search for.
        
        Returns:
            list[MethodDefOrRef]: a list of MethodDefOrRef objects corresponding to full_name.
        """
        cdef bytes full_type_name
        cdef bytes method_name
        cdef net_row_objects.TypeDef method_type
        cdef list full_type_name_args
        cdef list results
        cdef net_row_objects.MemberRef member
        cdef net_table_objects.TypeDefTable tdeftable
        if full_name.endswith(b'..cctor'):
            full_type_name = full_name.replace(b'..cctor', b'')
            method_name = b'.cctor'
        else:
            full_type_name_args = full_name.split(b'.')
            method_name = full_type_name_args[-1]
            full_type_name = b'.'.join(full_type_name_args[:-1])
        tdeftable = <net_table_objects.TypeDefTable>self.get_metadata_table('TypeDef')
        if tdeftable is not None:
            method_type = tdeftable.get_type_by_full_name(full_type_name)
            if method_type:
                return method_type.get_methods_by_name(method_name)
        # check through memberrefs to be safe
        results = list()
        if self.has_metadata_table('MemberRef'):
            results.extend(self.get_metadata_table('MemberRef').get_member_refs_by_full_name(full_name))
        return results

    cpdef net_row_objects.TypeRef get_typeref_by_full_name(self, bytes full_name):
        """ Obtains a TypeRef by its full name, including namespace.

        Args:
            full_name (bytes): The full name, including namespace, of the TypeRef to search for.
        
        Returns:
            net_row_objects.TypeRef: A TypeRef corresponding to full_name, None if not found.
        """
        return self.get_metadata_table('TypeRef').get_type_by_full_name(full_name)

    cpdef net_table_objects.TableObject get_metadata_table(self, str name):
        """ Obtains a TableObject corresponding to name which represents a single metadata Table.

        Args:
            name (str): The name of the table to obtain.
        
        Returns:
            net_table_objects.TableObject: The metadata table object corresponding to name, None if it doesnt exist.
        """
        cdef net_processing.MetadataTableHeapObject mheap = <net_processing.MetadataTableHeapObject>self.get_heap('#~')
        if mheap is not None:
            return mheap.get_table(name)
        return None
    
    cpdef bint has_metadata_table(self, str name):
        """ Informs the user whether or not a metadata table name exists in the executable

        Args:
            name (bytes): The name of the metadata table to check for.
        
        Returns:
            bool: True if the table exists, False otherwise.
        """
        cdef net_processing.MetadataTableHeapObject mheap = <net_processing.MetadataTableHeapObject>self.get_heap('#~')
        if mheap is not None:
            return mheap.has_table(name)
        return False

    cpdef net_processing.HeapObject get_heap(self, str name):
        """ Obtains a HeapObject representing a parsed heap within the .NET metadata directory.

        Args:
            name (str): The name of the heap to obtain.
        
        Returns:
            net_processing.HeapObject: a HeapObject corresponding to name, None if it doesnt exist.
        """
        if name == '#-':
            return self.get_metadata_dir().get_heap('#~')
        return self.get_metadata_dir().get_heap(name)
    
    cpdef dict get_heaps(self):
        """ Obtains a dictionary representing all heaps in the executable.

        Returns:
            dict[str, net_processing.HeapObject]: A dict containing all the heaps in the executable, keyed by name.
        """
        return self.get_metadata_dir().get_heaps()

    cpdef bint has_heap(self, str name):
        """ Informs the user whether or not a heap exists within an executable.

        Args:
            name (str): The name of the heap to check.
        
        Returns:
            bool: True if the heap exists, False otherwise.
        """
        if name == '#-':
            return '#~' in self.get_metadata_dir().get_heaps()
        return name in self.get_metadata_dir().get_heaps()

    cpdef list get_user_strings(self):
        """ Obtains a list of referenced user strings.  If methods are encrypted, this may return no strings.

        Returns:
            list[bytes]: A list containing all the items of the #US heap that are referenced by code.
        """
        cdef net_processing.UserStringsHeapObject stream = <net_processing.UserStringsHeapObject>self.get_heap('#US')
        if stream is not None:
            return stream.get_items()
        return list()

    cpdef list get_strings(self):
        """ Obtains a list of metadata table strings.

        Returns:
            list[bytes]: A list containing all strings in the #Strings heap.
        """
        cdef net_processing.StringHeapObject stream = <net_processing.StringHeapObject> self.get_heap('#Strings')
        if stream is not None:
            return stream.get_items()
        return list()

    cpdef bint has_user_string(self, bytes string):
        """ Informs the user whether a user string string exists in the binary.
        See DotNetPeFile.get_user_strings() for caveats.

        Args:
            string (bytes): A UTF-16LE encoded string to check for.

        Returns:
            bool: True if the string exists within #US, False otherwise.
        """
        return string in self.get_user_strings()

    cpdef bint has_string(self, bytes string):
        """ Informs the user whether a string exists in the binary.

        Args:
            string (bytes): A UTF-8 encoded string to check for.

        Returns:
            bool: True if the string exists within #Strings, False otherwise.
        """
        cdef net_processing.StringHeapObject string_heap = self.get_heap('#Strings')
        cdef bytes item = string
        if item[-1] != 0:
            item += b'\x00'
        return string_heap.has_item(item)

    cpdef list get_resources(self):
        """ Obtains a list of resources referenced by ManifestResources.

        Returns:
            list[net_structs.DotNetResourceSet]: A list containing python representations of all resources in the .NET metadata.
        """
        cdef list results
        cdef net_table_objects.TableObject resources
        cdef net_row_objects.RowObject item
        cdef uint32_t com_offset
        cdef uint32_t resources_offset
        cdef unsigned long resources_size
        cdef unsigned int resource_offset = 0
        cdef bytes rsrc_name
        cdef bytes rsrc_data
        cdef IMAGE_DATA_DIRECTORY * resources_dir
        cdef IMAGE_DATA_DIRECTORY com_table_directory
        cdef char * data_view = <char*>self.get_pe().get_data_view()
        results = list()
        resources = self.get_metadata_table('ManifestResource')
        if resources:
            com_table_directory = self.get_pe().get_directory_by_idx(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
            com_offset = self.get_pe().get_physical_by_rva(com_table_directory.VirtualAddress)
            com_offset += 24
            resources_dir = <IMAGE_DATA_DIRECTORY*>(<char*>data_view + com_offset)
            resources_offset = self.get_pe().get_physical_by_rva(resources_dir.VirtualAddress)
            for item in resources:
                if item['Implementation'].get_raw_value() == 0:
                    resource_offset = <unsigned int>resources_offset + item['Offset'].get_raw_value()
                    resource_size = (<int*>(data_view + resource_offset))[0]
                    resource_offset += 4
                    rsrc_name = item.get_column('Name').get_value()
                    rsrc_data = self.get_exe_data()[resource_offset:resource_offset + resource_size]
                    results.append(DotNetResourceSet(rsrc_data, self, force_name=rsrc_name))
        return results

    cpdef bytes get_resource_by_name(self, bytes name):
        """ Obtain a ManifestResource's data by name.

        Returns:
            bytes: The resource data corresponding to name, None if it doesnt exist.
        """
        cdef list resources = self.get_resources()
        for rsrc_obj in resources:
            for rsrc in rsrc_obj.get_resources():
                if rsrc.get_name() == name:
                    return rsrc.get_data()
        return None

    cpdef list get_exported_types(self):
        """ Obtains a list of all exported TypeDefs in the assembly.

        Returns:
            list[net_row_objects.TypeDef]: A list containing python representations of all exported TypeDefs in the assembly.
        """
        cdef net_row_objects.TypeDef tdef
        cdef int flags
        cdef list result
        result = list()
        if self.has_metadata_table('TypeDef'):
            for tdef in self.get_metadata_table('TypeDef'):
                flags = tdef['Flags'].get_value()
                if flags & net_structs.CorTypeAttr.tdPublic:
                    result.append(tdef)
        return result

    def find_methods_by_regex(self, regex: re.Pattern):
        """ Obtains a list of methods matching a provided regex pattern.

        Args:
            regex (re.Pattern): The regex pattern to match

        Returns:
            list[net_row_objects.MethodDef]: A list containing all MethodDef objects that match regex.
        """
        cdef list results
        cdef net_row_objects.MethodDef method
        cdef bytes method_data
        results = list()
        if self.has_metadata_table('MethodDef'):
            for method in self.get_metadata_table('MethodDef'):
                if not method.has_body():
                    continue
                method_data = method.get_method_data()
                if regex.search(method_data):
                    results.append(method)
        return results

    cpdef list get_types_by_name(self, bytes type_name):
        """ Obtains a list of TypeDefs matching type_name

        Args:
            type_name (bytes): The type name to search for.

        Returns:
            list[net_row_objects.TypeDef]: A list containing all TypeDef objects that match name.
        """
        cdef net_table_objects.TypeDefTable table
        table = <net_table_objects.TypeDefTable>self.get_metadata_table('TypeDef')
        if table is not None:
            return table.get_types_by_name(type_name)
        return list()

    cpdef net_row_objects.TypeDefOrRef get_type_by_full_name(self, bytes type_full_name):
        """ Obtains a TypeDef or TypeRef (TypeDefOrRef) object that corresponds to type_full_name.
        The type_full_name must include the namespace.

        Args:
            type_full_name (bytes): The full type name, including namespace, to search for.

        Returns:
            list[net_row_objects.TypeDefOrRef]: A list containing all TypeDefOrRef objects that match type_full_name.
        """
        cdef net_row_objects.TypeDef test
        cdef net_table_objects.TypeDefTable tdeftable
        cdef net_table_objects.TypeRefTable treftable
        tdeftable = <net_table_objects.TypeDefTable> self.get_metadata_table('TypeDef')
        if tdeftable is not None:
            test = tdeftable.get_type_by_full_name(type_full_name)
            if test is not None:
                return test
        treftable = <net_table_objects.TypeRefTable> self.get_metadata_table('TypeRef')
        if treftable is not None:
            return treftable.get_type_by_full_name(type_full_name)
        return None

    cpdef int delete_user_string(self, unsigned int us_index):
        """ Deletes a user string at us_index

        Args:
            us_index (unsigned int): The #US index to delete.

        Returns:
            int: The difference in size of the #US heap once us_index is deleted.
        """
        return self.get_heap('#US').del_item(<int>us_index)

    cpdef list get_user_string_usages(self, unsigned long us_index):
        """ Obtains a list of XREFS for #US at us_index.

        Args:
            us_index (unsigned long): The #US index to obtain references for.

        Returns:
            list[int, int]: A list of tuples containing the metadata token and the instruction offset for string references.
        """
        cdef list usages
        cdef net_row_objects.MethodDef method
        cdef net_cil_disas.MethodDisassembler disas
        cdef int x 
        cdef net_cil_disas.Instruction instr
        cdef unsigned long token
        usages = list()
        for method in self.get_metadata_table('MethodDef'):
            if method['RVA'].get_value() == 0:
                continue
            disas = method.disassemble_method()
            if disas is None:
                continue
            for x in range(<int>len(disas)):
                instr = disas.get_instr_at_index(x)
                if instr.get_name() == 'ldstr':
                    token = int.from_bytes(instr.get_arguments()[:3], 'little')
                    if token == us_index:
                        usages.append((method.get_token(), instr.get_instr_offset()))
        return usages

    cpdef void patch_instruction(self, net_row_objects.MethodDef method_obj, bytes patch_bytes, unsigned long instr_offset, unsigned long orig_size) except *:
        """ Patch a method's code.

        Args:
            method_obj (net_row_objects.MethodDef): The method to patch.
            patch_bytes (bytes): The bytes to patch in.
            instr_offset (unsigned long): The instruction method to start patching at.
            orig_size (unsigned long): The original code's size.
        """
        cdef net_cil_disas.MethodDisassembler disas = None
        cdef uint32_t rva = 0
        cdef uint32_t offset = 0
        cdef uint32_t patch_offset = 0
        cdef bytes exe_data = None
        if method_obj is None:
            raise Exception('Cant patch a NoneType method object')
        if method_obj.get_column('RVA').get_raw_value() != 0:
            disas = method_obj.disassemble_method()
            patch_offset = disas.get_header_size() + instr_offset  # needs to be zero based not 1 based.
            exe_data = method_obj.get_method_data()
            exe_data = exe_data[:patch_offset] + patch_bytes + exe_data[patch_offset + orig_size:]
            method_obj.set_method_data(exe_data)

    cpdef net_row_objects.MethodDef get_entry_point(self):
        """ Obtains a MethodDef representing the managed entrypoint of the executable.

        Returns:
            net_row_objects.MethodDef: A MethodDef object representing the executable's entry point, or None if it doesnt exist.
        """
        try:
            return self.get_token_value(self.get_pe().get_net_header().EntryPoint.EntryPointToken)
        except net_exceptions.InvalidTokenException:
            return None

    cpdef void set_entry_point(self, unsigned int ep_token):
        """ Patches the executable to change the entry point to ep_token

        Args:
            ep_token (unsigned int): The new entrypoint's metadata token.
        """
        cdef IMAGE_COR20_HEADER new_net_header = self.get_pe().get_net_header()
        cdef bytes new_cor_bytes
        cdef bytes current_exe_data
        cdef bytes new_exe_data
        new_net_header.EntryPoint.EntryPointToken = ep_token
        current_exe_data = self.get_exe_data()
        new_cor_bytes = PyBytes_FromStringAndSize(<char*>&new_net_header, sizeof(IMAGE_COR20_HEADER))
        new_exe_data = current_exe_data[:self.get_cor_header_offset()] + new_cor_bytes + current_exe_data[self.get_cor_header_offset() + new_net_header.cb:]
        self.set_exe_data(new_exe_data)

    cpdef object get_token_value(self, unsigned long token):
        """ Obtains a python representation of a metadata token.

        Args:
            token (unsigned long): The metadata token to obtain.

        Returns:
            object: Can either be a RowObject or a bytes object.  A bytes object is only returned if the token maps to the #US heap.  None if not found.
        """
        cdef str tbl_name
        cdef int table_rid
        try:
            tbl_name, table_rid = net_tokens.get_Signature().decode_token(token)
            if not tbl_name:
                return None
            if tbl_name.startswith('#'):
                if not self.has_heap(tbl_name):
                    return None
                return self.get_heap(tbl_name).get_item(table_rid)
            else:
                if not self.has_metadata_table(tbl_name):
                    return None
                return self.get_metadata_table(tbl_name).get(table_rid)
        except net_exceptions.InvalidTokenException:
            return None

    cpdef str get_product_version(self):
        """ Obtains ProductVersion from the PE's string table.  Used in some obfuscators for string decryption.
        TODO: Remove pefile.PE dependency.

        Returns:
            str: The PE's ProductVersion string.
        """
        #this is used so little times that we may as well just use PeFile for it.
        #TODO: Eventually remove this dependency for pefile.
        if self.__versioninfo_str is None:
            pe = pefile.PE(data=self.get_exe_data())
            for fileinfo in pe.FileInfo:
                for item in fileinfo:
                    if hasattr(item, 'StringTable'):
                        for st in item.StringTable:
                            for entry in st.entries.items():
                                if entry[0] == b'ProductVersion':
                                    return entry[1].decode()
            self.__versioninfo_str = ''
        return self.__versioninfo_str

    def __eq__(self, other):
        return isinstance(other, DotNetPeFile) and other.get_exe_data() == self.get_exe_data()

cpdef DotNetPeFile try_get_dotnetpe(str file_path='', bytes pe_data=bytes(), bint dont_process=False):
    """ Obtains a DotNetPeFile from either a file_path or pe_data. 

    Args:
        file_path (str): The filepath for the PE file.  Optional if pe_data is valid.
        pe_data (bytes): the PE's byte representation.  Optional if file_path is valid.

    Returns:
        dotnetpefile.DotNetPeFile: A DotNetPeFile representing the inputted executable, None if invalid.
    """
    cdef DotNetPeFile dotnetpe = None
    try:
        dotnetpe = DotNetPeFile(file_path, pe_data, no_processing=dont_process)
        if not dotnetpe.metadata_dir.is_valid_directory:
            return None
        return dotnetpe
    except (net_exceptions.NotADotNetFile, ValueError):
        return None
    except net_exceptions.TooManyMethodParameters:
        logger.error(
            "Unable to create DotNetPeFile object. This is likely due to an excessive number of method parameters.")
        return None
    except net_exceptions.DotNetUtilsException as e:
        logger.exception(f"Dotnetutils error: {e} (this may indicate a malformed sample or an issue in dotnetutils)")
        return None
