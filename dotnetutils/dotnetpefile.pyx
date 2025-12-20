#cython: language_level=3
#distutils: language=c++

import re
import pefile
import hashlib
import traceback
import binascii

from dotnetutils.net_structs import DotNetResourceSet
from dotnetutils import net_exceptions
from logging import getLogger

from dotnetutils cimport net_tokens
from dotnetutils cimport net_row_objects, net_table_objects, net_patch
from dotnetutils cimport net_structs, net_processing, net_cil_disas
from cpython.datetime cimport datetime
from libc.stdint cimport uintptr_t, uint32_t, uint64_t
from dotnetutils.net_structs cimport IMAGE_DOS_HEADER, IMAGE_RESOURCE_DATA_ENTRY, IMAGE_RESOURCE_DIRECTORY, IMAGE_RESOURCE_DIRECTORY_ENTRY, VS_VERSIONINFO, IMAGE_DIRECTORY_ENTRY_RESOURCE, IMAGE_DATA_DIRECTORY, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, IMAGE_SECTION_HEADER, IMAGE_FILE_HEADER, IMAGE_COR20_HEADER, IMAGE_NT_OPTIONAL_HDR64_MAGIC
from dotnetutils.net_structs cimport IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_CNT_UNINITIALIZED_DATA, COMIMAGE_FLAGS_NATIVE_ENTRYPOINT, IMAGE_OPTIONAL_HEADER32, IMAGE_OPTIONAL_HEADER64, IMAGE_BASE_RELOCATION, IMAGE_DEBUG_DIRECTORY, IMAGE_IMPORT_DESCRIPTOR, IMAGE_THUNK_DATA32, IMAGE_THUNK_DATA64
from dotnetutils.net_structs cimport IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_DEBUG, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_ORDINAL_FLAG32, IMAGE_DEBUG_DIRECTORY, IMAGE_ORDINAL_FLAG64, IMAGE_NT_OPTIONAL_HDR32_MAGIC
from cpython.buffer cimport PyObject_GetBuffer, PyBuffer_Release, PyBUF_ANY_CONTIGUOUS, PyBUF_WRITABLE
from cpython.bytes cimport PyBytes_FromStringAndSize

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

    cpdef uint64_t get_offset_from_rva(self, uint64_t rva):
        """Obtain a PE file offset from a RVA.
        
        Args:
            rva (uint64_t): The RVA to obtain the offset for.
        
        Returns:
            uint64_t: <uint64_t>-1 if not found, the file offset for the RVA otherwise.
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
        return <uint64_t>-1

    cpdef uint64_t get_rva_from_offset(self, uint64_t offset):
        """Obtain a PE RVA from a file offset.
        
        Args:
            rva (uint64_t): The file offset to obtain the RVA for.
        
        Returns:
            uint64_t: <uint64_t>-1 if not found, the file RVA for the file offset otherwise.
        """
        cdef IMAGE_SECTION_HEADER sec_hdr
        cdef dict sec_hdr_dict
        for x in range(len(self.__sections)):
            sec_hdr_dict = self.__sections[x]
            sec_hdr = sec_hdr_dict
            if sec_hdr.PointerToRawData <= offset < (sec_hdr.PointerToRawData + sec_hdr.SizeOfRawData):
                return sec_hdr.VirtualAddress + (offset - sec_hdr.PointerToRawData)
        return <uint64_t>-1

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

    cpdef uint64_t get_physical_by_rva(self, uint64_t rva):
        """See PeFile.get_offset_from_rva()

        Args:
            rva (uint64_t): See PeFile.get_offset_from_rva()
    
        Returns:
            uint64_t: See PeFile.get_offset_from_rva()
        """
        return self.get_offset_from_rva(rva)

    cdef int get_sec_index_va(self, uint64_t va_addr):
        """OObtain the section header index that corresponds to a RVA.

        Args:
            va_addr (uint64_t): The VA to obtain the section header index for.

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

    cdef int get_sec_index_phys(self, uint64_t offset):
        """OObtain the section header index that corresponds to a offset.

        Args:
            offset (uint64_t): The VA to obtain the section header index for.

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
        cdef uint64_t offset = 0
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
        
        Returns:
            DotNetPeFile: A DotNetPeFile, raises net_exceptions.NotADotNetFile if there is an error parsing.

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
        return self.raise_exc_on_invalid_method

    cpdef void patch_dpe(self, uint64_t va, int diff, bytes stream_name, uint64_t target_va, bytes new_data, uint64_t target_end, bint dont_update_methods):
        if self.get_pe().is_64bit():
            self.__patch_dpe64(va, diff, stream_name, target_va, dont_update_methods, new_data, target_end)
        else:
            self.__patch_dpe32(va, diff, stream_name, target_va, dont_update_methods, new_data, target_end)

    cdef uint64_t __get_offset_from_memview(self, Py_buffer view_obj, uint64_t rva):
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

    cdef uint64_t __get_rva_from_memview(self, Py_buffer view_obj, uint64_t offset):
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

    cdef void __update_net_vas(self, uint64_t va_addr, int difference, bytes stream_name, uint64_t target_addr, bint in_streams, bint before_streams, bytearray new_exe_data, bytes old_exe_data, Py_buffer new_exe_view, int padding_offset, int amt_padding, int target_rawsize_difference, bint dont_update_methods, bytes new_data, uint64_t target_end):
        """ Handles the .NET Portions of patching.  Checks over the metadata tables, rvas etc.

        Args:
            va_addr (uint64_t):  The va_addr where the changes occur.
            difference (int): The difference in the binary once the changes are complete.
            dpe (DotNetPeFile): The dotnetpe instance to modify
            stream_name (bytes): stream name that youre editing, if applicable.  can be None
            target_addr (uint64_t): An address within the block of data that you are attempting to modify.
            in_streams (bint): Whether or not the target is within the metadata directory.
            before_streams (bint): Whether or not the target is before the metadata directory.
            new_exe_data (bytearray): The current exe data with all the prior updates.
            old_exe_data (bytearray): The old exe data.
            new_exe_view (Py_buffer): A writable view to new_exe_data.  Will be released by this function.
            padding_offset (int): offset of section padding.
            amt_padding (int): Amt to pad.
        """
        cdef PeFile pe = self.get_pe()
        cdef uint64_t metadata_offset = 0
        cdef uint64_t streams_offset = 0
        cdef int number_of_streams = 0
        cdef bytes number_of_streams_bytes = None
        cdef int length_of_str = 0
        cdef bint passed_userstrings = False
        cdef uint64_t orig_streams_offset = 0
        cdef net_processing.HeapObject heap_obj = None
        cdef int x = 0
        cdef uint64_t orig_offset = 0
        cdef int offset = 0
        cdef bytearray name = None
        cdef int size = 0
        cdef uint64_t stream_offset = 0
        cdef int * patch_ptr = NULL
        cdef int last_difference = 0
        cdef net_table_objects.TableObject tobj = None
        cdef uint32_t resource_rva = 0
        cdef bint in_table = False
        cdef int old_size = 0
        cdef bytes new_stream_data = None
        cdef bytes result = None
        cdef dict heaps_by_offset = dict()
        cdef bytes padding = None
        cdef uint64_t target_offset = pe.get_offset_from_rva(target_addr)
        cdef int hdr_size = 0
        cdef bint in_same_section = pe.get_sec_index_va(pe.get_net_header().MetaData.VirtualAddress) == pe.get_sec_index_va(target_addr)
        cdef uint64_t patch_start = pe.get_offset_from_rva(va_addr)
        cdef dict method_padding = dict()
        cdef list methods = list()
        cdef uint32_t padding_counter = 0
        cdef uint64_t new_method_rva = 0
        cdef uint32_t amt_method_padding = 0
        cdef uint64_t method_offset = 0
        cdef uint64_t min_method_rva = 0
        cdef net_row_objects.MethodDef mdef2 = None
        cdef net_processing.MetadataTableHeapObject mheap = self.get_heap('#~')
        metadata_offset = pe.get_offset_from_rva(pe.get_net_header().MetaData.VirtualAddress)
        streams_offset = metadata_offset + 12
        number_of_streams = <int>(metadata_offset + 12)
        number_of_streams_bytes = old_exe_data[number_of_streams:number_of_streams + 4]
        length_of_str = int.from_bytes(number_of_streams_bytes, 'little')
        streams_offset += length_of_str + 6
        number_of_streams = int.from_bytes(old_exe_data[streams_offset:streams_offset + 2], 'little')
        streams_offset += 2
        passed_userstrings = False
        orig_streams_offset = streams_offset
        for heap_obj in self.get_heaps().values():
            heaps_by_offset[heap_obj.get_offset()] = heap_obj
        if in_streams and before_streams:
            raise net_exceptions.InvalidArgumentsException()
        if in_streams and difference != 0:
            for x in range(number_of_streams):
                orig_offset = streams_offset
                offset = int.from_bytes(old_exe_data[streams_offset:streams_offset + 4], 'little')
                streams_offset += 4
                size = int.from_bytes(old_exe_data[streams_offset: streams_offset + 4], 'little')
                streams_offset += 4
                name = bytearray()
                while old_exe_data[streams_offset] != 0:
                    name += bytes([old_exe_data[streams_offset]])
                    streams_offset += 1
                streams_offset += 1
                hdr_size = <int>(streams_offset - orig_offset)
                while hdr_size % 4 != 0:
                    hdr_size += 1
                streams_offset = orig_offset + hdr_size
                stream_offset = metadata_offset + offset
                if name == stream_name and not passed_userstrings:
                    passed_userstrings = True
                    # fix the size of user strings stream
                    # append the stream data
                    patch_ptr = <int*>&(<char*>new_exe_view.buf)[orig_offset + 4]
                    patch_ptr[0] = <int>(size + difference)
                if (stream_name is None and target_offset < stream_offset) or (passed_userstrings and stream_name != name):
                    # fix the offset of the rest of the streams
                    patch_ptr = <int*>&(<char*>new_exe_view.buf)[orig_offset]
                    patch_ptr[0] = <int>(offset + difference)
                    if stream_offset in heaps_by_offset:
                        #If its not in here it could be a phantom heap, ignore.
                        heap_obj = heaps_by_offset[stream_offset]
                        heap_obj.update_offset(<int>(stream_offset + difference))

            if orig_streams_offset <= target_offset < streams_offset:
                last_difference += difference

        #Let reconstruct executable handle updating heap offsets and sizes internally.
        tobj = self.get_metadata_table('MethodDef')
        if tobj is not None and difference != 0:
            methods = list(tobj)
            methods.sort(key=method_rva_sort)
            for mdef_obj in methods:
                cobj = mdef_obj.get_column('RVA')
                resource_offset = cobj.get_raw_value()
                if resource_offset == 0:
                    continue
                if resource_offset == va_addr:
                    in_table = True
                    continue
                resource_rva = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view, resource_offset, va_addr, difference, target_addr)
                if resource_rva != resource_offset:
                    in_table = True
                    cobj.set_raw_value(<unsigned int>resource_rva)
        
        tobj = self.get_metadata_table('FieldRVA')
        if tobj is not None and difference != 0:
            for x in range(1, len(tobj) + 1):
                rva_obj = tobj.get(<int>x)
                cobj = rva_obj.get_column('RVA')
                resource_offset = cobj.get_raw_value()
                if resource_offset == 0:
                    continue
                if resource_offset == va_addr:
                    in_table = True
                    continue
                resource_rva = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view, resource_offset, va_addr, difference, target_addr)
                if resource_offset != resource_rva:
                    in_table = True
                    cobj.set_raw_value(<unsigned int>resource_rva)
        PyBuffer_Release(&new_exe_view)

        if amt_padding != 0 and padding_offset != 0 and difference != 0:
            padding = b'\x00' * amt_padding
            new_exe_data = new_exe_data[:padding_offset] + padding + new_exe_data[padding_offset:]
            if before_streams and not in_same_section:
                last_difference += amt_padding
        if before_streams and in_same_section and difference != 0:
            #if its before streams, we dont want to update the data itself, just our held offsets.
            for heap_obj in heaps_by_offset.values():
                heap_obj.update_offset(heap_obj.get_offset() + difference)
        elif before_streams and difference != 0:
            for heap_obj in heaps_by_offset.values():
                heap_obj.update_offset(heap_obj.get_offset() + target_rawsize_difference)
        if (in_streams and stream_name is not None) or in_table:
            #Headers and such should match.  Just start patching in the heaps.  Method code also should be equivalent.
            #One thing thats sort of assumed here is that we are not updating the offset of the metadata heap (otherwise wed have to re initialize metadata header offsets).  I cant really think of a reason to do that though.
            for offset in heaps_by_offset.keys():
                heap_obj = heaps_by_offset[offset]
                old_size = heap_obj.get_size()
                new_stream_data = heap_obj.to_bytes()
                new_exe_data = new_exe_data[:offset + last_difference] + new_stream_data + new_exe_data[offset + old_size + last_difference:]
                heap_obj.update_size(<int>len(new_stream_data))
                last_difference += <int>len(new_stream_data) - old_size
        result = bytes(new_exe_data)
        if new_data is not None:
            result = result[:patch_start] + new_data + result[target_end:]
            self.set_exe_data(result)
        else:
            if stream_name is None:
                raise net_exceptions.InvalidArgumentsException()
            self.set_exe_data(result)
        tobj = self.get_metadata_table('MethodDef')
        if tobj is not None and not dont_update_methods:
            padding_counter = 0
            methods = list(tobj)
            methods.sort(key=method_rva_sort)
            while True:
                amt_method_padding = 0
                x = 0
                for mdef_obj in methods:
                    resource_offset = mdef_obj.get_column('RVA').get_raw_value()
                    if resource_offset == 0:
                        continue
                    if resource_offset % 4 != 0:
                        if resource_offset == va_addr:
                            raise Exception()
                        new_rva = resource_offset
                        while new_rva % 4 != 0:
                            new_rva += 1
                        amt_method_padding = <uint32_t>(new_rva - resource_offset)
                        padding = b'\x00' * amt_method_padding
                        method_offset = self.get_pe().get_offset_from_rva(resource_offset)
                        if pe.is_64bit():
                            self.__patch_dpe64(resource_offset, <int>amt_method_padding, None, resource_offset, True, padding, method_offset)
                        else:
                            self.__patch_dpe32(resource_offset, <int>amt_method_padding, None, resource_offset, True, padding, method_offset)
                        mdef_obj = self.get_token_value(mdef_obj.get_token())
                        for mdef2 in methods:
                            if mdef2.get_column('RVA').get_value() == resource_offset:
                                mdef2.get_column('RVA').set_raw_value(<unsigned int>new_rva)
                        method_offset = self.get_pe().get_offset_from_rva(new_rva)
                        padding_counter += 1
                        method_offset = mheap.get_offset()
                        new_rva = mheap.get_size()
                        new_stream_data = mheap.to_bytes()
                        if len(new_stream_data) != new_rva:
                            raise net_exceptions.InvalidArgumentsException()
                        result = self.get_exe_data()
                        result = result[:method_offset] + new_stream_data + result[method_offset + new_rva:]
                        self.set_exe_data(result)
                        break
                    x += 1
                if amt_method_padding == 0:
                    break
        self.verify_dpe(dont_update_methods)

    cpdef void verify_dpe(self, bint dont_check_method_align) except *:
        cdef bytes exe_data = self.get_exe_data()
        cdef IMAGE_DOS_HEADER * dos = NULL
        cdef Py_buffer exe_view
        cdef IMAGE_NT_HEADERS32 * nthdr32 = NULL
        cdef IMAGE_NT_HEADERS64 * nthdr64 = NULL
        cdef uint64_t bad_value = <uint64_t>-1
        cdef uint64_t offset = 0
        cdef uint64_t rva = 0
        cdef PeFile pe = self.get_pe()
        cdef unsigned int x = 0
        cdef IMAGE_DATA_DIRECTORY datadir
        cdef unsigned int net_offset = 0
        cdef IMAGE_COR20_HEADER * corhdr = NULL
        cdef unsigned short val = 0
        cdef net_row_objects.RowObject robj = None
        cdef net_table_objects.TableObject tobj = None
        cdef unsigned char first_byte = 0
        PyObject_GetBuffer(exe_data, &exe_view, PyBUF_ANY_CONTIGUOUS)
        dos = <IMAGE_DOS_HEADER*>(<char*>exe_view.buf)
        if dos.e_magic != 0x5A4D:
            raise Exception('dos header magic is invalid')
        nthdr32 = <IMAGE_NT_HEADERS32*>(<char*>exe_view.buf + dos.e_lfanew)
        if nthdr32.Signature != 0x4550:
            raise Exception('NT Header signature invalid')

        if nthdr32.FileHeader.Machine == 0:
            raise Exception('File header machine invalid.')\
        
        if self.get_pe().is_64bit():
            nthdr64 = <IMAGE_NT_HEADERS64*>nthdr32
            if nthdr64.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC:
                raise Exception('invalid optional header magic')

            if nthdr64.OptionalHeader.SizeOfCode > nthdr64.OptionalHeader.SizeOfImage:
                raise Exception('invalid size of code')

            if nthdr64.OptionalHeader.SizeOfInitializedData > nthdr64.OptionalHeader.SizeOfImage:
                raise Exception('Invalid size of initialized data')

            if nthdr64.OptionalHeader.SizeOfUninitializedData > nthdr64.OptionalHeader.SizeOfImage:
                raise Exception('invalid size of uninitialized data')

            if nthdr64.OptionalHeader.AddressOfEntryPoint != 0:
                offset = pe.get_offset_from_rva(nthdr64.OptionalHeader.AddressOfEntryPoint)
                if offset == bad_value:
                    raise Exception('Bad entry point value.')
            if nthdr64.OptionalHeader.Win32VersionValue != 0:
                raise Exception('Invalid Win32VersionValue')
            
            for x in range(nthdr64.OptionalHeader.NumberOfRvaAndSizes):
                datadir = nthdr64.OptionalHeader.DataDirectory[x]
                if datadir.VirtualAddress == 0:
                    continue
                offset = pe.get_offset_from_rva(datadir.VirtualAddress)
                if offset == bad_value:
                    raise Exception('Error with data directory {}'.format(x))
                if x == IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
                    net_offset = <unsigned int>offset

        else:
            if nthdr32.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC:
                raise Exception('invalid optional header magic')

            if nthdr32.OptionalHeader.SizeOfCode > nthdr32.OptionalHeader.SizeOfImage:
                raise Exception('invalid size of code')

            if nthdr32.OptionalHeader.SizeOfInitializedData > nthdr32.OptionalHeader.SizeOfImage:
                raise Exception('Invalid size of initialized data')

            if nthdr32.OptionalHeader.SizeOfUninitializedData > nthdr32.OptionalHeader.SizeOfImage:
                raise Exception('invalid size of uninitialized data')

            if nthdr32.OptionalHeader.AddressOfEntryPoint != 0:
                offset = pe.get_offset_from_rva(nthdr32.OptionalHeader.AddressOfEntryPoint)
                if offset == bad_value:
                    raise Exception('Bad entry point value.')
            if nthdr32.OptionalHeader.Win32VersionValue != 0:
                raise Exception('Invalid Win32VersionValue')
            
            for x in range(nthdr32.OptionalHeader.NumberOfRvaAndSizes):
                datadir = nthdr32.OptionalHeader.DataDirectory[x]
                if datadir.VirtualAddress == 0:
                    continue
                offset = pe.get_offset_from_rva(datadir.VirtualAddress)
                if offset == bad_value:
                    raise Exception('Error with data directory {}'.format(x))
                if x == IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
                    net_offset = <unsigned int>offset

        if net_offset == 0:
            raise Exception('not a dotnet?')
        
        corhdr = <IMAGE_COR20_HEADER*>(<char*>exe_view.buf + net_offset)
        if corhdr.cb != sizeof(IMAGE_COR20_HEADER):
            raise Exception('invalid cor20 hdr cb.')
        
        if corhdr.MetaData.VirtualAddress == 0 or corhdr.MetaData.Size == 0:
            raise Exception('Invalid metadata data directory.')

        offset = pe.get_offset_from_rva(corhdr.MetaData.VirtualAddress)
        if offset == bad_value:
            raise Exception('Invalid metadata data directory - bad va.')

        net_offset = (<unsigned int*>(<char*>exe_view.buf + offset))[0]
        if net_offset != 0x424A5342:
            raise Exception('Invalid metadata directory signature')
        
        val = (<unsigned short*>(<char*>exe_view.buf + offset + 4))[0]
        if val != 1:
            raise Exception('Invalid metadata directory MajorVersion')
        val = (<unsigned short*>(<char*>exe_view.buf + offset + 6))[0]
        if val != 1:
            raise Exception('Invalid metadata directory MinorVersion')
        
        net_offset = (<unsigned int *>(<char*>exe_view.buf + offset + 8))[0]
        if net_offset != 0:
            raise Exception('Invalid metadata directory reserved.')

        if self.has_metadata_table('MethodDef'):
            for robj in self.get_metadata_table('MethodDef'):
                offset = <uint64_t>robj.get_column('RVA').get_value()
                if offset == 0:
                    continue
                rva = offset
                if rva % 4 != 0 and not dont_check_method_align:
                    raise Exception('Method RVA {} is not aligned'.format(hex(robj.get_token())))
                                
                offset = pe.get_offset_from_rva(offset)
                if offset == bad_value:
                    raise Exception('Method token {} has bad rva'.format(hex(robj.get_token())))
                first_byte = (<unsigned char*>exe_view.buf)[offset]
                if not dont_check_method_align:
                    if (first_byte & 0x3 == 2):
                        pass
                    elif (first_byte & 0x3 == 3):
                        val = (<unsigned short*>(<char*>exe_view.buf + offset))[0]
                        if (val >> 12) != 3:
                            raise Exception('Invalid method header at method: {}'.format(hex(robj.get_token())))
                    else:
                        raise Exception('Error invalid header start byte for method {}'.format(hex(robj.get_token())))
                    if robj.disassemble_method() is None:
                        raise Exception('For whatever reason, disassemble method failed on method {}'.format(hex(robj.get_token())))
                
        PyBuffer_Release(&exe_view)

    cpdef void __patch_dpe32(self, uint64_t va, int diff, bytes stream_name, uint64_t target_addr, bint dont_update_methods, bytes new_data, uint64_t target_end):
        cdef PeFile pe = self.get_pe()
        cdef bytearray new_exe_data = bytearray(self.get_exe_data())
        cdef Py_buffer new_exe_view
        cdef IMAGE_DOS_HEADER * dos_header = NULL
        cdef IMAGE_NT_HEADERS32 * nt_headers = NULL
        cdef IMAGE_SECTION_HEADER * sec_header = NULL
        cdef IMAGE_SECTION_HEADER * prev_section_header = NULL
        cdef int section_offset = 0
        cdef Py_ssize_t x = 0
        cdef unsigned int old_rawsize = 0
        cdef unsigned int new_rawsize = 0
        cdef int target_rawsize_difference = 0
        cdef unsigned int required_val = 0
        cdef unsigned int new_va_val = 0
        cdef unsigned int size_of_code = 0
        cdef unsigned int size_of_uninitialized_data = 0
        cdef unsigned int size_of_initialized_data = 0
        cdef IMAGE_OPTIONAL_HEADER32 * opt_header = NULL
        cdef IMAGE_OPTIONAL_HEADER32 original_optional_header
        cdef unsigned long size_of_image = 0
        cdef IMAGE_DATA_DIRECTORY * data_dir = NULL
        cdef IMAGE_COR20_HEADER * cor_header = NULL
        cdef uint64_t net_header_offset = 0
        cdef bytes old_exe_data = bytes(new_exe_data)
        cdef uint64_t reloc_va = 0
        cdef unsigned int reloc_size = 0
        cdef uint64_t offset = 0
        cdef uint64_t debug_va = 0
        cdef IMAGE_BASE_RELOCATION * base_reloc = NULL
        cdef uint64_t reloc_offset = 0
        cdef IMAGE_DEBUG_DIRECTORY * debug_struct = NULL
        cdef uint64_t current_va = 0
        cdef uint64_t new_va = 0
        cdef uint64_t imports_offset = 0
        cdef IMAGE_IMPORT_DESCRIPTOR * import_descriptor = NULL
        cdef unsigned int orig_name = 0
        cdef uint64_t thunk_offset = 0
        cdef IMAGE_THUNK_DATA32 * thunk_data = NULL
        cdef uint64_t resource_offset = 0
        cdef uint64_t resource_rva = 0
        cdef uint64_t debug_offset = 0
        cdef int amt_padding = 0
        cdef int padding_offset = 0
        cdef bint in_streams = False
        cdef bint before_streams = False
        cdef uint64_t patch_start = pe.get_offset_from_rva(va)

        PyObject_GetBuffer(new_exe_data, &new_exe_view, PyBUF_WRITABLE)
        dos_header = <IMAGE_DOS_HEADER*>new_exe_view.buf
        nt_headers = <IMAGE_NT_HEADERS32*>(<uintptr_t>new_exe_view.buf + dos_header.e_lfanew)
        section_offset = pe.get_elfanew() + sizeof(IMAGE_FILE_HEADER) + 4 + nt_headers.FileHeader.SizeOfOptionalHeader
        if diff != 0:
            for x in range(nt_headers.FileHeader.NumberOfSections):
                section_header = <IMAGE_SECTION_HEADER*>(<uintptr_t>new_exe_view.buf + section_offset)
                if section_header.VirtualAddress <= target_addr < (section_header.VirtualAddress + section_header.Misc.VirtualSize):
                    old_rawsize = section_header.SizeOfRawData
                    new_rawsize = old_rawsize + diff
                    if new_rawsize % nt_headers.OptionalHeader.FileAlignment != 0:
                        new_rawsize = new_rawsize + (nt_headers.OptionalHeader.FileAlignment - (new_rawsize % nt_headers.OptionalHeader.FileAlignment))
                    amt_padding = new_rawsize - old_rawsize - diff
                    padding_offset = section_header.PointerToRawData + old_rawsize
                    section_header.SizeOfRawData = new_rawsize
                    section_header.Misc.VirtualSize = section_header.Misc.VirtualSize + amt_padding + diff
                    target_rawsize_difference = new_rawsize - old_rawsize
                elif section_header.VirtualAddress > target_addr:
                    section_header.PointerToRawData += target_rawsize_difference
                    required_val = prev_section_header.VirtualAddress + prev_section_header.Misc.VirtualSize
                    if section_header.VirtualAddress <= required_val:
                        new_va_val = section_header.VirtualAddress + nt_headers.OptionalHeader.SectionAlignment
                        while new_va_val < required_val:
                            new_va_val += nt_headers.OptionalHeader.SectionAlignment
                        section_header.VirtualAddress = new_va_val

                if section_header.Characteristics & IMAGE_SCN_CNT_CODE:
                    size_of_code += section_header.SizeOfRawData

                if section_header.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA:
                    size_of_initialized_data += section_header.SizeOfRawData
                
                if section_header.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA:
                    size_of_uninitialized_data += section_header.SizeOfRawData

                prev_section_header = section_header
                section_offset += sizeof(IMAGE_SECTION_HEADER)

            optional_header = &nt_headers.OptionalHeader
            original_optional_header = optional_header[0]
            size_of_image = section_header.VirtualAddress + section_header.Misc.VirtualSize
            size_of_image += (optional_header.SectionAlignment - (
                        size_of_image % nt_headers.OptionalHeader.SectionAlignment))
            nt_headers.OptionalHeader.AddressOfEntryPoint = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view, nt_headers.OptionalHeader.AddressOfEntryPoint, va, diff, target_addr)
            for x in range(optional_header.NumberOfRvaAndSizes):
                data_dir = &optional_header.DataDirectory[x]
                if data_dir.VirtualAddress != 0:
                    if data_dir.VirtualAddress <= target_addr < (data_dir.VirtualAddress + data_dir.Size):
                        data_dir.Size += diff
                    data_dir.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view, data_dir.VirtualAddress, va, diff, target_addr)
            
            optional_header.SizeOfCode = size_of_code
            optional_header.SizeOfInitializedData = size_of_initialized_data
            optional_header.SizeOfUninitializedData = size_of_uninitialized_data
            optional_header.SizeOfImage = size_of_image

            optional_header.BaseOfCode = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view, optional_header.BaseOfCode, va, diff, target_addr)
            optional_header.BaseOfData = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view, optional_header.BaseOfData, va, diff, target_addr)

            net_header_offset = self.get_cor_header_offset()
            cor_header = <IMAGE_COR20_HEADER*>(<uintptr_t>new_exe_view.buf + net_header_offset)

            if target_addr < cor_header.MetaData.VirtualAddress:
                before_streams = True
            if cor_header.MetaData.VirtualAddress <= target_addr < (cor_header.MetaData.VirtualAddress + cor_header.MetaData.Size):
                in_streams = True
                cor_header.MetaData.Size += diff
            if cor_header.Resources.VirtualAddress <= target_addr < (cor_header.Resources.VirtualAddress + cor_header.Resources.Size):
                cor_header.Resources.Size += diff

            cor_header.MetaData.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view, cor_header.MetaData.VirtualAddress, va, diff, target_addr)

            cor_header.Resources.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view, cor_header.Resources.VirtualAddress,
                                                                va, diff, target_addr)
            cor_header.StrongNameSignature.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view,
                                                                        cor_header.StrongNameSignature.VirtualAddress,
                                                                        va, diff, target_addr)
            cor_header.CodeManagerTable.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view,
                                                                    cor_header.CodeManagerTable.VirtualAddress, va,
                                                                    diff, target_addr)
            cor_header.VTableFixups.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view, cor_header.VTableFixups.VirtualAddress,
                                                                va, diff, target_addr)
            cor_header.ExportAddressTableJumps.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view,
                                                                            cor_header.ExportAddressTableJumps.VirtualAddress,
                                                                            va, diff, target_addr)
            cor_header.ManagedNativeHeader.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view,
                                                                        cor_header.ManagedNativeHeader.VirtualAddress,
                                                                        va, diff, target_addr)
            if cor_header.Flags & COMIMAGE_FLAGS_NATIVE_ENTRYPOINT != 0:
                cor_header.EntryPoint.EntryPointRVA = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view, cor_header.EntryPoint.EntryPointRVA,
                                                                    va, diff, target_addr)

            # now process the reloc dir
            if IMAGE_DIRECTORY_ENTRY_BASERELOC < optional_header.NumberOfRvaAndSizes:
                reloc_va = original_optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
                reloc_size = original_optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size
                if reloc_va != 0:
                    reloc_offset = pe.get_offset_from_rva(reloc_va)
                    offset = 0
                    while offset < reloc_size:
                        base_reloc = <IMAGE_BASE_RELOCATION*> (<uintptr_t>new_exe_view.buf + reloc_offset + offset)
                        base_reloc.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view, base_reloc.VirtualAddress, va,
                                                                diff, target_addr) 
                        offset += base_reloc.BlockSize

            if IMAGE_DIRECTORY_ENTRY_DEBUG < optional_header.NumberOfRvaAndSizes:
                #process debug dir
                debug_va = original_optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress
                if debug_va != 0:
                    debug_offset = pe.get_offset_from_rva(debug_va)
                    debug_struct = <IMAGE_DEBUG_DIRECTORY*>(<uintptr_t>new_exe_view.buf + debug_offset)
                    current_va = debug_struct.AddressOfRawData
                    new_va = net_patch.get_fixed_rva(pe, new_exe_view, current_va, va, diff, target_addr)
                    if current_va != new_va:
                        debug_struct.AddressOfRawData = <uint32_t>new_va
                        debug_struct.PointerToRawData += diff
                
            # now process imports dir
            if IMAGE_DIRECTORY_ENTRY_IMPORT < optional_header.NumberOfRvaAndSizes:
                imports_offset = original_optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
                if imports_offset != 0:
                    imports_offset = pe.get_offset_from_rva(imports_offset)
                    while True:
                        import_descriptor = <IMAGE_IMPORT_DESCRIPTOR*>(<uintptr_t>new_exe_view.buf + <uintptr_t>imports_offset)
                        if import_descriptor.Name == 0:
                            break
                        orig_name = import_descriptor.Name
                        import_descriptor.Name = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view, import_descriptor.Name, va, diff, target_addr)
                        thunk_offset = pe.get_offset_from_rva(import_descriptor.FirstThunk)
                        while True:
                            thunk_data = <IMAGE_THUNK_DATA32*>(<uintptr_t>new_exe_view.buf + thunk_offset)
                            if thunk_data.u1.AddressOfData == 0:
                                break
                            if (thunk_data.u1.AddressOfData & IMAGE_ORDINAL_FLAG32) == 0:
                                # name import, fix.
                                thunk_data.u1.AddressOfData = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view, thunk_data.u1.AddressOfData, va,
                                                                            diff, target_addr)
                            thunk_offset += sizeof(IMAGE_THUNK_DATA32)
                        import_descriptor.FirstThunk = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view, import_descriptor.FirstThunk, va,
                                                                        diff, target_addr)

                        thunk_offset = pe.get_offset_from_rva(import_descriptor.DUMMYUNIONNAME1.OriginalFirstThunk)
                        while True:
                            thunk_data = <IMAGE_THUNK_DATA32*>(<uintptr_t>new_exe_view.buf + thunk_offset)
                            if thunk_data.u1.AddressOfData == 0:
                                break
                            if (thunk_data.u1.AddressOfData & IMAGE_ORDINAL_FLAG32) == 0:
                                # name import, fix.
                                thunk_data.u1.AddressOfData = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view, thunk_data.u1.AddressOfData, va,
                                                                            diff, target_addr)
                            thunk_offset += sizeof(IMAGE_THUNK_DATA32)
                        import_descriptor.DUMMYUNIONNAME1.OriginalFirstThunk = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view,
                                                                                            import_descriptor.DUMMYUNIONNAME1.OriginalFirstThunk,
                                                                                            va, diff, target_addr)
                        imports_offset += sizeof(IMAGE_IMPORT_DESCRIPTOR)
            if IMAGE_DIRECTORY_ENTRY_RESOURCE < optional_header.NumberOfRvaAndSizes:
                resource_offset = original_optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress
                if resource_offset != 0:
                    resource_rva = resource_offset
                    resource_offset = pe.get_offset_from_rva(resource_offset)
                    net_patch.fixup_resource_directory(resource_offset, resource_rva, resource_offset, pe, new_exe_view, va, diff, target_addr)
        else:
            if (stream_name is not None) and new_data is None:
                #New data can be None if dont_update_methods is true.
                pass
            elif new_data is not None:
                old_exe_data = old_exe_data[:patch_start] + new_data + old_exe_data[target_end:]
                self.set_exe_data(old_exe_data)
                return
            else:
                raise net_exceptions.InvalidArgumentsException()
        self.__update_net_vas(va, diff, stream_name, target_addr, in_streams, before_streams, new_exe_data, old_exe_data, new_exe_view, padding_offset, amt_padding, target_rawsize_difference, dont_update_methods, new_data, target_end)

    cpdef void __patch_dpe64(self, uint64_t va, int diff, bytes stream_name, uint64_t target_addr, bint dont_update_methods, bytes new_data, uint64_t patch_end):
        cdef PeFile pe = self.get_pe()
        cdef bytearray new_exe_data = bytearray(self.get_exe_data())
        cdef Py_buffer new_exe_view
        cdef IMAGE_DOS_HEADER * dos_header = NULL
        cdef IMAGE_NT_HEADERS64 * nt_headers = NULL
        cdef IMAGE_SECTION_HEADER * sec_header = NULL
        cdef IMAGE_SECTION_HEADER * prev_section_header = NULL
        cdef int section_offset = 0
        cdef Py_ssize_t x = 0
        cdef unsigned int old_rawsize = 0
        cdef unsigned int new_rawsize = 0
        cdef int target_rawsize_difference = 0
        cdef unsigned int required_val = 0
        cdef unsigned int new_va_val = 0
        cdef unsigned int size_of_code = 0
        cdef unsigned int size_of_uninitialized_data = 0
        cdef unsigned int size_of_initialized_data = 0
        cdef IMAGE_OPTIONAL_HEADER64 * opt_header = NULL
        cdef IMAGE_OPTIONAL_HEADER64 original_optional_header
        cdef unsigned long size_of_image = 0
        cdef IMAGE_DATA_DIRECTORY * data_dir = NULL
        cdef IMAGE_COR20_HEADER * cor_header = NULL
        cdef uint64_t net_header_offset = 0
        cdef bytes old_exe_data = bytes(new_exe_data)
        cdef uint64_t reloc_va = 0
        cdef unsigned int reloc_size = 0
        cdef uint64_t offset = 0
        cdef uint64_t debug_va = 0
        cdef IMAGE_BASE_RELOCATION * base_reloc = NULL
        cdef uint64_t reloc_offset = 0
        cdef IMAGE_DEBUG_DIRECTORY * debug_struct = NULL
        cdef uint64_t current_va = 0
        cdef uint64_t new_va = 0
        cdef uint64_t imports_offset = 0
        cdef IMAGE_IMPORT_DESCRIPTOR * import_descriptor = NULL
        cdef unsigned int orig_name = 0
        cdef uint64_t thunk_offset = 0
        cdef IMAGE_THUNK_DATA64 * thunk_data = NULL
        cdef uint64_t resource_offset = 0
        cdef uint64_t resource_rva = 0
        cdef uint64_t debug_offset = 0
        cdef int amt_padding = 0
        cdef int padding_offset = 0
        cdef bint in_streams = False
        cdef bint before_streams = False
        cdef uint64_t patch_start = pe.get_offset_from_rva(va)

        PyObject_GetBuffer(new_exe_data, &new_exe_view, PyBUF_WRITABLE)
        dos_header = <IMAGE_DOS_HEADER*>new_exe_view.buf
        nt_headers = <IMAGE_NT_HEADERS64*>(<uintptr_t>new_exe_view.buf + dos_header.e_lfanew)
        section_offset = pe.get_elfanew() + sizeof(IMAGE_FILE_HEADER) + 4 + nt_headers.FileHeader.SizeOfOptionalHeader
        if diff != 0:
            for x in range(nt_headers.FileHeader.NumberOfSections):
                section_header = <IMAGE_SECTION_HEADER*>(<uintptr_t>new_exe_view.buf + section_offset)
                if section_header.VirtualAddress <= target_addr < (section_header.VirtualAddress + section_header.Misc.VirtualSize):
                    old_rawsize = section_header.SizeOfRawData
                    new_rawsize = old_rawsize + diff
                    if new_rawsize % nt_headers.OptionalHeader.FileAlignment != 0:
                        new_rawsize = new_rawsize + (nt_headers.OptionalHeader.FileAlignment - (new_rawsize % nt_headers.OptionalHeader.FileAlignment))
                    amt_padding = new_rawsize - old_rawsize - diff
                    padding_offset = section_header.PointerToRawData + old_rawsize
                    section_header.SizeOfRawData = new_rawsize
                    section_header.Misc.VirtualSize = section_header.Misc.VirtualSize + amt_padding + diff
                    target_rawsize_difference = new_rawsize - old_rawsize
                elif section_header.VirtualAddress > target_addr:
                    section_header.PointerToRawData += target_rawsize_difference
                    required_val = prev_section_header.VirtualAddress + prev_section_header.Misc.VirtualSize
                    if section_header.VirtualAddress <= required_val:
                        new_va_val = section_header.VirtualAddress + nt_headers.OptionalHeader.SectionAlignment
                        while new_va_val < required_val:
                            new_va_val += nt_headers.OptionalHeader.SectionAlignment
                        section_header.VirtualAddress = new_va_val

                if section_header.Characteristics & IMAGE_SCN_CNT_CODE:
                    size_of_code += section_header.SizeOfRawData

                if section_header.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA:
                    size_of_initialized_data += section_header.SizeOfRawData
                
                if section_header.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA:
                    size_of_uninitialized_data += section_header.SizeOfRawData

                prev_section_header = section_header
                section_offset += sizeof(IMAGE_SECTION_HEADER)

            optional_header = &nt_headers.OptionalHeader
            original_optional_header = optional_header[0]
            size_of_image = section_header.VirtualAddress + section_header.Misc.VirtualSize
            size_of_image += (optional_header.SectionAlignment - (
                        size_of_image % nt_headers.OptionalHeader.SectionAlignment))
            nt_headers.OptionalHeader.AddressOfEntryPoint = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view, nt_headers.OptionalHeader.AddressOfEntryPoint, va, diff, target_addr)
            for x in range(optional_header.NumberOfRvaAndSizes):
                data_dir = &optional_header.DataDirectory[x]
                if data_dir.VirtualAddress != 0:
                    if data_dir.VirtualAddress <= target_addr < (data_dir.VirtualAddress + data_dir.Size):
                        data_dir.Size += diff
                    data_dir.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view, data_dir.VirtualAddress, va, diff, target_addr)
            optional_header.SizeOfCode = size_of_code
            optional_header.SizeOfInitializedData = size_of_initialized_data
            optional_header.SizeOfUninitializedData = size_of_uninitialized_data
            optional_header.SizeOfImage = size_of_image

            optional_header.BaseOfCode = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view, optional_header.BaseOfCode, va, diff, target_addr)

            net_header_offset = self.get_cor_header_offset()
            cor_header = <IMAGE_COR20_HEADER*>(<uintptr_t>new_exe_view.buf + net_header_offset)
            if target_addr < cor_header.MetaData.VirtualAddress:
                before_streams = True
            
            if cor_header.MetaData.VirtualAddress <= target_addr < (cor_header.MetaData.VirtualAddress + cor_header.MetaData.Size):
                cor_header.MetaData.Size += diff
                in_streams = True
            if cor_header.Resources.VirtualAddress <= target_addr < (cor_header.Resources.VirtualAddress + cor_header.Resources.Size):
                cor_header.Resources.Size += diff
            cor_header.MetaData.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view, cor_header.MetaData.VirtualAddress, va, diff, target_addr)
            cor_header.Resources.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view, cor_header.Resources.VirtualAddress,
                                                                va, diff, target_addr)
            cor_header.StrongNameSignature.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view,
                                                                        cor_header.StrongNameSignature.VirtualAddress,
                                                                        va, diff, target_addr)
            cor_header.CodeManagerTable.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view,
                                                                    cor_header.CodeManagerTable.VirtualAddress, va,
                                                                    diff, target_addr)
            cor_header.VTableFixups.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view, cor_header.VTableFixups.VirtualAddress,
                                                                va, diff, target_addr)
            cor_header.ExportAddressTableJumps.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view,
                                                                            cor_header.ExportAddressTableJumps.VirtualAddress,
                                                                            va, diff, target_addr)
            cor_header.ManagedNativeHeader.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view,
                                                                        cor_header.ManagedNativeHeader.VirtualAddress,
                                                                        va, diff, target_addr)
            if cor_header.Flags & COMIMAGE_FLAGS_NATIVE_ENTRYPOINT != 0:
                cor_header.EntryPoint.EntryPointRVA = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view, cor_header.EntryPoint.EntryPointRVA,
                                                                    va, diff, target_addr)

            # now process the reloc dir
            if IMAGE_DIRECTORY_ENTRY_BASERELOC < optional_header.NumberOfRvaAndSizes:
                reloc_va = original_optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
                reloc_size = original_optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size
                if reloc_va != 0:
                    reloc_offset = pe.get_offset_from_rva(reloc_va)
                    offset = 0
                    while offset < reloc_size:
                        base_reloc = <IMAGE_BASE_RELOCATION*> (<uintptr_t>new_exe_view.buf + reloc_offset + offset)
                        base_reloc.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view, base_reloc.VirtualAddress, va,
                                                                diff, target_addr)                                
                        offset += base_reloc.BlockSize

            if IMAGE_DIRECTORY_ENTRY_DEBUG < optional_header.NumberOfRvaAndSizes:
                #process debug dir
                debug_va = original_optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress
                if debug_va != 0:
                    debug_offset = pe.get_offset_from_rva(debug_va)
                    debug_struct = <IMAGE_DEBUG_DIRECTORY*>(<uintptr_t>new_exe_view.buf + debug_offset)
                    current_va = debug_struct.AddressOfRawData
                    new_va = net_patch.get_fixed_rva(pe, new_exe_view, current_va, va, diff, target_addr)
                    if current_va != new_va:
                        debug_struct.AddressOfRawData = <uint32_t>new_va
                        debug_struct.PointerToRawData += diff
                
            # now process imports dir
            if IMAGE_DIRECTORY_ENTRY_IMPORT < optional_header.NumberOfRvaAndSizes:
                imports_offset = original_optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
                if imports_offset != 0:
                    imports_offset = pe.get_offset_from_rva(imports_offset)
                    while True:
                        import_descriptor = <IMAGE_IMPORT_DESCRIPTOR*>(<uintptr_t>new_exe_view.buf + <uintptr_t>imports_offset)
                        if import_descriptor.Name == 0:
                            break
                        orig_name = import_descriptor.Name
                        import_descriptor.Name = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view, import_descriptor.Name, va, diff, target_addr)
                        thunk_offset = pe.get_offset_from_rva(import_descriptor.FirstThunk)
                        while True:
                            thunk_data = <IMAGE_THUNK_DATA64*>(<uintptr_t>new_exe_view.buf + thunk_offset)
                            if thunk_data.u1.AddressOfData == 0:
                                break
                            if (thunk_data.u1.AddressOfData & IMAGE_ORDINAL_FLAG64) == 0:
                                # name import, fix.
                                thunk_data.u1.AddressOfData = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view, thunk_data.u1.AddressOfData, va,
                                                                            diff, target_addr)
                            thunk_offset += sizeof(IMAGE_THUNK_DATA64)
                        import_descriptor.FirstThunk = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view, import_descriptor.FirstThunk, va,
                                                                        diff, target_addr)

                        thunk_offset = pe.get_offset_from_rva(import_descriptor.DUMMYUNIONNAME1.OriginalFirstThunk)
                        while True:
                            thunk_data = <IMAGE_THUNK_DATA64*>(<uintptr_t>new_exe_view.buf + thunk_offset)
                            if thunk_data.u1.AddressOfData == 0:
                                break
                            if (thunk_data.u1.AddressOfData & IMAGE_ORDINAL_FLAG64) == 0:
                                # name import, fix.
                                thunk_data.u1.AddressOfData = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view, thunk_data.u1.AddressOfData, va,
                                                                            diff, target_addr)
                            thunk_offset += sizeof(IMAGE_THUNK_DATA64)
                        import_descriptor.DUMMYUNIONNAME1.OriginalFirstThunk = <uint32_t>net_patch.get_fixed_rva(pe, new_exe_view,
                                                                                            import_descriptor.DUMMYUNIONNAME1.OriginalFirstThunk,
                                                                                            va, diff, target_addr)
                        imports_offset += sizeof(IMAGE_IMPORT_DESCRIPTOR)
            if IMAGE_DIRECTORY_ENTRY_RESOURCE < optional_header.NumberOfRvaAndSizes:
                resource_offset = original_optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress
                if resource_offset != 0:
                    resource_rva = resource_offset
                    resource_offset = pe.get_offset_from_rva(resource_offset)
                    net_patch.fixup_resource_directory(resource_offset, resource_rva, resource_offset, pe, new_exe_view, va, diff, target_addr)
        else:
            if (stream_name is not None) and new_data is None:
                #New data can be None if dont_update_methods is true.
                pass
            elif new_data is not None:
                old_exe_data = old_exe_data[:patch_start] + new_data + old_exe_data[patch_end:]
                self.set_exe_data(old_exe_data)
            else:
                raise net_exceptions.InvalidArgumentsException()
        self.__update_net_vas(va, diff, stream_name, target_addr, in_streams, before_streams, new_exe_data, old_exe_data, new_exe_view, padding_offset, amt_padding, target_rawsize_difference, dont_update_methods, new_data, patch_end)


    cpdef void update_streams(self):
        cdef net_processing.HeapObject heap_obj = None
        cdef bytes exe_data = self.get_exe_data()
        for heap_obj in self.get_heaps().values():
            exe_data = exe_data[:heap_obj.get_offset()] + heap_obj.to_bytes() + exe_data[heap_obj.get_offset() + heap_obj.get_size():]

    cpdef void reinit_dpe(self, bint no_processing):
        self.original_exe_data = bytes(self.exe_data)
        self.metadata_dir = net_metadata.MetaDataDirectory(self)
        self.__versioninfo_str = None
        if not self.metadata_dir.is_valid_directory:
            return
        self.metadata_dir.process_metadata_heap(no_processing)

    cpdef uint64_t get_cor_header_offset(self):
        """ Obtain the file offset of the IMAGE_COR20_HEADER structure.

        Returns:
            uint64_t: The offset of the IMAGE_COR20_HEADER structure.
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
        #TODO: update this to use get_member_refs().
        results = list()
        if self.has_metadata_table('MemberRef'):
            for member in self.get_metadata_table('MemberRef'):
                if member.get_full_name() == full_name:
                    results.append(member)
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
        cdef uint64_t com_offset
        cdef uint64_t resources_offset
        cdef unsigned long resources_size
        cdef bytes rsrc_name
        cdef bytes rsrc_data
        cdef IMAGE_DATA_DIRECTORY * resources_dir
        cdef IMAGE_DATA_DIRECTORY com_table_directory
        results = list()
        resources = self.get_metadata_table('ManifestResource')
        if resources:
            com_table_directory = self.get_pe().get_directory_by_idx(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
            com_offset = self.get_pe().get_physical_by_rva(com_table_directory.VirtualAddress)
            com_offset += 24
            resources_dir = <IMAGE_DATA_DIRECTORY*>(<uintptr_t>self.get_pe().get_data_view() + com_offset)
            resources_offset = self.get_pe().get_physical_by_rva(resources_dir.VirtualAddress)
            for item in resources:
                if item['Implementation'].get_raw_value() == 0:
                    resource_offset = resources_offset + item['Offset'].get_raw_value()
                    resource_size = int.from_bytes(self.get_exe_data()[resource_offset:resource_offset + 4], 'little')
                    resource_offset += 4
                    rsrc_name = item['Name'].get_value()
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
        cdef uint64_t rva = 0
        cdef uint64_t offset = 0
        cdef uint64_t patch_offset = 0
        cdef bytes exe_data = None

        if method_obj['RVA'].get_raw_value() != 0:
            disas = method_obj.disassemble_method()
            if disas is None:
                raise net_exceptions.InvalidArgumentsException()
            rva = <uint64_t>method_obj['RVA'].get_raw_value()
            offset = self.get_pe().get_offset_from_rva(rva)
            patch_offset = offset + disas.get_header_size() + instr_offset  # needs to be zero based not 1 based.
            exe_data = self.get_exe_data()
            self.set_exe_data(exe_data[:patch_offset] + patch_bytes + exe_data[patch_offset + orig_size:])

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
        if self.__versioninfo_str == None:
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
