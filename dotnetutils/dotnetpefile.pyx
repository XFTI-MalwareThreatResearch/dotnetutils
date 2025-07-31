#cython: language_level=3

import os
import re
import pefile
from dotnetutils cimport net_tokens
from dotnetutils import net_exceptions, net_patch
from dotnetutils cimport net_row_objects, net_table_objects
from dotnetutils.net_structs import DotNetResourceSet
from dotnetutils cimport net_structs, net_processing, net_cil_disas
from logging import getLogger
from ctypes import sizeof
from cpython.datetime cimport datetime
from libc.stdint cimport uintptr_t, uint32_t
from dotnetutils.net_structs cimport IMAGE_DOS_HEADER, IMAGE_RESOURCE_DATA_ENTRY, IMAGE_RESOURCE_DIRECTORY, IMAGE_RESOURCE_DIRECTORY_ENTRY, VS_VERSIONINFO, IMAGE_DIRECTORY_ENTRY_RESOURCE, IMAGE_DATA_DIRECTORY, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, IMAGE_SECTION_HEADER, IMAGE_FILE_HEADER, IMAGE_COR20_HEADER, IMAGE_NT_OPTIONAL_HDR64_MAGIC
from cpython.buffer cimport PyObject_GetBuffer, PyBuffer_Release, PyBUF_ANY_CONTIGUOUS
from cpython.bytes cimport PyBytes_FromStringAndSize

logger = getLogger(__name__)

cdef class PeFile:
    def __cinit__(self, bytes file_data):
        self.__file_data = bytearray(file_data)
        self.__sections = list()
        PyObject_GetBuffer(self.__file_data, &self.__file_view, PyBUF_ANY_CONTIGUOUS)
        self.__parse()

    def __dealloc__(self):
        PyBuffer_Release(&self.__file_view)

    cdef __add_section(self, IMAGE_SECTION_HEADER * sec_hdr):
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

    cpdef unsigned int get_offset_from_rva(self, unsigned int rva):
        cdef IMAGE_SECTION_HEADER sec_hdr
        cdef int sec_size
        cdef dict sec_hdr_dict
        for x in range(len(self.__sections)):
            sec_hdr_dict = self.__sections[x]
            sec_hdr = sec_hdr_dict
            sec_size = max(sec_hdr.SizeOfRawData, sec_hdr.Misc.VirtualSize)
            if sec_hdr.VirtualAddress <= rva < (sec_hdr.VirtualAddress + sec_size):
                return sec_hdr.PointerToRawData + (rva - sec_hdr.VirtualAddress)
        return -1

    cpdef unsigned int get_rva_from_offset(self, unsigned int offset):
        cdef IMAGE_SECTION_HEADER sec_hdr
        cdef dict sec_hdr_dict
        for x in range(len(self.__sections)):
            sec_hdr_dict = self.__sections[x]
            sec_hdr = sec_hdr_dict
            if sec_hdr.PointerToRawData <= offset < (sec_hdr.PointerToRawData + sec_hdr.SizeOfRawData):
                return sec_hdr.VirtualAddress + (offset - sec_hdr.PointerToRawData)
        return -1

    cpdef IMAGE_DATA_DIRECTORY get_directory_by_idx(self, int idx):
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
        return self.__is_64bit

    cpdef list get_sections(self):
        return self.__sections

    cpdef int get_elfanew(self):
        return self.__nt_headers_offset

    cdef uintptr_t get_data_view(self):
        return <uintptr_t>self.__file_view.buf

    cpdef unsigned int get_physical_by_rva(self, unsigned int rva):
        return self.get_offset_from_rva(rva)

cdef class DotNetPeFile:
    def __init__(self, str file_path='', bytes pe_data=bytes(), bint no_processing=False):
        """
        Represents a .NET pe file.
        :param file_path: The file path to the file
        :param pe_data: The raw bytes of the PE file
        """
        cdef IMAGE_DATA_DIRECTORY com_table_directory
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
        except ValueError:
            raise net_exceptions.NotADotNetFile
        try:
            com_table_directory = self.pe.get_directory_by_idx(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
            if com_table_directory.VirtualAddress == 0 or com_table_directory.Size == 0:
                raise net_exceptions.NotADotNetFile
        except IndexError:
            raise net_exceptions.NotADotNetFile
        self.__cor_header_offset = self.pe.get_offset_from_rva(com_table_directory.VirtualAddress)
        self.added_strings = list()
        self.debug_counter = 0
        self.logging_str = ''
        self.original_exe_data = bytes(self.exe_data)
        self.metadata_dir = net_metadata.MetaDataDirectory(self)
        self.__versioninfo_str = None
        if not self.metadata_dir.is_valid_directory:
            return
        self.metadata_dir.process_metadata_heap(no_processing)


    cpdef unsigned int get_cor_header_offset(self):
        return self.__cor_header_offset

    cpdef void add_log_msg(self, str msg):
        self.logging_str += msg

    cpdef str get_log_str(self):
        return self.logging_str

    cpdef bytes get_original_exe_data(self):
        """
        Obtain the original exe data, before any manipulation.
        """
        return self.original_exe_data

    cpdef bytes get_exe_data(self):
        """
        Obtain the current exe data dotnetutils is parsing / manipulating
        NOTE: This can return an invalid PE if reconstruct_executable() wasnt called after change_value() or patching was done.
        """
        return self.exe_data

    cpdef net_metadata.MetaDataDirectory get_metadata_dir(self):
        """
        Obtain the metadata directory.
        """
        return self.metadata_dir

    cpdef void add_string(self, str string) except *:
        """
        Not the greatest way to do this, but the correct way would require rewriting reconstruct_executable().

        Marks a string to be added into the #Strings heap.  The string is not added at any specific location.
        Intended to be used for adding markers that a deobfuscator has proccessed a file.
        """
        
        self.added_strings.append(string.encode('ascii'))

    cpdef void set_exe_data(self, bytes exe_data):
        """
        Internal use only.  Sets exe_data property and reinitializes pe property.
        """
        self.exe_data = bytes(exe_data)
        self.pe = PeFile(exe_data)

    cpdef PeFile get_pe(self):
        """
        Obtains a pefile.PE object representing the current executable.
        """
        return self.pe

    cpdef IMAGE_COR20_HEADER get_cor20_header(self):
        """
        Obtains the COR20 header.
        """
        return self.metadata_dir.get_net_header()

    cpdef int get_processor_bits(self):
        """
        Determines what procesor bits (32 or 64) the .NET Assembly actually runs as.
        see dnSpy's dnSpy.Decompiler.TargetFrameworkUtils.GetArchString
        """
        cdef int c
        c = 0
        cor_header = self.get_cor20_header()
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
        """
        Get methods matching name
        :param name: the name of the methods you would like to obtain
        :return: A list of methods matching name
        """
        cdef net_table_objects.MethodDefTable mtable
        mtable = <net_table_objects.MethodDefTable>self.get_metadata_table('MethodDef')
        if mtable is not None:
            return mtable.get_methods_by_name(name)
        return list()

    cpdef net_row_objects.MethodDef get_method_by_rid(self, int rid):
        """
        Obtains a method by RID
        :param rid: the RID of the method
        :return: the method matching RID
        """
        return self.get_metadata_table('MethodDef').get(rid)

    cpdef list get_methods_by_full_name(self, bytes full_name):
        """
        Obtains a method by its full name
        :param full_name: the full name of the method
        :return: A method matching the full_name
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
            for member in self.get_metadata_table('MemberRef'):
                if member.get_full_name() == full_name:
                    results.append(member)
        return results

    cpdef net_row_objects.TypeRef get_typeref_by_full_name(self, bytes full_name):
        return self.get_metadata_table('TypeRef').get_type_by_full_name(full_name)

    cpdef net_table_objects.TableObject get_metadata_table(self, str name):
        """
        Obtain a table from the .NET metadata tables.
        :param name: the name of the table
        :return: A TableObject that represents the table, or None if it doesn't exist.
        """
        cdef net_table_objects.MetadataHeap mheap
        mheap = <net_table_objects.MetadataHeap>self.get_heap('#~')
        if mheap is not None:
            return mheap.obtain_table(name)
        return None
    
    cpdef bint has_metadata_table(self, str name):
        """
        Check if the binary has a metadata table denoted by Name.
        """
        cdef net_table_objects.MetadataHeap mheap
        mheap = <net_table_objects.MetadataHeap>self.get_heap('#~')
        if mheap is not None:
            return mheap.has_table(name)
        return False

    cpdef object get_heap(self, str name):
        """
        Obtain a heap by name
        :param name: name of the heap
        :return: A Stream object
        """
        return self.get_metadata_dir().get_heap(name)
    
    cpdef dict get_heaps(self):
        """
        Obtains a dictionary Dict[heap name, heap object] representing all known heaps in the assembly.
        """
        return self.get_metadata_dir().get_heaps()

    cpdef bint has_heap(self, str name):
        """
        Return True if a heap 'name' exists in the Assembly.
        """
        return name in self.get_metadata_dir().get_heaps()

    cpdef list get_user_strings(self):
        """
        Obtains all user strings.  User strings are strings used within the program.
        :return: A list of user strings
        """
        cdef net_processing.UserStringsStream stream
        stream = <net_processing.UserStringsStream>self.get_heap('#US')
        if stream is not None:
            return stream.get_items()
        return list()

    cpdef list get_strings(self):
        """
        Obtains all normal strings.  strings are used in the metadata tables.
        :return: A list of strings
        """
        cdef net_processing.StringStream stream
        stream = <net_processing.StringStream> self.get_heap('#Strings')
        if stream is not None:
            return stream.get_items()
        return list()

    cpdef bint has_user_string(self, bytes string):
        """
        Returns True if 'string' exists within the #US stream.
        If string is bytes, it should be utf-16le encoded.
        """
        return string in self.get_user_strings()

    cpdef bint has_string(self, bytes string):
        """
        Returns True if 'string' exists within the #Strings stream.
        If string is bytes, it should be utf-8 encoded.
        """
        return string in self.get_strings()

    cpdef list get_resources(self):
        """
        Obtains a list of resources
        :return: a list of DotNetResourceSet objects
        """
        cdef list results
        cdef net_table_objects.TableObject resources
        cdef net_row_objects.RowObject item
        cdef unsigned long com_offset
        cdef unsigned long resources_offset
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
        """
        Obtain a ManifestResource by its name.
        """
        cdef list resources
        resources = self.get_resources()
        for rsrc_obj in resources:
            for rsrc in rsrc_obj.get_resources():
                if rsrc.get_name() == name:
                    return rsrc.get_data()
        return None

    cpdef list get_exported_types(self):
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
        """
        Obtains methods by regex
        :param regex: the regex to use (re.Compile only)
        :return: A list of methods matching regex.
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
        """
        Obtains a type by name
        :param type_name: the name of the type
        :return: a list of TypeDef objects matching type_name
        """
        cdef net_table_objects.TypeDefTable table
        table = <net_table_objects.TypeDefTable>self.get_metadata_table('TypeDef')
        if table is not None:
            return table.get_types_by_name(type_name)
        return list()

    cpdef net_row_objects.TypeDefOrRef get_type_by_full_name(self, bytes type_full_name):
        """
        Obtains a type by full name
        :param type_full_name: the full name of the type
        :return: a TypeDef object matching type_full_name
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

    cpdef bytes reconstruct_executable(self) except *:
        """
        Obtain the executable with all changes to the strings, metadata, code and user strings section intact.

        Could pretty easily adapt this to include other streams as well, felt like these were the most needed.
        
        #NOTE: For the most part, this currently only patches in user strings and method code, as well as stuff done through change_value().
        To add a string to the #Strings heap, use DotNetPeFile.add_string()
        """

        cdef net_processing.BlobStream blob_stream
        cdef net_processing.StringStream strings_stream
        cdef net_processing.GuidStream guid_stream
        cdef net_table_objects.MetadataHeap metadata_heap
        cdef list original_strings_items
        cdef str table_name
        cdef net_table_objects.TableObject table_obj
        cdef net_row_objects.RowObject row_obj
        cdef net_row_objects.ColumnValue orig_col_obj
        cdef bytes str_val
        cdef bytes metadata_heap_data
        cdef DotNetPeFile curr_dpe
        cdef list col_objs
        cdef unsigned long x
        cdef unsigned long y

        #first go through all the columns and apply any changes that need to be applied.
        blob_stream = net_processing.BlobStream(None, None, self, dummy=True)
        strings_stream = net_processing.StringStream(None, None, self, dummy=True)
        guid_stream = net_processing.GuidStream(None, None, self, dummy=True)
        metadata_heap = self.get_heap('#~')
        original_strings_items = self.get_heap('#Strings').get_items()
        for table_name, table_obj in metadata_heap.get_tables().items():
            for x in range(1, len(table_obj) + 1):
                row_obj = table_obj[x]
                col_objs = list(row_obj)
                for y in range(len(col_objs)):
                    orig_col_obj = col_objs[y]
                    current_byte_value = orig_col_obj.get_value()
                    if orig_col_obj.has_value():
                        if isinstance(orig_col_obj.get_col_type(), net_tokens.CodedToken):
                            if orig_col_obj.get_col_type().is_stream():
                                #if the current value is none, just leave it alone for now.
                                if current_byte_value != None:
                                    if orig_col_obj.get_col_type() != net_tokens.get_UserStringsStream():
                                        if orig_col_obj.get_col_type() == net_tokens.get_StringsStream():
                                            new_raw_value = strings_stream.find_index(orig_col_obj.get_value())
                                            if new_raw_value == -1:
                                                new_raw_value = strings_stream.append_item(orig_col_obj.get_value())
                                            if orig_col_obj.get_original_value() in original_strings_items:
                                                original_strings_items.remove(orig_col_obj.get_original_value())
                                            orig_col_obj.set_raw_value(new_raw_value)
                                        elif orig_col_obj.get_col_type() == net_tokens.get_GuidStream():
                                            if orig_col_obj.get_col_type() == net_tokens.get_StringsStream():
                                                new_raw_value = guid_stream.find_index(orig_col_obj.get_value())
                                                if new_raw_value == -1:
                                                    new_raw_value = guid_stream.append_item(orig_col_obj.get_value())
                                                orig_col_obj.set_raw_value(new_raw_value)
                                        elif orig_col_obj.get_col_type() == net_tokens.get_BlobStream():
                                            if orig_col_obj.get_col_type() == net_tokens.get_StringsStream():
                                                new_raw_value = blob_stream.find_index(orig_col_obj.get_value())
                                                if new_raw_value == -1:
                                                    new_raw_value = blob_stream.append_item(orig_col_obj.get_value())
                                                orig_col_obj.set_raw_value(new_raw_value)
                                        else:
                                            raise net_exceptions.InvalidTokenException(orig_col_obj.get_col_type(), orig_col_obj.get_raw_value())

                            else:
                                if orig_col_obj.get_col_type().is_fixed_value() and orig_col_obj.get_col_type().get_fixed_size() != -1:
                                    if orig_col_obj.get_changed_value() != None:
                                        orig_col_obj.set_raw_value(orig_col_obj.get_changed_value())

        #add any extra strings to our fake #Strings heap.
        for str_val in self.added_strings:
            strings_stream.append_item(str_val)

        # in addition to this, check the strings stream for any strings that were not connected to the metadata tables.
        new_string_items = strings_stream.get_items()

        for item in new_string_items:
            if item in original_strings_items:
                original_strings_items.remove(item)

        for item in original_strings_items:
            if len(item) != 0:
                strings_stream.append_item(item)
        #so now that weve applied all the changes to the various streams, go through each of them and ensure that the heap_offset_size is updated.
        for heap_name, heap_value in self.get_heaps().items():
            if isinstance(heap_value, net_processing.Stream):
                if heap_name == b'#~' or heap_name == '#US':
                    continue  #just to be safe.
                heap_id = None
                if heap_name == '#Blob':
                    if len(blob_stream.get_data()) > 65536:
                        self.get_metadata_dir().get_metadata_table_header().set_heap_offset_size(net_structs.BITMASK_BLOB, 4)
                    heap_id = net_structs.BITMASK_BLOB
                elif heap_name == '#Strings':
                    if len(strings_stream.get_data()) > 65536:
                        self.get_metadata_dir().get_metadata_table_header().set_heap_offset_size(net_structs.BITMASK_STRINGS, 4)
                    heap_id = net_structs.BITMASK_STRINGS
                elif heap_name == '#GUID':
                    if len(guid_stream.get_data()) > 65536:
                        self.get_metadata_dir().get_metadata_table_header().set_heap_offset_size(net_structs.BITMASK_GUID, 4)
                    heap_id = net_structs.BITMASK_GUID
        #begin patching in various streams.  Start with the metadata heap.
        #problem: we cant patch the stuff in individually.  Has to be all or nothing.
        curr_exe_data = self.get_exe_data()
        metadata_heap_data = self.get_heap('#~').to_bytes()
        if len(metadata_heap_data) < self.get_metadata_dir().get_metadata_heap_size():
            metadata_heap_data += (b'\x00' * (self.get_metadata_dir().get_metadata_heap_size() - len(metadata_heap_data)))
        if len(metadata_heap_data) < self.get_metadata_dir().get_metadata_heap_size():
            raise net_exceptions.InvalidMetadataException
        curr_exe_data = net_patch.apply_pe_fixups(self.get_pe(), curr_exe_data,
                                                  self.get_pe().get_rva_from_offset(self.get_heap('#~').get_start_offset()),
                                                  len(metadata_heap_data) - self.get_metadata_dir().get_metadata_heap_size(), self, True)
        curr_exe_data = curr_exe_data[:self.get_heap('#~').get_start_offset()] + metadata_heap_data + curr_exe_data[self.get_heap(
            '#~').get_start_offset() + self.get_metadata_dir().get_metadata_heap_size():]

        curr_exe_data = bytes(curr_exe_data)

        curr_dpe = DotNetPeFile(pe_data=curr_exe_data, no_processing=True)

        strings_heap = strings_stream
        orig_strings_heap = self.get_heap('#Strings')
        strings_data = strings_heap.get_data()
        if len(strings_heap.get_data()) < orig_strings_heap.get_size():
            strings_data += (b'\x00' * (orig_strings_heap.get_size() - len(strings_data)))

        if len(strings_data) < orig_strings_heap.get_size():
            raise net_exceptions.ReconstructionFailedException

        curr_exe_data = net_patch.apply_pe_fixups(curr_dpe.get_pe(), curr_exe_data,
                                                  curr_dpe.get_pe().get_rva_from_offset(orig_strings_heap.get_offset()),
                                                  len(strings_data) - orig_strings_heap.get_size(), curr_dpe, True)
        curr_strings = curr_dpe.get_heap('#Strings')
        curr_exe_data = curr_exe_data[:curr_strings.get_offset()] + strings_data + curr_exe_data[
                                                                             curr_strings.get_offset() + curr_strings.get_size():]
        curr_exe_data = bytes(curr_exe_data)
        if self.has_heap('#US'):
            curr_dpe = DotNetPeFile(pe_data=curr_exe_data)
            current_us_heap = curr_dpe.get_heap('#US')
            new_us_heap = self.get_heap('#US')
            us_data = new_us_heap.get_data()
            if len(us_data) < current_us_heap.get_size():
                us_data += (b'\x00' * (current_us_heap.get_size() - len(us_data)))

            if len(us_data) < current_us_heap.get_size():
                raise net_exceptions.ReconstructionFailedException

            curr_exe_data = net_patch.apply_pe_fixups(curr_dpe.get_pe(), curr_exe_data,
                                                    curr_dpe.get_pe().get_rva_from_offset(current_us_heap.get_offset()),
                                                    len(us_data) - current_us_heap.get_size(), curr_dpe, True)
            curr_exe_data = bytes(curr_exe_data[:current_us_heap.get_offset()] + us_data + curr_exe_data[current_us_heap.get_offset() + current_us_heap.get_size():])
            self.set_exe_data(curr_exe_data)
            return curr_exe_data
        else:
            curr_exe_data = bytes(curr_exe_data)
            self.set_exe_data(curr_exe_data)
            return curr_exe_data

    cpdef int delete_user_string(self, int us_index):
        """
        Handles deletion of a user string.  Caller needs to handle instances where the string itself is used, everything else should be handled.
        """
        cdef int difference
        cdef net_row_objects.MethodDef method
        cdef net_cil_disas.MethodDisassembler disas
        cdef list instr_list
        cdef unsigned long method_code_offset
        cdef net_cil_disas.Instruction instr
        cdef unsigned long token
        cdef unsigned long new_token
        cdef unsigned long instr_offset
        difference = self.get_heap('#US').del_item(us_index)
        for method in self.get_metadata_table('MethodDef'):
            if not method.has_body():
                continue
            disas = method.disassemble_method()
            instr_list = disas.get_list_of_instrs()
            method_code_offset = self.get_pe().get_offset_from_rva(method['RVA'].get_value()) + disas.get_header_size()
            for x in range(len(disas)):
                instr = instr_list[x]
                if instr.get_name() == 'ldstr':
                    token = int.from_bytes(instr.get_arguments()[:3], 'little')
                    if token != us_index:
                        if token > us_index:
                            new_token = token - difference
                            instr_offset = method_code_offset + instr.get_instr_offset()
                            self.set_exe_data(self.get_exe_data()[:instr_offset] + b'\x72' + int.to_bytes(new_token, 3,
                                                                                                  'little') + b'\x70' + self.get_exe_data()[
                                                                                                                        instr_offset + 5:])
        return difference

    cpdef list get_user_string_usages(self, unsigned long us_index):
        """
        Useful for deleting strings that are used multiple times throughout the binary.
        Returns references of the strings in the form of (method_name, instr index)
        """
        cdef list usages
        cdef net_row_objects.MethodDef method
        cdef net_cil_disas.MethodDisassembler disas
        cdef list instr_list
        cdef int x 
        cdef net_cil_disas.Instruction instr
        cdef unsigned long token
        usages = list()
        for method in self.get_metadata_table('MethodDef'):
            if method['RVA'].get_value() == 0:
                continue
            disas = method.disassemble_method()
            instr_list = disas.get_list_of_instrs()
            for x in range(len(disas)):
                instr = instr_list[x]
                if instr.get_name() == 'ldstr':
                    token = int.from_bytes(instr.get_arguments()[:3], 'little')
                    if token == us_index:
                        usages.append((method.get_full_name(), x))
        return usages

    cpdef void patch_instruction(self, net_row_objects.MethodDef method_obj, bytes patch_bytes, unsigned long instr_offset, unsigned long orig_size) except *:
        """
        Patch an instruction.
        """
        if method_obj['RVA'].get_raw_value() != 0:
            disas = method_obj.disassemble_method()
            rva = method_obj['RVA'].get_raw_value()
            offset = self.get_pe().get_offset_from_rva(rva)
            patch_offset = offset + disas.get_header_size() + instr_offset  # needs to be zero based not 1 based.
            exe_data = self.get_exe_data()
            self.set_exe_data(exe_data[:patch_offset] + patch_bytes + exe_data[patch_offset + orig_size:])

    cpdef net_row_objects.MethodDef get_entry_point(self):
        """
        Obtains an object representing the file's entry point.
        """
        try:
            return self.get_token_value(self.metadata_dir.get_net_header().EntryPoint.EntryPointToken)
        except net_exceptions.InvalidTokenException:
            return None

    cpdef set_entry_point(self, unsigned int ep_token):
        """
        Sets metadata token "ep_token" as the entry point.
        """
        cdef IMAGE_COR20_HEADER new_net_header = self.metadata_dir.get_net_header()
        cdef bytes new_cor_bytes
        cdef bytes current_exe_data
        cdef bytes new_exe_data
        new_net_header.EntryPoint.EntryPointToken = ep_token
        current_exe_data = self.get_exe_data()
        new_cor_bytes = PyBytes_FromStringAndSize(<char*>&new_net_header, sizeof(IMAGE_COR20_HEADER))
        new_exe_data = current_exe_data[:self.get_cor_header_offset()] + new_cor_bytes + current_exe_data[self.get_cor_header_offset() + new_net_header.cb:]
        self.set_exe_data(new_exe_data)

    cpdef object get_token_value(self, unsigned long token):
        """
        Obtain a token's DotNetUtils representation.
        :param token: The token to process
        :return: The token's corresponding object.
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

    cpdef str get_productversion(self):
        #this is used so little times that we may as well just use PeFile for it.
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


#TODO: Multiple methods can have the same full name - e.x when overriding parameters.
cpdef DotNetPeFile try_get_dotnetpe(str file_path='', bytes pe_data=bytes(), bint dont_process=False):
    """
    Helper function - creates and returns a dotnetpefile object
    Handles certain errors by returning None.
    """
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
