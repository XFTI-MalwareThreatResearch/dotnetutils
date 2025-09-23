#cython: language_level=3
#distutils: language=c++

import re
import pefile
from dotnetutils.net_structs import DotNetResourceSet
from dotnetutils import net_exceptions
from logging import getLogger
from ctypes import sizeof


from dotnetutils cimport net_tokens
from dotnetutils cimport net_row_objects, net_table_objects, net_patch
from dotnetutils cimport net_structs, net_processing, net_cil_disas
from cpython.datetime cimport datetime
from libc.stdint cimport uintptr_t, uint32_t, uint64_t
from dotnetutils.net_structs cimport IMAGE_DOS_HEADER, IMAGE_RESOURCE_DATA_ENTRY, IMAGE_RESOURCE_DIRECTORY, IMAGE_RESOURCE_DIRECTORY_ENTRY, VS_VERSIONINFO, IMAGE_DIRECTORY_ENTRY_RESOURCE, IMAGE_DATA_DIRECTORY, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, IMAGE_SECTION_HEADER, IMAGE_FILE_HEADER, IMAGE_COR20_HEADER, IMAGE_NT_OPTIONAL_HDR64_MAGIC
from dotnetutils.net_structs cimport IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_CNT_UNINITIALIZED_DATA, COMIMAGE_FLAGS_NATIVE_ENTRYPOINT, IMAGE_OPTIONAL_HEADER32, IMAGE_OPTIONAL_HEADER64, IMAGE_BASE_RELOCATION, IMAGE_DEBUG_DIRECTORY, IMAGE_IMPORT_DESCRIPTOR, IMAGE_THUNK_DATA32, IMAGE_THUNK_DATA64
from dotnetutils.net_structs cimport IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_DEBUG, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_ORDINAL_FLAG32, IMAGE_DEBUG_DIRECTORY, IMAGE_ORDINAL_FLAG64
from cpython.buffer cimport PyObject_GetBuffer, PyBuffer_Release, PyBUF_ANY_CONTIGUOUS, PyBUF_WRITABLE
from cpython.bytes cimport PyBytes_FromStringAndSize

logger = getLogger(__name__)

def get_offset_sort_func(obj):
    return obj.get_offset()

cdef class PeFile:
    """
    Small custom PeFile implementation.
    Designed to ensure less python dependencies.
    """
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

    cpdef uint64_t get_offset_from_rva(self, uint64_t rva):
        """
        Obtain the file offset from a RVA.
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
        """
        Obtain the RVA from a file offset.
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
        """
        Obtain a data directory by index.
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
        """
        Returns True if the file is 64 bit, False otherwise.
        """
        return self.__is_64bit

    cpdef list get_sections(self):
        """
        Return a list of section headers.
        """
        return self.__sections

    cpdef int get_elfanew(self):
        """
        Obtain the value of MS_DOS_HEADER.e_lfanew.
        """
        return self.__nt_headers_offset

    cdef uintptr_t get_data_view(self):
        """
        Obtain a pointer to the underlying file data.
        Mostly for internal use.
        """
        return <uintptr_t>self.__file_view.buf

    cpdef bytes get_file_data(self):
        """
        Obtain a byte copy of the exe data.
        """
        return bytes(self.__file_data)

    cpdef uint64_t get_physical_by_rva(self, uint64_t rva):
        """
        Same as PeFile.get_offset_from_rva()
        """
        return self.get_offset_from_rva(rva)

    cdef int get_sec_index_va(self, uint64_t va_addr):
        cdef dict sec_hdr = None
        cdef int x = 0
        for sec_hdr in self.get_sections():
            if sec_hdr['VirtualAddress'] <= va_addr < (sec_hdr['VirtualAddress'] + sec_hdr['Misc']['VirtualSize']):
                return x
            x += 1
        return -1

    cdef int get_sec_index_phys(self, uint64_t offset):
        cdef dict sec_hdr = None
        cdef int x = 0
        for sec_hdr in self.get_sections():
            if sec_hdr['PointerToRawData'] <= offset < (sec_hdr['PointerToRawData'] + sec_hdr['SizeOfRawData']):
                return x
            x += 1
        return -1

    cdef void update_va(self, uint64_t va_addr, int difference, DotNetPeFile dpe, bint in_streams, bint do_reconstruction, bytes stream_name, int sec_index):
        if difference == 0:
            return
        if self.is_64bit():
            self.__update_va64(va_addr, difference, dpe, in_streams, stream_name, sec_index)
        else:
            self.__update_va32(va_addr, difference, dpe, in_streams, stream_name, sec_index)

        self.__update_metadata_rvas(va_addr, difference, dpe)
        if do_reconstruction:
            dpe.reconstruct_executable()

    cdef void __update_metadata_rvas(self, uint64_t va_addr, int difference, DotNetPeFile dpe):
        cdef net_row_objects.MethodDef mdef_obj = None
        cdef net_row_objects.RowObject rva_obj = None
        cdef net_table_objects.MethodDefTable mdef_table = dpe.get_metadata_table('MethodDef')
        cdef net_table_objects.FieldRVATable rva_table = dpe.get_metadata_table('FieldRVA')
        cdef net_row_objects.ColumnValue cobj = None
        cdef Py_ssize_t x = 0
        if mdef_table is not None:
            for x in range(1, len(mdef_table) + 1):
                mdef_obj = mdef_table.get(<int>x)
                cobj = mdef_obj.get_column('RVA')
                if cobj.get_raw_value() > va_addr: #TODO: should this be >=?
                    cobj.set_raw_value(cobj.get_raw_value() + difference)

        if rva_table is not None:
            for x in range(1, len(rva_table) + 1):
                rva_obj = rva_table.get(<int>x)
                cobj = rva_obj.get_column('RVA')
                if cobj.get_raw_value() > va_addr: #TODO: should this be >=?
                    cobj.set_raw_value(cobj.get_raw_value() + difference)

    #TODO: add support for exports
    cdef void __update_va32(self, uint64_t va_addr, int difference, DotNetPeFile dpe, bint in_streams, bytes stream_name, int sec_index):
        cdef bytearray new_exe_data = bytearray(dpe.get_exe_data())
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
        cdef uint64_t metadata_offset = 0
        cdef uint64_t streams_offset = 0
        cdef bytes number_of_streams_bytes = None
        cdef int length_of_str = 0
        cdef int number_of_streams = 0
        cdef bint passed_userstrings = False
        cdef uint64_t orig_offset = 0
        cdef int size = 0
        cdef uint64_t stream_offset = 0
        cdef uint64_t orig_streams_offset = 0
        cdef bytes new_size = None
        cdef int amt_padding = 0
        cdef int padding_offset = 0
        cdef int r_offset = 0
        cdef int r_rva = 0
        cdef bytes num_data = None
        cdef bytes padding = None
        cdef int patch_var = 0
        cdef int * patch_ptr = NULL
        cdef net_processing.HeapObject heap_obj = None
        cdef uint64_t va_offset = self.get_offset_from_rva(va_addr)   

        PyObject_GetBuffer(new_exe_data, &new_exe_view, PyBUF_WRITABLE)
        dos_header = <IMAGE_DOS_HEADER*>new_exe_view.buf
        nt_headers = <IMAGE_NT_HEADERS32*>(<uintptr_t>new_exe_view.buf + dos_header.e_lfanew)
        #TODO: add some verification.
        section_offset = self.get_elfanew() + sizeof(IMAGE_FILE_HEADER) + 4 + nt_headers.FileHeader.SizeOfOptionalHeader
        for x in range(nt_headers.FileHeader.NumberOfSections):
            section_header = <IMAGE_SECTION_HEADER*>(<uintptr_t>new_exe_view.buf + section_offset)
            if sec_index == x:
                old_rawsize = section_header.SizeOfRawData
                new_rawsize = old_rawsize + difference
                new_rawsize = new_rawsize + (nt_headers.OptionalHeader.FileAlignment - (new_rawsize % nt_headers.OptionalHeader.FileAlignment))
                amt_padding = new_rawsize - old_rawsize - difference
                padding_offset = section_header.PointerToRawData + old_rawsize
                section_header.SizeOfRawData = new_rawsize
                section_header.Misc.VirtualSize = section_header.Misc.VirtualSize + amt_padding + difference
                target_rawsize_difference = new_rawsize - old_rawsize
            elif section_header.VirtualAddress > va_addr:
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
        nt_headers.OptionalHeader.AddressOfEntryPoint = <uint32_t>net_patch.get_fixed_rva(self, new_exe_view, nt_headers.OptionalHeader.AddressOfEntryPoint, va_addr, difference)
        for x in range(optional_header.NumberOfRvaAndSizes):
            data_dir = &optional_header.DataDirectory[x]
            if data_dir.VirtualAddress != 0:
                data_dir.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(self, new_exe_view, data_dir.VirtualAddress, va_addr, difference)
        
        optional_header.SizeOfCode = size_of_code
        optional_header.SizeOfInitializedData = size_of_initialized_data
        optional_header.SizeOfUninitializedData = size_of_uninitialized_data
        optional_header.SizeOfImage = size_of_image

        optional_header.BaseOfCode = <uint32_t>net_patch.get_fixed_rva(self, new_exe_view, optional_header.BaseOfCode, va_addr, difference)
        optional_header.BaseOfData = <uint32_t>net_patch.get_fixed_rva(self, new_exe_view, optional_header.BaseOfData, va_addr, difference)

        net_header_offset = dpe.get_cor_header_offset()
        cor_header = <IMAGE_COR20_HEADER*>(<uintptr_t>new_exe_view.buf + net_header_offset)

        cor_header.MetaData.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(self, new_exe_view, cor_header.MetaData.VirtualAddress, va_addr, difference)

        if cor_header.MetaData.VirtualAddress <= va_addr < (cor_header.MetaData.VirtualAddress + cor_header.MetaData.Size):
            #FIXME: while this fixes the issue regarding inserting blank strings stream,
            #I think it may hypothetically cause other issues.  Not sure.  Might need to remove <= and replace with < again.
            cor_header.MetaData.Size = cor_header.MetaData.Size + difference
        cor_header.Resources.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(self, new_exe_view, cor_header.Resources.VirtualAddress,
                                                            va_addr, difference)
        cor_header.StrongNameSignature.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(self, new_exe_view,
                                                                    cor_header.StrongNameSignature.VirtualAddress,
                                                                    va_addr, difference)
        cor_header.CodeManagerTable.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(self, new_exe_view,
                                                                cor_header.CodeManagerTable.VirtualAddress, va_addr,
                                                                difference)
        cor_header.VTableFixups.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(self, new_exe_view, cor_header.VTableFixups.VirtualAddress,
                                                            va_addr, difference)
        cor_header.ExportAddressTableJumps.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(self, new_exe_view,
                                                                        cor_header.ExportAddressTableJumps.VirtualAddress,
                                                                        va_addr, difference)
        cor_header.ManagedNativeHeader.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(self, new_exe_view,
                                                                    cor_header.ManagedNativeHeader.VirtualAddress,
                                                                    va_addr, difference)
        if cor_header.Flags & COMIMAGE_FLAGS_NATIVE_ENTRYPOINT != 0:
            cor_header.EntryPoint.EntryPointRVA = <uint32_t>net_patch.get_fixed_rva(self, new_exe_view, cor_header.EntryPoint.EntryPointRVA,
                                                                va_addr, difference)

        # now process the reloc dir
        if IMAGE_DIRECTORY_ENTRY_BASERELOC < optional_header.NumberOfRvaAndSizes:
            reloc_va = original_optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
            reloc_size = original_optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size
            if reloc_va != 0:
                reloc_offset = self.get_offset_from_rva(reloc_va)
                offset = 0
                while offset < reloc_size:
                    base_reloc = <IMAGE_BASE_RELOCATION*> (<uintptr_t>new_exe_view.buf + reloc_offset + offset)
                    base_reloc.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(self, new_exe_view, base_reloc.VirtualAddress, va_addr,
                                                            difference)                                
                    offset += sizeof(IMAGE_BASE_RELOCATION) + base_reloc.BlockSize

        if IMAGE_DIRECTORY_ENTRY_DEBUG < optional_header.NumberOfRvaAndSizes:
            #process debug dir
            debug_va = original_optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress
            if debug_va != 0:
                debug_offset = self.get_offset_from_rva(debug_va)
                debug_struct = <IMAGE_DEBUG_DIRECTORY*>(<uintptr_t>new_exe_view.buf + debug_offset)
                current_va = debug_struct.AddressOfRawData
                new_va = net_patch.get_fixed_rva(self, new_exe_view, current_va, va_addr, difference)
                if current_va != new_va:
                    debug_struct.AddressOfRawData = <uint32_t>new_va
                    debug_struct.PointerToRawData += difference
            
        # now process imports dir
        if IMAGE_DIRECTORY_ENTRY_IMPORT < optional_header.NumberOfRvaAndSizes:
            imports_offset = original_optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
            if imports_offset != 0:
                imports_offset = self.get_offset_from_rva(imports_offset)
                while True:
                    import_descriptor = <IMAGE_IMPORT_DESCRIPTOR*>(<uintptr_t>new_exe_view.buf + <uintptr_t>imports_offset)
                    if import_descriptor.Name == 0:
                        break
                    orig_name = import_descriptor.Name
                    import_descriptor.Name = <uint32_t>net_patch.get_fixed_rva(self, new_exe_view, import_descriptor.Name, va_addr, difference)
                    thunk_offset = self.get_offset_from_rva(import_descriptor.FirstThunk)
                    while True:
                        thunk_data = <IMAGE_THUNK_DATA32*>(<uintptr_t>new_exe_view.buf + thunk_offset)
                        if thunk_data.u1.AddressOfData == 0:
                            break
                        if (thunk_data.u1.AddressOfData & IMAGE_ORDINAL_FLAG32) == 0:
                            # name import, fix.
                            thunk_data.u1.AddressOfData = <uint32_t>net_patch.get_fixed_rva(self, new_exe_view, thunk_data.u1.AddressOfData, va_addr,
                                                                        difference)
                        thunk_offset += sizeof(IMAGE_THUNK_DATA32)
                    import_descriptor.FirstThunk = <uint32_t>net_patch.get_fixed_rva(self, new_exe_view, import_descriptor.FirstThunk, va_addr,
                                                                    difference)

                    thunk_offset = self.get_offset_from_rva(import_descriptor.DUMMYUNIONNAME1.OriginalFirstThunk)
                    while True:
                        thunk_data = <IMAGE_THUNK_DATA32*>(<uintptr_t>new_exe_view.buf + thunk_offset)
                        if thunk_data.u1.AddressOfData == 0:
                            break
                        if (thunk_data.u1.AddressOfData & IMAGE_ORDINAL_FLAG32) == 0:
                            # name import, fix.
                            thunk_data.u1.AddressOfData = <uint32_t>net_patch.get_fixed_rva(self, new_exe_view, thunk_data.u1.AddressOfData, va_addr,
                                                                        difference)
                        thunk_offset += sizeof(IMAGE_THUNK_DATA32)
                    import_descriptor.DUMMYUNIONNAME1.OriginalFirstThunk = <uint32_t>net_patch.get_fixed_rva(self, new_exe_view,
                                                                                        import_descriptor.DUMMYUNIONNAME1.OriginalFirstThunk,
                                                                                        va_addr, difference)
                    imports_offset += sizeof(IMAGE_IMPORT_DESCRIPTOR)
        if IMAGE_DIRECTORY_ENTRY_RESOURCE < optional_header.NumberOfRvaAndSizes:
            resource_offset = original_optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress
            if resource_offset != 0:
                resource_rva = resource_offset
                resource_offset = self.get_offset_from_rva(resource_offset)
                net_patch.fixup_resource_directory(resource_offset, resource_rva, resource_offset, self, new_exe_view, va_addr, difference)
        # now process .NET heaps.
        metadata_offset = self.get_offset_from_rva(dpe.get_metadata_dir().get_net_header().MetaData.VirtualAddress)
        streams_offset = metadata_offset + 12
        number_of_streams = <int>(metadata_offset + 12)
        number_of_streams_bytes = old_exe_data[number_of_streams:number_of_streams + 4]
        length_of_str = int.from_bytes(number_of_streams_bytes, 'little')
        streams_offset += length_of_str + 6
        number_of_streams = int.from_bytes(old_exe_data[streams_offset:streams_offset + 2], 'little')
        streams_offset += 2
        passed_userstrings = False
        orig_streams_offset = streams_offset
        if in_streams:
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
                streams_offset += (4 - (streams_offset % 4))
                stream_offset = metadata_offset + offset
                if name == stream_name and not passed_userstrings:
                    passed_userstrings = True
                    # fix the size of user strings stream
                    # append the stream data
                    patch_ptr = <int*>&(<char*>new_exe_view.buf)[orig_offset + 4]
                    patch_ptr[0] = <int>(size + difference)
                elif passed_userstrings:
                    # fix the offset of the rest of the streams
                    heap_obj = dpe.get_heap(name.decode())
                    if heap_obj is None:
                        raise Exception('null heap obj')
                    patch_ptr = <int*>&(<char*>new_exe_view.buf)[orig_offset]
                    patch_ptr[0] = <int>(offset + difference)
            if orig_streams_offset <= va_offset <= streams_offset:
                offset = int.from_bytes(old_exe_data[orig_streams_offset:orig_streams_offset+4], 'little')
                patch_ptr = <int*>&(<char*>new_exe_view.buf)[orig_streams_offset]
                patch_ptr[0] = <int>(offset+difference)
        #Let reconstruct executable handle updating heap offsets and sizes internally.
        PyBuffer_Release(&new_exe_view)
        if amt_padding != 0 and padding_offset != 0:
            padding = b'\x00' * amt_padding
            new_exe_data = new_exe_data[:padding_offset] + padding + new_exe_data[padding_offset:]
        dpe.set_exe_data(bytes(new_exe_data))
        #TODO: make sure this can properly handle EXE files that have multiple fake heaps.

    cdef void __update_va64(self, uint64_t va_addr, int difference, DotNetPeFile dpe, bint in_streams, bytes stream_name, int sec_index):
        cdef bytearray new_exe_data = bytearray(dpe.get_exe_data())
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
        cdef uint64_t metadata_offset = 0
        cdef uint64_t streams_offset = 0
        cdef bytes number_of_streams_bytes = None
        cdef int length_of_str = 0
        cdef int number_of_streams = 0
        cdef bint passed_userstrings = False
        cdef uint64_t orig_offset = 0
        cdef int size = 0
        cdef uint64_t stream_offset = 0
        cdef uint64_t orig_streams_offset = 0
        cdef bytes new_size = None
        cdef int amt_padding = 0
        cdef int padding_offset = 0
        cdef int r_offset = 0
        cdef int r_rva = 0
        cdef bytes num_data = None
        cdef bytes padding = None
        cdef int patch_var = 0
        cdef int * patch_ptr = NULL
        cdef net_processing.HeapObject heap_obj = None
        cdef uint64_t va_offset = self.get_offset_from_rva(va_addr)

        PyObject_GetBuffer(new_exe_data, &new_exe_view, PyBUF_WRITABLE)
        dos_header = <IMAGE_DOS_HEADER*>new_exe_view.buf
        nt_headers = <IMAGE_NT_HEADERS64*>(<uintptr_t>new_exe_view.buf + dos_header.e_lfanew)
        #TODO: add some verification.
        section_offset = self.get_elfanew() + sizeof(IMAGE_FILE_HEADER) + 4 + nt_headers.FileHeader.SizeOfOptionalHeader
        for x in range(nt_headers.FileHeader.NumberOfSections):
            section_header = <IMAGE_SECTION_HEADER*>(<uintptr_t>new_exe_view.buf + section_offset)

            if sec_index == x:
                old_rawsize = section_header.SizeOfRawData
                new_rawsize = old_rawsize + difference
                new_rawsize = new_rawsize + (nt_headers.OptionalHeader.FileAlignment - (new_rawsize % nt_headers.OptionalHeader.FileAlignment))
                amt_padding = new_rawsize - old_rawsize - difference
                padding_offset = section_header.PointerToRawData + old_rawsize
                section_header.SizeOfRawData = new_rawsize
                section_header.Misc.VirtualSize = section_header.Misc.VirtualSize + amt_padding + difference
                target_rawsize_difference = new_rawsize - old_rawsize
            elif section_header.VirtualAddress > va_addr:
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
        nt_headers.OptionalHeader.AddressOfEntryPoint = <uint32_t>net_patch.get_fixed_rva(self, new_exe_view, nt_headers.OptionalHeader.AddressOfEntryPoint, va_addr, difference)
        for x in range(optional_header.NumberOfRvaAndSizes):
            data_dir = &optional_header.DataDirectory[x]
            if data_dir.VirtualAddress != 0:
                data_dir.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(self, new_exe_view, data_dir.VirtualAddress, va_addr, difference)
        
        optional_header.SizeOfCode = size_of_code
        optional_header.SizeOfInitializedData = size_of_initialized_data
        optional_header.SizeOfUninitializedData = size_of_uninitialized_data
        optional_header.SizeOfImage = size_of_image

        optional_header.BaseOfCode = <uint32_t>net_patch.get_fixed_rva(self, new_exe_view, optional_header.BaseOfCode, va_addr, difference)

        net_header_offset = dpe.get_cor_header_offset()
        cor_header = <IMAGE_COR20_HEADER*>(<uintptr_t>new_exe_view.buf + net_header_offset)

        cor_header.MetaData.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(self, new_exe_view, cor_header.MetaData.VirtualAddress, va_addr, difference)

        if cor_header.MetaData.VirtualAddress <= va_addr < (cor_header.MetaData.VirtualAddress + cor_header.MetaData.Size):
            #FIXME: while this fixes the issue regarding inserting blank strings stream,
            #I think it may hypothetically cause other issues.  Not sure.  Might need to remove <= and replace with < again.
            cor_header.MetaData.Size = cor_header.MetaData.Size + difference
        cor_header.Resources.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(self, new_exe_view, cor_header.Resources.VirtualAddress,
                                                            va_addr, difference)
        cor_header.StrongNameSignature.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(self, new_exe_view,
                                                                    cor_header.StrongNameSignature.VirtualAddress,
                                                                    va_addr, difference)
        cor_header.CodeManagerTable.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(self, new_exe_view,
                                                                cor_header.CodeManagerTable.VirtualAddress, va_addr,
                                                                difference)
        cor_header.VTableFixups.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(self, new_exe_view, cor_header.VTableFixups.VirtualAddress,
                                                            va_addr, difference)
        cor_header.ExportAddressTableJumps.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(self, new_exe_view,
                                                                        cor_header.ExportAddressTableJumps.VirtualAddress,
                                                                        va_addr, difference)
        cor_header.ManagedNativeHeader.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(self, new_exe_view,
                                                                    cor_header.ManagedNativeHeader.VirtualAddress,
                                                                    va_addr, difference)
        if cor_header.Flags & COMIMAGE_FLAGS_NATIVE_ENTRYPOINT != 0:
            cor_header.EntryPoint.EntryPointRVA = <uint32_t>net_patch.get_fixed_rva(self, new_exe_view, cor_header.EntryPoint.EntryPointRVA,
                                                                va_addr, difference)

        # now process the reloc dir
        if IMAGE_DIRECTORY_ENTRY_BASERELOC < optional_header.NumberOfRvaAndSizes:
            reloc_va = original_optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
            reloc_size = original_optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size
            if reloc_va != 0:
                reloc_offset = self.get_offset_from_rva(reloc_va)
                offset = 0
                while offset < reloc_size:
                    base_reloc = <IMAGE_BASE_RELOCATION*> (<uintptr_t>new_exe_view.buf + reloc_offset + offset)
                    base_reloc.VirtualAddress = <uint32_t>net_patch.get_fixed_rva(self, new_exe_view, base_reloc.VirtualAddress, va_addr,
                                                            difference)                                
                    offset += sizeof(IMAGE_BASE_RELOCATION) + base_reloc.BlockSize

        if IMAGE_DIRECTORY_ENTRY_DEBUG < optional_header.NumberOfRvaAndSizes:
            #process debug dir
            debug_va = original_optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress
            if debug_va != 0:
                debug_offset = self.get_offset_from_rva(debug_va)
                debug_struct = <IMAGE_DEBUG_DIRECTORY*>(<uintptr_t>new_exe_view.buf + debug_offset)
                current_va = debug_struct.AddressOfRawData
                new_va = net_patch.get_fixed_rva(self, new_exe_view, current_va, va_addr, difference)
                if current_va != new_va:
                    debug_struct.AddressOfRawData = <uint32_t>new_va
                    debug_struct.PointerToRawData += difference
            
        # now process imports dir
        if IMAGE_DIRECTORY_ENTRY_IMPORT < optional_header.NumberOfRvaAndSizes:
            imports_offset = original_optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
            if imports_offset != 0:
                imports_offset = self.get_offset_from_rva(imports_offset)
                while True:
                    import_descriptor = <IMAGE_IMPORT_DESCRIPTOR*>(<uintptr_t>new_exe_view.buf + <uintptr_t>imports_offset)
                    if import_descriptor.Name == 0:
                        break
                    orig_name = import_descriptor.Name
                    import_descriptor.Name = <uint32_t>net_patch.get_fixed_rva(self, new_exe_view, import_descriptor.Name, va_addr, difference)
                    thunk_offset = self.get_offset_from_rva(import_descriptor.FirstThunk)
                    while True:
                        thunk_data = <IMAGE_THUNK_DATA64*>(<uintptr_t>new_exe_view.buf + thunk_offset)
                        if thunk_data.u1.AddressOfData == 0:
                            break
                        if (thunk_data.u1.AddressOfData & IMAGE_ORDINAL_FLAG64) == 0:
                            # name import, fix.
                            thunk_data.u1.AddressOfData = <uint32_t>net_patch.get_fixed_rva(self, new_exe_view, thunk_data.u1.AddressOfData, va_addr,
                                                                        difference)
                        thunk_offset += sizeof(IMAGE_THUNK_DATA64)
                    import_descriptor.FirstThunk = <uint32_t>net_patch.get_fixed_rva(self, new_exe_view, import_descriptor.FirstThunk, va_addr,
                                                                    difference)

                    thunk_offset = self.get_offset_from_rva(import_descriptor.DUMMYUNIONNAME1.OriginalFirstThunk)
                    while True:
                        thunk_data = <IMAGE_THUNK_DATA64*>(<uintptr_t>new_exe_view.buf + thunk_offset)
                        if thunk_data.u1.AddressOfData == 0:
                            break
                        if (thunk_data.u1.AddressOfData & IMAGE_ORDINAL_FLAG64) == 0:
                            # name import, fix.
                            thunk_data.u1.AddressOfData = <uint32_t>net_patch.get_fixed_rva(self, new_exe_view, thunk_data.u1.AddressOfData, va_addr,
                                                                        difference)
                        thunk_offset += sizeof(IMAGE_THUNK_DATA64)
                    import_descriptor.DUMMYUNIONNAME1.OriginalFirstThunk = <uint32_t>net_patch.get_fixed_rva(self, new_exe_view,
                                                                                        import_descriptor.DUMMYUNIONNAME1.OriginalFirstThunk,
                                                                                        va_addr, difference)
                    imports_offset += sizeof(IMAGE_IMPORT_DESCRIPTOR)
        if IMAGE_DIRECTORY_ENTRY_RESOURCE < optional_header.NumberOfRvaAndSizes:
            resource_offset = original_optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress
            if resource_offset != 0:
                resource_rva = resource_offset
                resource_offset = self.get_offset_from_rva(resource_offset)
                net_patch.fixup_resource_directory(resource_offset, resource_rva, resource_offset, self, new_exe_view, va_addr, difference)
        # now process .NET heaps.
        metadata_offset = self.get_offset_from_rva(dpe.get_metadata_dir().get_net_header().MetaData.VirtualAddress)
        streams_offset = metadata_offset + 12
        number_of_streams = <int>(metadata_offset + 12)
        number_of_streams_bytes = old_exe_data[number_of_streams:number_of_streams + 4]
        length_of_str = int.from_bytes(number_of_streams_bytes, 'little')
        streams_offset += length_of_str + 6
        number_of_streams = int.from_bytes(old_exe_data[streams_offset:streams_offset + 2], 'little')
        streams_offset += 2
        passed_userstrings = False
        orig_streams_offset = streams_offset
        if in_streams:
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
                streams_offset += (4 - (streams_offset % 4))
                stream_offset = metadata_offset + offset
                if name == stream_name and not passed_userstrings:
                    passed_userstrings = True
                    # fix the size of user strings stream
                    # append the stream data
                    patch_ptr = <int*>&(<char*>new_exe_view.buf)[orig_offset + 4]
                    patch_ptr[0] = <int>(size + difference)
                elif passed_userstrings:
                    # fix the offset of the rest of the streams
                    heap_obj = dpe.get_heap(name.decode())
                    if heap_obj is None:
                        raise Exception('null heap obj')
                    patch_ptr = <int*>&(<char*>new_exe_view.buf)[orig_offset]
                    patch_ptr[0] = <int>(offset + difference)
            if orig_streams_offset <= va_offset <= streams_offset:
                offset = int.from_bytes(old_exe_data[orig_streams_offset:orig_streams_offset+4], 'little')
                patch_ptr = <int*>&(<char*>new_exe_view.buf)[orig_streams_offset]
                patch_ptr[0] = <int>(offset+difference)
        #Let reconstruct executable handle updating heap offsets and sizes internally.
        PyBuffer_Release(&new_exe_view)
        if amt_padding != 0 and padding_offset != 0:
            padding = b'\x00' * amt_padding
            new_exe_data = new_exe_data[:padding_offset] + padding + new_exe_data[padding_offset:]
        dpe.set_exe_data(bytes(new_exe_data))
        #TODO: make sure this can properly handle EXE files that have multiple fake heaps

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
        self.original_exe_data = bytes(self.exe_data)
        self.metadata_dir = net_metadata.MetaDataDirectory(self)
        self.__versioninfo_str = None
        self.debug_counter = 0
        if not self.metadata_dir.is_valid_directory:
            return
        self.metadata_dir.process_metadata_heap(no_processing)

    cpdef uint64_t get_cor_header_offset(self):
        return self.__cor_header_offset

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
        Marks a string to be added into the #Strings heap.  The string is not added at any specific location.
        Intended to be used for adding markers that a deobfuscator has proccessed a file.
        """
        
        self.get_heap('#Strings').append_item(string.encode('utf-8'))

    cdef void set_exe_data(self, bytes exe_data):
        """
        Internal use only.  Sets exe_data property and reinitializes pe property.
        """
        self.exe_data = bytes(exe_data)
        self.pe = PeFile(exe_data)

    cpdef PeFile get_pe(self):
        """
        Obtains a PeFile object representing the current executable.
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
        Obtains a list of methods by matching its full name
        :param full_name: the full name of the method
        :return: A list of methods matching the full_name
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
        """
        Obtains a net_row_objects.TypeRef value matching the full name "full_name"
        """
        return self.get_metadata_table('TypeRef').get_type_by_full_name(full_name)

    cpdef net_table_objects.TableObject get_metadata_table(self, str name):
        """
        Obtain a table from the .NET metadata tables.
        :param name: the name of the table
        :return: A TableObject that represents the table, or None if it doesn't exist.
        """
        cdef net_processing.MetadataTableHeapObject mheap = <net_processing.MetadataTableHeapObject>self.get_heap('#~')
        if mheap is not None:
            return mheap.get_table(name)
        return None
    
    cpdef bint has_metadata_table(self, str name):
        """
        Check if the binary has a metadata table denoted by Name.
        """
        cdef net_processing.MetadataTableHeapObject mheap = <net_processing.MetadataTableHeapObject>self.get_heap('#~')
        if mheap is not None:
            return mheap.has_table(name)
        return False

    cpdef net_processing.HeapObject get_heap(self, str name):
        """
        Obtain a heap by name
        :param name: name of the heap
        :return: A Stream object
        """
        if name == '#-':
            return self.get_metadata_dir().get_heap('#~')
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
        cdef net_processing.UserStringsHeapObject stream = <net_processing.UserStringsHeapObject>self.get_heap('#US')
        if stream is not None:
            return stream.get_items()
        return list()

    cpdef list get_strings(self):
        """
        Obtains all normal strings.  strings are used in the metadata tables.
        :return: A list of strings
        """
        cdef net_processing.StringHeapObject stream = <net_processing.StringHeapObject> self.get_heap('#Strings')
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
        """
        Obtains a list of all types that are exported for access outside the binary.
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
        Obtains a list of types by name
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
        """
        cdef bytearray new_exe_data = bytearray(self.get_exe_data())
        cdef list heaps_by_offset = list()
        cdef int last_difference = 0
        cdef net_processing.HeapObject heap_obj
        cdef bytes new_data = None
        cdef int old_size = 0
        cdef bytes result = None
        
        #Headers and such should match.  Just start patching in the heaps.  Method code also should be equivalent.
        for heap_obj in self.get_heaps().values():
            heaps_by_offset.append(heap_obj)
        #One thing thats sort of assumed here is that we are not updating the offset of the metadata heap (otherwise wed have to re initialize metadata header offsets).  I cant really think of a reason to do that though.
        heaps_by_offset.sort(key=get_offset_sort_func)
        for heap_obj in heaps_by_offset:
            old_size = heap_obj.get_size()
            new_data = heap_obj.to_bytes()
            new_exe_data = new_exe_data[:heap_obj.get_offset() + last_difference] + new_data + new_exe_data[heap_obj.get_offset() + old_size + last_difference:]
            heap_obj.update_offset(heap_obj.get_offset() + last_difference)
            heap_obj.update_size(<int>len(new_data))
            last_difference += <int>len(new_data) - old_size
        result = bytes(new_exe_data)
        self.set_exe_data(result)
        return result

    cpdef int delete_user_string(self, unsigned int us_index):
        """
        Handles deletion of a user string.  Caller needs to handle instances where the string itself is used, everything else should be handled.
        Returns the difference in bytes between the new size of the #US heap and the previous size.  This allows the caller to patch up the binary using net_patch.
        """
        self.get_heap('#US').del_item(<int>us_index)

    cpdef list get_user_string_usages(self, unsigned long us_index):
        """
        Useful for deleting strings that are used multiple times throughout the binary.
        Returns references of the strings in the form of (method_name, instr index)
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
            for x in range(<int>len(disas)):
                instr = disas.get_instr_at_index(x)
                if instr.get_name() == 'ldstr':
                    token = int.from_bytes(instr.get_arguments()[:3], 'little')
                    if token == us_index:
                        usages.append((method.get_full_name(), x))
        return usages

    cpdef void patch_instruction(self, net_row_objects.MethodDef method_obj, bytes patch_bytes, unsigned long instr_offset, unsigned long orig_size) except *:
        """
        Patch an instruction using byte manipulation.
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

    cpdef str get_product_version(self):
        """
        Obtains ProductVersion from the StringTable.
        This is used by some obfuscators to decrypt strings.
        """
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
