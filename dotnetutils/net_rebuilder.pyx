#cython: language_level=3
#distutils: language=c++
from dotnetutils.dotnetpefile cimport DotNetPeFile
from dotnetutils.net_row_objects cimport MethodDef, RowObject
from dotnetutils.net_table_objects cimport TableObject
from dotnetutils.net_metadata cimport MetaDataHeader
from dotnetutils.net_structs cimport IMAGE_DOS_HEADER, IMAGE_NT_HEADERS32, IMAGE_NT_OPTIONAL_HDR64_MAGIC, IMAGE_FILE_HEADER, IMAGE_SECTION_HEADER
from dotnetutils.net_structs cimport IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_READ, IMAGE_DIRECTORY_ENTRY_IMPORT
from dotnetutils.net_structs cimport IMAGE_IMPORT_DESCRIPTOR, IMAGE_THUNK_DATA32, IMAGE_COR20_HEADER, IMAGE_BASE_RELOCATION
from dotnetutils.net_structs cimport IMAGE_IMPORT_BY_NAME, IMAGE_DATA_DIRECTORY, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_SCN_MEM_DISCARDABLE
from dotnetutils.net_structs cimport IMAGE_SCN_MEM_EXECUTE, IMAGE_DIRECTORY_ENTRY_RESOURCE, IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_CNT_UNINITIALIZED_DATA, IMAGE_SCN_MEM_DISCARDABLE
from dotnetutils.net_processing cimport HeapObject
from libc.string cimport memcmp, memset, memcpy, strcpy, strlen
from libc.stdint cimport uint16_t, uintptr_t
from dotnetutils.net_utils cimport align_32, convert_pointer_to_bytes
from cpython.buffer cimport PyObject_GetBuffer, PyBuffer_Release, PyBUF_ANY_CONTIGUOUS, PyBUF_WRITABLE, Py_buffer




cdef class NetRebuilder:
    def __init__(self, DotNetPeFile dpe):
        self.__dpefile = dpe
        self.__pe = self.__dpefile.get_pe()

    cdef size_t __build_imports32(self, DotNetPeFile dotnet, bytearray result, uint32_t rva):
        cdef IMAGE_IMPORT_DESCRIPTOR imp[2]
        cdef IMAGE_THUNK_DATA32 thunk[2]
        cdef size_t imp_size = 0
        cdef size_t ilt_size = sizeof(IMAGE_THUNK_DATA32) * 2
        cdef size_t func_name_offset = 0
        cdef bytes dllname = b'mscoree.dll\x00'
        cdef bytes funcname = b'_CorExeMain\x00'
        cdef bytes temp = None
        cdef size_t dllname_size = len(dllname)
        cdef uint32_t align_addr = 0
        memset(imp, 0, sizeof(imp))
        memset(thunk, 0, sizeof(thunk))
        imp[0].DUMMYUNIONNAME1.OriginalFirstThunk = rva + sizeof(imp) + dllname_size
        imp[0].Name = rva + sizeof(imp)
        imp[0].FirstThunk = imp[0].DUMMYUNIONNAME1.OriginalFirstThunk + sizeof(thunk)
        if dotnet.get_pe().is_dll():
            funcname = b'_CorDllMain\x00'
        func_name_offset = sizeof(imp) + dllname_size + (sizeof(thunk) * 2)
        if (func_name_offset % 2) != 0:
            func_name_offset += 1
        thunk[0].u1.AddressOfData = rva + func_name_offset
        #start writing the iat
        temp = convert_pointer_to_bytes(<uintptr_t>imp, sizeof(imp))
        result.extend(temp)
        imp_size += len(temp)
        result.extend(dllname)
        imp_size += len(dllname)
        temp = convert_pointer_to_bytes(<uintptr_t>thunk, sizeof(thunk))
        result.extend(temp)
        imp_size += len(temp)
        result.extend(temp)
        imp_size += len(temp)
        if (imp_size % 2) != 0:
            result.extend(b'\x00')
            imp_size += 1
        result.extend(b'\x00\x00')
        result.extend(funcname)
        imp_size += len(funcname) + 2
        return imp_size


    cdef size_t __build_stub32(self, DotNetPeFile dotnet, bytearray result, uint32_t imports_offset, uint32_t image_base):
        cdef Py_buffer current_data
        cdef bytes stub = None
        cdef IMAGE_IMPORT_DESCRIPTOR * imps = NULL
        PyObject_GetBuffer(result, &current_data, PyBUF_ANY_CONTIGUOUS)
        imps = <IMAGE_IMPORT_DESCRIPTOR*>current_data.buf
        stub = b'\xFF\x25' + int.to_bytes(image_base + imps.FirstThunk, 4, 'little')
        result.extend(stub)
        PyBuffer_Release(&current_data)
        return len(stub)

    cdef dict __build_net_heaps(self, bytearray result, dict method_rvas, dict field_rvas, list heaps_order):
        cdef uint32_t offset = 0
        cdef HeapObject heap = None
        cdef uint32_t token = 0
        cdef uint32_t mrva = 0
        cdef int rid = 0
        cdef MethodDef method = None
        cdef RowObject fieldrva = None
        cdef TableObject tobj = None
        cdef str heap_name = None
        cdef bytes data = None
        cdef dict results = dict()
        cdef bytes versionstr = None
        cdef uint32_t versionstr_padding = 0
        cdef bytearray tmp = bytearray()
        cdef MetaDataHeader mdatahdr = self.__dpefile.get_metadata_table_header()
        cdef uint32_t mdata_root_offset = 0
        cdef bytearray tmp2 = bytearray()
        cdef dict streamhdr_offsets = dict()
        cdef uint32_t streamhdr_offset = 0
        cdef dict old_method_rvas = dict()
        cdef dict old_field_rvas = dict()
        mdata_root_offset = <uint32_t>len(result)
        result.extend(int.to_bytes(0x424A5342, 4, 'little'))
        result.extend(int.to_bytes(mdatahdr.majorversion, 2, 'little'))
        result.extend(int.to_bytes(mdatahdr.minorversion, 2, 'little'))
        result.extend(b'\x00\x00\x00\x00')
        result.extend(int.to_bytes(mdatahdr.versionstr_length, 4, 'little'))
        result.extend(mdatahdr.versionstr)
        versionstr_padding = align_32(<uint32_t>len(mdatahdr.versionstr), 4)
        versionstr_padding = versionstr_padding - len(mdatahdr.versionstr)
        result.extend(versionstr_padding * b'\x00')
        result.extend(mdatahdr.flags, 2, 'little')
        result.extend(int.to_bytes(len(heaps_order), 2, 'little'))
        mdata_root_offset = <uint32_t>len(result) - mdata_root_offset
        if self.__dpefile.has_metadata_table('MethodDef'):
            for token, mrva in method_rvas.items():
                method = self.__dpefile.get_token_value(token)
                old_method_rvas[method.get_token()] = method.get_column('RVA').get_raw_value()
                method.get_column('RVA').set_raw_value(mrva)
        if self.__dpefile.has_metadata_table('FieldRVA'):
            tobj = self.__dpefile.get_metadata_table('FieldRVA')
            for rid, mrva in field_rvas.items():
                fieldrva = tobj.get(rid)
                old_field_rvas[fieldrva.get_rid()] = fieldrva.get_column('RVA').get_raw_value()
                fieldrva.get_column('RVA').set_raw_value(mrva)

        for heap_name in heaps_order:
            heap = self.__dpefile.get_heap(heap_name)
            data = heap.to_bytes()
            results[heap_name] = offset
            tmp.extend(data)
            offset += <uint32_t>len(data)
        for heap_name in heaps_order:
            streamhdr_offsets[heap_name] = streamhdr_offset
            tmp2.extend(int.to_bytes(0, 4, 'little'))
            streamhdr_offset += 4
            heap = self.__dpefile.get_heap(heap_name)
            result.extend(int.to_bytes(len(heap.to_bytes()), 4, 'little'))
            results.extend(heap.get_name())
            versionstr_padding = align_32(<uint32_t>len(heap.get_name()), 4) - <uint32_t>len(heap.get_name())
            results.extend(b'\x00' * versionstr_padding)
            streamhdr_offset += 4 + <uint32_t>len(heap.get_name()) + versionstr_padding
        for heap_name in heaps_order:
            offset = streamhdr_offsets[heap_name]
            tmp2 = tmp2[:offset] + int.to_bytes(mdata_root_offset + streamhdr_offset + results[heap_name]) + tmp2[offset + 4:]
        result.extend(tmp2)
        result.extend(tmp)
        #restore old rvas for consistency
        for offset, streamhdr_offset in old_method_rvas.items():
            self.__dpefile.get_token_value(offset).get_column('RVA').set_raw_value(streamhdr_offset)
        for offset, streamhdr_offset in old_field_rvas.items():
            self.__dpefile.get_metadata_table('FieldRVA').get(offset).get_column('RVA').set_raw_value(streamhdr_offset)
        return results

    cdef size_t __build_net_resources(self, bytearray result, uint32_t rva):
        cdef object rsrc = None
        cdef size_t result_start = len(result)
        for rsrc in self.__dpefile.get_resources():
            result.extend(rsrc.get_data())
        return len(result) - result_start

    cdef size_t __build_net_headers(self, bytearray result, uint32_t rva, uint32_t metadata_rva, uint32_t metadata_size):
        cdef IMAGE_COR20_HEADER cor20
        cdef IMAGE_COR20_HEADER old_header = self.__dpefile.get_net_header()
        cdef MethodDef ep = self.__dpefile.get_entry_point()
        cdef bytearray temp = bytearray()
        cdef uint32_t current_rva = rva + sizeof(IMAGE_COR20_HEADER)
        cdef uint32_t current_size = sizeof(IMAGE_COR20_HEADER)
        cdef uint32_t offset = 0
        cdef uint32_t rsrc_size = 0
        cdef bytes data = None
        memset(&cor20, 0, sizeof(cor20))
        cor20.cb = sizeof(IMAGE_COR20_HEADER)
        cor20.MajorRuntimeVersion = old_header.MajorRuntimeVersion
        cor20.MinorRuntimeVersion = old_header.MinorRuntimeVersion
        cor20.MajorImageVersion = old_header.MajorImageVersion
        cor20.MinorImageVersion = old_header.MinorImageVersion
        cor20.Flags = old_header.Flags
        if ep is not None:
            cor20.EntryPoint.EntryPointToken = ep.get_token()
        cor20.MetaData.VirtualAddress = metadata_rva
        cor20.MetaData.Size = metadata_size
        rsrc_size = self.__build_net_resources(temp, current_rva)
        if rsrc_size != 0:
            cor20.Resources.VirtualAddress = current_rva
            cor20.Resources.Size = rsrc_size
        current_rva += rsrc_size
        if old_header.StrongNameSignature.VirtualAddress != 0 and old_header.StrongNameSignature.Size != 0:
            offset = self.__pe.get_offset_from_rva(old_header.StrongNameSignature.VirtualAddress)
            data = self.__dpefile.get_exe_data()[offset:offset+old_header.StrongNameSignature.Size]
            cor20.StrongNameSignature.VirtualAddress = current_rva
            cor20.StrongNameSignature.Size = <uint32_t>len(data)
            temp.extend(data)
            current_rva += <uint32_t>len(data)

        if old_header.CodeManagerTable.VirtualAddress != 0 and old_header.CodeManagerTable.Size != 0:
            offset = self.__pe.get_offset_from_rva(old_header.CodeManagerTable.VirtualAddress)
            data = self.__dpefile.get_exe_data()[offset:offset+old_header.CodeManagerTable.Size]
            cor20.CodeManagerTable.VirtualAddress = current_rva
            cor20.CodeManagerTable.Size = <uint32_t>len(data)
            temp.extend(data)
            current_rva += <uint32_t>len(data)

        if old_header.VTableFixups.VirtualAddress != 0 and old_header.VTableFixups.Size != 0:
            offset = self.__pe.get_offset_from_rva(old_header.VTableFixups.VirtualAddress)
            data = self.__dpefile.get_exe_data()[offset:offset+old_header.VTableFixups.Size]
            cor20.VTableFixups.VirtualAddress = current_rva
            cor20.VTableFixups.Size = <uint32_t>len(data)
            temp.extend(data)
            current_rva += <uint32_t>len(data)

        if old_header.ExportAddressTableJumps.VirtualAddress != 0 and old_header.ExportAddressTableJumps.Size != 0:
            offset = self.__pe.get_offset_from_rva(old_header.ExportAddressTableJumps.VirtualAddress)
            data = self.__dpefile.get_exe_data()[offset:offset+old_header.ExportAddressTableJumps.Size]
            cor20.ExportAddressTableJumps.VirtualAddress = current_rva
            cor20.ExportAddressTableJumps.Size = <uint32_t>len(data)
            temp.extend(data)
            current_rva += <uint32_t>len(data)

        if old_header.ManagedNativeHeader.VirtualAddress != 0 and old_header.ManagedNativeHeader.Size != 0:
            offset = self.__pe.get_offset_from_rva(old_header.ManagedNativeHeader.VirtualAddress)
            data = self.__dpefile.get_exe_data()[offset:offset+old_header.ManagedNativeHeader.Size]
            cor20.ManagedNativeHeader.VirtualAddress = current_rva
            cor20.ManagedNativeHeader.Size = <uint32_t>len(data)
            temp.extend(data)
            current_rva += <uint32_t>len(data)
        
        result.extend(convert_pointer_to_bytes(<uintptr_t>&cor20, sizeof(IMAGE_COR20_HEADER)))
        current_size += <uint32_t>len(temp)
        result.extend(temp)
        return current_size
    
    cdef size_t __build_relocations_directory32(self, bytearray result, uint32_t stub_reloc_rva):
        cdef IMAGE_BASE_RELOCATION base_reloc
        cdef uint16_t entries[2]
        cdef uint32_t page_off = stub_reloc_rva & 0xFFF
        memset(&base_reloc, 0, sizeof(base_reloc))
        base_reloc.VirtualAddress = stub_reloc_rva & ~0xFFF
        base_reloc.BlockSize = 12
        entries[0] = (3 << 12) | page_off
        entries[1] = 0
        result.extend(convert_pointer_to_bytes(<uintptr_t>&base_reloc, sizeof(base_reloc)))
        result.extend(convert_pointer_to_bytes(<uintptr_t>entries, sizeof(entries)))
        return 12

    cdef size_t __build_resource_directory64(self, bytearray result, uint32_t resource_offset):
        return 0
    
    cdef size_t __build_relocations_directory64(self, bytearray result, uint32_t relocations_offset):
        return 0

    cdef size_t __build_stub64(self, DotNetPeFile dotnet, bytearray result, uint32_t imports_offset):
        return 0

    cdef dict __build_method_data(self, bytearray result, uint32_t methods_rva):
        cdef MethodDef mdef = None
        cdef dict results = dict()
        cdef uint32_t offset = 0
        cdef bytes data = None
        cdef uint32_t amt_padding = 0
        if not self.__dpefile.has_metadata_table('MethodDef'):
            return results
        for mdef in self.__dpefile.get_metadata_table('MethodDef'):
            if mdef.has_body():
                data = mdef.get_method_data()
                results[mdef.get_token()] = methods_rva + offset
                offset += <uint32_t>len(data)
                amt_padding = offset
                offset = align_32(offset, 4)
                amt_padding = offset - amt_padding
                result.extend(data)
                result.extend(b'\x00' * amt_padding)
        return results

    cdef dict __build_fieldrva_data(self, bytearray result, uint32_t fieldrva_rva):
        cdef RowObject fieldrva = None
        cdef dict results = dict()
        cdef uint32_t offset = 0
        cdef bytes data = None
        if not self.__dpefile.has_metadata_table('FieldRVA'):
            return results
        for fieldrva in self.__dpefile.get_metadata_table('FieldRVA'):
            data = fieldrva.get_data()
            if data is None:
                raise Exception('Could not get fieldrva\'s data')
            results[fieldrva.get_rid()] = fieldrva_rva + offset
            offset += <uint32_t>len(data)
            result.extend(data)
        return results

    cdef bytes __rebuild_64(self):
        return None

    cdef bytes __rebuild_32(self):
        cdef bytes orig_data = self.__dpefile.get_exe_data()
        cdef IMAGE_DOS_HEADER * dos_header = <IMAGE_DOS_HEADER*>self.__pe.get_data_view()
        cdef IMAGE_NT_HEADERS32 * nt_headers = <IMAGE_NT_HEADERS32*>((<char*>dos_header) + dos_header.e_lfanew)
        cdef size_t opt_header_offset = dos_header.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER)
        cdef IMAGE_SECTION_HEADER sect_header
        cdef bytearray headers = bytearray()
        cdef bytearray result = bytearray()
        cdef size_t current_sect_raw_size = 0
        cdef uint32_t imports_offset = 0
        cdef uint32_t current_offset = 0
        cdef uint32_t current_size = 0
        cdef uint32_t imports_size = 0
        cdef uint32_t first_section_rva = 0
        cdef uint32_t imports_rva = 0
        cdef int amt_sections = 2
        cdef IMAGE_DATA_DIRECTORY data_dir
        cdef bytearray temp = bytearray()
        cdef dict heap_mappings = None
        cdef dict method_mappings = None
        cdef dict field_mappings = None
        cdef uint32_t methods_size = 0
        cdef uint32_t fields_size = 0
        cdef uint32_t methods_rva = 0
        cdef uint32_t metadata_rva = 0
        cdef uint32_t metadata_size = 0
        cdef uint32_t cor_rva = 0
        cdef uint32_t cor_size = 0
        cdef Py_ssize_t x = 0
        cdef dict data_dir_offsets = dict()
        cdef dict heaps_mappings = None
        cdef uint32_t data_dir_rva = 0
        cdef bytes data = None
        cdef uint32_t offset = 0
        cdef uint32_t first_sect_offset = 0
        cdef uint32_t first_sect_size = 0
        cdef uint32_t stub_rva = 0
        cdef uint32_t first_sect_vsize = 0
        cdef uint32_t relocs_vsize = 0
        cdef uint32_t size_of_code = 0
        cdef uint32_t size_of_init_data = 0
        cdef uint32_t size_of_uninit_data = 0
        cdef uint32_t size_of_image
        cdef IMAGE_SECTION_HEADER * sechdrs = NULL
        cdef bint has_rsrc = False

        cdef Py_buffer headers_view
        headers.extend(orig_data[:dos_header.e_lfanew])
        headers.extend(b'PE\x00\x00')
        headers.extend(orig_data[dos_header.e_lfanew + 4: dos_header.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER)])
        memset(&sect_header, 0, sizeof(IMAGE_SECTION_HEADER))
        strcpy(sect_header.Name, '.text')
        sect_header.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE
        data_dir = self.__pe.get_directory_by_idx(IMAGE_DIRECTORY_ENTRY_RESOURCE)
        if data_dir.VirtualAddress != 0:
            amt_sections += 1
        first_sect_offset = (<uint32_t>len(headers)) + (amt_sections * sizeof(sect_header)) + methods_size
        fields_size = align_32(first_sect_offset, nt_headers.OptionalHeader.FileAlignment)
        first_sect_offset = fields_size
        result.extend(b'\x00' * (fields_size - first_sect_offset))
        fields_size = 0

        first_section_rva = (<uint32_t>len(result)) + (amt_sections*sizeof(sect_header))
        first_section_rva = align_32(first_section_rva, nt_headers.OptionalHeader.SectionAlignment)
        if self.__pe.is_dll():
            nt_headers.OptionalHeader.ImageBase = 0x10000000
        else:
            nt_headers.OptionalHeader.ImageBase = 0x00400000
        imports_size = self.__build_imports32(self.__dpefile, temp, first_section_rva + 4, nt_headers.OptionalHeader.ImageBase)
        self.__build_stub32(self.__dpefile, result, first_section_rva + 4, nt_headers.OptionalHeader.ImageBase)
        result.extend(temp)
        temp = bytearray()
        imports_rva = first_section_rva + 4
        #pad to four
        fields_size = align_32(imports_rva + imports_size, 4)
        methods_size = fields_size - imports_rva - imports_size
        fields_size = 0
        result.extend(b'\x00' * methods_size)
        methods_rva = imports_rva + imports_size + methods_size
        methods_size = 0
        methods_size = <uint32_t>len(result)
        method_mappings = self.__build_method_data(result, methods_rva)
        methods_size = <uint32_t>len(result) - methods_size
        fields_size = <uint32_t>len(result)
        field_mappings = self.__build_fieldrva_data(result, methods_rva + methods_size)
        fields_size = <uint32_t>len(result) - fields_size
        metadata_size = <uint32_t>len(result)
        heaps_mappings = self.__build_net_heaps(result,  method_mappings, field_mappings, list(self.__dpefile.get_heaps().keys()))
        metadata_size = <uint32_t>len(result) - metadata_size
        metadata_rva = methods_rva + methods_size + fields_size
        cor_rva = metadata_rva + metadata_size
        cor_size = self.__build_net_headers(result, cor_rva, metadata_rva, metadata_size)
        data_dir_rva = cor_rva + cor_size
        for x in range(nt_headers.OptionalHeader.NumberOfRvaAndSizes):
            if x != IMAGE_DIRECTORY_ENTRY_IMPORT and x != IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR and x != IMAGE_DIRECTORY_ENTRY_BASERELOC and x != IMAGE_DIRECTORY_ENTRY_RESOURCE:
                offset = nt_headers.OptionalHeader.DataDirectory[x].VirtualAddress
                if offset == 0:
                    continue
                data_dir_offsets[x] = (data_dir_rva, nt_headers.OptionalHeader.DataDirectory[x].Size)
                
                offset = self.__pe.get_offset_from_rva(offset)
                result.extend(orig_data[offset:offset + nt_headers.OptionalHeader.DataDirectory[x].Size])

        #align up TODO is 4 align above messing with this
        first_sect_size = align_32(<uint32_t>len(result), nt_headers.OptionalHeader.FileAlignment)
        sect_header.Misc_Union.VirtualSize = <uint32_t>len(result)
        first_sect_vsize = sect_header.Misc_Union.VirtualSize
        sect_header.PointerToRawData = first_sect_offset
        sect_header.SizeOfRawData = first_sect_size
        sect_header.VirtualAddress = first_section_rva
        result.extend(b'\x00' * (first_sect_size - len(result)))
        headers.extend(convert_pointer_to_bytes(<uintptr_t>&sect_header, sizeof(sect_header)))
        memset(&sect_header, 0, sizeof(sect_header))
        strcpy(sect_header.Name, '.reloc')
        sect_header.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE
        sect_header.PointerToRawData = first_sect_offset + first_sect_size
        sect_header.VirtualAddress = first_section_rva + first_sect_vsize
        relocs_vsize = self.__build_relocations_directory32(result, first_section_rva + 2)
        sect_header.Misc_Union.VirtualSize = relocs_vsize
        relocs_vsize = align_32(relocs_vsize, nt_headers.OptionalHeader.FileAlignment)
        result.extend(b'\x00' * (relocs_vsize - sect_header.Misc_Union.VirtualSize))
        sect_header.SizeOfRawData = relocs_vsize
        headers.extend(convert_pointer_to_bytes(<uintptr_t>&sect_header, sizeof(IMAGE_SECTION_HEADER)))
        if data_dir.VirtualAddress != 0:
            has_rsrc = True
            #we also need a .rsrc section.
            #For the data, just copy the original relocs
            offset = self.__pe.get_offset_from_rva(data_dir.VirtualAddress)
            data = orig_data[offset:offset+data_dir.Size]
            memset(&sect_header, 0, sizeof(sect_header))
            strcpy(sect_header.Name, '.rsrc')
            sect_header.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
            sect_header.PointerToRawData = first_sect_offset + first_sect_size + relocs_vsize
            sect_header.Misc_Union.VirtualSize = <uint32_t>len(data)
            relocs_vsize = align_32(<uint32_t>len(data), nt_headers.OptionalHeader.FileAlignment)
            sect_header.SizeOfRawData = relocs_vsize
            data = data + b'\x00' * (relocs_vsize - len(data))
            result.extend(data)
            headers.extend(convert_pointer_to_bytes(<uintptr_t>&sect_header, sizeof(IMAGE_SECTION_HEADER)))
        headers.extend(result)
        PyObject_GetBuffer(headers, &headers_view, PyBUF_WRITABLE)
        dos_header = <IMAGE_DOS_HEADER*>headers_view.buf
        nt_headers = <IMAGE_NT_HEADERS32*>((<char*>dos_header) + dos_header.e_lfanew)
        nt_headers.FileHeader.NumberOfSections = amt_sections
        nt_headers.FileHeader.PointerToSymbolTable = 0
        nt_headers.FileHeader.NumberOfSymbols = 0
        sechdrs = <IMAGE_SECTION_HEADER*>((<char*>nt_headers) + 4 + sizeof(IMAGE_FILE_HEADER) + nt_headers.FileHeader.SizeOfOptionalHeader)
        for x in range(nt_headers.FileHeader.NumberOfSections):
            sect_header = sechdrs[x]
            if sect_header.Characteristics & IMAGE_SCN_CNT_CODE:
                size_of_code += sect_header.SizeOfRawData
            if sect_header.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA:
                size_of_init_data += sect_header.SizeOfRawData
            if sect_header.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA:
                size_of_uninit_data += sect_header.SizeOfRawData
            size_of_image += sect_header.SizeOfRaWData
        nt_headers.OptionalHeader.SizeOfCode = size_of_code
        nt_headers.OptionalHeader.SizeOfInitializedData = size_of_init_data
        nt_headers.OptionalHeader.SizeOfUninitializedData = size_of_uninit_data
        nt_headers.OptionalHeader.SizeOfHeaders = align_32(dos_header.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + nt_headers.FileHeader.SizeOfOptionalHeader + (sizeof(IMAGE_SECTION_HEADER) * amt_sections), nt_headers.OptionalHeader.FileALignment)
        nt_headers.OptionalHeader.SizeOfImage = nt_headers.OptionalHeader.SizeOfHeaders + size_of_image
        nt_headers.OptionalHeader.BaseOfCode = first_section_rva
        nt_headers.OptionalHeader.BaseOfData = first_section_rva + first_sect_vsize
        nt_headers.OptionalHeader.AddressOfEntryPoint = first_section_rva
        nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = imports_rva
        nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = imports_size
        nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress = cor_rva
        nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size = cor_size
        nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = reloc_va
        nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = reloc_size
        if has_rsrc:
            nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = resource_rva
            nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = resource_size
        PyBuffer_Release(&headers_view)
        #TODO: update OptionalHeader CheckSum
        return bytes(headers)

    cdef bytes rebuild(self):
        cdef bytearray data = bytearray()
        cdef IMAGE_DOS_HEADER * dos_header = <IMAGE_DOS_HEADER*>self.__pe.get_data_view()
        cdef IMAGE_NT_HEADERS32 * nt_headers = <IMAGE_NT_HEADERS32*>((<char*>dos_header) + dos_header.e_lfanew)
        if nt_headers.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            return self.__rebuild_64()
        return self.__rebuild_32()

