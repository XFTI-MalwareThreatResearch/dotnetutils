#cython: language_level=3
#distutils: language=c++
from dotnetutils.dotnetpefile cimport DotNetPeFile
from dotnetutils.net_row_objects import MethodDef, RowObject
from dotnetutils.net_structs cimport IMAGE_DOS_HEADER, IMAGE_NT_HEADERS32, IMAGE_NT_OPTIONAL_HDR64_MAGIC, IMAGE_FILE_HEADER, IMAGE_SECTION_HEADER
from dotnetutils.net_structs cimport IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_EXECUTE, IMAGE_DIRECTORY_ENTRY_IMPORT
from dotnetutils.net_structs cimport IMAGE_IMPORT_BY_NAME
from dotnetutils.net_processing cimport HeapObject
from libc.string cimport memcmp, memset, memcpy, strcpy
from dotnetutils.net_utils cimport align_32, convert_pointer_to_bytes



cdef class NetRebuilder:
    def __init__(self, DotNetPeFile dpe):
        self.__dpefile = dpe
        self.__pe = self.__dpefile.get_pe()

    cdef size_t __build_imports32(self, DotNetPeFile dotnet, bytearray result, uint32_t rva):
        cdef IMAGE_IMPORT_DESCRIPTOR imp[2]
        cdef IMAGE_THUNK_DATA32 thunk[2]
        cdef IMAGE_IMPORT_BY_NAME name
        cdef size_t imp_size = 0
        cdef size_t ilt_size = sizeof(IMAGE_THUNK_DATA32) * 2
        cdef size_t name_offset = 0
        char dllname[] = {'m', 's', 'c', 'o', 'r', 'e', 'e', '.', 'd','l', 'l', '\x00'} 
        char funcname[] = {'_', 'C', 'o', 'r', 'E', 'x', 'e', 'M', 'a', 'i', 'n', '\x00'}
        cdef bytes temp = None
        memset(imp, 0, sizeof(imp))
        memset(thunk, 0, sizeof(thunk))
        memset(&name, 0, sizeof(name))
        imp[0].DUMMYUNIONNAME1.OriginalFirstThunk = rva + sizeof(imp) + dllname
        imp[0].Name = rva + sizeof(imp) + ilt_size
        imp[0].FirstThunk = rva + sizeof(imp) + ilt_size + dllname + sizeof(thunk)
        if dotnet.get_pe().is_dll():
            strcpy(funcname, '_CorDllMain')
        name_offset = rva + sizeof(imp) + ilt_size + sizeof(dllname) + (sizeof(thunk) * 2)
        thunk[0].u1.AddressOfData = rva + name_offset
        #start writing the iat
        temp = convert_pointer_to_bytes(imp, sizeof(imp))
        result.extend(temp)
        imp_size += len(temp)
        temp = convert_pointer_to_bytes(dllname, sizeof(dllname))
        result.extend(temp)
        imp_size += len(temp)
        temp = convert_pointer_to_bytes(thunk, sizeof(thunk))
        result.extend(temp)
        imp_size += len(temp)
        result.extend(temp)
        imp_size += len(temp)
        temp = convert_pointer_to_bytes(funcname, sizeof(funcname))
        result.extend(temp)
        imp_size += len(temp)
        return imp_size


    cdef size_t __build_stub32(self, DotNetPeFile dotnet, bytearray result, uint32_t imports_offset):
        cdef Py_buffer current_data
        cdef bytes stub = None
        cdef IMAGE_IMPORT_DESCRIPTOR * imps = NULL
        PyObject_GetBuffer(result, &current_data, PyBUF_ANY_CONTIGUOUS)
        imps = <IMAGE_IMPORT_DESCRIPTOR*>current_data.buf
        stub = b'\xFF\x25' + int.to_bytes(imps.FirstThunk, 4, 'little')
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
        cdef DotNetPeFile copype = DotNetPeFile(pe_data=self.__dpefile.get_exe_data())
        cdef dict results = dict()
        cdef bytes versionstr = None
        cdef uint32_t versionstr_padding = 0
        cdef bytearray tmp = bytearray()
        cdef MetaDataHeader mdatahdr = copype.get_metadata_table_header()
        cdef uint32_t mdata_root_offset = 0
        cdef bytearray tmp2 = bytearray()
        cdef dict streamhdr_offsets = dict()
        cdef uint32_t streamhdr_offset = 0
        #TODO add metadata headers in here
        mdata_root_offset = <uint32_t>len(result)
        result.extend(int.to_bytes(0x424A5342, 4, 'little'))
        result.extend(int.to_bytes(mdatahdr.majorversion, 2, 'little'))
        result.extend(int.to_bytes(mdatahdr.minorversion, 2, 'little'))
        result.extend(b'\x00\x00\x00\x00')
        result.extend(int.to_bytes(mdatahdr.versionstr_length, 4, 'little'))
        result.extend(mdatahdr.versionstr)
        versionstr_padding = align_32(<uint32_t>len(mdatahdr.versionstr), 4)
        versionstr_padding = versionstr_padding - len(metadata.versionstr)
        result.extend(versionstr_padding * b'\x00')
        result.extend(mdatahdr.flags, 2, 'little')
        result.extend(int.to_bytes(len(heaps_order), 2, 'little'))
        mdata_root_offset = <uint32_t>len(result) - mdata_root_offset
        if copype.has_metadata_table('MethodDef'):
            for token, mrva in method_rvas.items():
                method = copype.get_token_value(token)
                method.get_column('RVA').set_raw_value(mrva)
        if copype.has_metadat_table('FieldRVA'):
            tobj = copype.get_metadata_table('FieldRVA')
            for rid, mrva in field_rvas.items():
                fieldrva = tobj.get(rid)
                fieldrva.get_column('RVA').set_raw_value(mrva)

        for heap_name in heaps_order:
            heap = copype.get_heap(heap_name)
            data = heap.get_data()
            results[heap_name] = offset
            tmp.extend(data)
            offset += <uint32_t>len(data)
        for heap_name in heaps_order:
            streamhdr_offsets[heap_name] = streamhdr_offset
            tmp2.extend(int.to_bytes(0, 4, 'little'))
            streamhdr_offset += 4
            heap = copype.get_heap(heap_name)
            result.extend(int.to_bytes(len(heap.get_data()), 4, 'little'))
            results.extend(heap.get_name())
            versionstr_padding = align_32(<uint32_t>len(heap.get_name()), 4) - <uint32_t>len(heap.get_name())
            results.extend(b'\x00' * versionstr_padding)
            streamhdr_offset += 4 + <uint32_t>len(heap.get_name()) + versionstr_padding
        for heap_name in heaps_order:
            offset = streamhdr_offsets[heap_name]
            tmp2 = tmp2[:offset] + int.to_bytes(mdata_root_offset + streamhdr_offset + results[heap_name]) + tmp2[offset + 4:]
        result.extend(tmp2)
        result.extend(tmp)
        return results

    cdef size_t __build_net_headers(self, bytearray result, uint32_t rva, dict heap_mappings):
        cdef IMAGE_COR20_HEADER cor20
        memset(&cor20, 0, sizeof(cor20))
        cor20.cb = sizeof(IMAGE_COR20_HEADER)

        return 0

    cdef size_t __build_resource_directory32(self, bytearray result, uint32_t resource_offset):
        return 0
    
    cdef size_t __build_relocations_directory32(self, bytearray result, uint32_t relocations_offset):
        return 0

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
                raise Exception('Could not get fieldrva's data')
            results[fieldrva.get_rid()] = fieldrva_rva + offset
            offset += <uint32_t>len(data)
            result.extend(data)
        return results

    cdef bytes __rebuild_64(self):
        return None

    cdef bytes __rebuild_32(self):
        cdef bytes orig_data = self.__dpefile.get_exe_data()
        cdef IMAGE_DOS_HEADER * dos_header = <IMAGE_DOS_HEADER*>self.__pe.get_data_view()
        cdef IMAGE_NT_HEADERS32 * nt_headers = <IMAGE_NT_HEADERS32*>((<char*>)dos_header) + dos_header.e_lfanew
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
        cdef int amt_sections = 1
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
        cdef dict heaps_mappings = None
        headers.extend(orig_data[:dos_header.e_lfanew])
        headers.extend(b'PE\x00\x00')
        headers.extend(orig_data[dos_header.e_lfanew + 4: dos_header.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER)])
        memset(&sect_header, 0, sizeof(IMAGE_SECTION_HEADER))
        sect_header.Name = b'.text\x00\x00\x00'
        sect_header.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXEUTE
        result.extend(b'\x00' * (sect_header.PointerToRawData - len(result)))
        data_dir = self.__pe.get_directory_by_idx(IMAGE_DIRECTORY_ENTRY_BASERELOC)
        if data_dir.VirtualAddress != 0:
            amt_sections += 1
        data_dir = self.__pe.get_directory_by_idx(IMAGE_DIRECTORY_ENTRY_RESOURCE)
        if data_dir.VirtualAddress != 0:
            amt_sections += 1
        first_section_rva = (<uint32_t>len(result)) + (amt_sections*sizeof(sect_header))
        first_section_rva = align_32(first_section_rva, nt_headers.OptionalHeader.SectionAlignment)
        self.__build_stub32(self.__dpefile, result, first_section_rva + 4)
        imports_size = self.__build_imports32(self.__dpefile, result, first_section_rva + 4)
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

        


        




        headers.extend(result)
        return bytes(headers)
        
        
        

        





    cdef bytes rebuild(self):
        cdef bytearray data = bytearray()
        cdef IMAGE_DOS_HEADER * dos_header = <IMAGE_DOS_HEADER*>self.__pe.get_data_view()
        cdef IMAGE_NT_HEADERS32 * nt_headers = <IMAGE_NT_HEADERS32*>((<char*>)dos_header) + dos_header.e_lfanew
        if nt_headers.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            return self.__rebuild_64()
        return self.__rebuild_32()

