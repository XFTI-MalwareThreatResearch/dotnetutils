#cython: language_level=3
#distutils: language=c++
from dotnetutils.dotnetpefile cimport DotNetPeFile
from dotnetutils.net_row_objects cimport MethodDef, RowObject, Field
from dotnetutils.net_table_objects cimport TableObject
from dotnetutils.net_metadata cimport MetaDataHeader
from dotnetutils.net_structs cimport IMAGE_DOS_HEADER, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64, IMAGE_NT_OPTIONAL_HDR64_MAGIC, IMAGE_FILE_HEADER, IMAGE_SECTION_HEADER
from dotnetutils.net_structs cimport IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_READ, IMAGE_DIRECTORY_ENTRY_IMPORT
from dotnetutils.net_structs cimport IMAGE_IMPORT_DESCRIPTOR, IMAGE_THUNK_DATA32, IMAGE_THUNK_DATA64, IMAGE_COR20_HEADER, IMAGE_BASE_RELOCATION
from dotnetutils.net_structs cimport IMAGE_IMPORT_BY_NAME, IMAGE_DATA_DIRECTORY, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_SCN_MEM_DISCARDABLE
from dotnetutils.net_structs cimport IMAGE_SCN_MEM_EXECUTE, IMAGE_DIRECTORY_ENTRY_RESOURCE, IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_CNT_UNINITIALIZED_DATA, IMAGE_SCN_MEM_DISCARDABLE
from dotnetutils.net_structs cimport IMAGE_DIRECTORY_ENTRY_DEBUG, IMAGE_RESOURCE_DIRECTORY, IMAGE_RESOURCE_DIRECTORY_ENTRY, IMAGE_RESOURCE_DATA_ENTRY, IMAGE_OPTIONAL_HEADER32, IMAGE_OPTIONAL_HEADER64
from dotnetutils.net_processing cimport HeapObject
from libc.string cimport memcmp, memset, memcpy, strcpy, strlen
from libc.stdint cimport uint16_t, uintptr_t, int64_t, uint32_t, uint64_t
from dotnetutils.net_utils cimport align_32, convert_pointer_to_bytes
from cpython.buffer cimport PyObject_GetBuffer, PyBuffer_Release, PyBUF_ANY_CONTIGUOUS, PyBUF_WRITABLE, Py_buffer

cdef void _fix_resource_directory_rvas(Py_buffer *rsrc_view, uint32_t dir_offset, uint32_t root_offset, uint32_t data_len, int rva_delta) except *:
    cdef IMAGE_RESOURCE_DIRECTORY * rsrc_dir = NULL
    cdef IMAGE_RESOURCE_DIRECTORY_ENTRY * sub_entry = NULL
    cdef IMAGE_RESOURCE_DATA_ENTRY * data_entry = NULL
    cdef uint32_t entries_offset = 0
    cdef uint32_t entry_count = 0
    cdef uint32_t x = 0
    cdef uint32_t child_offset = 0
    cdef uint32_t data_entry_offset = 0
    cdef int64_t fixed_rva = 0

    if dir_offset + <uint32_t>sizeof(IMAGE_RESOURCE_DIRECTORY) > data_len:
        raise ValueError('Resource directory points outside copied resource data')

    rsrc_dir = <IMAGE_RESOURCE_DIRECTORY*>((<char*>rsrc_view.buf) + dir_offset)
    entry_count = <uint32_t>rsrc_dir.NumberOfNamedEntries + <uint32_t>rsrc_dir.NumberOfIdEntries
    entries_offset = dir_offset + <uint32_t>sizeof(IMAGE_RESOURCE_DIRECTORY)
    if entries_offset + (entry_count * <uint32_t>sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)) > data_len:
        raise ValueError('Resource directory entries point outside copied resource data')

    for x in range(entry_count):
        sub_entry = <IMAGE_RESOURCE_DIRECTORY_ENTRY*>((<char*>rsrc_view.buf) + entries_offset + (x * <uint32_t>sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)))
        if sub_entry.OffsetToData.OffsetToDirectory.DataIsDirectory:
            child_offset = root_offset + sub_entry.OffsetToData.OffsetToDirectory.OffsetToDirectory
            _fix_resource_directory_rvas(rsrc_view, child_offset, root_offset, data_len, rva_delta)
        else:
            data_entry_offset = root_offset + sub_entry.OffsetToData.OffsetToData
            if data_entry_offset + <uint32_t>sizeof(IMAGE_RESOURCE_DATA_ENTRY) > data_len:
                raise ValueError('Resource data entry points outside copied resource data')
            data_entry = <IMAGE_RESOURCE_DATA_ENTRY*>((<char*>rsrc_view.buf) + data_entry_offset)
            fixed_rva = <int64_t>data_entry.OffsetToData + <int64_t>rva_delta
            if fixed_rva < 0 or fixed_rva > 0xFFFFFFFF:
                raise ValueError('Resource data RVA fixup overflowed')
            data_entry.OffsetToData = <uint32_t>fixed_rva


cdef tuple _copy_resource_section(object pe, DotNetPeFile dotnet, uint32_t new_section_rva):
    cdef IMAGE_DATA_DIRECTORY data_dir = pe.get_directory_by_idx(IMAGE_DIRECTORY_ENTRY_RESOURCE)
    cdef bytes orig_data = dotnet.get_exe_data()
    cdef dict section = None
    cdef uint32_t old_section_rva = 0
    cdef uint32_t old_section_raw = 0
    cdef uint32_t old_section_raw_size = 0
    cdef uint32_t old_section_vsize = 0
    cdef uint32_t root_offset = 0
    cdef uint32_t resource_rva = 0
    cdef uint32_t resource_size = 0
    cdef uint32_t virtual_size = 0
    cdef int rva_delta = 0
    cdef bytearray data = bytearray()
    cdef Py_buffer rsrc_view

    if data_dir.VirtualAddress == 0 or data_dir.Size == 0:
        return (b'', 0, 0, 0)

    for section in pe.get_sections():
        old_section_rva = <uint32_t>section['VirtualAddress']
        old_section_vsize = <uint32_t>section['Misc']['VirtualSize']
        old_section_raw_size = <uint32_t>section['SizeOfRawData']
        if old_section_vsize < old_section_raw_size:
            old_section_vsize = old_section_raw_size
        if old_section_rva <= data_dir.VirtualAddress < old_section_rva + old_section_vsize:
            old_section_raw = <uint32_t>section['PointerToRawData']
            break
    else:
        old_section_rva = data_dir.VirtualAddress
        old_section_raw = <uint32_t>pe.get_offset_from_rva(data_dir.VirtualAddress)
        old_section_raw_size = data_dir.Size
        old_section_vsize = data_dir.Size

    if old_section_raw >= len(orig_data):
        raise ValueError('Resource section raw offset is outside the executable')
    if old_section_raw + old_section_raw_size > len(orig_data):
        old_section_raw_size = <uint32_t>len(orig_data) - old_section_raw
    if old_section_raw_size == 0:
        return (b'', 0, 0, 0)

    root_offset = data_dir.VirtualAddress - old_section_rva
    if root_offset >= old_section_raw_size:
        raise ValueError('Resource directory RVA is outside the copied resource section')

    data.extend(orig_data[old_section_raw:old_section_raw + old_section_raw_size])
    rva_delta = <int>new_section_rva - <int>old_section_rva
    PyObject_GetBuffer(data, &rsrc_view, PyBUF_WRITABLE)
    try:
        _fix_resource_directory_rvas(&rsrc_view, root_offset, root_offset, <uint32_t>len(data), rva_delta)
    finally:
        PyBuffer_Release(&rsrc_view)

    resource_rva = new_section_rva + root_offset
    resource_size = data_dir.Size
    if old_section_vsize > old_section_raw_size:
        virtual_size = old_section_vsize
    else:
        virtual_size = old_section_raw_size
    return (bytes(data), resource_rva, resource_size, virtual_size)




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
        memset(imp, 0, sizeof(imp))
        memset(thunk, 0, sizeof(thunk))
        imp[0].DUMMYUNIONNAME1.OriginalFirstThunk = rva + <uint32_t>sizeof(imp) + <uint32_t>dllname_size
        imp[0].Name = rva + sizeof(imp)
        imp[0].FirstThunk = imp[0].DUMMYUNIONNAME1.OriginalFirstThunk + sizeof(thunk)
        if self.__pe.is_dll():
            funcname = b'_CorDllMain\x00'
        func_name_offset = <uint32_t>sizeof(imp) + dllname_size + (<uint32_t>sizeof(thunk) * 2)
        if (func_name_offset % 2) != 0:
            func_name_offset += 1
        thunk[0].u1.AddressOfData = rva + <uint32_t>func_name_offset
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

    cdef size_t __build_imports64(self, DotNetPeFile dotnet, bytearray result, uint32_t rva):
        cdef IMAGE_IMPORT_DESCRIPTOR imp[2]
        cdef IMAGE_THUNK_DATA64 thunk[2]
        cdef size_t imp_size = 0
        cdef size_t func_name_offset = 0
        cdef bytes dllname = b'mscoree.dll\x00'
        cdef bytes funcname = b'_CorExeMain\x00'
        cdef bytes temp = None
        cdef size_t dllname_size = len(dllname)
        memset(imp, 0, sizeof(imp))
        memset(thunk, 0, sizeof(thunk))
        imp[0].DUMMYUNIONNAME1.OriginalFirstThunk = rva + <uint32_t>sizeof(imp) + <uint32_t>dllname_size
        imp[0].Name = rva + <uint32_t>sizeof(imp)
        imp[0].FirstThunk = imp[0].DUMMYUNIONNAME1.OriginalFirstThunk + <uint32_t>sizeof(thunk)
        if self.__pe.is_dll():
            funcname = b'_CorDllMain\x00'
        func_name_offset = <uint32_t>sizeof(imp) + dllname_size + (<uint32_t>sizeof(thunk) * 2)
        if (func_name_offset % 2) != 0:
            func_name_offset += 1
        thunk[0].u1.AddressOfData = rva + <uint32_t>func_name_offset
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

    cdef dict __build_net_heaps(self, bytearray result, dict method_rvas, dict field_rvas, list heaps_order):
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
        cdef MetaDataHeader mdatahdr = self.__dpefile.get_metadata_dir().metadata_header
        cdef uint32_t root_start = <uint32_t>len(result)
        cdef uint32_t root_header_size = 0
        cdef uint32_t stream_headers_size = 0
        cdef uint32_t heap_data_offset = 0
        cdef uint32_t stream_offset = 0
        cdef uint32_t padding = 0
        cdef bytearray heap_data = bytearray()
        cdef dict heap_bytes = dict()
        cdef dict old_method_rvas = dict()
        cdef dict old_field_rvas = dict()
        cdef bytes name = None

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
            heap_bytes[heap_name] = data
            results[heap_name] = heap_data_offset
            heap_data.extend(data)
            heap_data_offset += <uint32_t>len(data)

        root_header_size = 4 + 2 + 2 + 4 + 4 + <uint32_t>len(mdatahdr.versionstr)
        root_header_size = align_32(root_header_size, 4)
        root_header_size += 2 + 2

        for heap_name in heaps_order:
            heap = self.__dpefile.get_heap(heap_name)
            name = heap.get_name() + b'\x00'
            padding = align_32(<uint32_t>len(name), 4) - <uint32_t>len(name)
            stream_headers_size += 4 + 4 + <uint32_t>len(name) + padding

        result.extend(int.to_bytes(0x424A5342, 4, 'little'))
        result.extend(int.to_bytes(mdatahdr.majorversion, 2, 'little'))
        result.extend(int.to_bytes(mdatahdr.minorversion, 2, 'little'))
        result.extend(int.to_bytes(0, 4, 'little'))
        result.extend(int.to_bytes(len(mdatahdr.versionstr), 4, 'little'))
        result.extend(mdatahdr.versionstr)
        padding = align_32(<uint32_t>len(result) - root_start, 4) - (<uint32_t>len(result) - root_start)
        result.extend(b'\x00' * padding)
        result.extend(int.to_bytes(mdatahdr.flags, 2, 'little'))
        result.extend(int.to_bytes(len(heaps_order), 2, 'little'))

        for heap_name in heaps_order:
            heap = self.__dpefile.get_heap(heap_name)
            data = <bytes>heap_bytes[heap_name]
            stream_offset = root_header_size + stream_headers_size + <uint32_t>results[heap_name]
            result.extend(int.to_bytes(stream_offset, 4, 'little'))
            result.extend(int.to_bytes(len(data), 4, 'little'))
            name = heap.get_name() + b'\x00'
            result.extend(name)
            padding = align_32(<uint32_t>len(name), 4) - <uint32_t>len(name)
            result.extend(b'\x00' * padding)
            results[heap_name] = stream_offset

        result.extend(heap_data)

        for token, mrva in old_method_rvas.items():
            self.__dpefile.get_token_value(token).get_column('RVA').set_raw_value(mrva)
        for rid, mrva in old_field_rvas.items():
            self.__dpefile.get_metadata_table('FieldRVA').get(rid).get_column('RVA').set_raw_value(mrva)
        return results

    cdef size_t __build_net_resources(self, bytearray result, uint32_t rva):
        cdef object rsrc = None
        cdef size_t result_start = len(result)
        cdef bytes data = None
        for rsrc in self.__dpefile.get_resources():
            data = rsrc.get_data()
            result.extend(int.to_bytes(<uint32_t>len(data), 4, 'little'))
            result.extend(data)
        return len(result) - result_start

    cdef size_t __build_net_headers(self, bytearray result, uint32_t rva, uint32_t metadata_rva, uint32_t metadata_size):
        cdef IMAGE_COR20_HEADER cor20
        cdef IMAGE_COR20_HEADER old_header = self.__pe.get_net_header()
        cdef MethodDef ep = self.__dpefile.get_entry_point()
        cdef bytearray temp = bytearray()
        cdef uint32_t current_rva = rva + <uint32_t>sizeof(IMAGE_COR20_HEADER)
        cdef uint32_t current_size = <uint32_t>sizeof(IMAGE_COR20_HEADER)
        cdef uint32_t offset = 0
        cdef uint32_t rsrc_size = 0
        cdef bytes data = None
        memset(&cor20, 0, sizeof(cor20))
        cor20.cb = <uint32_t>sizeof(IMAGE_COR20_HEADER)
        cor20.MajorRuntimeVersion = old_header.MajorRuntimeVersion
        cor20.MinorRuntimeVersion = old_header.MinorRuntimeVersion
        cor20.Flags = old_header.Flags
        if ep is not None:
            cor20.EntryPoint.EntryPointToken = ep.get_token()
        cor20.MetaData.VirtualAddress = metadata_rva
        cor20.MetaData.Size = metadata_size
        rsrc_size = <uint32_t>self.__build_net_resources(temp, current_rva)
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
        # The x64 CLR entry stub below uses RIP-relative addressing, so it does not
        # need a relocation entry for the import thunk reference.
        return 0

    cdef size_t __build_stub64(self, DotNetPeFile dotnet, bytearray result, uint32_t imports_offset, uint64_t image_base, bytearray temp):
        cdef uint32_t stub_rva = imports_offset - 6
        cdef bytes stub = None
        cdef Py_buffer current_data
        cdef int rel32 = <int>imports_offset - <int>(stub_rva + 6)
        cdef uint32_t target_rva = 0
        PyObject_GetBuffer(temp, &current_data, PyBUF_ANY_CONTIGUOUS)
        imps = <IMAGE_IMPORT_DESCRIPTOR*>current_data.buf
        rel32 = <uint32_t>(imps.FirstThunk - (stub_rva + 6))
        stub = b'\xFF\x25' + int.to_bytes(rel32, 4, 'little')
        PyBuffer_Release(&current_data)
        result.extend(stub)
        return len(stub)

    cdef size_t __build_stub32(self, DotNetPeFile dotnet, bytearray result, uint32_t imports_offset, uint32_t image_base, bytearray temp):
        cdef Py_buffer current_data
        cdef bytes stub = None
        cdef IMAGE_IMPORT_DESCRIPTOR * imps = NULL
        PyObject_GetBuffer(temp, &current_data, PyBUF_ANY_CONTIGUOUS)
        imps = <IMAGE_IMPORT_DESCRIPTOR*>current_data.buf
        stub = b'\xFF\x25' + int.to_bytes(image_base + imps.FirstThunk, 4, 'little')
        PyBuffer_Release(&current_data)
        result.extend(stub)
        return len(stub)

    cdef dict __build_method_data(self, bytearray result, uint32_t methods_rva):
        cdef MethodDef mdef = None
        cdef dict results = dict()
        cdef uint32_t offset = 0
        cdef bytes data = None
        cdef uint32_t amt_padding = 0
        if not self.__dpefile.has_metadata_table('MethodDef'):
            return results
        for mdef in self.__dpefile.get_metadata_table('MethodDef'):
            data = mdef.get_method_data()
            if mdef.has_body() and len(data) != 0:# Should allow for the insertion of new methods.
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
        cdef Field fobj = None
        if not self.__dpefile.has_metadata_table('FieldRVA'):
            return results
        for fieldrva in self.__dpefile.get_metadata_table('FieldRVA'):
            fobj = fieldrva.get_column('Field').get_value()
            data = fobj.get_data()
            if data is None:
                raise Exception('Could not get fieldrva\'s data {} {}'.format(fieldrva.get_rid(), hex(fobj.get_token())))
            results[fieldrva.get_rid()] = fieldrva_rva + offset
            offset += <uint32_t>len(data)
            result.extend(data)
        return results

    cdef bytes __rebuild_64(self):
        cdef bytes orig_data = self.__dpefile.get_exe_data()
        cdef IMAGE_DOS_HEADER * dos_header = <IMAGE_DOS_HEADER*>self.__pe.get_data_view()
        cdef IMAGE_NT_HEADERS64 * nt_headers = <IMAGE_NT_HEADERS64*>((<char*>dos_header) + dos_header.e_lfanew)
        cdef IMAGE_SECTION_HEADER sect_header
        cdef bytearray headers = bytearray()
        cdef bytearray result = bytearray()
        cdef uint32_t imports_size = 0
        cdef uint32_t first_section_rva = 0
        cdef uint32_t imports_rva = 0
        cdef int amt_sections = 1
        cdef IMAGE_DATA_DIRECTORY data_dir
        cdef bytearray temp = bytearray()
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
        cdef dict heaps_mappings = None
        cdef uint32_t data_dir_rva = 0
        cdef bytes data = None
        cdef uint32_t offset = 0
        cdef uint32_t first_sect_offset = 0
        cdef uint32_t first_sect_size = 0
        cdef uint32_t first_sect_vsize = 0
        cdef uint32_t size_of_code = 0
        cdef uint32_t size_of_init_data = 0
        cdef uint32_t size_of_uninit_data = 0
        cdef uint32_t size_of_image = 0
        cdef IMAGE_SECTION_HEADER * sechdrs = NULL
        cdef bint has_rsrc = False
        cdef Py_buffer headers_view
        cdef uint32_t rsrc_size = 0
        cdef uint32_t resource_size = 0
        cdef uint32_t resource_rva = 0
        cdef uint32_t resource_vsize = 0
        cdef uint32_t checksum = 0
        cdef uint32_t checksum_offset = 0

        headers.extend(orig_data[:dos_header.e_lfanew])
        headers.extend(b'PE\x00\x00')
        headers.extend(orig_data[dos_header.e_lfanew + 4: dos_header.e_lfanew + 4 + <uint32_t>sizeof(IMAGE_FILE_HEADER) + nt_headers.FileHeader.SizeOfOptionalHeader])

        data_dir = self.__pe.get_directory_by_idx(IMAGE_DIRECTORY_ENTRY_RESOURCE)
        if data_dir.VirtualAddress != 0:
            amt_sections += 1
        first_sect_offset = (
            <uint32_t>len(headers) +
            <uint32_t>(amt_sections * sizeof(IMAGE_SECTION_HEADER))
        )
        first_sect_offset = align_32(first_sect_offset, nt_headers.OptionalHeader.FileAlignment)

        first_section_rva = align_32(first_sect_offset, nt_headers.OptionalHeader.SectionAlignment)

        if self.__pe.is_dll():
            nt_headers.OptionalHeader.ImageBase = 0x0000000180000000
        else:
            nt_headers.OptionalHeader.ImageBase = 0x0000000140000000
        imports_rva = first_section_rva + 6

        imports_size = <uint32_t>self.__build_imports64(self.__dpefile, temp, imports_rva)

        self.__build_stub64(self.__dpefile, result, imports_rva, nt_headers.OptionalHeader.ImageBase, temp)
        result.extend(temp)
        temp = bytearray()

        fields_size = align_32(imports_rva + imports_size, 4)
        methods_size = fields_size - imports_rva - imports_size
        fields_size = 0
        result.extend(b'\x00' * methods_size)
        methods_rva = imports_rva + imports_size + methods_size

        methods_size = <uint32_t>len(result)
        method_mappings = self.__build_method_data(result, methods_rva)
        methods_size = <uint32_t>len(result) - methods_size
        fields_size = <uint32_t>len(result)
        field_mappings = self.__build_fieldrva_data(result, methods_rva + methods_size)
        fields_size = <uint32_t>len(result) - fields_size
        metadata_size = <uint32_t>len(result)
        heaps_mappings = self.__build_net_heaps(result, method_mappings, field_mappings, list(self.__dpefile.get_heaps().keys()))
        metadata_size = <uint32_t>len(result) - metadata_size
        metadata_rva = methods_rva + methods_size + fields_size
        cor_rva = metadata_rva + metadata_size
        cor_size = <uint32_t>self.__build_net_headers(result, cor_rva, metadata_rva, metadata_size)
        data_dir_rva = cor_rva + cor_size

        for x in range(nt_headers.OptionalHeader.NumberOfRvaAndSizes):
            if x != IMAGE_DIRECTORY_ENTRY_IMPORT and x != IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR and x != IMAGE_DIRECTORY_ENTRY_BASERELOC and x != IMAGE_DIRECTORY_ENTRY_RESOURCE:
                offset = nt_headers.OptionalHeader.DataDirectory[x].VirtualAddress
                if offset == 0:
                    continue
                offset = self.__pe.get_offset_from_rva(offset)
                result.extend(orig_data[offset:offset + nt_headers.OptionalHeader.DataDirectory[x].Size])

        first_sect_size = align_32(<uint32_t>len(result), nt_headers.OptionalHeader.FileAlignment)
        memset(&sect_header, 0, sizeof(IMAGE_SECTION_HEADER))
        strcpy(sect_header.Name, '.text')
        sect_header.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE
        sect_header.Misc.VirtualSize = <uint32_t>len(result)
        first_sect_vsize = sect_header.Misc.VirtualSize
        sect_header.PointerToRawData = first_sect_offset
        sect_header.SizeOfRawData = first_sect_size
        sect_header.VirtualAddress = first_section_rva
        result.extend(b'\x00' * (first_sect_size - len(result)))
        headers.extend(convert_pointer_to_bytes(<uintptr_t>&sect_header, sizeof(sect_header)))

        if data_dir.VirtualAddress != 0:
            has_rsrc = True
            memset(&sect_header, 0, sizeof(sect_header))
            strcpy(sect_header.Name, '.rsrc')
            sect_header.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
            sect_header.PointerToRawData = first_sect_offset + first_sect_size
            sect_header.VirtualAddress = align_32(first_section_rva + first_sect_vsize, nt_headers.OptionalHeader.SectionAlignment)
            data, resource_rva, resource_size, resource_vsize = _copy_resource_section(self.__pe, self.__dpefile, sect_header.VirtualAddress)
            sect_header.Misc.VirtualSize = resource_vsize
            rsrc_size = align_32(<uint32_t>len(data), nt_headers.OptionalHeader.FileAlignment)
            sect_header.SizeOfRawData = rsrc_size
            result.extend(data + b'\x00' * (rsrc_size - len(data)))
            headers.extend(convert_pointer_to_bytes(<uintptr_t>&sect_header, sizeof(IMAGE_SECTION_HEADER)))

        headers.extend(b'\x00' * (first_sect_offset - len(headers)))
        headers.extend(result)
        PyObject_GetBuffer(headers, &headers_view, PyBUF_WRITABLE)
        dos_header = <IMAGE_DOS_HEADER*>headers_view.buf
        nt_headers = <IMAGE_NT_HEADERS64*>((<char*>dos_header) + dos_header.e_lfanew)
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
            size_of_image = max(size_of_image, align_32(sect_header.Misc.VirtualSize, nt_headers.OptionalHeader.SectionAlignment) + sect_header.VirtualAddress)
        nt_headers.OptionalHeader.SizeOfCode = size_of_code
        nt_headers.OptionalHeader.SizeOfInitializedData = size_of_init_data
        nt_headers.OptionalHeader.SizeOfUninitializedData = size_of_uninit_data
        nt_headers.OptionalHeader.SizeOfHeaders = first_sect_offset
        nt_headers.OptionalHeader.SizeOfImage = align_32(size_of_image, nt_headers.OptionalHeader.SectionAlignment)
        nt_headers.OptionalHeader.BaseOfCode = first_section_rva
        nt_headers.OptionalHeader.AddressOfEntryPoint = first_section_rva
        nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = imports_rva
        nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = imports_size
        nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress = cor_rva
        nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size = cor_size
        nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0
        nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0
        if has_rsrc:
            nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = resource_rva
            nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = resource_vsize
        nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0
        nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0

        checksum_offset = dos_header.e_lfanew + 4 + <uint32_t>sizeof(IMAGE_FILE_HEADER)
        checksum_offset += <uint32_t>( <uint64_t>(&nt_headers.OptionalHeader.CheckSum) - <uint64_t>(&nt_headers.OptionalHeader))
        checksum = self.calculate_pe_checksum(<unsigned char *>headers_view.buf, <size_t>len(headers), checksum_offset)
        PyBuffer_Release(&headers_view)
        return bytes(headers)

    cdef uint32_t calculate_pe_checksum(self, unsigned char * data, size_t length, size_t checksum_offset):
        """
        PE checksum algorithm used for OptionalHeader.CheckSum.

        checksum_offset is the file offset of OptionalHeader.CheckSum.
        The 4 checksum bytes are treated as zero.
        """
        cdef size_t i = 0
        cdef uint64_t checksum = 0
        cdef uint32_t word = 0

        while i + 1 < length:
            if i == checksum_offset:
                word = 0
                i += 4
                checksum += word
                continue

            word = (<uint16_t*> &data[i])[0]
            checksum += word

            checksum = (checksum & 0xffff) + (checksum >> 16)
            i += 2

        if i < length:
            checksum += data[i]
            checksum = (checksum & 0xffff) + (checksum >> 16)

        checksum = (checksum & 0xffff) + (checksum >> 16)
        checksum = checksum + length

        return <uint32_t> checksum

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
        cdef uint32_t size_of_image = 0
        cdef IMAGE_SECTION_HEADER * sechdrs = NULL
        cdef bint has_rsrc = False
        cdef uint32_t relocs_size = 0
        cdef Py_buffer headers_view
        cdef uint32_t rsrc_vsize = 0
        cdef uint32_t rsrc_size = 0
        cdef uint32_t reloc_va = 0
        cdef uint32_t resource_size = 0
        cdef uint32_t resource_rva = 0
        cdef uint32_t resource_vsize = 0
        cdef uint32_t checksum = 0
        cdef size_t checksum_offset = 0
        cdef uint32_t header_padding = 0
        headers.extend(orig_data[:dos_header.e_lfanew])
        headers.extend(b'PE\x00\x00')
        headers.extend(orig_data[dos_header.e_lfanew + 4: dos_header.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + nt_headers.FileHeader.SizeOfOptionalHeader])
        memset(&sect_header, 0, sizeof(IMAGE_SECTION_HEADER))
        strcpy(sect_header.Name, '.text')
        sect_header.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE
        data_dir = self.__pe.get_directory_by_idx(IMAGE_DIRECTORY_ENTRY_RESOURCE)
        if data_dir.VirtualAddress != 0:
            amt_sections += 1
        first_sect_offset = (
            <uint32_t>len(headers) +
            <uint32_t>(amt_sections * sizeof(IMAGE_SECTION_HEADER))
        )
        first_sect_offset = align_32(first_sect_offset, nt_headers.OptionalHeader.FileAlignment)

        first_section_rva = align_32(first_sect_offset, nt_headers.OptionalHeader.SectionAlignment)

        if self.__pe.is_dll():
            nt_headers.OptionalHeader.ImageBase = 0x10000000
        else:
            nt_headers.OptionalHeader.ImageBase = 0x00400000
        imports_rva = first_section_rva + 6
        imports_size = <uint32_t>self.__build_imports32(self.__dpefile, temp, imports_rva)
        self.__build_stub32(self.__dpefile, result, first_section_rva + 4, nt_headers.OptionalHeader.ImageBase, temp)
        result.extend(temp)
        temp = bytearray()
        #pad to four
        fields_size = align_32(imports_rva + imports_size, 4)
        methods_size = fields_size - imports_rva - imports_size
        fields_size = 0
        result.extend(b'\x00' * methods_size)
        methods_rva = imports_rva + imports_size + methods_size
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
        cor_size = <uint32_t>self.__build_net_headers(result, cor_rva, metadata_rva, metadata_size)
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
        first_sect_size = <uint32_t>(len(result) - header_padding)
        first_sect_size = align_32(first_sect_size, nt_headers.OptionalHeader.FileAlignment)
        sect_header.Misc.VirtualSize = <uint32_t>len(result)
        first_sect_vsize = sect_header.Misc.VirtualSize
        sect_header.PointerToRawData = first_sect_offset
        sect_header.SizeOfRawData = first_sect_size
        sect_header.VirtualAddress = first_section_rva
        result.extend(b'\x00' * (first_sect_size - len(result)))
        headers.extend(convert_pointer_to_bytes(<uintptr_t>&sect_header, sizeof(sect_header)))
        memset(&sect_header, 0, sizeof(sect_header))
        strcpy(sect_header.Name, '.reloc')
        sect_header.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE
        sect_header.PointerToRawData = first_sect_offset + first_sect_size
        sect_header.VirtualAddress = align_32(first_section_rva + first_sect_vsize, nt_headers.OptionalHeader.SectionAlignment)
        reloc_va = sect_header.VirtualAddress
        relocs_vsize = <uint32_t>self.__build_relocations_directory32(result, first_section_rva + 2)
        sect_header.Misc.VirtualSize = relocs_vsize
        relocs_size = align_32(relocs_vsize, nt_headers.OptionalHeader.FileAlignment)
        result.extend(b'\x00' * (relocs_size - sect_header.Misc.VirtualSize))
        sect_header.SizeOfRawData = relocs_size
        headers.extend(convert_pointer_to_bytes(<uintptr_t>&sect_header, sizeof(IMAGE_SECTION_HEADER)))
        if data_dir.VirtualAddress != 0:
            has_rsrc = True
            memset(&sect_header, 0, sizeof(sect_header))
            strcpy(sect_header.Name, '.rsrc')
            sect_header.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
            sect_header.PointerToRawData = first_sect_offset + first_sect_size + relocs_size
            sect_header.VirtualAddress = align_32(reloc_va + relocs_vsize, nt_headers.OptionalHeader.SectionAlignment)
            data, resource_rva, resource_size, resource_vsize = _copy_resource_section(self.__pe, self.__dpefile, sect_header.VirtualAddress)
            sect_header.Misc.VirtualSize = resource_vsize
            rsrc_size = align_32(<uint32_t>len(data), nt_headers.OptionalHeader.FileAlignment)
            sect_header.SizeOfRawData = rsrc_size
            data = data + b'\x00' * (rsrc_size - len(data))
            result.extend(data)
            headers.extend(convert_pointer_to_bytes(<uintptr_t>&sect_header, sizeof(IMAGE_SECTION_HEADER)))
        headers.extend(b'\x00' * (first_sect_offset - len(headers)))
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
            size_of_image = max(size_of_image, align_32(sect_header.Misc.VirtualSize, nt_headers.OptionalHeader.SectionAlignment) + sect_header.VirtualAddress)
        nt_headers.OptionalHeader.SizeOfCode = size_of_code
        nt_headers.OptionalHeader.SizeOfInitializedData = size_of_init_data
        nt_headers.OptionalHeader.SizeOfUninitializedData = size_of_uninit_data
        nt_headers.OptionalHeader.SizeOfHeaders = first_sect_offset
        nt_headers.OptionalHeader.SizeOfImage = align_32(size_of_image, nt_headers.OptionalHeader.SectionAlignment)
        nt_headers.OptionalHeader.BaseOfCode = first_section_rva
        nt_headers.OptionalHeader.BaseOfData = first_section_rva + first_sect_vsize
        nt_headers.OptionalHeader.AddressOfEntryPoint = first_section_rva
        nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = imports_rva
        nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = imports_size
        nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress = cor_rva
        nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size = cor_size
        nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = reloc_va
        nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = relocs_vsize
        if has_rsrc:
            nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = resource_rva
            nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = resource_vsize
        nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0
        nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0

        checksum_offset = dos_header.e_lfanew + 4 + <uint32_t>sizeof(IMAGE_FILE_HEADER)
        checksum_offset += <size_t>( <size_t>(&nt_headers.OptionalHeader.CheckSum) - <size_t>(&nt_headers.OptionalHeader))
        checksum = self.calculate_pe_checksum(<unsigned char *>headers_view.buf, <size_t>len(headers), checksum_offset)
        PyBuffer_Release(&headers_view)
        #TODO: update OptionalHeader CheckSum
        return bytes(headers)

    cpdef bytes rebuild(self):
        cdef bytearray data = bytearray()
        cdef IMAGE_DOS_HEADER * dos_header = <IMAGE_DOS_HEADER*>self.__pe.get_data_view()
        cdef IMAGE_NT_HEADERS32 * nt_headers = <IMAGE_NT_HEADERS32*>((<char*>dos_header) + dos_header.e_lfanew)
        if nt_headers.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            return self.__rebuild_64()
        return self.__rebuild_32()