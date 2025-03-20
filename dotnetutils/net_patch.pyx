#cython: language_level=3

from dotnetutils import net_exceptions
from dotnetutils cimport dotnetpefile
from dotnetutils.net_utils cimport convert_pointer_to_bytes
from cpython.buffer cimport PyObject_GetBuffer, PyBuffer_Release, PyBUF_ANY_CONTIGUOUS
from libc.stdint cimport uintptr_t
from libc.string cimport memcmp

import hashlib

from cpython.bytes cimport PyBytes_FromStringAndSize

from dotnetutils.net_structs cimport IMAGE_SECTION_HEADER, IMAGE_SCN_CNT_CODE, IMAGE_OPTIONAL_HEADER32, COMIMAGE_FLAGS_NATIVE_ENTRYPOINT, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_DEBUG, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_ORDINAL_FLAG32, IMAGE_ORDINAL_FLAG64, IMAGE_DIRECTORY_ENTRY_RESOURCE, IMAGE_OPTIONAL_HEADER64, IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_CNT_UNINITIALIZED_DATA, IMAGE_DATA_DIRECTORY, IMAGE_RESOURCE_DATA_ENTRY, IMAGE_FILE_HEADER, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64, IMAGE_RESOURCE_DIRECTORY_ENTRY, IMAGE_RESOURCE_DIRECTORY, IMAGE_DATA_DIRECTORY, IMAGE_IMPORT_DESCRIPTOR, IMAGE_COR20_HEADER, IMAGE_BASE_RELOCATION, IMAGE_THUNK_DATA32, IMAGE_THUNK_DATA64, IMAGE_DEBUG_DIRECTORY

cdef bytes insert_blank_userstrings32(dotnetpefile.DotNetPeFile dotnetpe, bytes exe_data):
    cdef bytearray new_exe_data
    cdef Py_buffer exe_data_view
    cdef IMAGE_DOS_HEADER * dos_header
    cdef IMAGE_NT_HEADERS32 * nt_headers
    cdef int metadata_offset
    cdef int streams_offset
    cdef int number_of_streams
    cdef int length_of_str
    cdef int current_offset
    cdef int x
    cdef bytes name
    cdef int us_size
    cdef int new_header_offset
    cdef int us_offset
    cdef bytes new_streamheader
    cdef int new_stream_offset
    cdef dotnetpefile.PeFile new_pe
    cdef int new_data_va
    cdef int stream_amt_offset
    cdef int new_data_offset
    cdef bytes number_of_streams_bytes
    new_exe_data = bytearray(exe_data)
    PyObject_GetBuffer(new_exe_data, &exe_data_view, PyBUF_ANY_CONTIGUOUS)
    dos_header = <IMAGE_DOS_HEADER*>exe_data_view.buf
    nt_headers = <IMAGE_NT_HEADERS32*>exe_data_view.buf + dos_header.e_lfanew

    metadata_offset = dotnetpe.get_pe().get_offset_from_rva(dotnetpe.get_metadata_dir().get_net_header().MetaData.VirtualAddress)
    streams_offset = metadata_offset + 12
    number_of_streams = metadata_offset + 12
    number_of_streams_bytes = exe_data[number_of_streams:number_of_streams + 4]
    length_of_str = int.from_bytes(number_of_streams_bytes, 'little')
    streams_offset += length_of_str + 6
    number_of_streams = int.from_bytes(exe_data[streams_offset:streams_offset + 2], 'little')
    #change the number of streams later.
    streams_offset += 2
    current_offset = streams_offset
    for x in range(number_of_streams):
        stream_offset = int.from_bytes(exe_data[current_offset:current_offset+4], 'little')
        current_offset += 4
        stream_size = int.from_bytes(exe_data[current_offset:current_offset+4], 'little')
        current_offset += 4
        name = bytes()
        while exe_data[current_offset] != 0:
            name += bytes([exe_data[current_offset]])
            current_offset += 1
        current_offset += (4 - (current_offset % 4))
    #construct the new streamheader.
    us_size = 1
    new_header_offset = current_offset
    us_offset = stream_offset + stream_size
    new_streamheader = int.to_bytes(us_offset, 4, 'little') + int.to_bytes(us_size, 4, 'little')
    new_streamheader += b'#US\x00'
    #new_streamheader = int.to_bytes(us_offset + len(new_streamheader), 4, 'little') + new_streamheader[4:]
    amt_to_align = (4 - ((current_offset + 12) % 4))
    new_streamheader += b'\x00' * amt_to_align

    new_streamheader = int.to_bytes(us_offset + len(new_streamheader), 4, 'little') + new_streamheader[4:]
    #fix the offsets of streamhaeders
    current_offset = streams_offset
    for x in range(number_of_streams):
        stream_offset = int.from_bytes(exe_data[current_offset:current_offset+4], 'little')
        new_stream_offset = stream_offset + len(new_streamheader)
        new_exe_data = new_exe_data[:current_offset] + int.to_bytes(new_stream_offset, 4, 'little') + new_exe_data[current_offset + 4:]
        current_offset += 8
        while new_exe_data[current_offset] != 0:
            current_offset += 1
        current_offset += (4 - (current_offset % 4))
        
    new_exe_data = bytearray(apply_pe_fixups(dotnetpe.get_pe(), bytes(new_exe_data), dotnetpe.get_pe().get_rva_from_offset(new_header_offset), len(new_streamheader), dotnetpe, False))
    new_exe_data = new_exe_data[:new_header_offset] + new_streamheader + new_exe_data[new_header_offset:]
    new_data_offset = us_offset + metadata_offset + len(new_streamheader)
    new_pe = dotnetpefile.PeFile(bytes(new_exe_data))
    new_data_va = new_pe.get_rva_from_offset(new_data_offset)
    new_exe_data = bytearray(apply_pe_fixups(new_pe, bytes(new_exe_data), new_data_va, 1, dotnetpe, False))
    new_exe_data = new_exe_data[:new_data_offset] + bytes([0]) + new_exe_data[new_data_offset:]
    stream_amt_offset = streams_offset - 2
    new_exe_data = new_exe_data[:stream_amt_offset] + int.to_bytes(number_of_streams + 1, 2, 'little') + new_exe_data[stream_amt_offset + 2:]
    PyBuffer_Release(&exe_data_view)
    return bytes(new_exe_data)

cdef bytes insert_blank_userstrings64(dotnetpefile.DotNetPeFile dotnetpe, bytes exe_data):
    cdef bytearray new_exe_data
    cdef Py_buffer exe_data_view
    cdef IMAGE_DOS_HEADER * dos_header
    cdef IMAGE_NT_HEADERS64 * nt_headers
    cdef int metadata_offset
    cdef int streams_offset
    cdef int number_of_streams
    cdef int length_of_str
    cdef int current_offset
    cdef int x
    cdef bytes name
    cdef int us_size
    cdef int new_header_offset
    cdef int us_offset
    cdef bytes new_streamheader
    cdef int new_stream_offset
    cdef dotnetpefile.PeFile new_pe
    cdef int new_data_va
    cdef int stream_amt_offset
    cdef int new_data_offset
    cdef bytes number_of_streams_bytes
    new_exe_data = bytearray(exe_data)
    PyObject_GetBuffer(new_exe_data, &exe_data_view, PyBUF_ANY_CONTIGUOUS)
    dos_header = <IMAGE_DOS_HEADER*>exe_data_view.buf
    nt_headers = <IMAGE_NT_HEADERS64*>(<uintptr_t>exe_data_view.buf + dos_header.e_lfanew)

    metadata_offset = dotnetpe.get_pe().get_offset_from_rva(dotnetpe.get_metadata_dir().get_net_header().MetaData.VirtualAddress)
    streams_offset = metadata_offset + 12
    number_of_streams = metadata_offset + 12
    number_of_streams_bytes = exe_data[number_of_streams:number_of_streams + 4]
    length_of_str = int.from_bytes(number_of_streams_bytes, 'little')
    streams_offset += length_of_str + 6
    number_of_streams = int.from_bytes(exe_data[streams_offset:streams_offset + 2], 'little')
    #change the number of streams later.
    streams_offset += 2
    current_offset = streams_offset
    for x in range(number_of_streams):
        stream_offset = int.from_bytes(exe_data[current_offset:current_offset+4], 'little')
        current_offset += 4
        stream_size = int.from_bytes(exe_data[current_offset:current_offset+4], 'little')
        current_offset += 4
        name = bytes()
        while exe_data[current_offset] != 0:
            name += bytes([exe_data[current_offset]])
            current_offset += 1
        current_offset += (4 - (current_offset % 4))
    #construct the new streamheader.
    us_size = 1
    new_header_offset = current_offset
    us_offset = stream_offset + stream_size
    new_streamheader = int.to_bytes(us_offset, 4, 'little') + int.to_bytes(us_size, 4, 'little')
    new_streamheader += b'#US\x00'
    #new_streamheader = int.to_bytes(us_offset + len(new_streamheader), 4, 'little') + new_streamheader[4:]
    amt_to_align = (4 - ((current_offset + 12) % 4))
    new_streamheader += b'\x00' * amt_to_align

    new_streamheader = int.to_bytes(us_offset + len(new_streamheader), 4, 'little') + new_streamheader[4:]
    #fix the offsets of streamhaeders
    current_offset = streams_offset
    for x in range(number_of_streams):
        stream_offset = int.from_bytes(exe_data[current_offset:current_offset+4], 'little')
        new_stream_offset = stream_offset + len(new_streamheader)
        new_exe_data = new_exe_data[:current_offset] + int.to_bytes(new_stream_offset, 4, 'little') + new_exe_data[current_offset + 4:]
        current_offset += 8
        while new_exe_data[current_offset] != 0:
            current_offset += 1
        current_offset += (4 - (current_offset % 4))
        
    new_exe_data = bytearray(apply_pe_fixups(dotnetpe.get_pe(), bytes(new_exe_data), dotnetpe.get_pe().get_rva_from_offset(new_header_offset), len(new_streamheader), dotnetpe, False))
    new_exe_data = new_exe_data[:new_header_offset] + new_streamheader + new_exe_data[new_header_offset:]
    new_data_offset = us_offset + metadata_offset + len(new_streamheader)
    new_pe = dotnetpefile.PeFile(bytes(new_exe_data))
    new_data_va = new_pe.get_rva_from_offset(new_data_offset)
    new_exe_data = bytearray(apply_pe_fixups(new_pe, bytes(new_exe_data), new_data_va, 1, dotnetpe, False))
    new_exe_data = new_exe_data[:new_data_offset] + bytes([0]) + new_exe_data[new_data_offset:]
    stream_amt_offset = streams_offset - 2
    new_exe_data = new_exe_data[:stream_amt_offset] + int.to_bytes(number_of_streams + 1, 2, 'little') + new_exe_data[stream_amt_offset + 2:]
    PyBuffer_Release(&exe_data_view)
    return bytes(new_exe_data)

cpdef bytes insert_blank_userstrings(dotnetpefile.DotNetPeFile dotnetpe, bytes exe_data):
    """
    Patches a binary to insert a blank #US Stream
    Some obfuscators dont have any strings so theres no #US.
    FIXME: binaries patched by this method are currently unable to be executed.
    """
    if dotnetpe.get_pe().is_64bit():
        return insert_blank_userstrings64(dotnetpe, exe_data)
    else:
        return insert_blank_userstrings32(dotnetpe, exe_data)

cdef void fixup_resource_data(int rsd_offset, bytes old_exe_data, dotnetpefile.PeFile old_pe, bytearray new_exe_data, int va_addr, int difference):
    """
    Performs the required modifications on a IMAGE_RESOURCE_DATA_ENTRY structure.
    :param rsd_offset: the offset of the IMAGE_RESOURCE_DATA_ENTRY structure
    """
    cdef Py_buffer old_exe_view
    cdef IMAGE_RESOURCE_DATA_ENTRY * data_struct = NULL
    cdef int rva = 0
    PyObject_GetBuffer(bytearray(old_exe_data), &old_exe_view, PyBUF_ANY_CONTIGUOUS)
    data_struct = <IMAGE_RESOURCE_DATA_ENTRY*>(<uintptr_t>old_exe_view.buf + <uintptr_t>rsd_offset)
    rva = data_struct.OffsetToData
    fixed_rva = get_fixed_rva(old_pe, bytes(new_exe_data), rva, va_addr, difference)
    data_struct.OffsetToData = fixed_rva
    new_exe_data = new_exe_data[:rsd_offset] + convert_pointer_to_bytes(<uintptr_t>data_struct, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)) + new_exe_data[rsd_offset + sizeof(IMAGE_RESOURCE_DATA_ENTRY):]
    PyBuffer_Release(&old_exe_view)

cdef void fixup_resource_directory(int rs_offset, int rs_rva, int orig_rs_offset, bytes old_exe_data, dotnetpefile.PeFile old_pe, bytearray new_exe_data, int va_addr, int difference):
    """
    Finds and fixes structures related to an image's resource directory.
    :param rs_offset: the offset to the directory
    :param rs_rva: the rva of the resource dir
    :param orig_rs_offset: the original resource offset
    """
    cdef Py_buffer old_exe_view
    cdef IMAGE_RESOURCE_DIRECTORY * rsrc_dir = NULL
    cdef unsigned int usable_rs_offset = rs_offset + sizeof(IMAGE_RESOURCE_DIRECTORY)
    cdef int x
    cdef IMAGE_RESOURCE_DIRECTORY_ENTRY * sub_entry = NULL
    cdef unsigned int r_offset
    PyObject_GetBuffer(bytearray(old_exe_data), &old_exe_view, PyBUF_ANY_CONTIGUOUS)
    rsrc_dir = <IMAGE_RESOURCE_DIRECTORY*>(<uintptr_t>old_exe_view.buf + <uintptr_t>rs_offset)
    for x in range(rsrc_dir.NumberOfNamedEntries + rsrc_dir.NumberOfIdEntries):
        sub_entry = <IMAGE_RESOURCE_DIRECTORY_ENTRY*> (<uintptr_t>old_exe_view.buf + <uintptr_t>usable_rs_offset)
        if sub_entry.OffsetToData.OffsetToDirectory.DataIsDirectory:
            r_offset = orig_rs_offset + sub_entry.OffsetToData.OffsetToDirectory.OffsetToDirectory
            fixup_resource_directory(r_offset, rs_rva, orig_rs_offset, old_exe_data, old_pe, new_exe_data, va_addr, difference)
        else:
            r_offset = orig_rs_offset + sub_entry.OffsetToData.OffsetToData
            fixup_resource_data(r_offset, old_exe_data, old_pe, new_exe_data, va_addr, difference)
        new_exe_data = new_exe_data[:usable_rs_offset] + convert_pointer_to_bytes(<uintptr_t>sub_entry, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)) + new_exe_data[
                                                                            usable_rs_offset + sizeof(
                                                                                IMAGE_RESOURCE_DIRECTORY_ENTRY):]

        usable_rs_offset += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)
    PyBuffer_Release(&old_exe_view)

cdef bytes apply_pe_fixups_32(dotnetpefile.PeFile old_pe, bytes old_exe_data, int va_addr, int difference, dotnetpefile.DotNetPeFile dotnetpe, bint in_streams):
    cdef int section_offset
    cdef IMAGE_NT_HEADERS32 * nt_headers = NULL
    cdef Py_buffer old_exe_view
    cdef bint passed_target_section
    cdef IMAGE_SECTION_HEADER * prev_section_header = NULL
    cdef int target_rawsize_difference
    cdef int amt_padding_needed
    cdef int padding_offset
    cdef unsigned int size_of_code
    cdef unsigned int size_of_uninitialized_data
    cdef unsigned int size_of_initialized_data
    cdef IMAGE_SECTION_HEADER * section_header = NULL
    cdef unsigned int old_rawsize
    cdef unsigned int new_rawsize
    cdef int amt_padding
    cdef unsigned int current_size
    cdef unsigned int old_virtsize
    cdef unsigned int new_virtsize
    cdef unsigned int required_val
    cdef bytearray new_exe_data
    cdef unsigned long size_of_image
    cdef IMAGE_DATA_DIRECTORY * data_dir
    cdef unsigned int net_header_offset
    cdef unsigned int optional_offset
    cdef unsigned int optional_end_offset
    cdef unsigned int reloc_va
    cdef unsigned int reloc_offset
    cdef unsigned int reloc_size
    cdef unsigned int debug_va
    cdef unsigned int debug_offset
    cdef unsigned int current_va
    cdef unsigned int new_va
    cdef unsigned int offset
    cdef unsigned int imports_offset
    cdef unsigned int resource_offset
    cdef unsigned int resource_rva
    cdef IMAGE_IMPORT_DESCRIPTOR * import_descriptor = NULL
    cdef IMAGE_DEBUG_DIRECTORY * debug_struct = NULL 
    cdef IMAGE_COR20_HEADER * cor_header = NULL
    cdef IMAGE_BASE_RELOCATION * base_reloc = NULL
    cdef unsigned int thunk_offset
    cdef unsigned int orig_name
    cdef IMAGE_THUNK_DATA32 * thunk_data = NULL
    cdef unsigned int metadata_offset
    cdef unsigned int streams_offset
    cdef unsigned int number_of_streams
    cdef unsigned int length_of_str
    cdef bint passed_userstrings
    cdef unsigned int x
    cdef unsigned int orig_offset
    cdef bytearray name
    cdef bytes new_size
    cdef bytes new_offset
    cdef bytes padding
    cdef bytes number_of_streams_bytes
    cdef IMAGE_OPTIONAL_HEADER32 * optional_header
    cdef IMAGE_OPTIONAL_HEADER32 original_optional_header
    new_exe_data = bytearray(old_exe_data)
    PyObject_GetBuffer(old_exe_data, &old_exe_view, PyBUF_ANY_CONTIGUOUS)
    nt_headers = <IMAGE_NT_HEADERS32*>(<uintptr_t>old_exe_view.buf + <uintptr_t>old_pe.get_elfanew())
    section_offset = old_pe.get_elfanew() + sizeof(IMAGE_FILE_HEADER) + 4 + nt_headers.FileHeader.SizeOfOptionalHeader
    passed_target_section = False
    target_rawsize_difference = 0
    amt_padding_needed = 0
    padding_offset = 0
    size_of_code = 0
    size_of_initialized_data = 0
    size_of_uninitialized_data = 0
    for _ in range(nt_headers.FileHeader.NumberOfSections):
        section_header = <IMAGE_SECTION_HEADER*> (<uintptr_t>old_exe_view.buf + section_offset)
        if section_header.VirtualAddress <= va_addr < (section_header.VirtualAddress + section_header.Misc.VirtualSize):
            passed_target_section = True
            old_rawsize = section_header.SizeOfRawData
            new_rawsize = old_rawsize + difference  # now align it up
            new_rawsize = new_rawsize + (nt_headers.OptionalHeader.FileAlignment - (
                        new_rawsize % nt_headers.OptionalHeader.FileAlignment))
            amt_padding = new_rawsize - old_rawsize - difference
            current_size = old_rawsize  # we aren't putting the data in first anymore.
            section_header.SizeOfRawData = new_rawsize
            amt_padding_needed = amt_padding
            padding_offset = section_header.PointerToRawData + current_size
            old_virtsize = section_header.Misc.VirtualSize
            new_virtsize = old_virtsize + amt_padding + difference
            section_header.Misc.VirtualSize = new_virtsize
            target_rawsize_difference = new_rawsize - old_rawsize
        elif passed_target_section:
            section_header.PointerToRawData += target_rawsize_difference
            # now deal with VAs - make sure the VA is greater than the last VA + size, if not add to it and realign
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

        new_exe_data = new_exe_data[:section_offset] + convert_pointer_to_bytes(<uintptr_t>section_header, sizeof(IMAGE_SECTION_HEADER)) + new_exe_data[
                                                                               section_offset + sizeof(
                                                                                   IMAGE_SECTION_HEADER):]
        prev_section_header = section_header
        section_offset += sizeof(IMAGE_SECTION_HEADER)
    optional_header = &nt_headers.OptionalHeader
    original_optional_header = optional_header[0] #save a copy of the optional header for later.
    size_of_image = section_header.VirtualAddress + section_header.Misc.VirtualSize
    size_of_image += (optional_header.SectionAlignment - (
                size_of_image % nt_headers.OptionalHeader.SectionAlignment))
    # once the sections are fixed, fix the optional header
    nt_headers.OptionalHeader.AddressOfEntryPoint = get_fixed_rva(old_pe, bytes(new_exe_data),
                                                                  optional_header.AddressOfEntryPoint,
                                                                  va_addr, difference)
    for x in range(optional_header.NumberOfRvaAndSizes):
        data_dir = &optional_header.DataDirectory[x]
        if data_dir.VirtualAddress != 0:
            data_dir.VirtualAddress = get_fixed_rva(old_pe, bytes(new_exe_data), data_dir.VirtualAddress, va_addr, difference)
    optional_header.SizeOfCode = size_of_code
    optional_header.SizeOfInitializedData = size_of_initialized_data
    optional_header.SizeOfUninitializedData = size_of_uninitialized_data
    optional_header.SizeOfImage = size_of_image
    optional_header.BaseOfCode = get_fixed_rva(old_pe, bytes(new_exe_data), nt_headers.OptionalHeader.BaseOfCode,
                                                         va_addr, difference)
    #THIS IS 32 bit ONLY!!!
    optional_header.BaseOfData = get_fixed_rva(old_pe, bytes(new_exe_data), nt_headers.OptionalHeader.BaseOfData,
                                                        va_addr, difference)
    # paste in the optional header
    optional_offset = old_pe.get_elfanew() + 4 + sizeof(IMAGE_FILE_HEADER)
    optional_end_offset = optional_offset + nt_headers.FileHeader.SizeOfOptionalHeader

    new_exe_data = new_exe_data[:optional_offset] + convert_pointer_to_bytes(<uintptr_t>&nt_headers.OptionalHeader, sizeof(IMAGE_OPTIONAL_HEADER32))[
                                                    :nt_headers.FileHeader.SizeOfOptionalHeader] + new_exe_data[
                                                                                                   optional_end_offset:]

    # now for the COR20 header.
    net_header_offset = dotnetpe.get_cor_header_offset()
    cor_header = <IMAGE_COR20_HEADER*> (<uintptr_t>old_exe_view.buf + net_header_offset)
    cor_header.MetaData.VirtualAddress = get_fixed_rva(old_pe, old_exe_data, cor_header.MetaData.VirtualAddress,
                                                       va_addr, difference)
    if cor_header.MetaData.VirtualAddress <= va_addr <= (cor_header.MetaData.VirtualAddress + cor_header.MetaData.Size):
        #FIXME: while this fixes the issue regarding inserting blank strings stream,
        #I think it may hypothetically cause other issues.  Not sure.  Might need to remove <= and replace with < again.
        cor_header.MetaData.Size = cor_header.MetaData.Size + difference
    cor_header.Resources.VirtualAddress = get_fixed_rva(old_pe, old_exe_data, cor_header.Resources.VirtualAddress,
                                                        va_addr, difference)
    cor_header.StrongNameSignature.VirtualAddress = get_fixed_rva(old_pe, old_exe_data,
                                                                  cor_header.StrongNameSignature.VirtualAddress,
                                                                  va_addr, difference)
    cor_header.CodeManagerTable.VirtualAddress = get_fixed_rva(old_pe, old_exe_data,
                                                               cor_header.CodeManagerTable.VirtualAddress, va_addr,
                                                               difference)
    cor_header.VTableFixups.VirtualAddress = get_fixed_rva(old_pe, old_exe_data, cor_header.VTableFixups.VirtualAddress,
                                                           va_addr, difference)
    cor_header.ExportAddressTableJumps.VirtualAddress = get_fixed_rva(old_pe, old_exe_data,
                                                                      cor_header.ExportAddressTableJumps.VirtualAddress,
                                                                      va_addr, difference)
    cor_header.ManagedNativeHeader.VirtualAddress = get_fixed_rva(old_pe, old_exe_data,
                                                                  cor_header.ManagedNativeHeader.VirtualAddress,
                                                                  va_addr, difference)
    if cor_header.Flags & COMIMAGE_FLAGS_NATIVE_ENTRYPOINT != 0:
        cor_header.EntryPoint.EntryPointRVA = get_fixed_rva(old_pe, old_exe_data, cor_header.EntryPoint.EntryPointRVA,
                                                            va_addr, difference)
    new_exe_data = new_exe_data[:net_header_offset] + convert_pointer_to_bytes(<uintptr_t>cor_header, sizeof(IMAGE_COR20_HEADER)) + new_exe_data[
                                                                          net_header_offset + sizeof(
                                                                              IMAGE_COR20_HEADER):]
    # now process the reloc dir
    if IMAGE_DIRECTORY_ENTRY_BASERELOC < optional_header.NumberOfRvaAndSizes:
        reloc_va = original_optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
        reloc_size = original_optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size
        if reloc_va != 0:
            reloc_offset = old_pe.get_offset_from_rva(reloc_va)
            offset = 0
            while offset < reloc_size:
                base_reloc = <IMAGE_BASE_RELOCATION*> (<uintptr_t>old_exe_view.buf + reloc_offset + offset)
                base_reloc.VirtualAddress = get_fixed_rva(old_pe, bytes(new_exe_data), base_reloc.VirtualAddress, va_addr,
                                                        difference)
                new_exe_data = new_exe_data[:reloc_offset + offset] + convert_pointer_to_bytes(<uintptr_t>base_reloc, sizeof(IMAGE_BASE_RELOCATION)) + new_exe_data[
                                                                                        reloc_offset + offset + sizeof(
                                                                                            IMAGE_BASE_RELOCATION):]                                   
                offset += sizeof(IMAGE_BASE_RELOCATION) + base_reloc.BlockSize

    if IMAGE_DIRECTORY_ENTRY_DEBUG < optional_header.NumberOfRvaAndSizes:
        #process debug dir
        debug_va = original_optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress
        if debug_va != 0:
            debug_offset = old_pe.get_offset_from_rva(debug_va)
            debug_struct = <IMAGE_DEBUG_DIRECTORY*>(<uintptr_t>old_exe_view.buf + debug_offset)
            current_va = debug_struct.AddressOfRawData
            new_va = get_fixed_rva(old_pe, bytes(new_exe_data), current_va, va_addr, difference)
            if current_va != new_va:
                debug_struct.AddressOfRawData = new_va
                debug_struct.PointerToRawData += difference
                new_exe_data = new_exe_data[:debug_offset] + convert_pointer_to_bytes(<uintptr_t>debug_struct, sizeof(IMAGE_DEBUG_DIRECTORY)) + new_exe_data[debug_offset + sizeof(IMAGE_DEBUG_DIRECTORY):]
        
    # now process imports dir
    sha_obj = hashlib.sha1()
    sha_obj.update(new_exe_data)
    if IMAGE_DIRECTORY_ENTRY_IMPORT < optional_header.NumberOfRvaAndSizes:
        imports_offset = original_optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
        if imports_offset != 0:
            imports_offset = old_pe.get_offset_from_rva(imports_offset)
            while True:
                import_descriptor = <IMAGE_IMPORT_DESCRIPTOR*>(<uintptr_t>old_exe_view.buf + <uintptr_t>imports_offset)
                if import_descriptor.Name == 0:
                    break
                orig_name = import_descriptor.Name
                import_descriptor.Name = get_fixed_rva(old_pe, bytes(new_exe_data), import_descriptor.Name, va_addr, difference)
                thunk_offset = old_pe.get_offset_from_rva(import_descriptor.FirstThunk)
                while True:
                    thunk_data = <IMAGE_THUNK_DATA32*>(<uintptr_t>old_exe_view.buf + thunk_offset)
                    if thunk_data.u1.AddressOfData == 0:
                        break
                    if (thunk_data.u1.AddressOfData & IMAGE_ORDINAL_FLAG32) == 0:
                        # name import, fix.
                        thunk_data.u1.AddressOfData = get_fixed_rva(old_pe, old_exe_data, thunk_data.u1.AddressOfData, va_addr,
                                                                    difference)
                    new_exe_data = new_exe_data[:thunk_offset] + convert_pointer_to_bytes(<uintptr_t>thunk_data, sizeof(IMAGE_THUNK_DATA32)) + new_exe_data[
                                                                                        thunk_offset + sizeof(IMAGE_THUNK_DATA32):]
                    
                    thunk_offset += sizeof(IMAGE_THUNK_DATA32)
                import_descriptor.FirstThunk = get_fixed_rva(old_pe, old_exe_data, import_descriptor.FirstThunk, va_addr,
                                                                difference)

                thunk_offset = old_pe.get_offset_from_rva(import_descriptor.DUMMYUNIONNAME.OriginalFirstThunk)
                while True:
                    thunk_data = <IMAGE_THUNK_DATA32*>(<uintptr_t>old_exe_view.buf + thunk_offset)
                    if thunk_data.u1.AddressOfData == 0:
                        break
                    if (thunk_data.u1.AddressOfData & IMAGE_ORDINAL_FLAG32) == 0:
                        # name import, fix.
                        thunk_data.u1.AddressOfData = get_fixed_rva(old_pe, bytes(new_exe_data), thunk_data.u1.AddressOfData, va_addr,
                                                                    difference)
                    new_exe_data = new_exe_data[:thunk_offset] + convert_pointer_to_bytes(<uintptr_t>thunk_data, sizeof(IMAGE_THUNK_DATA32)) + new_exe_data[
                                                                                        thunk_offset + sizeof(IMAGE_THUNK_DATA32):]
                    thunk_offset += sizeof(IMAGE_THUNK_DATA32)
                import_descriptor.DUMMYUNIONNAME.OriginalFirstThunk = get_fixed_rva(old_pe, bytes(new_exe_data),
                                                                                    import_descriptor.DUMMYUNIONNAME.OriginalFirstThunk,
                                                                                    va_addr, difference)
                new_exe_data = new_exe_data[:imports_offset] + convert_pointer_to_bytes(<uintptr_t>import_descriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR)) + new_exe_data[imports_offset + sizeof(IMAGE_IMPORT_DESCRIPTOR):]
                imports_offset += sizeof(IMAGE_IMPORT_DESCRIPTOR)
    if IMAGE_DIRECTORY_ENTRY_RESOURCE < optional_header.NumberOfRvaAndSizes:
        resource_offset = original_optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress
        if resource_offset != 0:
            resource_rva = resource_offset
            resource_offset = old_pe.get_offset_from_rva(resource_offset)
            fixup_resource_directory(resource_offset, resource_rva, resource_offset, old_exe_data, old_pe, new_exe_data, va_addr, difference)
            # Fixup the resources directory
    # now process .NET heaps.
    metadata_offset = old_pe.get_offset_from_rva(dotnetpe.get_metadata_dir().get_net_header().MetaData.VirtualAddress)
    streams_offset = metadata_offset + 12
    number_of_streams = metadata_offset + 12
    number_of_streams_bytes = old_exe_data[number_of_streams:number_of_streams + 4]
    length_of_str = int.from_bytes(number_of_streams_bytes, 'little')
    streams_offset += length_of_str + 6
    number_of_streams = int.from_bytes(old_exe_data[streams_offset:streams_offset + 2], 'little')
    streams_offset += 2
    passed_userstrings = False
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
            if stream_offset <= old_pe.get_offset_from_rva(va_addr) < (stream_offset + size):
                passed_userstrings = True
                # fix the size of user strings stream
                # append the stream data
                new_size = int.to_bytes(size + difference, 4, 'little')
                new_exe_data = new_exe_data[:orig_offset + 4] + new_size + new_exe_data[orig_offset + 8:]
            elif passed_userstrings:
                # fix the offset of the rest of the streams
                new_offset = int.to_bytes(offset + difference, 4, 'little')
                new_exe_data = new_exe_data[:orig_offset] + new_offset + new_exe_data[orig_offset + 4:]

    if amt_padding_needed != 0 and padding_offset != 0:
        padding = b'\x00' * amt_padding_needed
        new_exe_data = new_exe_data[:padding_offset] + padding + new_exe_data[padding_offset:]
    PyBuffer_Release(&old_exe_view)
    return bytes(new_exe_data)

cdef bytes apply_pe_fixups_64(dotnetpefile.PeFile old_pe, bytes old_exe_data, int va_addr, int difference, dotnetpefile.DotNetPeFile dotnetpe, bint in_streams):
    cdef int section_offset
    cdef IMAGE_NT_HEADERS64 * nt_headers = NULL
    cdef Py_buffer old_exe_view
    cdef bint passed_target_section
    cdef IMAGE_SECTION_HEADER * prev_section_header = NULL
    cdef int target_rawsize_difference
    cdef int amt_padding_needed
    cdef int padding_offset
    cdef unsigned int size_of_code
    cdef unsigned int size_of_uninitialized_data
    cdef unsigned int size_of_initialized_data
    cdef IMAGE_SECTION_HEADER * section_header = NULL
    cdef unsigned int old_rawsize
    cdef unsigned int new_rawsize
    cdef int amt_padding
    cdef unsigned int current_size
    cdef unsigned int old_virtsize
    cdef unsigned int new_virtsize
    cdef unsigned int required_val
    cdef bytearray new_exe_data
    cdef unsigned long size_of_image
    cdef IMAGE_DATA_DIRECTORY data_dir
    cdef unsigned int net_header_offset
    cdef unsigned int optional_offset
    cdef unsigned int optional_end_offset
    cdef unsigned int reloc_va
    cdef unsigned int reloc_offset
    cdef unsigned int reloc_size
    cdef unsigned int debug_va
    cdef unsigned int debug_offset
    cdef unsigned int current_va
    cdef unsigned int new_va
    cdef unsigned int offset
    cdef unsigned int imports_offset
    cdef unsigned int resource_offset
    cdef unsigned int resource_rva
    cdef IMAGE_IMPORT_DESCRIPTOR * import_descriptor = NULL
    cdef IMAGE_DEBUG_DIRECTORY * debug_struct = NULL 
    cdef IMAGE_COR20_HEADER * cor_header = NULL
    cdef IMAGE_BASE_RELOCATION * base_reloc = NULL
    cdef unsigned int thunk_offset
    cdef unsigned int orig_name
    cdef IMAGE_THUNK_DATA64 * thunk_data = NULL
    cdef unsigned int metadata_offset
    cdef unsigned int streams_offset
    cdef unsigned int number_of_streams
    cdef unsigned int length_of_str
    cdef bint passed_userstrings
    cdef unsigned int x
    cdef unsigned int orig_offset
    cdef bytearray name
    cdef bytes new_size
    cdef bytes new_offset
    cdef bytes padding
    cdef bytes number_of_Streams_bytes
    new_exe_data = bytearray(old_exe_data)
    PyObject_GetBuffer(new_exe_data, &old_exe_view, PyBUF_ANY_CONTIGUOUS)
    nt_headers = <IMAGE_NT_HEADERS64*>(<uintptr_t>old_exe_view.buf + old_pe.get_elfanew())
    section_offset = old_pe.get_elfanew() + sizeof(IMAGE_FILE_HEADER) + 4 + nt_headers.FileHeader.SizeOfOptionalHeader
    passed_target_section = False
    target_rawsize_difference = 0
    amt_padding_needed = 0
    padding_offset = 0
    size_of_code = 0
    size_of_initialized_data = 0
    size_of_uninitialized_data = 0
    for _ in range(nt_headers.FileHeader.NumberOfSections):
        section_header = <IMAGE_SECTION_HEADER*> (<uintptr_t>old_exe_view.buf + section_offset)
        if section_header.VirtualAddress <= va_addr < (section_header.VirtualAddress + section_header.Misc.VirtualSize):
            passed_target_section = True
            old_rawsize = section_header.SizeOfRawData
            new_rawsize = old_rawsize + difference  # now align it up
            new_rawsize = new_rawsize + (nt_headers.OptionalHeader.FileAlignment - (
                        new_rawsize % nt_headers.OptionalHeader.FileAlignment))
            amt_padding = new_rawsize - old_rawsize - difference
            current_size = old_rawsize  # we aren't putting the data in first anymore.
            section_header.SizeOfRawData = new_rawsize
            amt_padding_needed = amt_padding
            padding_offset = section_header.PointerToRawData + current_size
            old_virtsize = section_header.Misc.VirtualSize
            new_virtsize = old_virtsize + amt_padding + difference
            section_header.Misc.VirtualSize = new_virtsize
            target_rawsize_difference = new_rawsize - old_rawsize
        elif passed_target_section:
            section_header.PointerToRawData += target_rawsize_difference
            # now deal with VAs - make sure the VA is greater than the last VA + size, if not add to it and realign
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

        new_exe_data = new_exe_data[:section_offset] + convert_pointer_to_bytes(<uintptr_t>section_header, sizeof(IMAGE_SECTION_HEADER)) + new_exe_data[
                                                                               section_offset + sizeof(
                                                                                   IMAGE_SECTION_HEADER):]
        prev_section_header = section_header
        section_offset += sizeof(IMAGE_SECTION_HEADER)
    size_of_image = section_header.VirtualAddress + section_header.Misc.VirtualSize
    size_of_image += (nt_headers.OptionalHeader.SectionAlignment - (
                size_of_image % nt_headers.OptionalHeader.SectionAlignment))
    # once the sections are fixed, fix the optional header
    nt_headers.OptionalHeader.AddressOfEntryPoint = get_fixed_rva(old_pe, bytes(new_exe_data),
                                                                  nt_headers.OptionalHeader.AddressOfEntryPoint,
                                                                  va_addr, difference)
    for x in range(nt_headers.OptionalHeader.NumberOfRvaAndSizes):
        data_dir = nt_headers.OptionalHeader.DataDirectory[x]
        if data_dir.VirtualAddress != 0:
            data_dir.VirtualAddress = get_fixed_rva(old_pe, bytes(new_exe_data), data_dir.VirtualAddress, va_addr, difference)
    nt_headers.OptionalHeader.SizeOfCode = size_of_code
    nt_headers.OptionalHeader.SizeOfInitializedData = size_of_initialized_data
    nt_headers.OptionalHeader.SizeOfUninitializedData = size_of_uninitialized_data
    nt_headers.OptionalHeader.SizeOfImage = size_of_image
    nt_headers.OptionalHeader.BaseOfCode = get_fixed_rva(old_pe, bytes(new_exe_data), nt_headers.OptionalHeader.BaseOfCode,
                                                         va_addr, difference)
    # paste in the optional header
    optional_offset = old_pe.get_elfanew() + 4 + sizeof(IMAGE_FILE_HEADER)
    optional_end_offset = optional_offset + nt_headers.FileHeader.SizeOfOptionalHeader

    new_exe_data = new_exe_data[:optional_offset] + convert_pointer_to_bytes(<uintptr_t>&nt_headers.OptionalHeader, sizeof(IMAGE_OPTIONAL_HEADER64))[
                                                    :nt_headers.FileHeader.SizeOfOptionalHeader] + new_exe_data[
                                                                                                   optional_end_offset:]

    # now for the COR20 header.
    net_header_offset = dotnetpe.get_cor_header_offset()
    cor_header = <IMAGE_COR20_HEADER*> (<uintptr_t>old_exe_view.buf + net_header_offset)
    cor_header.MetaData.VirtualAddress = get_fixed_rva(old_pe, old_exe_data, cor_header.MetaData.VirtualAddress,
                                                       va_addr, difference)
    if cor_header.MetaData.VirtualAddress <= va_addr <= (cor_header.MetaData.VirtualAddress + cor_header.MetaData.Size):
        #FIXME: while this fixes the issue regarding inserting blank strings stream,
        #I think it may hypothetically cause other issues.  Not sure.  Might need to remove <= and replace with < again.
        cor_header.MetaData.Size = cor_header.MetaData.Size + difference
    cor_header.Resources.VirtualAddress = get_fixed_rva(old_pe, old_exe_data, cor_header.Resources.VirtualAddress,
                                                        va_addr, difference)
    cor_header.StrongNameSignature.VirtualAddress = get_fixed_rva(old_pe, old_exe_data,
                                                                  cor_header.StrongNameSignature.VirtualAddress,
                                                                  va_addr, difference)
    cor_header.CodeManagerTable.VirtualAddress = get_fixed_rva(old_pe, old_exe_data,
                                                               cor_header.CodeManagerTable.VirtualAddress, va_addr,
                                                               difference)
    cor_header.VTableFixups.VirtualAddress = get_fixed_rva(old_pe, old_exe_data, cor_header.VTableFixups.VirtualAddress,
                                                           va_addr, difference)
    cor_header.ExportAddressTableJumps.VirtualAddress = get_fixed_rva(old_pe, old_exe_data,
                                                                      cor_header.ExportAddressTableJumps.VirtualAddress,
                                                                      va_addr, difference)
    cor_header.ManagedNativeHeader.VirtualAddress = get_fixed_rva(old_pe, old_exe_data,
                                                                  cor_header.ManagedNativeHeader.VirtualAddress,
                                                                  va_addr, difference)
    if cor_header.Flags & COMIMAGE_FLAGS_NATIVE_ENTRYPOINT != 0:
        cor_header.EntryPoint.EntryPointRVA = get_fixed_rva(old_pe, old_exe_data, cor_header.EntryPoint.EntryPointRVA,
                                                            va_addr, difference)
    new_exe_data = new_exe_data[:net_header_offset] + convert_pointer_to_bytes(<uintptr_t>cor_header, sizeof(IMAGE_COR20_HEADER)) + new_exe_data[
                                                                          net_header_offset + sizeof(
                                                                              IMAGE_COR20_HEADER):]
    # now process the reloc dir
    reloc_va = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
    reloc_size = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size
    if reloc_va != 0:
        reloc_offset = old_pe.get_offset_from_rva(reloc_va)
        offset = 0
        while offset < reloc_size:
            base_reloc = <IMAGE_BASE_RELOCATION*> (<uintptr_t>old_exe_view.buf + reloc_offset + offset)
            base_reloc.VirtualAddress = get_fixed_rva(old_pe, bytes(new_exe_data), base_reloc.VirtualAddress, va_addr,
                                                      difference)
            new_exe_data = new_exe_data[:reloc_offset + offset] + convert_pointer_to_bytes(<uintptr_t>base_reloc, sizeof(IMAGE_BASE_RELOCATION)) + new_exe_data[
                                                                                      reloc_offset + offset + sizeof(
                                                                                          IMAGE_BASE_RELOCATION):]
            offset += sizeof(IMAGE_BASE_RELOCATION) + base_reloc.BlockSize

    #process debug dir
    debug_va = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress
    if debug_va != 0:
        debug_offset = old_pe.get_offset_from_rva(debug_va)
        debug_struct = <IMAGE_DEBUG_DIRECTORY*>(<uintptr_t>old_exe_view.buf + debug_offset)
        current_va = debug_struct.AddressOfRawData
        new_va = get_fixed_rva(old_pe, bytes(new_exe_data), current_va, va_addr, difference)
        if current_va != new_va:
            debug_struct.AddressOfRawData = new_va
            debug_struct.PointerToRawData += difference
            new_exe_data = new_exe_data[:debug_offset] + convert_pointer_to_bytes(<uintptr_t>debug_struct, sizeof(IMAGE_DEBUG_DIRECTORY)) + new_exe_data[debug_offset + sizeof(IMAGE_DEBUG_DIRECTORY):]

    # now process imports dir
    imports_offset = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
    if imports_offset != 0:
        imports_offset = old_pe.get_offset_from_rva(imports_offset)

        while True:
            import_descriptor = <IMAGE_IMPORT_DESCRIPTOR*>(<uintptr_t>old_exe_view.buf + imports_offset)
            if import_descriptor.Name == 0:
                break
            orig_name = import_descriptor.Name
            import_descriptor.Name = get_fixed_rva(old_pe, bytes(new_exe_data), import_descriptor.Name, va_addr, difference)
            thunk_offset = old_pe.get_offset_from_rva(import_descriptor.FirstThunk)
            while True:
                thunk_data = <IMAGE_THUNK_DATA64*>(<uintptr_t>old_exe_view.buf + thunk_offset)
                if thunk_data.u1.AddressOfData == 0:
                    break
                if (thunk_data.u1.AddressOfData & IMAGE_ORDINAL_FLAG64) == 0:
                    # name import, fix.
                    thunk_data.u1.AddressOfData = get_fixed_rva(old_pe, old_exe_data, thunk_data.u1.AddressOfData, va_addr,
                                                                difference)
                new_exe_data = new_exe_data[:thunk_offset] + convert_pointer_to_bytes(<uintptr_t>thunk_data, sizeof(IMAGE_THUNK_DATA64)) + new_exe_data[
                                                                                    thunk_offset + sizeof(IMAGE_THUNK_DATA64):]
                thunk_offset += sizeof(IMAGE_THUNK_DATA64)
            import_descriptor.FirstThunk = get_fixed_rva(old_pe, old_exe_data, import_descriptor.FirstThunk, va_addr,
                                                            difference)

            thunk_offset = old_pe.get_offset_from_rva(import_descriptor.DUMMYUNIONNAME.OriginalFirstThunk)
            while True:
                thunk_data = <IMAGE_THUNK_DATA64*>(<uintptr_t>old_exe_view.buf + thunk_offset)
                if thunk_data.u1.AddressOfData == 0:
                    break
                if (thunk_data.u1.AddressOfData & IMAGE_ORDINAL_FLAG64) == 0:
                    # name import, fix.
                    thunk_data.u1.AddressOfData = get_fixed_rva(old_pe, bytes(new_exe_data), thunk_data.u1.AddressOfData, va_addr,
                                                                difference)
                new_exe_data = new_exe_data[:thunk_offset] + convert_pointer_to_bytes(<uintptr_t>thunk_data, sizeof(IMAGE_THUNK_DATA64)) + new_exe_data[
                                                                                    thunk_offset + sizeof(IMAGE_THUNK_DATA64):]
                thunk_offset += sizeof(IMAGE_THUNK_DATA64)
            import_descriptor.DUMMYUNIONNAME.OriginalFirstThunk = get_fixed_rva(old_pe, bytes(new_exe_data),
                                                                                import_descriptor.DUMMYUNIONNAME.OriginalFirstThunk,
                                                                                va_addr, difference)
            new_exe_data = new_exe_data[:imports_offset] + convert_pointer_to_bytes(<uintptr_t>import_descriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR)) + new_exe_data[
                                                                                        imports_offset + sizeof(
                                                                                            IMAGE_IMPORT_DESCRIPTOR):]
            imports_offset += sizeof(IMAGE_IMPORT_DESCRIPTOR)

    resource_offset = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress
    if resource_offset != 0:
        resource_rva = resource_offset
        resource_offset = old_pe.get_offset_from_rva(resource_offset)
        fixup_resource_directory(resource_offset, resource_rva, resource_offset, old_exe_data, old_pe, new_exe_data, va_addr, difference)
        # Fixup the resources directory
    # now process .NET heaps.
    metadata_offset = old_pe.get_offset_from_rva(dotnetpe.get_metadata_dir().get_net_header().MetaData.VirtualAddress)
    streams_offset = metadata_offset + 12
    number_of_streams = metadata_offset + 12
    number_of_streams_bytes = old_exe_data[number_of_streams:number_of_streams + 4]
    length_of_str = int.from_bytes(number_of_streams_bytes, 'little')
    streams_offset += length_of_str + 6
    number_of_streams = int.from_bytes(old_exe_data[streams_offset:streams_offset + 2], 'little')
    streams_offset += 2
    passed_userstrings = False
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
            if stream_offset <= old_pe.get_offset_from_rva(va_addr) < (stream_offset + size):
                passed_userstrings = True
                # fix the size of user strings stream
                # append the stream data
                new_size = int.to_bytes(size + difference, 4, 'little')
                new_exe_data = new_exe_data[:orig_offset + 4] + new_size + new_exe_data[orig_offset + 8:]
            elif passed_userstrings:
                # fix the offset of the rest of the streams
                new_offset = int.to_bytes(offset + difference, 4, 'little')
                new_exe_data = new_exe_data[:orig_offset] + new_offset + new_exe_data[orig_offset + 4:]

    if amt_padding_needed != 0 and padding_offset != 0:
        padding = b'\x00' * amt_padding_needed
        new_exe_data = new_exe_data[:padding_offset] + padding + new_exe_data[padding_offset:]
    PyBuffer_Release(&old_exe_view)
    return bytes(new_exe_data)

cpdef bytes apply_pe_fixups(dotnetpefile.PeFile old_pe, bytes old_exe_data, int va_addr, int difference, dotnetpefile.DotNetPeFile dotnetpe, bint in_streams):
    """
    Fix PE VAs to account for added data.
    NOTE: Execute this function first, then patch in the new data.
    :param old_pe: A pefile.PE object that matches old_exe_data
    :param old_exe_data: The old exe's data
    :param va_addr: The RVA where the added data was appended
    :param difference: The amount of added data
    :param old_streams: a Streams object matching the old exe.
    :return: The new binary data, with updated VAs accounting for new data.
    #FIXME: Account for subtracting data - since this is going to be really complicated im just going to pad the exe
    At worst that will result in a binary of a larger size, at best a binary of the same size.
    """

    if difference == 0:
        return old_exe_data
    
    if difference < 0:
        raise net_exceptions.InvalidArgumentsException()
    # goal of this method is to replace the vas without adding any data.
    # first fixup the PE headers, then deal with COM and net metadata
    is_64bit = old_pe.is_64bit()

    if is_64bit:
        return apply_pe_fixups_64(old_pe, old_exe_data, va_addr, difference, dotnetpe, in_streams)
    else:
        return apply_pe_fixups_32(old_pe, old_exe_data, va_addr, difference, dotnetpe, in_streams)

cdef unsigned int get_fixed_rva(dotnetpefile.PeFile old_pe, bytes new_data, int addr, int old_userstrings_va, int userstrings_difference):
    """
    Fix an RVA accounting for new data
    :param old_pe: the old pefile.PE object
    :param new_data: the current new data
    :param addr: The RVA to fix
    :param old_userstrings_va: The RVA where the new data was inserted
    :param userstrings_difference: The amount of data added
    :return: A new RVA that accounts for new data.
    """
    cdef IMAGE_SECTION_HEADER old_section
    cdef bint passed_text = False
    cdef IMAGE_SECTION_HEADER target_section
    cdef IMAGE_SECTION_HEADER section
    cdef Py_buffer exe_data_view
    cdef IMAGE_DOS_HEADER * dos_header
    cdef IMAGE_NT_HEADERS32 * nt_headers
    cdef IMAGE_SECTION_HEADER * section_header
    cdef int difference
    cdef int x
    cdef bint found_old_section = False
    cdef bint found_target_section = False
    cdef unsigned int section_offset
    cdef IMAGE_SECTION_HEADER * new_section = NULL

    if addr == 0:
        return 0

    # first get the section of the OLD VA
    passed_text = False
    for section in old_pe.get_sections():
        if section.VirtualAddress <= old_userstrings_va < (section.VirtualAddress + section.Misc.VirtualSize):
            target_section = section
            found_target_section = True
            break

    if not found_target_section:
        raise net_exceptions.InvalidVirtualAddressException

    for section in old_pe.get_sections():
        if section.VirtualAddress <= addr < (section.VirtualAddress + section.Misc.VirtualSize):
            old_section = section
            found_old_section = True
        if memcmp(section.Name, target_section.Name, 8) == 0:
            passed_text = True
    if not found_old_section:
        raise net_exceptions.InvalidVirtualAddressException

    if not passed_text and memcmp(old_section.Name, target_section.Name, 8) != 0:
        return addr  # we don't need to change it here
    if memcmp(old_section.Name, target_section.Name, 8) == 0:
        # check if were past the userstrings va
        if old_userstrings_va <= addr:
            return addr + userstrings_difference
        return addr

    # any other section, add the old and new section difference
    PyObject_GetBuffer(new_data, &exe_data_view, PyBUF_ANY_CONTIGUOUS)
    dos_header = <IMAGE_DOS_HEADER*>(<uintptr_t>exe_data_view.buf)
    nt_headers = <IMAGE_NT_HEADERS32*>(<uintptr_t>exe_data_view.buf + dos_header.e_lfanew)
    section_offset = dos_header.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + nt_headers.FileHeader.SizeOfOptionalHeader
    for x in range(nt_headers.FileHeader.NumberOfSections):
        section_header = <IMAGE_SECTION_HEADER*>(<uintptr_t>exe_data_view.buf + section_offset)
        if memcmp(section_header.Name, old_section.Name, 8) == 0:
            new_section = section_header
            break
        section_offset += sizeof(IMAGE_SECTION_HEADER)
    
    if not new_section:
        PyBuffer_Release(&exe_data_view)
        raise net_exceptions.InvalidVirtualAddressException

    difference = new_section.VirtualAddress - old_section.VirtualAddress
    PyBuffer_Release(&exe_data_view)
    return addr + difference
