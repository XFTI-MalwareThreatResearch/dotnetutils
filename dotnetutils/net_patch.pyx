#cython: language_level=3
#distutils: language=c++

from dotnetutils import net_exceptions
from dotnetutils cimport dotnetpefile
from dotnetutils.net_utils cimport convert_pointer_to_bytes
from cpython.buffer cimport PyObject_GetBuffer, PyBuffer_Release, PyBUF_ANY_CONTIGUOUS
from libc.stdint cimport uintptr_t, uint64_t, uint32_t
from libc.string cimport memcmp, memcpy

import hashlib

from cpython.bytes cimport PyBytes_FromStringAndSize

from dotnetutils.net_structs cimport IMAGE_SECTION_HEADER, IMAGE_SCN_CNT_CODE, IMAGE_OPTIONAL_HEADER32, COMIMAGE_FLAGS_NATIVE_ENTRYPOINT, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_DEBUG, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_ORDINAL_FLAG32, IMAGE_ORDINAL_FLAG64, IMAGE_DIRECTORY_ENTRY_RESOURCE, IMAGE_OPTIONAL_HEADER64, IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_CNT_UNINITIALIZED_DATA, IMAGE_DATA_DIRECTORY, IMAGE_RESOURCE_DATA_ENTRY, IMAGE_FILE_HEADER, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64, IMAGE_RESOURCE_DIRECTORY_ENTRY, IMAGE_RESOURCE_DIRECTORY, IMAGE_DATA_DIRECTORY, IMAGE_IMPORT_DESCRIPTOR, IMAGE_COR20_HEADER, IMAGE_BASE_RELOCATION, IMAGE_THUNK_DATA32, IMAGE_THUNK_DATA64, IMAGE_DEBUG_DIRECTORY

cdef bytes insert_blank_userstrings32(dotnetpefile.DotNetPeFile dotnetpe):
    """
    NOTE: After running this method, dotnetpe will be stale.  Theres ways to fix this but they have downsides.
    In general, you should reinitialize the dotnetpe with the newly returned data.
    """
    cdef bytearray new_exe_data
    cdef uint64_t metadata_offset
    cdef uint64_t streams_offset
    cdef int number_of_streams
    cdef int length_of_str
    cdef uint64_t current_offset
    cdef int x
    cdef bytes name
    cdef int us_size
    cdef uint64_t new_header_offset
    cdef uint64_t us_offset
    cdef bytes new_streamheader
    cdef uint64_t new_stream_offset
    cdef uint64_t new_data_va
    cdef uint64_t stream_amt_offset
    cdef uint64_t new_data_offset
    cdef bytes number_of_streams_bytes
    cdef bytes exe_data = dotnetpe.get_pe().get_file_data()
    new_exe_data = bytearray(exe_data)

    metadata_offset = dotnetpe.get_pe().get_offset_from_rva(dotnetpe.get_metadata_dir().get_net_header().MetaData.VirtualAddress)
    streams_offset = metadata_offset + 12
    number_of_streams = <int>(metadata_offset + 12)
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
    amt_to_align = (4 - ((current_offset + 12) % 4))
    new_streamheader += b'\x00' * amt_to_align
    new_streamheader = int.to_bytes(us_offset + len(new_streamheader), 4, 'little') + new_streamheader[4:]
    #fix the offsets of streamhaeders
    current_offset = streams_offset
    for x in range(number_of_streams):
        stream_offset = int.from_bytes(exe_data[current_offset:current_offset+4], 'little')
        new_stream_offset = stream_offset + <int>len(new_streamheader)
        new_exe_data = new_exe_data[:current_offset] + int.to_bytes(new_stream_offset, 4, 'little') + new_exe_data[current_offset + 4:]
        current_offset += 8
        while new_exe_data[current_offset] != 0:
            current_offset += 1
        current_offset += (4 - (current_offset % 4))
    dotnetpe.get_pe().update_va(dotnetpe.get_pe().get_rva_from_offset(new_header_offset), <int>len(new_streamheader), dotnetpe, True, False)
    new_exe_data = bytearray(dotnetpe.get_exe_data())
    new_exe_data = new_exe_data[:new_header_offset] + new_streamheader + new_exe_data[new_header_offset:]
    dotnetpe.set_exe_data(bytes(new_exe_data))
    new_data_offset = us_offset + metadata_offset + <int>len(new_streamheader)
    new_data_va = dotnetpe.get_pe().get_rva_from_offset(new_data_offset)
    dotnetpe.get_pe().update_va(new_data_va, 1, dotnetpe, True, False)
    new_exe_data = bytearray(dotnetpe.get_exe_data())
    new_exe_data = new_exe_data[:new_data_offset] + bytes([0]) + new_exe_data[new_data_offset:]
    stream_amt_offset = streams_offset - 2
    new_exe_data = new_exe_data[:stream_amt_offset] + int.to_bytes(number_of_streams + 1, 2, 'little') + new_exe_data[stream_amt_offset + 2:]
    return bytes(new_exe_data)

cdef bytes insert_blank_userstrings64(dotnetpefile.DotNetPeFile dotnetpe):
    cdef bytearray new_exe_data
    cdef Py_buffer exe_data_view
    cdef IMAGE_DOS_HEADER * dos_header
    cdef IMAGE_NT_HEADERS64 * nt_headers
    cdef uint64_t metadata_offset
    cdef uint64_t streams_offset
    cdef int number_of_streams
    cdef int length_of_str
    cdef uint64_t current_offset
    cdef int x
    cdef bytes name
    cdef int us_size
    cdef uint64_t new_header_offset
    cdef uint64_t us_offset
    cdef bytes new_streamheader
    cdef uint64_t new_stream_offset
    cdef uint64_t new_data_va
    cdef uint64_t stream_amt_offset
    cdef uint64_t new_data_offset
    cdef bytes number_of_streams_bytes
    cdef bytes exe_data = dotnetpe.get_pe().get_file_data()
    new_exe_data = bytearray(exe_data)
    PyObject_GetBuffer(new_exe_data, &exe_data_view, PyBUF_ANY_CONTIGUOUS)
    dos_header = <IMAGE_DOS_HEADER*>exe_data_view.buf
    nt_headers = <IMAGE_NT_HEADERS64*>(<uintptr_t>exe_data_view.buf + dos_header.e_lfanew)

    metadata_offset = dotnetpe.get_pe().get_offset_from_rva(dotnetpe.get_metadata_dir().get_net_header().MetaData.VirtualAddress)
    streams_offset = metadata_offset + 12
    number_of_streams = <int>(metadata_offset + 12)
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
        new_stream_offset = stream_offset + <int>len(new_streamheader)
        new_exe_data = new_exe_data[:current_offset] + int.to_bytes(new_stream_offset, 4, 'little') + new_exe_data[current_offset + 4:]
        current_offset += 8
        while new_exe_data[current_offset] != 0:
            current_offset += 1
        current_offset += (4 - (current_offset % 4))
    PyBuffer_Release(&exe_data_view)
    #At this point we dont need exe_Data_view
    dotnetpe.get_pe().update_va(dotnetpe.get_pe().get_rva_from_offset(new_header_offset), <int>len(new_streamheader), dotnetpe, False, False)
    new_exe_data = bytearray(dotnetpe.get_exe_data())
    new_exe_data = new_exe_data[:new_header_offset] + new_streamheader + new_exe_data[new_header_offset:]
    dotnetpe.set_exe_data(bytes(new_exe_data))
    new_data_offset = us_offset + metadata_offset + <int>len(new_streamheader)
    new_data_va = dotnetpe.get_pe().get_rva_from_offset(new_data_offset)
    dotnetpe.get_pe().update_va(new_data_va, 1, dotnetpe, False, False)
    new_exe_data = bytearray(dotnetpe.get_exe_data())
    new_exe_data = new_exe_data[:new_data_offset] + bytes([0]) + new_exe_data[new_data_offset:]
    stream_amt_offset = streams_offset - 2
    new_exe_data = new_exe_data[:stream_amt_offset] + int.to_bytes(number_of_streams + 1, 2, 'little') + new_exe_data[stream_amt_offset + 2:]
    return bytes(new_exe_data)

cpdef bytes insert_blank_userstrings(dotnetpefile.DotNetPeFile dotnetpe):
    """
    Patches a binary to insert a blank #US Stream
    Some obfuscators dont have any strings so theres no #US.
    FIXME: binaries patched by this method are currently unable to be executed.
    """
    if dotnetpe.get_pe().is_64bit():
        return insert_blank_userstrings64(dotnetpe)
    else:
        return insert_blank_userstrings32(dotnetpe)

cdef void fixup_resource_directory(uint64_t rs_offset, uint64_t rs_rva, uint64_t orig_rs_offset, dotnetpefile.PeFile old_pe, Py_buffer new_exe_view, uint64_t va_addr, int difference):
    """
    Finds and fixes structures related to an image's resource directory.
    :param rs_offset: the offset to the directory
    :param rs_rva: the rva of the resource dir
    :param orig_rs_offset: the original resource offset
    """
    cdef IMAGE_RESOURCE_DIRECTORY * rsrc_dir = NULL
    cdef uint64_t usable_rs_offset = rs_offset + sizeof(IMAGE_RESOURCE_DIRECTORY)
    cdef int x
    cdef IMAGE_RESOURCE_DIRECTORY_ENTRY * sub_entry = NULL
    cdef uint64_t r_offset
    cdef uint64_t rva
    cdef uint64_t fixed_rva
    cdef IMAGE_RESOURCE_DATA_ENTRY * data_struct = NULL
    rsrc_dir = <IMAGE_RESOURCE_DIRECTORY*>(<uintptr_t>new_exe_view.buf + <uintptr_t>rs_offset)
    for x in range(rsrc_dir.NumberOfNamedEntries + rsrc_dir.NumberOfIdEntries):
        sub_entry = <IMAGE_RESOURCE_DIRECTORY_ENTRY*> (<uintptr_t>new_exe_view.buf + <uintptr_t>usable_rs_offset)
        if sub_entry.OffsetToData.OffsetToDirectory.DataIsDirectory:
            r_offset = orig_rs_offset + sub_entry.OffsetToData.OffsetToDirectory.OffsetToDirectory
            fixup_resource_directory(r_offset, rs_rva, orig_rs_offset, old_pe, new_exe_view, va_addr, difference)
        else:
            r_offset = orig_rs_offset + sub_entry.OffsetToData.OffsetToData
            data_struct = <IMAGE_RESOURCE_DATA_ENTRY*>(<uintptr_t>new_exe_view.buf + <uintptr_t>r_offset)
            rva = data_struct.OffsetToData
            fixed_rva = get_fixed_rva(old_pe, new_exe_view, rva, va_addr, difference)
            data_struct.OffsetToData = <uint32_t>fixed_rva
        usable_rs_offset += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)

cdef uint64_t get_fixed_rva(dotnetpefile.PeFile old_pe, Py_buffer exe_data_view, uint64_t addr, uint64_t old_userstrings_va, int userstrings_difference):
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
    cdef IMAGE_DOS_HEADER * dos_header
    cdef IMAGE_NT_HEADERS32 * nt_headers
    cdef IMAGE_SECTION_HEADER * section_header
    cdef int difference
    cdef int x
    cdef bint found_old_section = False
    cdef bint found_target_section = False
    cdef unsigned int section_offset
    cdef IMAGE_SECTION_HEADER * new_section = NULL

    if addr == 0 or old_userstrings_va >= addr:
        return addr

    # first get the section of the OLD VA
    passed_text = False
    for section in old_pe.get_sections():
        if not found_target_section and section.VirtualAddress <= old_userstrings_va < (section.VirtualAddress + section.Misc.VirtualSize):
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
        raise net_exceptions.InvalidVirtualAddressException
    difference = new_section.VirtualAddress - old_section.VirtualAddress
    return addr + difference
