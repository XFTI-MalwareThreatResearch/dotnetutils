#cython: language_level=3
#distutils: language=c++

from dotnetutils import net_exceptions
from dotnetutils cimport dotnetpefile
from dotnetutils cimport net_metadata
from dotnetutils cimport net_processing
from libc.stdint cimport uintptr_t, uint32_t
from libc.string cimport memcmp
from dotnetutils.net_structs cimport IMAGE_SECTION_HEADER, IMAGE_RESOURCE_DATA_ENTRY, IMAGE_FILE_HEADER, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS32, IMAGE_RESOURCE_DIRECTORY_ENTRY, IMAGE_RESOURCE_DIRECTORY

cpdef void insert_blank_userstrings(dotnetpefile.DotNetPeFile dotnetpe):
    """ Inserts a blank user strings stream (#US) into the dotnetpe.

    Args:
        dotnetpe (dotnetpefile.DotNetPeFile): the dotnetpe to add to.
    """
    cdef net_metadata.MetaDataDirectory mdir = dotnetpe.get_metadata_dir()
    mdir.metadata_header.num_streams += 1
    mdir.metadata_header.add_stream_header(b'#US', 1)
    mdir.heaps['#US'] = net_processing.UserStringsHeapObject(-1, 0, b'#US', dotnetpe)

cdef void fixup_resource_directory(uint32_t rs_offset, uint32_t rs_rva, uint32_t orig_rs_offset, dotnetpefile.PeFile old_pe, Py_buffer new_exe_view, uint32_t va_addr, int difference, uint32_t target_addr):
    """ Fixups offsets relating to the PE's resource directory.  This method is mostly used internally.
    """
    cdef IMAGE_RESOURCE_DIRECTORY * rsrc_dir = NULL
    cdef uint32_t usable_rs_offset = rs_offset + sizeof(IMAGE_RESOURCE_DIRECTORY)
    cdef int x
    cdef IMAGE_RESOURCE_DIRECTORY_ENTRY * sub_entry = NULL
    cdef uint32_t r_offset
    cdef uint32_t rva
    cdef uint32_t fixed_rva
    cdef IMAGE_RESOURCE_DATA_ENTRY * data_struct = NULL
    rsrc_dir = <IMAGE_RESOURCE_DIRECTORY*>(<uintptr_t>new_exe_view.buf + <uintptr_t>rs_offset)
    for x in range(rsrc_dir.NumberOfNamedEntries + rsrc_dir.NumberOfIdEntries):
        sub_entry = <IMAGE_RESOURCE_DIRECTORY_ENTRY*> (<uintptr_t>new_exe_view.buf + <uintptr_t>usable_rs_offset)
        if sub_entry.OffsetToData.OffsetToDirectory.DataIsDirectory:
            r_offset = orig_rs_offset + sub_entry.OffsetToData.OffsetToDirectory.OffsetToDirectory
            fixup_resource_directory(r_offset, rs_rva, orig_rs_offset, old_pe, new_exe_view, va_addr, difference, target_addr)
        else:
            r_offset = orig_rs_offset + sub_entry.OffsetToData.OffsetToData
            data_struct = <IMAGE_RESOURCE_DATA_ENTRY*>(<uintptr_t>new_exe_view.buf + <uintptr_t>r_offset)
            rva = data_struct.OffsetToData
            fixed_rva = get_fixed_rva(old_pe, new_exe_view, rva, va_addr, difference, target_addr)
            data_struct.OffsetToData = <uint32_t>fixed_rva
        usable_rs_offset += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)

cdef uint32_t get_fixed_rva(dotnetpefile.PeFile old_pe, Py_buffer exe_data_view, uint32_t addr, uint32_t old_userstrings_va, int userstrings_difference, uint32_t target_addr):
    """ Take an RVA, and obtain its "fixed" value.  The fixed value of an RVA is the RVA after accounting for the amount of bytes that will be added or subtracted by an operation.
    """
    cdef IMAGE_SECTION_HEADER old_section
    cdef bint passed_text = False
    cdef IMAGE_SECTION_HEADER target_section
    cdef IMAGE_SECTION_HEADER section
    cdef IMAGE_DOS_HEADER * dos_header
    cdef IMAGE_NT_HEADERS32 * nt_headers
    cdef IMAGE_SECTION_HEADER * section_header
    cdef int difference = 0
    cdef int x = 0
    cdef bint found_old_section = False
    cdef bint found_target_section = False
    cdef unsigned int section_offset = 0
    cdef IMAGE_SECTION_HEADER * new_section = NULL
    if addr == 0 or old_userstrings_va > addr:
        return addr

    # first get the section of the OLD VA
    passed_text = False
    for section in old_pe.get_sections():
        if section.VirtualAddress <= target_addr < (section.VirtualAddress + section.Misc.VirtualSize):
            target_section = section
            found_target_section = True
            break

    if not found_target_section:
        #could not find target section.
        raise net_exceptions.InvalidVirtualAddressException(addr)

    for section in old_pe.get_sections():
        if section.VirtualAddress <= addr < (section.VirtualAddress + section.Misc.VirtualSize):
            old_section = section
            found_old_section = True
            break
        if memcmp(section.Name, target_section.Name, 8) == 0:
            passed_text = True
    if not found_old_section:
        raise net_exceptions.InvalidVirtualAddressException(addr)

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
        raise net_exceptions.InvalidVirtualAddressException(addr)
    difference = new_section.VirtualAddress - old_section.VirtualAddress
    return addr + difference
