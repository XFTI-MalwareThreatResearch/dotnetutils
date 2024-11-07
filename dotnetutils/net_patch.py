import ctypes
import pefile
from dotnetutils import net_exceptions
from dotnetutils.net_structs import COMIMAGE_FLAGS_NATIVE_ENTRYPOINT, IMAGE_BASE_RELOCATION, \
    IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_RESOURCE, IMAGE_DOS_HEADER, \
    IMAGE_COR20_HEADER, IMAGE_FILE_HEADER, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64, \
    IMAGE_NT_OPTIONAL_HDR64_MAGIC, IMAGE_ORDINAL_FLAG32, IMAGE_ORDINAL_FLAG64, IMAGE_RESOURCE_DATA_ENTRY, \
    IMAGE_RESOURCE_DIRECTORY, IMAGE_RESOURCE_DIRECTORY_ENTRY, IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA, \
    IMAGE_SCN_CNT_UNINITIALIZED_DATA, IMAGE_SECTION_HEADER, IMAGE_THUNK_DATA32, IMAGE_THUNK_DATA64, IMAGE_DIRECTORY_ENTRY_DEBUG, \
    IMAGE_DEBUG_DIRECTORY

def insert_blank_userstrings(dotnetpe, exe_data):
    """
    Patches a binary to insert a blank #US Stream
    Some obfuscators dont have any strings so theres no #US.
    FIXME: binaries patched by this method are currently unable to be executed.
    """
    new_exe_data = bytearray(exe_data)
    dos_header = IMAGE_DOS_HEADER.from_buffer_copy(exe_data, 0)
    nt_headers = IMAGE_NT_HEADERS32.from_buffer_copy(exe_data, dos_header.e_lfanew)
    if nt_headers.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        nt_headers = IMAGE_NT_HEADERS64.from_buffer_copy(exe_data, dos_header.e_lfanew)

    metadata_offset = dotnetpe.get_pe().get_offset_from_rva(dotnetpe.get_metadata_dir().get_net_header().MetaData.VirtualAddress)
    streams_offset = metadata_offset + 12
    number_of_streams = metadata_offset + 12
    number_of_streams = exe_data[number_of_streams:number_of_streams + 4]
    length_of_str = int.from_bytes(number_of_streams, 'little')
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
        
    new_exe_data = apply_pe_fixups(dotnetpe.get_pe(), new_exe_data, dotnetpe.get_pe().get_rva_from_offset(new_header_offset), len(new_streamheader), dotnetpe, False)
    new_exe_data = new_exe_data[:new_header_offset] + new_streamheader + new_exe_data[new_header_offset:]
    new_data_offset = us_offset + metadata_offset + len(new_streamheader)
    new_pe = pefile.PE(data=new_exe_data)
    new_data_va = new_pe.get_rva_from_offset(new_data_offset)
    new_exe_data = apply_pe_fixups(new_pe, new_exe_data, new_data_va, 1, dotnetpe, False)
    new_exe_data = new_exe_data[:new_data_offset] + bytes([0]) + new_exe_data[new_data_offset:]
    stream_amt_offset = streams_offset - 2
    new_exe_data = new_exe_data[:stream_amt_offset] + int.to_bytes(number_of_streams + 1, 2, 'little') + new_exe_data[stream_amt_offset + 2:]
    return new_exe_data    


def apply_pe_fixups(old_pe, old_exe_data, va_addr, difference, dotnetpe, in_streams=True):
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
    new_exe_data = bytearray(old_exe_data)
    if difference == 0:
        return new_exe_data
    
    if difference < 0:
        raise net_exceptions.InvalidArgumentsException()
    # goal of this method is to replace the vas without adding any data.
    # first fixup the PE headers, then deal with COM and net metadata
    dos_header = IMAGE_DOS_HEADER.from_buffer_copy(old_exe_data, 0)
    nt_headers = IMAGE_NT_HEADERS32.from_buffer_copy(old_exe_data, dos_header.e_lfanew)
    is_64bit = False
    if nt_headers.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        nt_headers = IMAGE_NT_HEADERS64.from_buffer_copy(old_exe_data, dos_header.e_lfanew)
        is_64bit = True

    section_offset = dos_header.e_lfanew + ctypes.sizeof(
        IMAGE_FILE_HEADER) + 4 + nt_headers.FileHeader.SizeOfOptionalHeader
    passed_target_section = False
    prev_section_header = None
    target_rawsize_difference = 0
    amt_padding_needed = 0
    padding_offset = 0
    size_of_code = 0
    size_of_initialized_data = 0
    size_of_uninitialized_data = 0
    section_header = None
    for _ in range(nt_headers.FileHeader.NumberOfSections):
        section_header = IMAGE_SECTION_HEADER.from_buffer_copy(old_exe_data, section_offset)
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

        new_exe_data = new_exe_data[:section_offset] + bytes(section_header) + new_exe_data[
                                                                               section_offset + ctypes.sizeof(
                                                                                   section_header):]
        prev_section_header = section_header
        section_offset += ctypes.sizeof(section_header)
    size_of_image = section_header.VirtualAddress + section_header.Misc.VirtualSize
    size_of_image += (nt_headers.OptionalHeader.SectionAlignment - (
                size_of_image % nt_headers.OptionalHeader.SectionAlignment))
    # once the sections are fixed, fix the optional header
    nt_headers.OptionalHeader.AddressOfEntryPoint = get_fixed_rva(old_pe, new_exe_data,
                                                                  nt_headers.OptionalHeader.AddressOfEntryPoint,
                                                                  va_addr, difference)
    for x in range(nt_headers.OptionalHeader.NumberOfRvaAndSizes):
        data_dir = nt_headers.OptionalHeader.DataDirectory[x]
        if data_dir.VirtualAddress != 0:
            data_dir.VirtualAddress = get_fixed_rva(old_pe, new_exe_data, data_dir.VirtualAddress, va_addr, difference)
    nt_headers.OptionalHeader.SizeOfCode = size_of_code
    nt_headers.OptionalHeader.SizeOfInitializedData = size_of_initialized_data
    nt_headers.OptionalHeader.SizeOfUninitializedData = size_of_uninitialized_data
    nt_headers.OptionalHeader.SizeOfImage = size_of_image
    nt_headers.OptionalHeader.BaseOfCode = get_fixed_rva(old_pe, new_exe_data, nt_headers.OptionalHeader.BaseOfCode,
                                                         va_addr, difference)
    if not is_64bit:
        nt_headers.OptionalHeader.BaseOfData = get_fixed_rva(old_pe, new_exe_data, nt_headers.OptionalHeader.BaseOfData,
                                                            va_addr, difference)
    # paste in the optional header
    optional_offset = dos_header.e_lfanew + 4 + ctypes.sizeof(IMAGE_FILE_HEADER)
    optional_end_offset = optional_offset + nt_headers.FileHeader.SizeOfOptionalHeader
    new_exe_data = new_exe_data[:optional_offset] + bytes(nt_headers.OptionalHeader)[
                                                    :nt_headers.FileHeader.SizeOfOptionalHeader] + new_exe_data[
                                                                                                   optional_end_offset:]

    # now for the COR20 header.
    net_header_offset = dotnetpe.get_metadata_dir().get_net_header().get_file_offset()
    cor_header = IMAGE_COR20_HEADER.from_buffer_copy(old_exe_data, net_header_offset)
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
    new_exe_data = new_exe_data[:net_header_offset] + bytes(cor_header) + new_exe_data[
                                                                          net_header_offset + ctypes.sizeof(
                                                                              IMAGE_COR20_HEADER):]
    nt_headers = IMAGE_NT_HEADERS32.from_buffer_copy(old_exe_data, dos_header.e_lfanew)
    if nt_headers.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        nt_headers = IMAGE_NT_HEADERS64.from_buffer_copy(old_exe_data, dos_header.e_lfanew)
    # now process the reloc dir
    reloc_va = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
    reloc_size = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size
    if reloc_va != 0:
        reloc_offset = old_pe.get_offset_from_rva(reloc_va)
        offset = 0
        while offset < reloc_size:
            base_reloc = IMAGE_BASE_RELOCATION.from_buffer_copy(old_exe_data, reloc_offset + offset)
            base_reloc.VirtualAddress = get_fixed_rva(old_pe, new_exe_data, base_reloc.VirtualAddress, va_addr,
                                                      difference)
            new_exe_data = new_exe_data[:reloc_offset + offset] + bytes(base_reloc) + new_exe_data[
                                                                                      reloc_offset + offset + ctypes.sizeof(
                                                                                          IMAGE_BASE_RELOCATION):]
            offset += ctypes.sizeof(IMAGE_BASE_RELOCATION) + base_reloc.BlockSize

    #process debug dir
    debug_va = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress
    if debug_va != 0:
        debug_offset = old_pe.get_offset_from_rva(debug_va)
        debug_struct = IMAGE_DEBUG_DIRECTORY.from_buffer_copy(old_exe_data, debug_offset)
        current_va = debug_struct.AddressOfRawData
        new_va = get_fixed_rva(old_pe, new_exe_data, current_va, va_addr, difference)
        if current_va != new_va:
            debug_struct.AddressOfRawData = new_va
            debug_struct.PointerToRawData += difference
            new_exe_data = new_exe_data[:debug_offset] + bytes(debug_struct) + new_exe_data[debug_offset + ctypes.sizeof(IMAGE_DEBUG_DIRECTORY):]

    # now process imports dir
    imports_offset = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
    if imports_offset != 0:
        imports_offset = old_pe.get_offset_from_rva(imports_offset)

        while True:
            import_descriptor = IMAGE_IMPORT_DESCRIPTOR.from_buffer_copy(old_exe_data, imports_offset)
            if import_descriptor.Name == 0:
                break
            orig_name = import_descriptor.Name
            import_descriptor.Name = get_fixed_rva(old_pe, new_exe_data, import_descriptor.Name, va_addr, difference)
            IMAGE_THUNK_DATA = IMAGE_THUNK_DATA32
            IMAGE_ORDINAL_FLAG = IMAGE_ORDINAL_FLAG32
            thunk_offset = old_pe.get_offset_from_rva(import_descriptor.FirstThunk)
            if old_pe.OPTIONAL_HEADER.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC:
                IMAGE_THUNK_DATA = IMAGE_THUNK_DATA64
                IMAGE_ORDINAL_FLAG = IMAGE_ORDINAL_FLAG64
            while True:
                thunk_data = IMAGE_THUNK_DATA.from_buffer_copy(old_exe_data, thunk_offset)
                if thunk_data.u1.AddressOfData == 0:
                    break
                if (thunk_data.u1.AddressOfData & IMAGE_ORDINAL_FLAG) == 0:
                    # name import, fix.
                    thunk_data.u1.AddressOfData = get_fixed_rva(old_pe, old_exe_data, thunk_data.u1.AddressOfData, va_addr,
                                                                difference)
                new_exe_data = new_exe_data[:thunk_offset] + bytes(thunk_data) + new_exe_data[
                                                                                    thunk_offset + ctypes.sizeof(thunk_data):]
                thunk_offset += ctypes.sizeof(IMAGE_THUNK_DATA)
            import_descriptor.FirstThunk = get_fixed_rva(old_pe, old_exe_data, import_descriptor.FirstThunk, va_addr,
                                                            difference)

            thunk_offset = old_pe.get_offset_from_rva(import_descriptor.DUMMYUNIONNAME.OriginalFirstThunk)
            while True:
                thunk_data = IMAGE_THUNK_DATA.from_buffer_copy(old_exe_data, thunk_offset)
                if thunk_data.u1.AddressOfData == 0:
                    break
                if (thunk_data.u1.AddressOfData & IMAGE_ORDINAL_FLAG) == 0:
                    # name import, fix.
                    thunk_data.u1.AddressOfData = get_fixed_rva(old_pe, new_exe_data, thunk_data.u1.AddressOfData, va_addr,
                                                                difference)
                new_exe_data = new_exe_data[:thunk_offset] + bytes(thunk_data) + new_exe_data[
                                                                                    thunk_offset + ctypes.sizeof(thunk_data):]
                thunk_offset += ctypes.sizeof(IMAGE_THUNK_DATA)
            import_descriptor.DUMMYUNIONNAME.OriginalFirstThunk = get_fixed_rva(old_pe, new_exe_data,
                                                                                import_descriptor.DUMMYUNIONNAME.OriginalFirstThunk,
                                                                                va_addr, difference)
            new_exe_data = new_exe_data[:imports_offset] + bytes(import_descriptor) + new_exe_data[
                                                                                        imports_offset + ctypes.sizeof(
                                                                                            import_descriptor):]
            imports_offset += ctypes.sizeof(IMAGE_IMPORT_DESCRIPTOR)

    resource_offset = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress
    if resource_offset != 0:
        resource_rva = resource_offset
        resource_offset = old_pe.get_offset_from_rva(resource_offset)

        def fixup_resource_data(rsd_offset):
            """
            Performs the required modifications on a IMAGE_RESOURCE_DATA_ENTRY structure.
            :param rsd_offset: the offset of the IMAGE_RESOURCE_DATA_ENTRY structure
            """
            nonlocal old_exe_data
            nonlocal old_pe
            nonlocal new_exe_data
            nonlocal va_addr
            nonlocal difference
            data_struct = IMAGE_RESOURCE_DATA_ENTRY.from_buffer_copy(old_exe_data, rsd_offset)
            rva = data_struct.OffsetToData
            fixed_rva = get_fixed_rva(old_pe, new_exe_data, rva, va_addr, difference)
            data_struct.OffsetToData = fixed_rva
            new_exe_data = new_exe_data[:rsd_offset] + bytes(data_struct) + new_exe_data[rsd_offset + ctypes.sizeof(
                IMAGE_RESOURCE_DATA_ENTRY):]

        # Fixup the resources directory
        def fixup_resource_directory(rs_offset, rs_rva, orig_rs_offset):
            """
            Finds and fixes structures related to an image's resource directory.
            :param rs_offset: the offset to the directory
            :param rs_rva: the rva of the resource dir
            :param orig_rs_offset: the original resource offset
            """
            nonlocal old_exe_data
            nonlocal old_pe
            nonlocal new_exe_data
            nonlocal va_addr
            nonlocal difference
            rsrc_dir = IMAGE_RESOURCE_DIRECTORY.from_buffer_copy(old_exe_data, rs_offset)
            usable_rs_offset = rs_offset + ctypes.sizeof(IMAGE_RESOURCE_DIRECTORY)
            for _ in range(rsrc_dir.NumberOfNamedEntries + rsrc_dir.NumberOfIdEntries):
                sub_entry = IMAGE_RESOURCE_DIRECTORY_ENTRY.from_buffer_copy(old_exe_data, usable_rs_offset)
                if sub_entry.OffsetToData.OffsetToDirectory.DataIsDirectory:
                    r_offset = orig_rs_offset + sub_entry.OffsetToData.OffsetToDirectory.OffsetToDirectory
                    fixup_resource_directory(r_offset, rs_rva, orig_rs_offset)
                else:
                    r_offset = orig_rs_offset + sub_entry.OffsetToData.OffsetToData
                    fixup_resource_data(r_offset)
                new_exe_data = new_exe_data[:usable_rs_offset] + bytes(sub_entry) + new_exe_data[
                                                                                    usable_rs_offset + ctypes.sizeof(
                                                                                        IMAGE_RESOURCE_DIRECTORY_ENTRY):]
                usable_rs_offset += ctypes.sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)

        fixup_resource_directory(resource_offset, resource_rva, resource_offset)
    # now process .NET heaps.
    metadata_offset = old_pe.get_offset_from_rva(dotnetpe.get_metadata_dir().get_net_header().MetaData.VirtualAddress)
    streams_offset = metadata_offset + 12
    number_of_streams = metadata_offset + 12
    number_of_streams = old_exe_data[number_of_streams:number_of_streams + 4]
    length_of_str = int.from_bytes(number_of_streams, 'little')
    streams_offset += length_of_str + 6
    number_of_streams = int.from_bytes(old_exe_data[streams_offset:streams_offset + 2], 'little')
    streams_offset += 2
    passed_userstrings = False
    if in_streams:
        for _ in range(number_of_streams):
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
    return new_exe_data


def get_fixed_rva(old_pe, new_data, addr, old_userstrings_va, userstrings_difference):
    """
    Fix an RVA accounting for new data
    :param old_pe: the old pefile.PE object
    :param new_data: the current new data
    :param addr: The RVA to fix
    :param old_userstrings_va: The RVA where the new data was inserted
    :param userstrings_difference: The amount of data added
    :return: A new RVA that accounts for new data.
    """
    if addr == 0:
        return 0

    # first get the section of the OLD VA
    old_section = None
    passed_text = False
    target_section = None
    for section in old_pe.sections:
        if section.VirtualAddress <= old_userstrings_va < (section.VirtualAddress + section.Misc_VirtualSize):
            target_section = section
            break

    if not target_section:
        raise net_exceptions.InvalidVirtualAddressException

    for section in old_pe.sections:
        if section.VirtualAddress <= addr < (section.VirtualAddress + section.Misc_VirtualSize):
            old_section = section
        if section.Name == target_section.Name:
            passed_text = True
    if not old_section:
        raise net_exceptions.InvalidVirtualAddressException

    if not passed_text and old_section.Name != target_section.Name:
        return addr  # we don't need to change it here

    if old_section.Name == target_section.Name:
        # check if were past the userstrings va
        if old_userstrings_va <= addr:
            return addr + userstrings_difference
        return addr

    # any other section, add the old and new section difference
    dos_header = IMAGE_DOS_HEADER.from_buffer_copy(new_data, 0)
    nt_headers = IMAGE_NT_HEADERS32.from_buffer_copy(new_data, dos_header.e_lfanew)
    if nt_headers.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        nt_headers = IMAGE_NT_HEADERS64.from_buffer_copy(new_data, dos_header.e_lfanew)
    section_offset = dos_header.e_lfanew + 4 + ctypes.sizeof(
        IMAGE_FILE_HEADER) + nt_headers.FileHeader.SizeOfOptionalHeader
    new_section = None
    for _ in range(nt_headers.FileHeader.NumberOfSections):
        section_header = IMAGE_SECTION_HEADER.from_buffer_copy(new_data, section_offset)
        if bytes(section_header.Name) == old_section.Name:
            new_section = section_header
            break
        section_offset += ctypes.sizeof(IMAGE_SECTION_HEADER)

    if not new_section:
        raise net_exceptions.InvalidVirtualAddressException

    difference = new_section.VirtualAddress - old_section.VirtualAddress
    return addr + difference
