#cython: language_level=3
#distutils: language=c++
from dotnetutils.dotnetpefile import DotNetPeFile
from dotnetutils.net_structs import IMAGE_DOS_HEADER, IMAGE_NT_HEADERS32, IMAGE_NT_OPTIONAL_HDR64_MAGIC, IMAGE_FILE_HEADER, IMAGE_SECTION_HEADER
from dotnetutils.net_structs import IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_EXECUTE, IMAGE_DIRECTORY_ENTRY_IMPORT
from libc.string cimport memcmp, memset, memcpy
from dotnetutils.net_utils import align_32



cdef class NetRebuilder:
    def __init__(self, DotNetPeFile dpe):
        self.__dpefile = dpe
        self.__pe = self.__dpefile.get_pe()


    cdef bytes __rebuild_64(self):
        pass

    cdef bytes __rebuild_32(self):
        cdef bytes orig_data = self.__dpefile.get_exe_data()
        cdef IMAGE_DOS_HEADER * dos_header = <IMAGE_DOS_HEADER*>self.__pe.get_data_view()
        cdef IMAGE_NT_HEADERS32 * nt_headers = <IMAGE_NT_HEADERS32*>((<char*>)dos_header) + dos_header.e_lfanew
        cdef size_t opt_header_offset = dos_header.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER)
        cdef IMAGE_SECTION_HEADER sect_header
        cdef bytearray result = bytearray()
        cdef size_t current_sect_raw_size = 0
        result.extend(orig_data[:dos_header.e_lfanew])
        result.extend(b'PE\x00\x00')
        result.extend(orig_data[dos_header.e_lfanew + 4: dos_header.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER)])
        result.extend(orig_data[opt_header_offset: opt_header_offset + nt_headers.FileHeader.SizeOfOptionalHeader])
        memset(&sect_header, 0, sizeof(IMAGE_SECTION_HEADER))
        sect_header.Name = b'.text\x00\x00\x00'
        sect_header.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXEUTE
        sect_header.PointerToRawData = align_32(<uint32_t>len(result), nt_headers.OptionalHeader.FileAlignment)
        result.extend(b'\x00' * (sect_header.PointerToRawData - len(result)))
        
        
        

        





    cdef bytes rebuild(self):
        cdef bytearray data = bytearray()
        cdef IMAGE_DOS_HEADER * dos_header = <IMAGE_DOS_HEADER*>self.__pe.get_data_view()
        cdef IMAGE_NT_HEADERS32 * nt_headers = <IMAGE_NT_HEADERS32*>((<char*>)dos_header) + dos_header.e_lfanew
        if nt_headers.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            return self.__rebuild_64()
        return self.__rebuild_32()

