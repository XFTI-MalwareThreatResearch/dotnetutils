#cython: language_level=3
#distutils: language=c++
from dotnetutils.dotnetpefile cimport DotNetPeFile, PeFile
from libc.stdint cimport uint32_t

cdef class NetRebuilder:
    cdef DotNetPeFile __dpefile
    cdef PeFile __pe

    cdef bytes rebuild(self)

    cdef size_t __build_imports32(self, DotNetPeFile dotnet, bytearray result, uint32_t rva)

    cdef size_t __build_stub32(self, DotNetPeFile dotnet, bytearray result, uint32_t imports_offset, uint32_t image_base)

    cdef dict __build_net_heaps(self, bytearray result, dict method_rvas, dict field_rvas, list heaps_order)

    cdef size_t __build_net_resources(self, bytearray result, uint32_t rva)

    cdef size_t __build_net_headers(self, bytearray result, uint32_t rva, uint32_t metadata_rva, uint32_t metadata_size)
    
    cdef size_t __build_relocations_directory32(self, bytearray result, uint32_t stub_reloc_rva)

    cdef size_t __build_resource_directory64(self, bytearray result, uint32_t resource_offset)
    
    cdef size_t __build_relocations_directory64(self, bytearray result, uint32_t relocations_offset)

    cdef size_t __build_stub64(self, DotNetPeFile dotnet, bytearray result, uint32_t imports_offset)

    cdef dict __build_method_data(self, bytearray result, uint32_t methods_rva)

    cdef dict __build_fieldrva_data(self, bytearray result, uint32_t fieldrva_rva)

    cdef bytes __rebuild_64(self)

    cdef bytes __rebuild_32(self)
