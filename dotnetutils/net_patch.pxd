#cython: language_level=3
#distutils: language=c++

from dotnetutils cimport dotnetpefile
from libc.stdint cimport uint32_t

cdef uint32_t get_fixed_rva(dotnetpefile.PeFile old_pe, Py_buffer exe_data_view, uint32_t addr, uint32_t old_userstrings_va, int userstrings_difference, uint32_t target_addr)

cpdef void insert_blank_userstrings(dotnetpefile.DotNetPeFile dotnetpe)

cdef void fixup_resource_directory(uint32_t rs_offset, uint32_t rs_rva, uint32_t orig_rs_offset, dotnetpefile.PeFile old_pe, Py_buffer new_exe_view, uint32_t va_addr, int difference, uint32_t target_addr)
