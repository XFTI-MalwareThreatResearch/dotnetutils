#cython: language_level=3
#distutils: language=c++

from dotnetutils cimport dotnetpefile
from libc.stdint cimport uint64_t

cdef uint64_t get_fixed_rva(dotnetpefile.PeFile old_pe, Py_buffer exe_data_view, uint64_t addr, uint64_t old_userstrings_va, int userstrings_difference, uint64_t target_addr)

cpdef bytes insert_blank_userstrings(dotnetpefile.DotNetPeFile dotnetpe)

cdef void fixup_resource_directory(uint64_t rs_offset, uint64_t rs_rva, uint64_t orig_rs_offset, dotnetpefile.PeFile old_pe, Py_buffer new_exe_view, uint64_t va_addr, int difference, uint64_t target_addr)
