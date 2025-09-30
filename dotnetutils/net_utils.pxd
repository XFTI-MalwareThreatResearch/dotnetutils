#cython: language_level=3
#distutils: language=c++


from dotnetutils cimport dotnetpefile
from dotnetutils cimport net_structs
from dotnetutils cimport net_row_objects
from libc.stdint cimport uintptr_t

cdef bytes convert_pointer_to_bytes(uintptr_t address, unsigned long size)