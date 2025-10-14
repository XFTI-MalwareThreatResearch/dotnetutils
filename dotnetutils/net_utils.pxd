#cython: language_level=3
#distutils: language=c++

from dotnetutils cimport dotnetpefile
from dotnetutils cimport net_structs
from dotnetutils cimport net_row_objects
from dotnetutils cimport net_sigs
from libc.stdint cimport uintptr_t
from dotnetutils.net_structs cimport CorElementType

cdef bytes convert_pointer_to_bytes(uintptr_t address, unsigned long size)

cdef int get_size_of_cortype(CorElementType cor_type, bint is_64bit)

cdef bytes get_cor_type_name(net_structs.CorElementType element_type)

cpdef net_sigs.CorLibTypeSig get_cor_type_from_name(bytes type_name)

cdef bint is_cortype_number(CorElementType etype)

cdef bint is_cortype_signed(CorElementType etype)

cdef bint is_cortype_unsigned(CorElementType etype)