#cython: language_level=3
#distutils: language=c++


from dotnetutils import net_exceptions
from dotnetutils cimport net_tokens
from dotnetutils cimport net_structs
from dotnetutils cimport dotnetpefile
from dotnetutils cimport net_row_objects
from libc.stdint cimport uintptr_t
from cpython.bytes cimport PyBytes_FromStringAndSize


cdef bytes convert_pointer_to_bytes(uintptr_t address, unsigned long size):
    return PyBytes_FromStringAndSize(<char*>address, <Py_ssize_t>size)