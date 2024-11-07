#cython: language_level=3
from dotnetutils cimport dotnetpefile

cdef class Stream:
    cdef int offset
    cdef int size
    cdef bytes name
    cdef bytes data
    cdef dotnetpefile.DotNetPeFile dotnetpe

    cpdef bytes get_item(self, unsigned long index)

    cpdef void set_item(self, unsigned long index, bytes value)

    cpdef unsigned long del_item(self, unsigned long index)

    cpdef bytes get_name(self)

    cpdef bytes get_data(self)

    cpdef int get_offset(self)

    cpdef int get_size(self)

    cpdef Stream make_copy(self)

    cpdef Py_ssize_t find_index(self, bytes item)
    
    cpdef bint has_item(self, bytes item)

    cpdef dotnetpefile.DotNetPeFile get_dotnetpe(self)

cdef class StringStream(Stream):

    cpdef bytes get_item(self, unsigned long index)

    cpdef Py_ssize_t find_index(self, bytes item)

    cpdef unsigned long del_item(self, unsigned long index)

    cpdef list get_items(self)

    cpdef void set_item(self, unsigned long index, bytes value)

    cpdef unsigned long append_item(self, bytes value)

cdef class BlobStream(Stream):

    cpdef bytes get_item(self, unsigned long index)
        
    cpdef unsigned long del_item(self, unsigned long index)
    
    cpdef Py_ssize_t find_index(self, bytes item)

    cpdef unsigned long append_item(self, bytes raw_value)


cdef class GuidStream(Stream):
    cpdef bytes get_item(self, unsigned long index)

    cpdef unsigned long append_item(self, bytes raw_value)

    cpdef unsigned long del_item(self, unsigned long index)
    
    cpdef Py_ssize_t find_index(self, bytes item)


cdef class UserStringsStream(Stream):

    cpdef bytes get_item(self, unsigned long index)

    cpdef list get_items(self)

    cpdef unsigned long del_item(self, unsigned long index)

    cpdef unsigned long append_item(self, bytes bstring)

    cpdef unsigned long append_item_dns(self, object str_item)
    
    cpdef Py_ssize_t find_index(self, bytes item)
