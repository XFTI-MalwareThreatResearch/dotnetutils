#cython: language_level=3
#distutils: language=c++

from dotnetutils cimport dotnetpefile
from dotnetutils cimport net_table_objects
from dotnetutils cimport net_row_objects
from libcpp.vector cimport vector
from cpython.ref cimport PyObject

cdef class HeapObject:
    cdef int offset
    cdef int size
    cdef bytes name
    cdef bytearray raw_data
    cdef bint in_append_tx
    cdef bytearray tx_data

    cdef void update_bitmask(self, int new_size)

    cpdef int get_next_append_index(self)

    cpdef void begin_append_tx(self)

    cpdef void end_append_tx(self)

    cpdef int append_tx(self, bytes item)

    cdef dotnetpefile.DotNetPeFile dotnetpe

    cdef bytes read_item(self, int offset)

    cdef void update_offset(self, int offset)
    
    cdef void update_size(self, int size)
    
    cdef void update(self, int old_value, int new_value, int difference)

    cpdef int get_offset_of_item(self, object item)

    cpdef bint is_offset_referenced(self, int offset)

    cdef bytes compress_integer(self, unsigned long number)

    cdef void read(self)

    cpdef bytes to_bytes(self)

    cdef dotnetpefile.DotNetPeFile get_dotnetpe(self)
    
    cpdef bytes get_name(self)

    cpdef int get_offset(self)

    cpdef int get_size(self)

    cpdef int replace_item(self, int offset, object item)
    
    cpdef int append_item(self, object item)

    cpdef object get_item(self, int offset)

    cpdef bint has_item(self, object item)

    cpdef bint has_offset(self, int offset)

    cpdef int del_item(self, int offset)

    cpdef list get_items(self)

cdef class StringHeapObject(HeapObject):
    cdef dict metadata_references
    cdef int amt_trailing_zeroes

    cdef void __build_metadata_references(self)

    cpdef bint has_offset(self, int offset)

    cdef void read(self)

    cpdef bytes to_bytes(self)

    cdef dotnetpefile.DotNetPeFile get_dotnetpe(self)
    
    cpdef bytes get_name(self)

    cpdef int get_offset(self)

    cpdef int get_size(self)

    cpdef int replace_item(self, int offset, object item)
    
    cpdef object get_item(self, int offset)

cdef class BlobHeapObject(HeapObject):
    cdef dict metadata_references

    cdef void __build_metadata_references(self)

cdef class GuidHeapObject(HeapObject):
    cdef dict metadata_references

    cdef void __build_metadata_references(self)

cdef class UserStringsHeapObject(HeapObject):
    cdef vector[PyObject*] methods
    cdef bint warned
    cdef int amt_trailing_zeroes

    cdef void _fill_methods(self)

    cdef bytes sanitize_input(self, bytes data)

    cdef void register_method(self, net_row_objects.MethodDef method)

cdef class MetadataTableHeapObject(HeapObject):
    cdef net_table_objects.MetadataTableHeader header
    cdef int end_offset
    cdef int amt_padding
    cdef dict items

    cpdef net_table_objects.MetadataTableHeader get_header(self)

    cpdef net_table_objects.TableObject get_table(self, str name)

    cdef void process_tables(self)

    cpdef bint has_table(self, str name)

    cpdef list present_tables(self)

    cpdef bytes to_bytes(self)

    cpdef dict get_tables(self)

    cpdef int get_start_offset(self)