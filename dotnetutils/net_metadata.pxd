#cython: language_level=3
#distutils: language=c++

from dotnetutils cimport dotnetpefile, net_table_objects, net_processing
from dotnetutils.net_structs cimport IMAGE_COR20_HEADER
from libc.stdint cimport uint64_t


cdef class MetaDataHeader:
    """
    Represents the header at the beginning of the section where .NET stores metadata.
    """
    cdef int start_offset
    cdef int signature
    cdef int majorversion
    cdef int minorversion
    cdef int reserved
    cdef int versionstr_length
    cdef bytes versionstr
    cdef int flags
    cdef int num_streams
    cdef list streamheaders
    cdef int end_offset
    cdef dotnetpefile.DotNetPeFile dotnetpe

    cdef void parse_metadata_header(self, bytes file_data)

    cpdef bytes to_bytes(self)

    cdef list get_stream_headers(self)

cdef class MetaDataDirectory:
    """
    Represents the metadata directory.   
    """
    cdef dotnetpefile.DotNetPeFile dotnetpe
    cdef IMAGE_COR20_HEADER net_header
    cdef uint64_t net_header_offset
    cdef MetaDataHeader metadata_header
    cdef net_table_objects.MetadataTableHeader metadata_table_header
    cdef dict heaps
    cdef int metadata_heap_size
    cdef int metadata_file_offset
    cdef int metadata_file_size
    cdef bint is_valid_directory

    cdef bint __validate_stream_not_there(self, str name)

    cdef bint process_directory(self, bytes file_data) except *
    cdef void process_metadata_heap(self, bint dont_process)
    cpdef net_table_objects.MetadataTableHeader get_metadata_table_header(self)
    cpdef net_processing.HeapObject get_heap(self, str name)
    cpdef dict get_heaps(self)
    cpdef int get_metadata_heap_size(self)
    cpdef IMAGE_COR20_HEADER get_net_header(self)
