#cython: language_level=3
#distutils: language=c++
from dotnetutils cimport net_metadata
from dotnetutils cimport net_row_objects
from dotnetutils cimport net_table_objects
from dotnetutils cimport net_processing

from cpython.buffer cimport Py_buffer
from libc.stdint cimport uintptr_t, uint64_t, int64_t, uint32_t
from dotnetutils.net_structs cimport IMAGE_RESOURCE_DIRECTORY, IMAGE_DATA_DIRECTORY, IMAGE_COR20_HEADER, IMAGE_SECTION_HEADER, IMAGE_RESOURCE_DIRECTORY_ENTRY

cdef class PeFile:
    cdef list __sections
    cdef uint64_t  __image_base
    cdef unsigned int __nt_headers_offset
    cdef bint __is_64bit
    cdef bytearray __file_data
    cdef Py_buffer __file_view

    cpdef bint is_64bit(self)

    cpdef bint is_dll(self)

    cdef void __parse(self) except *

    cdef void __parse_64(self)

    cdef void __add_section(self, IMAGE_SECTION_HEADER * sec_hdr)

    cdef void __parse_32(self)
    
    cpdef uint32_t get_offset_from_rva(self, uint32_t rva)

    cpdef uint32_t get_rva_from_offset(self, uint32_t offset)

    cpdef IMAGE_DATA_DIRECTORY get_directory_by_idx(self, unsigned int idx)

    cpdef list get_sections(self)

    cpdef int get_elfanew(self)

    cdef uintptr_t get_data_view(self)

    cpdef bytes get_file_data(self)

    cpdef uint32_t get_physical_by_rva(self, uint32_t rva)

    cdef int get_sec_index_va(self, uint32_t va_addr)

    cdef int get_sec_index_phys(self, uint32_t offset)

    cpdef IMAGE_COR20_HEADER get_net_header(self)

cdef class DotNetPeFile:
    cdef str __versioninfo_str
    cdef str file_path
    cdef bytes exe_data
    cdef net_metadata.MetaDataDirectory metadata_dir
    cdef bytes original_exe_data
    cdef PeFile pe
    cdef bint raise_exc_on_invalid_method

    cdef void process_metadata_heap(self, bint dont_process)

    cdef bint should_raise_exc_on_invalid_method(self)

    cdef uint32_t __get_offset_from_memview(self, Py_buffer view_obj, uint32_t rva)

    cdef uint32_t __get_rva_from_memview(self, Py_buffer view_obj, uint32_t offset)
    
    cpdef void reinit_dpe(self, bint no_processing)

    cpdef void update_streams(self)

    cpdef uint32_t get_cor_header_offset(self)

    cpdef net_row_objects.MethodDef get_entry_point(self)

    cpdef list get_user_string_usages(self, unsigned long us_index)

    cpdef net_row_objects.TypeRef get_typeref_by_full_name(self, bytes full_name)

    cpdef int delete_user_string(self, unsigned int us_index)

    cpdef net_row_objects.TypeDefOrRef get_type_by_full_name(self, bytes type_full_name)

    cpdef list get_types_by_name(self, bytes type_name)

    cpdef bytes get_resource_by_name(self, bytes name)

    cpdef list get_exported_types(self)

    cpdef list get_resources(self)
    
    cpdef bint has_string(self, bytes string)

    cpdef bint has_user_string(self, bytes string)

    cpdef list get_strings(self)

    cpdef list get_user_strings(self)

    cpdef bint has_heap(self, str name)

    cpdef dict get_heaps(self)

    cpdef net_processing.HeapObject get_heap(self, str name)

    cpdef bint has_metadata_table(self, str name)

    cpdef void patch_instruction(self, net_row_objects.MethodDef method_obj, bytes patch_bytes, unsigned long instr_offset, unsigned long orig_size) except *

    cpdef net_table_objects.TableObject get_metadata_table(self, str name)

    cpdef list get_methods_by_full_name(self, bytes full_name)

    cpdef net_row_objects.MethodDef get_method_by_rid(self, int rid)

    cpdef list get_methods_by_name(self, bytes name)

    cpdef int get_processor_bits(self)

    cpdef object get_token_value(self, unsigned long token)

    cpdef PeFile get_pe(self)

    cpdef void set_exe_data(self, bytes exe_data)

    cpdef void add_string(self, str string) except *

    cpdef net_metadata.MetaDataDirectory get_metadata_dir(self)

    cpdef bytes get_exe_data(self)

    cpdef bytes get_original_exe_data(self)

    cpdef str get_product_version(self)

    cpdef void set_entry_point(self, unsigned int ep_token)

cpdef DotNetPeFile try_get_dotnetpe(str file_path=*, bytes pe_data=*, bint dont_process=*)