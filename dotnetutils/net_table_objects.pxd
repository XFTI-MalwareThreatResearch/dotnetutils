#cython: language_level=3
#distutils: language=c++


from dotnetutils cimport base, net_row_objects, net_structs
from libcpp.vector cimport vector
from cpython.ref cimport PyObject

cdef class TableObject:
    cdef vector[PyObject*] rows
    cdef str name
    cdef int tid
    cdef base.DotNetUtilsBaseType dotnetpe

    cdef list as_list(self)

    cpdef net_row_objects.RowObject get(self, int index)

    cdef void add_row(self, net_row_objects.RowObject row)

    cpdef bint has_index(self, int index)
        
    cdef void process(self)

    cdef void post_process(self)

    cpdef bytes to_bytes(self)

    cpdef str get_name(self)
    
    cpdef int get_tid(self)

cdef class MetadataTableHeader:
    cdef int start_offset
    cdef int reserved
    cdef int majorversion
    cdef int minorversion
    cdef int heapoffsetsizes_orig
    cdef int heapoffsetsizes_curr
    cdef int reserved2
    cdef unsigned long long valid
    cdef unsigned long long __sorted
    cdef list table_amt_rows
    cdef int end_offset
    cdef unsigned int extra_data_size
    cdef base.DotNetUtilsBaseType dotnetpe

    cdef void parse_table_header(self, bytes file_data)

    cpdef bytes to_bytes(self)

    cpdef void set_heap_offset_size(self, net_structs.CorHeapBitmask bitmask, int new_size)

    cpdef str get_heap_name_from_bitmask(self, net_structs.CorHeapBitmask bitmask)

    cpdef int get_heap_offset_size(self, net_structs.CorHeapBitmask bitmask)

cdef class TypeDefTable(TableObject):

    cpdef net_row_objects.TypeDef get_type_by_full_name(self, bytes full_name)

    cpdef list get_types_by_name(self, bytes name)

cdef class ClassLayoutTable(TableObject):

    cpdef net_row_objects.RowObject get_layout_by_parent(self, int parent)


cdef class MethodDefTable(TableObject):

    cpdef list get_methods_by_name(self, bytes name)

    cdef void post_process(self)

cdef class FieldRVATable(TableObject):
    cpdef net_row_objects.RowObject get_by_field_rid(self, int field_rid)

cdef class TypeRefTable(TableObject):

    cpdef net_row_objects.TypeRef get_type_by_full_name(self, bytes name)

cdef class MethodImplTable(TableObject):
    cdef dict __method_dict

    cdef void post_process(self)

    cpdef net_row_objects.MethodDefOrRef get_method_body(self, net_row_objects.MethodDefOrRef method_obj)

    cpdef bint is_method_in_table(self, net_row_objects.RowObject method_obj)
    
    cpdef net_row_objects.MethodDef get_method_definition(self, net_row_objects.RowObject method_obj, net_row_objects.TypeDef class_obj)
    
cdef class MethodSemanticsTable(TableObject):

    cpdef list get_semantics_for_item(self, net_row_objects.RowObject item)
    
    cpdef bint is_method_in_table(self, net_row_objects.RowObject method)

cdef class PropertyMapTable(TableObject):

    cpdef list get_properties_for_parent(self, net_row_objects.RowObject parent)
    
    cpdef net_row_objects.RowObject get_parent_for_property(self, net_row_objects.RowObject prop)

cdef class MemberRefTable(TableObject):

    cpdef net_row_objects.MemberRef get_ref_by_name(self, bytes name)

cdef dict NET_METADATA_TABLE_HANDLERS
cdef dict NET_METADATA_TABLE_TYPES

cpdef str get_table_name_from_id(int identifier)

cpdef int get_table_id_from_name(str name)

cdef int get_single_table_index_size(int table_id, list row_amt_list)

cdef int get_multiple_table_index_size(list potential_table_ids, list row_amt_list, int bits_used)