#cython: language_level=3

from dotnetutils cimport dotnetpefile, net_utils, net_cil_disas, net_tokens, net_table_objects, net_structs

cdef bytes get_cor_type_name(net_structs.CorElementType element_type)

cdef class RowObject:
    cdef dotnetpefile.DotNetPeFile dotnetpe
    cdef int rid
    cdef int file_offset
    cdef dict values
    cdef str table_name
    cdef list sizes

    cpdef ColumnValue get_column(self, str col_name) except *
    
    cpdef list get_sizes(self)

    cpdef dotnetpefile.DotNetPeFile get_dotnetpe(self)

    cpdef int get_rid(self) except *

    cpdef str get_table_name(self)

    cpdef int get_token(self) except *

    cpdef int get_file_offset(self)

    cpdef bint has_value(self, str val_name)

    cpdef int get_offset_to_col(self, str col_name)

    #cpdef int get_col_size(self, str col_name)

    cdef void process(self)

    cdef void post_process(self)

    cpdef bytes to_bytes(self)

    cdef void initialize_columns(self)

cdef class ColumnValue:
    cdef unsigned int col_size
    cdef unsigned int raw_value
    cdef str col_name
    cdef RowObject row_obj
    cdef net_tokens.BaseToken col_type
    cdef object formatted_value
    cdef object changed_value
    cdef object cached_value
    cdef dotnetpefile.DotNetPeFile dotnetpe
    cdef object original_value
    cdef object __formatter_param
    cdef object __formatter_method
    cdef bint __has_no_value

    cdef bytes get_value_as_bytes(self)

    cdef int get_value_as_int(self)

    cdef RowObject get_value_as_rowobject(self)

    cpdef void set_formatter_method(self, formatter_method, formatter_param)

    cdef int internal_get_size(self) except *

    cpdef object get_original_value(self)

    cpdef void change_value(self, object new_value)
    
    cdef object __retrieve_value(self)
    
    cpdef bint has_value(self)

    cpdef object get_value(self) except *

    cpdef void set_formatted_value(self, object value)

    cpdef object get_formatted_value(self) except *

    cpdef object get_changed_value(self)

    cpdef unsigned int get_raw_value(self) except *
    
    cpdef bint was_value_changed(self)
    
    cpdef void set_raw_value(self, unsigned int new_value)

    cpdef str get_value_table_name(self)
        
    cpdef tuple get_value_location(self)

    cpdef int get_value_rid(self)
        
    cpdef bytes to_bytes(self)

    cpdef net_tokens.BaseToken get_col_type(self)

cdef class TypeDefOrRef(RowObject):

    cpdef MethodDef get_cctor_method(self)

    cpdef TypeDef get_enclosing_type(self)

    cpdef RowObject get_classlayout_obj(self)

    cpdef TypeDefOrRef get_superclass(self)

    cpdef list get_interfaces(self)

    cpdef list get_child_classes(self)

    cpdef void _add_child_class(self, TypeDefOrRef obj)

    cpdef list get_member_refs(self)

    cpdef list get_generic_params(self)

    cpdef bint is_valuetype(self)

    cdef void process(self)

    cpdef list get_methods(self)

    cdef void post_process(self)

    cpdef bytes get_full_name(self)

    cpdef bytes get_class_path(self)

    cpdef Field get_field(self, bytes name)

    cpdef list get_methods_by_name(self, bytes name)

    cpdef TypeDefOrRef get_type(self)

cdef class TypeDef(TypeDefOrRef):
    cdef RowObject __classlayout_obj
    cdef list __interfaces
    cdef list __child_classes
    cdef public list _memberrefs
    cdef public list _generic_params
    cdef bytes __full_name
    cdef TypeDef __enclosing_type
    cdef bint __has_enclosing_type
    cdef TypeDefOrRef __superclass
    cdef bint __has_superclass
    cdef bint __has_interfaces
    cdef bint __is_valuetype
    cdef MethodDef __cctor_method

    cpdef MethodDef get_cctor_method(self)

    cpdef TypeDef get_enclosing_type(self)

    cpdef RowObject get_classlayout_obj(self)

    cpdef TypeDefOrRef get_superclass(self)

    cpdef list get_interfaces(self)

    cpdef list get_child_classes(self)

    cpdef void _add_child_class(self, TypeDefOrRef obj)

    cpdef list get_member_refs(self)

    cpdef list get_generic_params(self)

    cpdef bint is_valuetype(self)

    cdef void process(self)

    cpdef list get_methods(self)

    cdef void post_process(self)

    cpdef bytes get_full_name(self)

    cpdef bytes get_class_path(self)

    cpdef Field get_field(self, bytes name)

    cpdef list get_methods_by_name(self, bytes name)

cdef class Field(RowObject):
    cdef RowObject __rva_object
    cdef int __class_size
    cdef TypeDefOrRef __parent_type
    cdef object __sig_obj
    cdef TypeDefOrRef __field_type
    cdef list __xrefs

    cpdef list get_xrefs(self)

    cpdef void _add_xref(self, int rid, int instr_index)

    cpdef void _set_parent_type(self, TypeDefOrRef parent_type)

    cpdef TypeDefOrRef get_parent_type(self)

    cdef void process(self)

    cpdef net_utils.FieldSig get_field_signature(self)

    cdef void post_process(self)

    cdef void __initialize_sig(self)

    cpdef bint is_static(self)

    cpdef bytes get_data(self)

cdef class TypeRef(TypeDefOrRef):
    cdef list __methods
    cdef list __child_classes
    cdef list __interfaces
    cdef bytes __full_name
    cdef public list _memberrefs
    cdef TypeDefOrRef __superclass
    cdef MethodDef __cctor_method

    cpdef list get_member_refs(self)

    cpdef TypeDefOrRef get_superclass(self)

    cpdef list get_interfaces(self)

    cpdef void _add_child_class(self, TypeDefOrRef obj)

    cpdef list get_child_classes(self)

    cdef void process(self)

    cpdef list get_methods(self)

    cpdef list get_methods_by_name(self, bytes method_name)

    cpdef MethodDef get_cctor_method(self)

    cpdef bytes get_full_name(self)

cdef class MethodDefOrRef(RowObject):

    cpdef net_cil_disas.MethodDisassembler disassemble_method(self, bint no_save=*, bint original=*)

    cpdef bytes get_original_method_data(self)

    cpdef list get_xrefs(self)

    cpdef void _add_xref(self, int rid, int instr_index)

    cpdef void _set_parent_type(self, TypeDefOrRef parent_type)

    cpdef bint is_abstract(self)

    cdef void process(self)

    cdef void post_process(self)

    cpdef list get_param_types(self)

    cpdef bytes get_full_name(self)
    
    cpdef bint is_virtual(self)

    cpdef bint is_hidebysig(self)

    cpdef bint is_static_method(self)

    cpdef net_utils.MethodBaseSig get_method_signature(self)

    cpdef bint is_entrypoint(self)

    cpdef bint is_static_constructor(self)

    cpdef bint is_constructor(self)

    cpdef bytes get_method_data(self)

    cpdef bint has_body(self)

    cpdef TypeDefOrRef get_parent_type(self)

    cpdef bint has_return_value(self)

    cpdef bint method_has_this(self)

    cpdef int get_amt_params(self)

cdef class MethodDef(MethodDefOrRef):
    cdef public list _generic_params
    cdef bytes __full_name
    cdef bytes __current_method_hash
    cdef TypeDefOrRef __parent_type
    cdef bint __has_return_value
    cdef bint __method_has_this
    cdef net_utils.MethodSig __sig_obj
    cdef net_cil_disas.MethodDisassembler __disasm_obj
    cdef bint __has_invalid_signature
    cdef list __xrefs

    cpdef net_cil_disas.MethodDisassembler disassemble_method(self, bint no_save=*, bint original=*)

    cpdef bytes get_original_method_data(self)

    cpdef list get_xrefs(self)

    cpdef void _add_xref(self, int rid, int instr_index)

    cpdef void _set_parent_type(self, TypeDefOrRef parent_type)

    cpdef bint is_abstract(self)

    cdef void process(self)

    cdef void post_process(self)

    cpdef list get_param_types(self)

    cpdef bytes get_full_name(self)
    
    cpdef bint is_virtual(self)

    cpdef bint is_hidebysig(self)

    cpdef bint is_static_method(self)

    cpdef net_utils.MethodBaseSig get_method_signature(self)

    cpdef bint is_entrypoint(self)

    cpdef bint is_static_constructor(self)

    cpdef bint is_constructor(self)

    cpdef bytes get_method_data(self)

    cpdef bint has_body(self)

    cpdef TypeDefOrRef get_parent_type(self)

    cpdef bint has_return_value(self)

    cpdef bint method_has_this(self)

    cpdef int get_amt_params(self)

cdef class MemberRef(MethodDefOrRef):
    cdef bytes __full_name
    cdef TypeDefOrRef __parent_type
    cdef net_utils.MethodBaseSig __sig_obj
    cdef bint __method_has_this
    cdef bint __method_has_this_called
    cdef bint __is_field
    cdef bint __is_method
    cdef bint __method_has_return
    cdef bint __method_has_return_called
    cdef list __xrefs

    cpdef TypeDefOrRef get_parent_type(self)

    cpdef MethodDef get_method_impl(self)

    cpdef void _set_parent_type(self, TypeDefOrRef parent_type)

    cdef void post_process(self)

    cpdef bint is_field(self)
    
    cpdef bint is_method(self)

    cpdef bint is_hidebysig(self)
    
    cpdef bytes get_full_name(self)

    cpdef bint has_return_value(self)

    cpdef list get_param_types(self)

    cpdef bint method_has_this(self)

    cpdef int get_amt_params(self)

    cpdef net_utils.MethodBaseSig get_method_signature(self)

    cpdef list get_xrefs(self)

    cpdef void _add_xref(self, int rid, int instr_index)

    cpdef bint is_static_method(self)

cdef class GenericParam(RowObject):

    cdef void process(self)

cdef class MethodSpec(MethodDefOrRef):
    cdef object __parsed_sig
    cdef list __xrefs

    cpdef MethodDefOrRef get_method(self)
    
    cpdef bytes get_full_name(self)

    cpdef net_utils.MethodSig get_sig_obj(self)

    cpdef list get_xrefs(self)
    
    cpdef void _add_xref(self, int rid, int instr_index)


cdef class TypeSpec(TypeDefOrRef):
    cdef net_utils.TypeSig __parsed_sig
    cdef bint __has_invalid_signature

    cpdef void _add_child_class(self, TypeDefOrRef to_add)

    cpdef TypeDefOrRef get_type(self)
    
    cpdef bytes get_full_name(self)
    
    cpdef list get_methods(self)

    cpdef list get_member_refs(self)

    cpdef TypeDefOrRef get_superclass(self)

    cpdef net_utils.TypeSig get_sig_obj(self)
    
cdef class StandAloneSig(RowObject):
    cdef net_utils.TypeSig __parsed_sig
    cdef bint __has_invalid_signature
    cpdef net_utils.TypeSig get_sig_obj(self)

cdef class MethodImpl(RowObject):
    cdef RowObject __class
    cdef RowObject __declaration
    cdef MethodDef __body

    cpdef RowObject get_class(self)
    
    cpdef RowObject get_declaration(self)
    
    cpdef MethodDef get_body(self)
    
cdef class MethodSemantic(RowObject):
    
    cpdef MethodDef get_method(self)
    
    cpdef RowObject get_assocciation(self)
    
    cpdef bint is_setter(self)
    
    cpdef bint is_getter(self)

    cpdef bint is_other(self)
    
    cpdef bint is_add_on(self)
    
    cpdef bint is_remove_on(self)
    
    cpdef bint is_fire(self)
    
    
cdef class PropertyMap(RowObject):
        
    cdef void process(self)

    cpdef RowObject get_parent(self)
    
    cpdef list get_properties(self)


cdef get_rowobject_for_table(str table_id)