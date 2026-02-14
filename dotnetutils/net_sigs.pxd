#cython: language_level=3
#distutils: language=c++

from dotnetutils cimport net_structs, net_row_objects, base

cdef bint method_sig_compare(MethodBaseSig sig_one, MethodBaseSig sig_two, GenericInstMethodSig gensig, GenericInstSig gentypesig)

cdef bint type_sig_compare(TypeSig sig_one, TypeSig sig_two, GenericInstMethodSig gensig, GenericInstSig gentypesig)

cdef bint field_sig_compare(FieldSig sig_one, FieldSig sig_two, GenericInstMethodSig gensig, GenericInstSig gentypesig)

cdef class TypeSig:
    cdef net_structs.CorElementType __element_type

    cpdef net_structs.CorElementType get_element_type(self)

cdef class LeafSig(TypeSig):
    cdef TypeSig __next

    cpdef TypeSig get_next(self)

cdef class TypeDefOrRefSig(LeafSig):
    cdef net_row_objects.TypeDefOrRef __type_def_or_ref

    cpdef net_row_objects.TypeDefOrRef get_type(self)

cdef class CorLibTypeSig(TypeDefOrRefSig):
    pass

cdef class ClassOrValueTypeSig(TypeDefOrRefSig):
    pass

cdef class ValueTypeSig(ClassOrValueTypeSig):
    pass

cdef class ClassSig(ClassOrValueTypeSig):
    pass

cdef class GenericSig(LeafSig):
    cdef bint __is_type_var
    cdef int __number

    cpdef bint is_type_var(self)

    cpdef int get_number(self)

cdef class GenericVar(GenericSig):
    pass

cdef class GenericMVar(GenericSig):
    pass

cdef class SentinelSig(LeafSig):
    pass

cdef class FnPtrSig(LeafSig):
    cdef NonLeafSig __signature

    cpdef NonLeafSig get_signature(self)

cdef class GenericInstSig(LeafSig):
    cdef TypeSig __generic_type
    cdef int __gen_arg_count
    cdef list __generic_args

    cdef void add_generic_type(self, TypeSig obj)

    cpdef TypeSig get_generic_type(self)
    
    cpdef list get_generic_args(self)
    
    cpdef int get_generic_args_count(self)

cdef class NonLeafSig(TypeSig):
    cdef TypeSig __next_sig

    cpdef TypeSig get_next(self)

cdef class PtrSig(NonLeafSig):
    pass

cdef class ByRefSig(NonLeafSig):
    pass

cdef class ArraySigBase(NonLeafSig):
    pass

cdef class ArraySig(ArraySigBase):
    cdef int __rank
    cdef list __sizes
    cdef list __lower_bounds

    cpdef int get_rank(self)
    
    cpdef list get_sizes(self)
    
    cpdef list get_lower_bounds(self)

cdef class SZArraySig(ArraySigBase):
    cdef int __rank
    cdef list __sizes
    cdef list __lower_bounds

    cpdef int get_rank(self)
    
    cpdef list get_sizes(self)
    
    cpdef list get_lower_bounds(self)

cdef class ModifierSig(NonLeafSig):
    cdef net_row_objects.TypeDefOrRef __modifier

    cpdef net_row_objects.TypeDefOrRef get_modifier(self)

cdef class CModReqdSig(ModifierSig):
    pass

cdef class CModOptSig(ModifierSig):
    pass

cdef class PinnedSig(NonLeafSig):
    pass

cdef class ValueArraySig(NonLeafSig):
    cdef int __size

    cpdef int get_size(self)

cdef class ModuleSig(NonLeafSig):
    cdef int __index

    cpdef int get_index(self)

cdef class CallingConventionSig():
    cdef int __calling_conv
    cdef bytes __extra_data
    
    cpdef int get_calling_conv(self)
    
    cpdef bytes get_extra_data(self)

cdef class FieldSig(CallingConventionSig):
    cdef TypeSig __type_sig

    cpdef TypeSig get_type_sig(self)

cdef class MethodBaseSig(CallingConventionSig):
    cdef TypeSig __type_sig
    cdef list __parameters
    cdef int __gen_param_count
    cdef int __params_after_sentinel
    cdef TypeSig __return_type
    cdef base.DotNetUtilsBaseType dotnetpe
    cdef net_row_objects.MethodDef method

    cpdef TypeSig get_type_sig(self)
    
    cpdef list get_parameters(self)
    
    cpdef int get_generic_params_count(self)
    
    cpdef int get_params_after_sentinel(self)
    
    cpdef TypeSig get_return_type(self)

    cdef void setup_dotnetpe(self, base.DotNetUtilsBaseType dotnetpe, net_row_objects.RowObject method)

cdef class MethodSig(MethodBaseSig):
    cdef int __orig_token

    cpdef int get_orig_token(self)

cdef class PropertySig(MethodBaseSig):
    pass

cdef class LocalSig(CallingConventionSig):
    cdef list __local_vars

    cpdef list get_local_vars(self)

cdef class GenericInstMethodSig(CallingConventionSig):
    cdef list __generic_args

    cpdef list get_generic_args(self)

cdef class SignatureReader():
    cdef base.DotNetUtilsBaseType dotnetpe
    cdef net_structs.DotNetDataReader sig_io
    cdef int sig_type
    cdef int calling_conv
    cdef net_row_objects.RowObject reference
    cdef bint debug

    cpdef CallingConventionSig read_signature(self)

    cdef CallingConventionSig read_calling_convention_sig(self)

    cdef MethodSig handle_method_sig(self)

    cdef TypeSig handle_type_sig(self, bint read_first)

    cdef int read_integer_pointer(self)

    cdef FieldSig handle_field_sig(self)

    cdef LocalSig handle_local_sig(self)

    cdef PropertySig handle_property_sig(self)

    cdef GenericInstMethodSig handle_genericinst_sig(self)

    cdef bint is_generic(self)

    cdef int read_byte(self)

    cdef int read_compressed_integer(self)

    cdef net_row_objects.RowObject read_typedef_or_ref(self)

cpdef CorLibTypeSig get_CorSig_Void()

cpdef CorLibTypeSig get_CorSig_Boolean()

cpdef CorLibTypeSig get_CorSig_Char()

cpdef CorLibTypeSig get_CorSig_Void()

cpdef CorLibTypeSig get_CorSig_Byte()

cpdef CorLibTypeSig get_CorSig_SByte()

cpdef CorLibTypeSig get_CorSig_Int16()

cpdef CorLibTypeSig get_CorSig_UInt16()

cpdef CorLibTypeSig get_CorSig_Int32()

cpdef CorLibTypeSig get_CorSig_UInt32()

cpdef CorLibTypeSig get_CorSig_Int64()

cpdef CorLibTypeSig get_CorSig_UInt64()

cpdef CorLibTypeSig get_CorSig_Single()

cpdef CorLibTypeSig get_CorSig_Double()

cpdef CorLibTypeSig get_CorSig_String()

cpdef CorLibTypeSig get_CorSig_TypedReference()

cpdef CorLibTypeSig get_CorSig_IntPtr()

cpdef CorLibTypeSig get_CorSig_UIntPtr()

cpdef CorLibTypeSig get_CorSig_Object()