#cython: language_level=3
from dotnetutils cimport net_row_objects

cdef class BaseToken:
    cdef bint __is_stream
    cdef bint __is_fixed_value
    cdef int __fixed_size
    cdef list __token_types

    cpdef bint is_stream(self)

    cpdef bint is_fixed_value(self)

    cpdef int get_fixed_size(self)

    cpdef list get_token_types(self)
    
cdef class CodedToken(BaseToken):
    cdef int bits
    cdef int mask

    cpdef tuple decode_token(self, int token)

    cpdef int encode_token(self, net_row_objects.RowObject row_obj)

    cpdef str get_token_table(self, int token)

    cpdef int get_bits(self)

    cpdef int get_mask(self)

cdef class SingleTableCodedToken(BaseToken):
    cdef str table_name

    cpdef tuple decode_token(self, int token)


cdef class SignatureToken(BaseToken):

    cpdef tuple decode_token(self, int token)

    cpdef int encode_token(self, str table_name, int table_rid)

cpdef BaseToken get_TypeDefOrRef()

cpdef BaseToken get_HasConstant()

cpdef BaseToken get_HasCustomAttribute()

cpdef BaseToken get_HasFieldMarshal()

cpdef BaseToken get_HasDeclSecurity()

cpdef BaseToken get_MemberRefParent()

cpdef BaseToken get_HasSemantic()

cpdef BaseToken get_MethodDefOrRef()

cpdef BaseToken get_MemberForwarded()

cpdef BaseToken get_Implementation()

cpdef BaseToken get_CustomAttributeType()

cpdef BaseToken get_ResolutionScope()

cpdef BaseToken get_TypeOrMethodDef()

cpdef BaseToken get_HasCustomDebugInformation()

cpdef BaseToken get_StringsStream()

cpdef BaseToken get_UserStringsStream()

cpdef BaseToken get_BlobStream()

cpdef BaseToken get_GuidStream()

cpdef BaseToken get_MetadataStream()

cpdef BaseToken get_OneByteValue()

cpdef BaseToken get_TwoByteValue()

cpdef BaseToken get_FourByteValue()

cpdef BaseToken get_SingleTableIndex()

cpdef BaseToken get_Signature()
