#cython: language_level=3

"""
A lot of values in the MetaData tables are represented as tokens
Meaning they contain two values - a table and an RID.
This class can be used for decoding those tokens into readable values.
"""
from dotnetutils import net_exceptions
from dotnetutils cimport net_row_objects

cdef class BaseToken:
    def __init__(self, list token_types, bint is_stream, bint is_fixed_value, int fixed_size):
        self.__token_types = token_types
        self.__is_stream = is_stream
        self.__is_fixed_value = is_fixed_value
        self.__fixed_size = fixed_size

    cpdef bint is_stream(self):
        return self.__is_stream

    cpdef bint is_fixed_value(self):
        return self.__is_fixed_value

    cpdef int get_fixed_size(self):
        return self.__fixed_size

    cpdef list get_token_types(self):
        return self.__token_types

cdef class CodedToken(BaseToken):
    def __init__(self, int bits, list token_types, bint is_stream=False, bint is_fixed_value=False, int fixed_size=-1):
        BaseToken.__init__(self, token_types, is_stream, is_fixed_value, fixed_size)
        self.bits = bits
        self.mask = (1 << bits) - 1
        if len(self.get_token_types()) == 0 and not self.is_fixed_value():
            raise net_exceptions.InvalidTokenException('CodedToken', 0)

    cpdef tuple decode_token(self, unsigned int token):
        if self.is_stream():
            return self.get_token_types()[0], token
        elif self.is_fixed_value():
            return None, token
        else:
            rid = token >> self.bits
            index = (token & self.mask)
            try:
                return self.get_token_types()[index], rid
            except IndexError:
                raise net_exceptions.InvalidTokenException('CodedToken', token)

    cpdef int encode_token(self, net_row_objects.RowObject row_obj):
        index = self.get_token_types().index(row_obj.get_table_name())
        if index < 0:
            return -1
        coded_token = (row_obj.get_rid() << self.bits) | index
        return coded_token

    cpdef str get_token_table(self, unsigned int token):
        if self.is_stream():
            return self.get_token_types()[0]
        elif not self.is_fixed_value():
            index = (token & self.mask)
            try:
                return self.get_token_types()[index]
            except IndexError:
                raise net_exceptions.InvalidTokenException('CodedToken', token)
        return None

    cpdef int get_bits(self):
        return self.bits

    cpdef int get_mask(self):
        return self.mask

    def __eq__(self, obj: object) -> bool:
        if isinstance(obj, CodedToken):
            return self.get_mask() == obj.get_mask() and \
                   self.get_bits() == obj.get_bits() and self.is_stream() == obj.is_stream() and \
                   self.is_fixed_value() == obj.is_fixed_value() and self.get_token_types() == obj.get_token_types()
        return False
    
    def __str__(self):
        return 'CodedToken {}'.format(self.get_token_types())


cdef class SingleTableCodedToken(BaseToken):
    def __init__(self, str table_name):
        BaseToken.__init__(self, [table_name], False, False, -1)
        self.table_name = table_name

    cpdef tuple decode_token(self, unsigned int token):
        return self.table_name, token
    
    def __str__(self):
        return 'Single Table Token {}'.format(self.table_name)


cdef class SignatureToken(BaseToken):
    def __init__(self):
        BaseToken.__init__(self, list(), False, False, -1)

    cpdef tuple decode_token(self, unsigned int token):
        token_type = (token >> 24)
        token_val = (token & 0x00FFFFFF)
        if token_type == 0x11:
            return 'StandAloneSig', token_val
        elif token_type == 0x06:
            return 'MethodDef', token_val
        elif token_type == 0x04:
            return 'Field', token_val
        elif token_type == 0x0A:
            return 'MemberRef', token_val
        elif token_type == 0x1B:
            return 'TypeSpec', token_val
        elif token_type == 0x2B:
            return 'MethodSpec', token_val
        elif token_type == 0x70:
            return '#US', token_val
        elif token_type == 0x1:
            return 'TypeRef', token_val
        elif token_type == 0x2:
            return 'TypeDef', token_val
        raise net_exceptions.InvalidTokenException('SignatureToken', token)

    cpdef int encode_token(self, str table_name, int table_rid):
        if table_name == 'StandAloneSig':
            token_type = 0x11
        elif table_name == 'MethodDef':
            token_type = 0x06
        elif table_name == 'Field':
            token_type = 0x04
        elif table_name == 'MemberRef':
            token_type = 0x0A
        elif table_name == 'TypeSpec':
            token_type = 0x1B
        elif table_name == 'MethodSpec':
            token_type = 0x2B
        elif table_name == '#US':
            token_type = 0x70
        elif table_name == 'TypeRef':
            token_type = 0x1
        elif table_name == 'TypeDef':
            token_type = 0x2
        else:
            raise net_exceptions.OperationNotSupportedException()
        coded_value = token_type
        coded_value = (coded_value << 24) | table_rid
        return coded_value

#having trouble getting these to not be null, going to just do this for now.

cpdef BaseToken get_TypeDefOrRef():
    return CodedToken(2, ['TypeDef', 'TypeRef', 'TypeSpec'])

cpdef BaseToken get_HasConstant():
    return CodedToken(2, ['Field', 'Param', 'Property'])

cpdef BaseToken get_HasCustomAttribute():
    return CodedToken(5, ['MethodDef', 'Field', 'TypeRef', 'TypeDef',
                                    'Param', 'InterfaceImpl', 'MemberRef', 'Module',
                                    'DeclSecurity', 'Property', 'Event', 'StandAloneSig',
                                    'ModuleRef', 'TypeSpec', 'Assembly', 'AssemblyRef',
                                    'File', 'ExportedType', 'ManifestResource', 'GenericParam',
                                    'GenericParamConstraint', 'MethodSpec', '', ''])

cpdef BaseToken get_HasFieldMarshal():
    return CodedToken(1, ['Field', 'Param'])

cpdef BaseToken get_HasDeclSecurity():
    return CodedToken(2, ['TypeDef', 'MethodDef', 'Assembly'])

cpdef BaseToken get_MemberRefParent():
    return CodedToken(3, ['TypeDef', 'TypeRef', 'ModuleRef', 'MethodDef', 'TypeSpec'])

cpdef BaseToken get_HasSemantic():
    return CodedToken(1, ['Event', 'Property'])

cpdef BaseToken get_MethodDefOrRef():
    return CodedToken(1, ['MethodDef', 'MemberRef'])

cpdef BaseToken get_MemberForwarded():
    return CodedToken(1, ['Field', 'MethodDef'])

cpdef BaseToken get_Implementation():
    return CodedToken(2, ['File', 'AssemblyRef', 'ExportedType'])

cpdef BaseToken get_CustomAttributeType():
    return CodedToken(3, ['', '', 'MethodDef', 'MemberRef'])

cpdef BaseToken get_ResolutionScope():
    return CodedToken(2, ['Module', 'ModuleRef', 'AssemblyRef', 'TypeRef'])

cpdef BaseToken get_TypeOrMethodDef():
    return CodedToken(1, ['TypeDef', 'MethodDef'])

cpdef BaseToken get_HasCustomDebugInformation():
    return CodedToken(5, ['MethodDef', 'Field', 'TypeRef', 'TypeDef',
                                           'Param', 'InterfaceImpl', 'MemberRef', 'Module',
                                           'DeclSecurity', 'Property', 'Event', 'StandAloneSig',
                                           'ModuleRef', 'TypeSpec', 'Assembly', 'AssemblyRef',
                                           'File', 'ExportedType', 'ManifestResource', 'GenericParam',
                                           'GenericParamConstraint', 'MethodSpec', 'Document', 'LocalScope',
                                           'LocalVariable', 'LocalConstant', 'ImportScope'])

cpdef BaseToken get_StringsStream():
    return CodedToken(0, ['#Strings'], is_stream=True)

cpdef BaseToken get_UserStringsStream():
    return CodedToken(0, ['#US'], is_stream=True)

cpdef BaseToken get_BlobStream():
    return CodedToken(0, ['#Blob'], is_stream=True)

cpdef BaseToken get_GuidStream():
    return CodedToken(0, ['#GUID'], is_stream=True)

cpdef BaseToken get_MetadataStream():
    return CodedToken(0, ['#~'], is_stream=True)

cpdef BaseToken get_OneByteValue():
    return CodedToken(0, [], is_fixed_value=True, fixed_size=1)

cpdef BaseToken get_TwoByteValue():
    return CodedToken(0, [], is_fixed_value=True, fixed_size=2)

cpdef BaseToken get_FourByteValue():
    return CodedToken(0, [], is_fixed_value=True, fixed_size=4)

cpdef BaseToken get_SingleTableIndex():
    return  CodedToken(0, [], is_fixed_value=True)

cpdef BaseToken get_Signature():
    return SignatureToken()