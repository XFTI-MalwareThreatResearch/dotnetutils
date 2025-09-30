from dotnetutils cimport net_structs, dotnetpefile, net_row_objects, net_tokens
from dotnetutils import net_exceptions

cdef class TypeSig:
    def __init__(self, net_structs.CorElementType element_type):
        self.__element_type = element_type

    cpdef net_structs.CorElementType get_element_type(self):
        return self.__element_type


cdef class LeafSig(TypeSig):
    def __init__(self, net_structs.CorElementType element_type, TypeSig _next):
        TypeSig.__init__(self, element_type)
        self.__next = _next

    cpdef TypeSig get_next(self):
        return self.__next


cdef class TypeDefOrRefSig(LeafSig):
    def __init__(self, net_structs.CorElementType element_type, TypeSig _next, net_row_objects.TypeDefOrRef type_def_or_ref):
        LeafSig.__init__(self, element_type, _next)
        self.__type_def_or_ref = type_def_or_ref

    cpdef net_row_objects.TypeDefOrRef get_type(self):
        return self.__type_def_or_ref

    def __eq__(self, other):
        return isinstance(other, TypeDefOrRefSig) and self.get_type() == other.get_type()


cdef class CorLibTypeSig(TypeDefOrRefSig):
    def __init__(self, net_structs.CorElementType element_type, TypeSig _next, net_row_objects.RowObject type_def_or_ref):
        TypeDefOrRefSig.__init__(self, element_type, _next, type_def_or_ref)

    def __eq__(self, other):
        return isinstance(other, CorLibTypeSig) and other.get_element_type() == self.get_element_type()

    def __str__(self):
        return 'CorLibTypeSig: {}'.format(self.get_element_type())


cdef class ClassOrValueTypeSig(TypeDefOrRefSig):
    def __init__(self, net_structs.CorElementType element_type, TypeSig _next, net_row_objects.RowObject type_def_or_ref):
        TypeDefOrRefSig.__init__(self, element_type, _next, type_def_or_ref)


cdef class ValueTypeSig(ClassOrValueTypeSig):
    def __init__(self, TypeSig _next, net_row_objects.RowObject type_def_or_ref):
        ClassOrValueTypeSig.__init__(self, net_structs.CorElementType.ELEMENT_TYPE_VALUETYPE, _next, type_def_or_ref)

    def __eq__(self, other):
        return isinstance(other, ValueTypeSig) and other.get_type() == self.get_type()


cdef class ClassSig(ClassOrValueTypeSig):
    def __init__(self, TypeSig _next, net_row_objects.RowObject type_def_or_ref):
        ClassOrValueTypeSig.__init__(self, net_structs.CorElementType.ELEMENT_TYPE_CLASS, _next, type_def_or_ref)

    def __eq__(self, other):
        return isinstance(other, ClassSig) and self.get_type() == other.get_type()

    def __str__(self):
        return 'ClassSig: next={}, type_def_or_ref={}'.format(self.get_next(), self.get_type())
    
    def __hash__(self):
        return hash(self.get_type())


cdef class GenericSig(LeafSig):
    def __init__(self, net_structs.CorElementType element_type, TypeSig _next, bint is_type_var, int number):
        LeafSig.__init__(self, element_type, _next)
        self.__is_type_var = is_type_var
        self.__number = number

    cpdef bint is_type_var(self):
        return self.__is_type_var
    
    cpdef int get_number(self):
        return self.__number
    
    def __eq__(self, other):
        return isinstance(other, GenericSig) and self.get_element_type() == other.get_element_type() and self.is_type_var() == other.is_type_var() and other.get_number() == self.get_number()


cdef class GenericVar(GenericSig):
    def __init__(self, TypeSig _next, int number):
        GenericSig.__init__(self, net_structs.CorElementType.ELEMENT_TYPE_VAR, _next, True, number)

    def __str__(self):
        return 'GenericVar: next={}, is_type_var={}, number={}'.format(self.get_next(), self.is_type_var(), self.get_number())


cdef class GenericMVar(GenericSig):
    def __init__(self, TypeSig _next, int number):
        GenericSig.__init__(self, net_structs.CorElementType.ELEMENT_TYPE_MVAR, _next, False, number)


cdef class SentinelSig(LeafSig):
    def __init__(self, TypeSig _next):
        LeafSig.__init__(self, net_structs.CorElementType.ELEMENT_TYPE_SENTINEL, _next)


cdef class FnPtrSig(LeafSig):
    def __init__(self, TypeSig _next, NonLeafSig signature):
        LeafSig.__init__(self, net_structs.CorElementType.ELEMENT_TYPE_FNPTR, _next)
        self.__signature = signature

    cpdef NonLeafSig get_signature(self):
        return self.__signature


cdef class GenericInstSig(LeafSig):
    def __init__(self, TypeSig _next, TypeSig generic_type, int gen_arg_count=0):
        LeafSig.__init__(self, net_structs.CorElementType.ELEMENT_TYPE_GENERICINST, _next)
        self.__generic_type = generic_type
        self.__gen_arg_count = gen_arg_count
        self.__generic_args = list()

    cdef void add_generic_type(self, TypeSig obj):
        self.__generic_args.append(obj)

    cpdef TypeSig get_generic_type(self):
        return self.__generic_type
    
    cpdef list get_generic_args(self):
        return self.__generic_args
    
    cpdef int get_generic_args_count(self):
        return self.__gen_arg_count

    def __eq__(self, other):
        return isinstance(other, GenericInstSig) and self.get_generic_type() == other.get_generic_type() and \
               self.get_generic_args_count() == other.get_generic_args_count() and other.get_generic_args() == self.get_generic_args()
    
    def __str__(self):
        return 'GenericInstSig: {} {}'.format(self.get_generic_type(), self.get_generic_args())


cdef class NonLeafSig(TypeSig):
    def __init__(self, net_structs.CorElementType element_type, TypeSig next_sig):
        TypeSig.__init__(self, element_type)
        self.__next_sig = next_sig

    cpdef TypeSig get_next_sig(self):
        return self.__next_sig
    
    def __eq__(self, other):
        return isinstance(other, NonLeafSig) and self.get_next_sig() == other.get_next_sig() and self.get_element_type() == other.get_element_type()


cdef class PtrSig(NonLeafSig):
    def __init__(self, TypeSig next_sig):
        NonLeafSig.__init__(self, net_structs.CorElementType.ELEMENT_TYPE_PTR, next_sig)

    def __eq__(self, other):
        return isinstance(other, PtrSig) and self.get_next_sig() == other.get_next_sig()


cdef class ByRefSig(NonLeafSig):
    def __init__(self, TypeSig next_sig):
        NonLeafSig.__init__(self, net_structs.CorElementType.ELEMENT_TYPE_BYREF, next_sig)

    def __eq__(self, other):
        return isinstance(other, ByRefSig) and self.get_next_sig() == other.get_next_sig()


cdef class ArraySigBase(NonLeafSig):
    def __init__(self, net_structs.CorElementType element_type, TypeSig next_sig):
        NonLeafSig.__init__(self, element_type, next_sig)


cdef class ArraySig(ArraySigBase):
    def __init__(self, TypeSig next_sig, int rank, list sizes, list lower_bounds):
        ArraySigBase.__init__(self, net_structs.CorElementType.ELEMENT_TYPE_ARRAY, next_sig)
        self.__rank = rank
        self.__sizes = sizes
        self.__lower_bounds = lower_bounds

    cpdef int get_rank(self):
        return self.__rank
    
    cpdef list get_sizes(self):
        return self.__sizes
    
    cpdef list get_lower_bounds(self):
        return self.__lower_bounds
    
    def __eq__(self, other):
        return isinstance(other, ArraySig) and other.get_rank() == self.get_rank() and other.get_sizes() == self.get_sizes() and other.get_lower_bounds() == self.get_lower_bounds() and other.get_next_sig() == self.get_next_sig()


cdef class SZArraySig(ArraySigBase):
    def __init__(self, TypeSig next_sig):
        ArraySigBase.__init__(self, net_structs.CorElementType.ELEMENT_TYPE_SZARRAY, next_sig)
        self.__rank = 1
        self.__sizes = list()
        self.__lower_bounds = list()

    cpdef int get_rank(self):
        return self.__rank
    
    cpdef list get_sizes(self):
        return self.__sizes
    
    cpdef list get_lower_bounds(self):
        return self.__lower_bounds

    def __eq__(self, other):
        return isinstance(other, SZArraySig) and self.get_next_sig() == other.get_next_sig() and self.get_sizes() == other.get_sizes() and self.get_rank() == other.get_rank() and self.get_lower_bounds() == other.get_lower_bounds()
    
    def __str__(self):
        return 'SZArraySig: rank={}, sizes={}, lower_bounds={}, next={}'.format(self.get_rank(), self.get_sizes(), self.get_lower_bounds(), self.get_next_sig())


cdef class ModifierSig(NonLeafSig):
    def __init__(self, TypeSig next_sig, int modifier, net_structs.CorElementType element_type=net_structs.CorElementType.ELEMENT_TYPE_MODIFIER):
        NonLeafSig.__init__(self, element_type, next_sig)
        self.__modifier = modifier

    cpdef int get_modifier(self):
        return self.__modifier
    
    def __eq__(self, other):
        return isinstance(other, ModifierSig) and self.get_element_type() == other.get_element_type() and self.get_modifier() == other.get_modifier() and self.get_next_sig() == other.get_next_sig()


cdef class CModReqdSig(ModifierSig):
    def __init__(self, TypeSig next_sig, int modifier):
        ModifierSig.__init__(self, next_sig, modifier, element_type=net_structs.CorElementType.ELEMENT_TYPE_CMOD_REQD)


cdef class CmodOptSig(ModifierSig):
    def __init__(self, TypeSig next_sig, int modifier):
        ModifierSig.__init__(self, next_sig, modifier, element_type=net_structs.CorElementType.ELEMENT_TYPE_CMOD_OPT)


cdef class PinnedSig(NonLeafSig):
    def __init__(self, TypeSig next_sig):
        NonLeafSig.__init__(self, net_structs.CorElementType.ELEMENT_TYPE_PINNED, next_sig)


cdef class ValueArraySig(NonLeafSig):
    def __init__(self, TypeSig next_sig, int size):
        NonLeafSig.__init__(self, net_structs.CorElementType.ELEMENT_TYPE_VALUEARRAY, next_sig)
        self.__size = size

    cpdef int get_size(self):
        return self.__size
    
    def __eq__(self, other):
        return isinstance(other, ValueArraySig) and other.get_size() == self.get_size() and other.get_next_sig() == self.get_next_sig()


cdef class ModuleSig(NonLeafSig):
    def __init__(self, TypeSig next_sig, int index):
        NonLeafSig.__init__(self, net_structs.CorElementType.ELEMENT_TYPE_MODULE, next_sig)
        self.__index = index

    cpdef int get_index(self):
        return self.__index
    
    def __eq__(self, other):
        return isinstance(other, ModuleSig) and other.get_index() == self.get_index() and self.get_next_sig() == other.get_next_sig()

cdef class CallingConventionSig():
    def __init__(self, int calling_conv, bytes extra_data):
        self.__calling_conv = calling_conv
        self.__extra_data = extra_data
    
    cpdef int get_calling_conv(self):
        return self.__calling_conv
    
    cpdef bytes get_extra_data(self):
        return self.__extra_data


cdef class FieldSig(CallingConventionSig):
    def __init__(self, int calling_conv, bytes extra_data, TypeSig type_sig):
        CallingConventionSig.__init__(self, calling_conv, extra_data)
        self.__type_sig = type_sig

    cpdef TypeSig get_type_sig(self):
        return self.__type_sig
    
    def __str__(self):
        return 'FieldSig: {} {}'.format(self.get_calling_conv(), self.get_type_sig())
    
    def __eq__(self, other):
        return isinstance(other, FieldSig) and self.get_calling_conv() == other.get_calling_conv() and self.get_extra_data() == other.get_extra_data() and self.get_type_sig() == other.get_type_sig()


cdef class MethodBaseSig(CallingConventionSig):
    def __init__(self, int calling_conv, bytes extra_data, TypeSig type_sig, list parameters, int gen_param_count, int params_after_sentinel,
                 TypeSig return_type):
        CallingConventionSig.__init__(self, calling_conv, extra_data)
        self.__type_sig = type_sig
        self.__parameters = parameters
        self.__gen_param_count = gen_param_count
        self.__params_after_sentinel = params_after_sentinel
        self.__return_type = return_type
        self.dotnetpe = None
        self.method = None

    cpdef TypeSig get_type_sig(self):
        return self.__type_sig
    
    cpdef list get_parameters(self):
        return self.__parameters
    
    cpdef int get_generic_params_count(self):
        return self.__gen_param_count
    
    cpdef int get_params_after_sentinel(self):
        return self.__params_after_sentinel
    
    cpdef TypeSig get_return_type(self):
        return self.__return_type

    cdef void setup_dotnetpe(self, dotnetpefile.DotNetPeFile dotnetpe, net_row_objects.RowObject method):
        self.dotnetpe = dotnetpe  # TODO: make a better way to do this.
        self.method = method

    def __eq__(self, other):
        if other == None:
            return False
        if not isinstance(other, MethodBaseSig):
            return False
        return self.get_type_sig() == other.get_type_sig() and self.get_parameters() == other.get_parameters() and self.get_return_type() == other.get_return_type()
    
    def __str__(self):
        return 'MethodBaseSig: TypeSig: {} Parameters: {} ReturnType: {}'.format(self.get_type_sig(), self.get_parameters(), self.get_return_type())

cdef class MethodSig(MethodBaseSig):
    def __init__(self, int calling_conv, bytes extra_data, TypeSig type_sig, list parameters, int gen_param_count, int params_after_sentinel,
                 int orig_token, TypeSig return_type):
        MethodBaseSig.__init__(self, calling_conv, extra_data, type_sig, parameters, gen_param_count,
                               params_after_sentinel, return_type)
        self.__orig_token = orig_token

    cpdef int get_orig_token(self):
        return self.__orig_token


cdef class PropertySig(MethodBaseSig):
    def __init__(self, int calling_conv, bytes extra_data, TypeSig type_sig, list parameters, int gen_param_count, int params_after_sentinel,
                 TypeSig return_type):
        MethodBaseSig.__init__(self, calling_conv, extra_data, type_sig, parameters, gen_param_count,
                               params_after_sentinel, return_type)


cdef class LocalSig(CallingConventionSig):
    def __init__(self, int calling_conv, bytes extra_data, list local_vars):
        CallingConventionSig.__init__(self, calling_conv, extra_data)
        self.__local_vars = local_vars

    cpdef list get_local_vars(self):
        return self.__local_vars


cdef class GenericInstMethodSig(CallingConventionSig):
    def __init__(self, int calling_conv, bytes extra_data, list generic_args):
        CallingConventionSig.__init__(self, calling_conv, extra_data)
        self.__generic_args = generic_args

    cpdef list get_generic_args(self):
        return self.__generic_args


cdef class SignatureReader():
    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, bytes data, net_row_objects.RowObject reference=None):
        self.dotnetpe = dotnetpe
        self.sig_io = net_structs.DotNetDataReader(data)
        self.sig_type = self.read_byte()
        self.reference = reference
        self.debug = False
        if self.sig_type == -1:
            raise net_exceptions.InvalidSignatureException('No sig_type')
        self.calling_conv = self.sig_type & net_structs.CorCallingConvention.Mask

    cpdef CallingConventionSig read_signature(self):
        try:
            return self.read_calling_convention_sig()
        except:
            # ignore due to likely corrupted metadata, file might still run.
            raise net_exceptions.InvalidSignatureException('read_signature')

    cdef CallingConventionSig read_calling_convention_sig(self):
        cdef net_structs.CorCallingConvention sig_type
        sig_type = <net_structs.CorCallingConvention>self.calling_conv
        if sig_type == net_structs.CorCallingConvention.Default:
            return self.handle_method_sig()
        elif sig_type == net_structs.CorCallingConvention.C:
            return self.handle_method_sig()
        elif sig_type == net_structs.CorCallingConvention.StdCall:
            return self.handle_method_sig()
        elif sig_type == net_structs.CorCallingConvention.ThisCall:
            return self.handle_method_sig()
        elif sig_type == net_structs.CorCallingConvention.FastCall:
            return self.handle_method_sig()
        elif sig_type == net_structs.CorCallingConvention.VarArg:
            return self.handle_method_sig()
        elif sig_type == net_structs.CorCallingConvention.Unmanaged:
            return self.handle_method_sig()
        elif sig_type == net_structs.CorCallingConvention.NativeVarArg:
            return self.handle_method_sig()
        elif sig_type == net_structs.CorCallingConvention.Field:
            return self.handle_field_sig()
        elif sig_type == net_structs.CorCallingConvention.LocalSig:
            return self.handle_local_sig()
        elif sig_type == net_structs.CorCallingConvention.Property:
            return self.handle_property_sig()
        elif sig_type == net_structs.CorCallingConvention.GenericInst:
            return self.handle_genericinst_sig()
        elif sig_type == net_structs.CorCallingConvention.Generic:
            return self.handle_method_sig()
        raise net_exceptions.InvalidArgumentsException()

    cdef MethodSig handle_method_sig(self):
        calling_conv = self.sig_type
        type_sig = None
        parameters = list()
        gen_param_count = 0
        params_after_sentinel = 0

        if self.is_generic():
            gen_param_count = self.read_compressed_integer()
        num_params = self.read_compressed_integer()

        type_sig = self.handle_type_sig()
        if num_params > 250000:
            raise net_exceptions.TooManyMethodParameters(num_params)
        for i in range(num_params):
            param_type_sig = self.handle_type_sig()
            if isinstance(param_type_sig, SentinelSig):
                if params_after_sentinel == 0:
                    parameters = list()
                    params_after_sentinel = list()
                i -= 1
            else:
                parameters.append(param_type_sig)
        return MethodSig(calling_conv, None, None, parameters, gen_param_count, params_after_sentinel, 0, type_sig)

    cdef TypeSig handle_type_sig(self):
        cdef net_structs.CorElementType type_num

        type_num = <net_structs.CorElementType>self.read_byte()
        if type_num == net_structs.CorElementType.INVALID:
            return None  # TODO: Why is this needed - ConfuserEx
        if type_num == net_structs.CorElementType.ELEMENT_TYPE_VOID:
            return get_CorSig_Void()
        elif type_num == net_structs.CorElementType.ELEMENT_TYPE_BOOLEAN:
            return get_CorSig_Boolean()
        elif type_num == net_structs.CorElementType.ELEMENT_TYPE_CHAR:
            return get_CorSig_Char()
        elif type_num == net_structs.CorElementType.ELEMENT_TYPE_I1:
            return get_CorSig_SByte()
        elif type_num == net_structs.CorElementType.ELEMENT_TYPE_U1:
            return get_CorSig_Byte()
        elif type_num == net_structs.CorElementType.ELEMENT_TYPE_I2:
            return get_CorSig_Int16()
        elif type_num == net_structs.CorElementType.ELEMENT_TYPE_U2:
            return get_CorSig_UInt16()
        elif type_num == net_structs.CorElementType.ELEMENT_TYPE_I4:
            return get_CorSig_Int32()
        elif type_num == net_structs.CorElementType.ELEMENT_TYPE_U4:
            return get_CorSig_UInt32()
        elif type_num == net_structs.CorElementType.ELEMENT_TYPE_I8:
            return get_CorSig_Int64()
        elif type_num == net_structs.CorElementType.ELEMENT_TYPE_U8:
            return get_CorSig_UInt64()
        elif type_num == net_structs.CorElementType.ELEMENT_TYPE_R4:
            return get_CorSig_Single()
        elif type_num == net_structs.CorElementType.ELEMENT_TYPE_R8:
            return get_CorSig_Double()
        elif type_num == net_structs.CorElementType.ELEMENT_TYPE_STRING:
            return get_CorSig_String()
        elif type_num == net_structs.CorElementType.ELEMENT_TYPE_TYPEDBYREF:
            return get_CorSig_TypedReference()
        elif type_num == net_structs.CorElementType.ELEMENT_TYPE_I:
            return get_CorSig_IntPtr()
        elif type_num == net_structs.CorElementType.ELEMENT_TYPE_U:
            return get_CorSig_UIntPtr()
        elif type_num == net_structs.CorElementType.ELEMENT_TYPE_OBJECT:
            return get_CorSig_Object()
        elif type_num == net_structs.CorElementType.ELEMENT_TYPE_PTR:
            try:
                inner_type = self.handle_type_sig()
                return PtrSig(inner_type)
            except:
                raise net_exceptions.InvalidSignatureException('PtrSig')
        elif type_num == net_structs.CorElementType.ELEMENT_TYPE_BYREF:
            try:
                inner_type = self.handle_type_sig()
                return ByRefSig(inner_type)
            except:
                raise net_exceptions.InvalidSignatureException('ByRefSig')
        elif type_num == net_structs.CorElementType.ELEMENT_TYPE_VALUETYPE:
            try:
                inner_type = self.read_typedef_or_ref()
                return ValueTypeSig(None, inner_type)
            except:
                net_exceptions.InvalidSignatureException('ValueTypeSig')
        elif type_num == net_structs.CorElementType.ELEMENT_TYPE_CLASS:
            try:
                inner_type = self.read_typedef_or_ref()
                return ClassSig(None, inner_type)
            except:
                raise net_exceptions.InvalidSignatureException('ClassSig')
        elif type_num == net_structs.CorElementType.ELEMENT_TYPE_FNPTR:
            try:
                new_sig = self.read_calling_convention_sig()
                return FnPtrSig(None, new_sig)
            except:
                raise net_exceptions.InvalidSignatureException('FnPtrSig')
        elif type_num == net_structs.CorElementType.ELEMENT_TYPE_SZARRAY:
            try:
                inner_type = self.handle_type_sig()
                return SZArraySig(inner_type)
            except:
                raise net_exceptions.InvalidSignatureException('SZArraySig')
        elif type_num == net_structs.CorElementType.ELEMENT_TYPE_CMOD_REQD:
            try:
                typedef = self.read_typedef_or_ref()
                new_type = self.handle_type_sig()
                return CModReqdSig(typedef, new_type)
            except:
                raise net_exceptions.InvalidSignatureException('CModReqdSig')
        elif type_num == net_structs.CorElementType.ELEMENT_TYPE_CMOD_OPT:
            try:
                typedef = self.read_typedef_or_ref()
                new_type = self.handle_type_sig()
                return CmodOptSig(typedef, new_type)
            except:
                raise net_exceptions.InvalidSignatureException('CmodOptSig')
        elif type_num == net_structs.CorElementType.ELEMENT_TYPE_SENTINEL:
            return SentinelSig(None)
        elif type_num == net_structs.CorElementType.ELEMENT_TYPE_PINNED:
            try:
                inner_type = self.handle_type_sig()
                return PinnedSig(inner_type)
            except:
                raise net_exceptions.InvalidSignatureException("PinnedSig")
        elif type_num == net_structs.CorElementType.ELEMENT_TYPE_VAR:
            try:
                num = self.read_compressed_integer()
                return GenericVar(None, num)
            except:
                raise net_exceptions.InvalidSignatureException('GenericVar')
        elif type_num == net_structs.CorElementType.ELEMENT_TYPE_MVAR:
            try:
                num = self.read_compressed_integer()
                return GenericMVar(None, num)
            except:
                raise net_exceptions.InvalidSignatureException('GenericMVar')
        elif type_num == net_structs.CorElementType.ELEMENT_TYPE_VALUEARRAY:
            try:
                next_type = self.handle_type_sig()
                num = self.read_compressed_integer()
                return ValueArraySig(next_type, num)
            except:
                raise net_exceptions.InvalidSignatureException('ValueArraySig')
        elif type_num == net_structs.CorElementType.ELEMENT_TYPE_MODULE:
            try:
                num = self.read_compressed_integer()
                ctype = self.handle_type_sig()
                return ModuleSig(ctype, num)
            except:
                raise net_exceptions.InvalidSignatureException('ModuleSig')
        elif type_num == net_structs.CorElementType.ELEMENT_TYPE_GENERICINST:
            try:
                next_type = self.handle_type_sig()
                num = self.read_compressed_integer()
                generic_inst_sig = GenericInstSig(None, next_type, num)
                num_args = generic_inst_sig.get_generic_args_count()

                for i in range(num_args):
                    type_sig = self.handle_type_sig()
                    generic_inst_sig.add_generic_type(type_sig)
                return generic_inst_sig
            except:
                raise net_exceptions.InvalidSignatureException('GenericInstSig')
        elif type_num == net_structs.CorElementType.ELEMENT_TYPE_ARRAY:
            try:
                next_type = self.handle_type_sig()
                rank = self.read_compressed_integer()
                if rank == 0:
                    return ArraySig(next_type, rank, None, None)
                num = self.read_compressed_integer()
                sizes = list()
                for i in range(num):
                    size = self.read_compressed_integer()
                    sizes.append(size)
                lower_bounds = list()
                num = self.read_compressed_integer()
                for i in range(num):
                    size = self.read_compressed_integer()
                    lower_bounds.append(size)
                return ArraySig(next_type, rank, sizes, lower_bounds)
            except:
                raise net_exceptions.InvalidSignatureException('ArraySig')
        elif type_num == net_structs.CorElementType.ELEMENT_TYPE_INTERNAL:
            try:
                num = self.read_integer_pointer()
                return get_CorSig_IntPtr()
            except:
                raise net_exceptions.InvalidSignatureException('InternalSig')
        else:
            return None

    cdef int read_integer_pointer(self):
        intptr_size = 4
        if self.dotnetpe.get_pe().PE_TYPE == net_structs.IMAGE_OPTIONAL_MAGIC.IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            intptr_size = 8
        return int.from_bytes(self.sig_io.read(intptr_size), 'little')

    cdef FieldSig handle_field_sig(self):
        try:
            calling_conv = net_structs.CorCallingConvention.Field
            type_sig = self.handle_type_sig()
            return FieldSig(calling_conv, self.sig_io.read(), type_sig)
        except net_exceptions.TooManyMethodParameters as e:
            raise e
        except:
            raise net_exceptions.InvalidSignatureException('FieldSig')

    cdef LocalSig handle_local_sig(self):
        try:
            calling_conv = net_structs.CorCallingConvention.LocalSig
            amt_locals = self.read_compressed_integer()
            locals = list()
            for i in range(amt_locals):
                l_type = self.handle_type_sig()
                locals.append(l_type)
            return LocalSig(calling_conv, None, locals)
        except net_exceptions.TooManyMethodParameters as e:
            raise e
        except:
            raise net_exceptions.InvalidSignatureException('LocalSig')

    cdef PropertySig handle_property_sig(self):
        try:
            calling_conv = net_structs.CorCallingConvention.Property
            type_sig = None
            parameters = list()
            gen_param_count = 0
            params_after_sentinel = 0

            if self.is_generic():
                gen_param_count = self.read_compressed_integer()
            num_params = self.read_compressed_integer()

            type_sig = self.handle_type_sig()
            for i in range(num_params):
                param_type_sig = self.handle_type_sig()
                if isinstance(param_type_sig, SentinelSig):
                    if params_after_sentinel == 0:
                        parameters = list()
                        params_after_sentinel = list()
                    i -= 1
                else:
                    parameters.append(param_type_sig)
            return PropertySig(calling_conv, None, None, parameters, gen_param_count, params_after_sentinel, type_sig)
        except:
            raise net_exceptions.InvalidSignatureException('PropertySig')

    cdef GenericInstMethodSig handle_genericinst_sig(self):
        try:
            calling_conv = net_structs.CorCallingConvention.GenericInst
            count = self.read_compressed_integer()
            generic_args = list()
            for i in range(count):
                type_sig = self.handle_type_sig()
                generic_args.append(type_sig)
            return GenericInstMethodSig(calling_conv, None, generic_args)
        except:
            raise net_exceptions.InvalidSignatureException('GenericInstSig')

    cdef bint is_generic(self):
        return self.sig_type == net_structs.CorCallingConvention.Generic

    cdef int read_byte(self):
        bt = self.sig_io.read(1)
        if len(bt) != 1:
            return -1
        return bt[0]

    cdef int read_compressed_integer(self):
        size = self.read_byte()
        if (size & 0x80) == 0:
            pass
        elif (size & 0xC0) == 0x80:
            size = ((size & 0x3F) << 8) | self.read_byte()
        else:
            size = ((size & 0x1F) << 24) | (self.read_byte() << 16) | (self.read_byte() << 8) | self.read_byte()
        return size

    cdef net_row_objects.RowObject read_typedef_or_ref(self):
        try:
            table_name, table_rid = net_tokens.get_TypeDefOrRef().decode_token(self.read_compressed_integer())
            return self.dotnetpe.get_metadata_table(table_name).get(table_rid)
        except:
            raise net_exceptions.InvalidSignatureException('TypeDefOrRef')

class GenericArgsSubstitutor:
    def __init__(self):
        pass

    @staticmethod
    def substitute_method_signature(gis: GenericInstSig, method_sig: MethodSig):
        return_type = method_sig.get_return_type()
        if isinstance(return_type, GenericVar):
            return_type = gis.get_generic_args()[return_type.get_number()]
        elif isinstance(return_type, GenericInstSig):
            return_type = GenericArgsSubstitutor.substitute_genericinst_signature(gis, return_type)

        parameters = list()
        for param in method_sig.get_parameters():
            if isinstance(param, GenericVar):
                parameters.append(gis.get_generic_args()[param.get_number()])
            elif isinstance(param, GenericInstSig):
                parameters.append(GenericArgsSubstitutor.substitute_genericinst_signature(gis, param))
            else:
                parameters.append(param)

        return MethodSig(method_sig.get_calling_conv(), method_sig.get_extra_data(), method_sig.get_type_sig(), parameters, method_sig.get_generic_params_count(), method_sig.get_params_after_sentinel(), method_sig.get_orig_token(), return_type)
    
    @staticmethod
    def substitute_genericinst_signature(gis: GenericInstSig, generic_sig: GenericInstSig):
        new_sig = GenericInstSig(generic_sig.get_next(), generic_sig.get_generic_type(), generic_sig.get_generic_args_count())
        for generic_arg in generic_sig.get_generic_args():
            if isinstance(generic_arg, GenericVar):
                new_sig.add_generic_type(gis.get_generic_args()[generic_arg.get_number()])
            else:
                new_sig.add_generic_type(generic_arg)
        return new_sig

#same issues as net_tokens.  Kinda a bad solution but itll work for now.
cpdef CorLibTypeSig get_CorSig_Void():
    return CorLibTypeSig(net_structs.CorElementType.ELEMENT_TYPE_VOID, None, None)

cpdef CorLibTypeSig get_CorSig_Boolean():
    return CorLibTypeSig(net_structs.CorElementType.ELEMENT_TYPE_BOOLEAN, None, None)

cpdef CorLibTypeSig get_CorSig_Char():
    return CorLibTypeSig(net_structs.CorElementType.ELEMENT_TYPE_CHAR, None, None)

cpdef CorLibTypeSig get_CorSig_Byte():
    return CorLibTypeSig(net_structs.CorElementType.ELEMENT_TYPE_U1, None, None)

cpdef CorLibTypeSig get_CorSig_SByte():
    return CorLibTypeSig(net_structs.ELEMENT_TYPE_I1, None, None)

cpdef CorLibTypeSig get_CorSig_Int16():
    return CorLibTypeSig(net_structs.CorElementType.ELEMENT_TYPE_I2, None, None)

cpdef CorLibTypeSig get_CorSig_UInt16():
    return CorLibTypeSig(net_structs.CorElementType.ELEMENT_TYPE_U2, None, None)

cpdef CorLibTypeSig get_CorSig_Int32():
    return CorLibTypeSig(net_structs.CorElementType.ELEMENT_TYPE_I4, None, None)

cpdef CorLibTypeSig get_CorSig_UInt32():
    return CorLibTypeSig(net_structs.CorElementType.ELEMENT_TYPE_U4, None, None)

cpdef CorLibTypeSig get_CorSig_Int64():
    return CorLibTypeSig(net_structs.CorElementType.ELEMENT_TYPE_I8, None, None)

cpdef CorLibTypeSig get_CorSig_UInt64():
    return CorLibTypeSig(net_structs.CorElementType.ELEMENT_TYPE_U8, None, None)

cpdef CorLibTypeSig get_CorSig_Single():
    return CorLibTypeSig(net_structs.CorElementType.ELEMENT_TYPE_R4, None, None)

cpdef CorLibTypeSig get_CorSig_Double():
    return CorLibTypeSig(net_structs.CorElementType.ELEMENT_TYPE_R8, None, None)

cpdef CorLibTypeSig get_CorSig_String():
    return CorLibTypeSig(net_structs.CorElementType.ELEMENT_TYPE_STRING, None, None)

cpdef CorLibTypeSig get_CorSig_TypedReference():
    return CorLibTypeSig(net_structs.ELEMENT_TYPE_TYPEDBYREF, None, None)

cpdef CorLibTypeSig get_CorSig_IntPtr():
    return CorLibTypeSig(net_structs.CorElementType.ELEMENT_TYPE_I, None, None)

cpdef CorLibTypeSig get_CorSig_UIntPtr():
    return CorLibTypeSig(net_structs.CorElementType.ELEMENT_TYPE_U, None, None)

cpdef CorLibTypeSig get_CorSig_Object():
    return CorLibTypeSig(net_structs.CorElementType.ELEMENT_TYPE_OBJECT, None, None)

