#cython: language_level=3
from dotnetutils cimport net_row_objects, net_utils, dotnetpefile
from dotnetutils cimport net_emulator

cdef str remove_generics_from_name(str name)

cdef void initialize_array_helper(DotNetArray arr, net_row_objects.RowObject runtime_handle) except *

cdef void blockcopy_helper(DotNetArray src, object srcOffset, DotNetArray dst, object dstOffset, object count) except *

#NOTE: probably can remove cython sigs for all methods that arent in DotNetObject, its going to be called as a python object anyway.
cdef class DotNetObject:
    cdef net_emulator.DotNetEmulator emulator_obj
    cdef dict fields
    cdef net_row_objects.RowObject type_obj
    cdef net_utils.TypeSig type_sig_obj
    cdef list initialized_fields
    cdef bint __initialized

    cpdef net_emulator.DotNetEmulator get_emulator_obj(self)

    cpdef void set_emulator_obj(self, net_emulator.DotNetEmulator emulator_obj)

    cpdef void set_field(self, unsigned long idno, object val)

    cpdef object get_field(self, unsigned long idno)

    cpdef net_row_objects.TypeDefOrRef get_type_obj(self)

    cpdef void set_type_obj(self, net_row_objects.TypeDefOrRef type_obj)

    cpdef net_utils.TypeSig get_type_sig_obj(self)

    cpdef void set_type_sig_obj(self, net_utils.TypeSig type_sig_obj)

    cpdef void __initialize_field(self, unsigned long field_rid)

    cpdef initialize_type(self, type_obj)

    cpdef get_type(self)

cdef class DotNetNull(DotNetObject):
    pass

cdef class DotNetDynamicMethod(DotNetObject):
    cdef str name
    cdef net_row_objects.RowObject return_type
    cdef list parameter_types
    cdef bint skip_visibility
    cdef DotNetILGenerator il_generator
    cdef net_row_objects.RowObject parent_type
    cdef net_utils.MethodSig sig_obj
    cdef bint static

    cpdef get_dotnetpe(self)

    cpdef get_method_data(self)

    cpdef get_method_signature(self)

    cpdef method_has_this(self)

    cpdef is_static(self)

    cpdef has_return_value(self)

cdef class ArrayAddress:
    cdef list __internal_arrayaddr_array
    cdef int __internal_arrayaddr_index

    cpdef get_obj_ref(self)

    cpdef set_obj_ref(self, obj_ref)

cdef class DotNetType(DotNetObject):
    cdef net_row_objects.RowObject type_handle
    cdef net_utils.TypeSig sig_obj

    cpdef get_type_handle(self)


cdef class DotNetMonitor(DotNetObject):
    pass

cdef class DotNetDictionary(DotNetObject):
    cdef dict __internal_dict

cdef class DotNetConcurrentDictionary(DotNetDictionary):
    pass

cdef class DotNetStringBuilder(DotNetObject):
    cdef bytes char_array
    cdef bint is_wide

cdef class DotNetStream(DotNetObject):
    cdef object rsrc_stream

    cpdef DotNetArray ReadBytes(self, object count)

cdef class DotNetMemoryStream(DotNetObject):
    cdef object internal_data
    cdef bint writeable
    cdef int position
    
    cpdef object Read(self, DotNetArray buffer, object offset, object count)

    cpdef void Write(self, DotNetArray buffer, object offset, object count) except *

    cpdef DotNetArray ToArray(self)

cdef class DotNetAssemblyName(DotNetObject):
    cdef bytes name
    cdef DotNetAssembly assembly


cdef class DotNetManifestModule(DotNetObject):
    cdef DotNetAssembly dnassembly

cdef class DotNetDeflateStream(DotNetObject):
    cdef bint __decompress
    cdef Py_ssize_t position
    cdef bytes decompressed_buffer

    cpdef object Read(self, DotNetArray buffer, object offset, object count)

cdef class DotNetAssembly(DotNetObject):
    """
    This class is meant to fool checks to ensure that
    Deobfuscation methods are being executed by their assembly.
    """
    cdef net_row_objects.RowObject module

    cpdef get_module(self)

cdef class DotNetList(DotNetObject):
    cdef list internal

cdef class DotNetArray(DotNetObject):
    cdef list internal_array

    cpdef list get_internal_array(self)

    cpdef void set_internal_array(self, list int_array) except *

    cpdef void setup_default_value(self, unsigned long index, unsigned long size, bint init)

cdef class DotNetStackTrace(DotNetObject):
    cdef int skipFrames
    cdef bint fNeedFileInfo

cdef class DotNetStackFrame(DotNetObject):
    cdef net_emulator.DotNetEmulator current_emulator
    cdef int skip_frames

cdef class DotNetMemberInfo(DotNetObject):
    cdef net_row_objects.RowObject internal_method

cdef class DotNetConsole(DotNetObject):
    pass

cdef class DotNetThread(DotNetObject):
    cdef object __identifier
    cdef DotNetThreadStart __thread_start
    cdef object __internal_thread

    cpdef set_identifier(self, int identifier)


cdef class DotNetRuntimeHelpers(DotNetObject):
    pass

cdef class DotNetMath(DotNetObject):
    pass


cdef class DotNetBitConverter(DotNetObject):
    pass

cdef class DotNetBuffer(DotNetObject):
    pass

cdef class DotNetAppDomain(DotNetObject):
    pass

cdef class DotNetResolveEventHandler(DotNetObject):
    cdef net_row_objects.MethodDefOrRef __method_object
    
    cpdef net_row_objects.MethodDefOrRef get_method_obj(self)

cdef class DotNetEncoding(DotNetObject):
    cdef str name

cdef class DotNetString(DotNetObject):
    cdef list str_data
    cdef str str_encoding

    cpdef list get_str_data(self)

    cdef list __sanitize_data(self, str_data)

    cpdef bytes get_str_data_as_bytes(self)

    cpdef str get_str_encoding(self)

    cpdef bint is_encoding_wide(self)

    cpdef object IndexOf(self, object char_val)

    cpdef str get_str_data_as_str(self)

cdef class DotNetModule(DotNetObject):
    cdef net_row_objects.RowObject internal_module

cdef class DotNetModuleHandle(DotNetObject):
    cdef net_row_objects.RowObject internal_module

cdef class DotNetRuntimeTypeHandle(DotNetObject):
    cdef net_row_objects.RowObject internal_typedef

    cpdef get_internal_typedef(self)

cdef class DotNetRuntimeMethodHandle(DotNetObject):
    cdef net_row_objects.RowObject internal_method

cdef class DotNetFieldInfo(DotNetObject):
    cdef net_row_objects.Field internal_field

cdef class DotNetMethodBase(DotNetMemberInfo):
    pass

cdef class DotNetMethodInfo(DotNetMethodBase):
    pass

cdef class DotNetParameterInfo(DotNetObject):
    cdef net_utils.TypeSig internal_param

cdef class DotNetDelegate(DotNetObject):
    cdef DotNetType dn_type
    cdef DotNetMethodInfo dn_methodinfo

cdef class DotNetMulticastDelegate(DotNetDelegate):
    pass

cdef class DotNetConvert(DotNetObject):
    pass

cpdef enum DotNetStackBehaviour:
    Pop0 = 0
    Pop1 = 1
    Pop1_pop1 = 2
    Popi = 3
    Popi_pop1 = 4
    Popi_popi = 5
    Popi_popi8 = 6
    Popi_popi_popi = 7
    Popi_popr4 = 8
    Popi_popr8 = 9
    Popref = 10
    Popref_pop1 = 11
    Popref_popi = 12
    Popref_popi_popi = 13
    Popref_popi_popi8 = 14
    Popref_popi_popr4 = 15
    Popref_popi_popr8 = 16
    Popref_popi_popref = 17
    Push0 = 18
    Push1 = 19
    Push1_push1 = 20
    Pushi = 21
    Pushi8 = 22
    Pushr4 = 23
    Pushr8 = 24
    Pushref = 25
    Varpop = 26
    Varpush = 27
    Popref_popi_pop1 = 28

cpdef enum DotNetOperandType:
    InlineBrTarget = 0
    InlineField = 1
    InlineI = 2
    InlineI8 = 3
    InlineMethod = 4
    InlineNone = 5
    InlinePhi = 6
    InlineR = 7
    InlineSig = 9
    InlineString = 10
    InlineSwitch = 11
    InlineTok = 12
    InlineType = 13
    InlineVar = 14
    ShortInlineBrTarget = 15
    ShortInlineI = 16
    ShortInlineR = 17
    ShortInlineVar = 18

cpdef enum DotNetOpCodeType:
    Annotation = 0
    Macro = 1
    Nternal = 2
    Objmodel = 3
    Prefix = 4
    Primitive = 5


cpdef enum DotNetFlowControl:
    Branch = 0
    Break = 1
    Call = 2
    Cond_Branch = 3
    Meta = 4
    Next = 5
    Phi = 6
    Return = 7
    Throw = 8


cdef class DotNetOpCode(DotNetObject):
    cdef str stringname
    cdef DotNetStackBehaviour pop
    cdef DotNetStackBehaviour push
    cdef DotNetOpCodeType operand
    cdef DotNetOpCodeType op_type
    cdef int size
    cdef int s1
    cdef int s2
    cdef DotNetFlowControl ctrl
    cdef bint endsjmpblk
    cdef int stack

    cpdef get_net_cil_equiv(self)

    cpdef _get_opcode(self)


cdef class DotNetOpCodes(DotNetObject):
    pass


cdef class DotNetILGenerator(DotNetObject):
    cdef bytes method_body

    cpdef __internal_emit_noargs(self, opcode)

    cpdef __internal_emit_call(self, opcode, method_obj)


cdef class NameOnlyTypeRef():
    cdef str name

    cpdef get_full_name(self)


cdef class DotNetIntPtr(DotNetObject):
    cdef object value

cdef class DotNetSortedList(DotNetList):
    pass

cdef class DotNetHashTable(DotNetConcurrentDictionary):
    pass


cdef class DotNetRSACryptoServiceProvider(DotNetObject):
    pass

cdef class DotNetBinaryReader(DotNetObject):
    cdef DotNetObject stream # can be either a DotNetStream or DotNetMemoryStream


cdef class DotNetMarshal(DotNetObject):
    pass


cdef class DotNetGCHandle(DotNetObject):
    cdef object __target
    cdef object __type

cdef class DotNetWaitCallback(DotNetObject):
    cdef net_row_objects.MethodDef __method_object
    cdef object __object

cdef class DotNetFunc(DotNetObject):
    cdef net_row_objects.MethodDef __method_object
    cdef object __object

cdef class DotNetThreadPool(DotNetObject):
    pass

cdef class DotNetThreadStart(DotNetObject):
    cdef object __object
    cdef net_row_objects.MethodDef __method_object

    cpdef get_method_object(self)

cdef class DotNetDebugger(DotNetObject):
    pass


cdef class DotNetComparison(DotNetObject):
    cdef object __object
    cdef net_row_objects.RowObject __method_object

    cpdef get_method_object(self)

cdef class DotNetGC(DotNetObject):
    pass

cdef class DotNetPath(DotNetObject):
    pass

cdef class DotNetEnvironment(DotNetObject):
    pass

cdef class DotNetResolveEventArgs(DotNetObject):
    cdef DotNetString __name

cdef class DotNetSymmetricAlgorithm(DotNetObject):
    cdef DotNetArray __key
    cdef DotNetArray __iv
    cdef int __mode
    cdef int __padding

cdef class DotNetICryptoTransform(DotNetObject):
    cdef DotNetSymmetricAlgorithm provider

cdef class DotNetDESDecryptor(DotNetICryptoTransform):
    cdef object des_object

cdef class DotNetDESCryptoServiceProvider(DotNetSymmetricAlgorithm):
    pass

cdef class DotNetApplication(DotNetObject):
    pass

cdef class DotNetHashAlgorithm(DotNetObject):
    pass

cdef class DotNetMD5CryptoServiceProvider(DotNetHashAlgorithm):
    pass

cdef class DotNet3DESDecryptor(DotNetICryptoTransform):
    cdef object des_object
    
cdef class DotNet3DESCryptoServiceProvider(DotNetSymmetricAlgorithm):
    pass

cdef dict NET_EMULATE_TYPE_REGISTRATIONS