#cython: language_level=3

import cython
import copy
import numpy
import sys
import time
import ctypes
import os
import io
import threading
from dotnetutils import net_exceptions
from collections import defaultdict
from dotnetutils import net_structs as py_net_structs
from dotnetutils cimport net_utils, net_tokens, net_opcodes, net_cil_disas, net_structs, net_row_objects, net_emu_types, net_table_objects, dotnetpefile
from dotnetutils import net_emu_coretypes as py_net_emu_types
from cysignals.signals cimport sig_check

tlock = threading.Lock()

"""
A lot of the stuff below is for internal use mainly.
"""

def print_string_threadfn(string: str, fd):
    global tlock
    tlock.acquire()
    print(string)
    tlock.release()

cdef class CctorRegistry:
    def __init__(self):
        self.__executed_cctors = list()

    cpdef bint can_execute(self, net_row_objects.MethodDef method_obj):
        """
        Determine if a cctor was already executed and if not mark it as such.
        """
        if method_obj.get_rid() not in self.__executed_cctors:
            self.__executed_cctors.append(method_obj.get_rid())
            return True
        return False

cdef class EmulatorAppDomain:
    def __init__(self, dotnetpefile.DotNetPeFile dpe, DotNetEmulator emu_obj):
        self.__assemblyresolve_handlers = list()
        self.__resourceresolve_handlers = list()
        self.__loaded_assemblies = list()
        self.__current_thread_num = 1
        self.__emu_obj = emu_obj
        self.__calling_dotnetpe = None
        self.__executing_dotnetpe = None
        self.__current_emulator = None
        self.load_dotnetpe_as_assembly(dpe)

    cpdef dotnetpefile.DotNetPeFile get_calling_dotnetpe(self):
        return self.__calling_dotnetpe

    cpdef dotnetpefile.DotNetPeFile get_executing_dotnetpe(self):
        return self.__executing_dotnetpe

    cpdef DotNetEmulator get_current_emulator(self):
        return self.__current_emulator

    cpdef void set_current_emulator(self, DotNetEmulator emulator):
        self.__current_emulator = emulator

    cpdef void set_calling_dotnetpe(self, dotnetpefile.DotNetPeFile dpe):
        self.__calling_dotnetpe = dpe

    cpdef void set_executing_dotnetpe(self, dotnetpefile.DotNetPeFile dpe):
        self.__executing_dotnetpe = dpe

    cpdef EmulatorAppDomain get_current_appdomain(self):
        if self.get_current_emulator() is not None:
            return self.get_current_emulator().get_appdomain()
        return None

    cpdef int get_thread_id(self):
        cdef int curr
        curr = self.__current_thread_num
        self.__current_thread_num += 1
        return curr

    cpdef DotNetEmulator get_emulator_obj(self):
        return self.__emu_obj

    cpdef void add_resource_handler(self, net_row_objects.MethodDefOrRef obj):
        self.__resourceresolve_handlers.append(obj)

    cpdef void add_assembly_handler(self, net_row_objects.MethodDefOrRef obj):
        self.__assemblyresolve_handlers.append(obj)

    cpdef list get_loaded_assemblies(self):
        return self.__loaded_assemblies

    cpdef net_emu_types.DotNetAssembly load_assembly_from_bytes(self, bytes data):
        return self.load_dotnetpe_as_assembly(dotnetpefile.DotNetPeFile(pe_data=data))

    cpdef net_emu_types.DotNetAssembly load_dotnetpe_as_assembly(self, dotnetpefile.DotNetPeFile dpe):
        cdef net_row_objects.RowObject asm_obj
        cdef net_emu_types.DotNetAssembly result
        asm_obj = dpe.get_metadata_table('Assembly').get(0)
        result = net_emu_types.DotNetAssembly(self.get_emulator_obj(), asm_obj)
        if len(self.__loaded_assemblies) == 0:
            self.original_assembly = result
        self.__loaded_assemblies.append(result)
        return result

    cpdef net_emu_types.DotNetAssembly get_assembly_by_name(self, net_emu_types.DotNetString name):
        cdef net_emu_types.DotNetAssembly asm_obj
        cdef net_emu_types.DotNetAssemblyName asm_name_obj
        cdef net_emu_types.DotNetString asm_name_str
        cdef net_row_objects.MethodDefOrRef mrefdef_obj
        cdef net_row_objects.MethodDef mdef_obj
        cdef net_emu_types.DotNetObject arg_one
        cdef net_emu_types.DotNetResolveEventArgs arg_two
        #first check the resolve methods, see if we get anything from there.
        for mrefdef_obj in self.__assemblyresolve_handlers:
            if isinstance(mrefdef_obj, net_row_objects.MethodDef):
                mdef_obj = <net_row_objects.MethodDef> mrefdef_obj
                arg_one = net_emu_types.DotNetNull(self.get_emulator_obj()) #Not sure what arg_one actually is supposed to do but for now Null works.
                arg_two = net_emu_types.DotNetResolveEventArgs(self.get_emulator_obj(), name)
                emu_obj = self.get_emulator_obj().spawn_new_emulator(mdef_obj, method_params=[arg_one, arg_two])
                emu_obj.run_function()
                result_obj = emu_obj.get_stack().pop()
                if isinstance(result_obj, net_emu_types.DotNetAssembly):
                    return result_obj
        
        for asm_obj in self.__loaded_assemblies:
            asm_name_obj = asm_obj.GetName()
            asm_name_str = asm_name_obj.get_Name()
            if asm_name_str == name:
                return asm_obj
        return None

    cpdef bytes get_resource_by_name(self, net_emu_types.DotNetString name):
        cdef net_emu_types.DotNetAssembly asm_obj
        cdef net_emu_types.DotNetAssemblyName asm_name_obj
        cdef net_emu_types.DotNetString asm_name_str
        cdef net_row_objects.MethodDefOrRef mrefdef_obj
        cdef net_row_objects.MethodDef mdef_obj
        cdef net_emu_types.DotNetObject arg_one
        cdef net_emu_types.DotNetResolveEventArgs arg_two
        cdef bytes rsrc_name
        rsrc_name = name.get_str_data_as_bytes().decode(name.get_str_encoding()).encode('utf-8')
        #first check the resolve methods, see if we get anything from there.
        for mrefdef_obj in self.__resourceresolve_handlers:
            if isinstance(mrefdef_obj, net_row_objects.MethodDef):
                mdef_obj = <net_row_objects.MethodDef> mrefdef_obj
                arg_one = net_emu_types.DotNetNull(self.get_emulator_obj()) #Not sure what arg_one actually is supposed to do but for now Null works.
                arg_two = net_emu_types.DotNetResolveEventArgs(self.get_emulator_obj(), name)
                emu_obj = self.get_emulator_obj().spawn_new_emulator(mdef_obj, method_params=[arg_one, arg_two])
                emu_obj.run_function()
                result_obj = emu_obj.get_stack().pop()
                if isinstance(result_obj, net_emu_types.DotNetAssembly):
                    return result_obj.get_module().get_dotnetpe().get_resource_by_name(rsrc_name)
        return self.original_assembly.get_module().get_dotnetpe().get_resource_by_name(rsrc_name)

cdef class DotNetStack:

    def __init__(self, DotNetEmulator emulator, int max_stack_size):
        self.__emulator = emulator
        self.__internal_stack = list()
        self.__max_stack_size = max_stack_size

    cdef void append(self, object obj):
        # if not self.__verify_obj_type(obj):
        #    raise net_exceptions.EmulatorStackTypeUnknown(type(obj))

        # if len(self) == self.__max_stack_size:
        #    raise net_exceptions.EmualatorMaxStackSizeViolated()
        self.__internal_stack.append(obj)

    cpdef object pop(self):
        obj = self.__internal_stack.pop()
        return obj

    """def __verify_obj_type(self, obj):
        if obj == None:  # allow NoneType
            return True

        if isinstance(obj, net_emu_types.DotNetObject):
            return True

        if isinstance(obj, net_emu_types.ArrayAddress):
            return True

        if hasattr(obj, 'dtype'):  # allow numpy.dtype
            return True

        if isinstance(obj, net_row_objects.RowObject):
            return True  # TODO: should RowObjects be allowed?

        if isinstance(obj, bool):  # allow bool
            return True

        if isinstance(obj, bytes) or isinstance(obj, bytearray):
            return True

        return False"""

    cpdef void clear(self):
        self.__internal_stack.clear()

    def __getitem__(self, item):
        return self.__internal_stack[item]

    def __str__(self) -> str:
        return str(self.__internal_stack)

    def __len__(self) -> int:
        return len(self.__internal_stack)


"""
Represents the memory space of a .NET executable.
Can be used to obtain changes to a binary made at runtime etc.
"""


class DotNetMemorySpace:
    def __init__(self, dotnetpe):
        self.__load_pe(dotnetpe.get_exe_data())

    def __load_pe(self, pe_data):
        dos_header = py_net_structs.IMAGE_DOS_HEADER.from_buffer_copy(pe_data, 0)
        nt_headers = py_net_structs.IMAGE_NT_HEADERS32.from_buffer_copy(pe_data, dos_header.e_lfanew)
        if nt_headers.OptionalHeader.Magic == net_structs.IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            nt_headers = py_net_structs.IMAGE_NT_HEADERS64.from_buffer_copy(pe_data, dos_header.e_lfanew)
        self.__base_address = nt_headers.OptionalHeader.ImageBase
        self.__internal_memory = bytearray([0] * nt_headers.OptionalHeader.SizeOfImage)

        # first copy the headers
        self.__memcpy_internal(self.__internal_memory, 0, pe_data, 0, nt_headers.OptionalHeader.SizeOfHeaders)

        # now handle the sections
        sec_offset = nt_headers.FileHeader.SizeOfOptionalHeader + dos_header.e_lfanew + 4 + ctypes.sizeof(
            py_net_structs.IMAGE_FILE_HEADER)
        self.__sec_offset = sec_offset
        self.__dos_header = dos_header
        self.__nt_headers = nt_headers
        for _ in range(nt_headers.FileHeader.NumberOfSections):
            sec_header = py_net_structs.IMAGE_SECTION_HEADER.from_buffer_copy(pe_data, sec_offset)
            self.__memcpy_internal(self.__internal_memory, sec_header.VirtualAddress, pe_data,
                                   sec_header.PointerToRawData, sec_header.SizeOfRawData)
            sec_offset += ctypes.sizeof(py_net_structs.IMAGE_SECTION_HEADER)

        # should be okay enough for now.

    def __memcpy_internal(self, dest, d_off, source, s_off, size):
        for x in range(size):
            dest[d_off + x] = source[s_off + x]

    def write_memory(self, va, data):
        self.__memcpy_internal(self.__internal_memory, va, data, len(data))

    def read_memory(self, va, amt):
        return self.__internal_memory[va:va + amt]

    def __calculate_current_file_size(self):
        last_section_offset = 0
        last_section_size = 0
        sec_offset = self.__sec_offset
        for x in range(self.__nt_headers.FileHeader.NumberOfSections):
            sec_header = py_net_structs.IMAGE_SECTION_HEADER.from_buffer_copy(self.__internal_memory, sec_offset)
            if sec_header.PointerToRawData > last_section_offset:
                last_section_offset = sec_header.PointerToRawData
                last_section_size = sec_header.SizeOfRawData
            sec_offset += ctypes.sizeof(py_net_structs.IMAGE_SECTION_HEADER)

        return last_section_offset + last_section_size

    def get_mem_after_va(self, va):
        return self.__internal_memory[va:]

    def dump_executable(self):
        total_size = self.__calculate_current_file_size()
        buffer = bytearray([0] * total_size)

        # Copy headers
        self.__memcpy_internal(buffer, 0, self.__internal_memory, 0, self.__nt_headers.OptionalHeader.SizeOfHeaders)
        # copy sections
        sec_offset = self.__sec_offset
        for x in range(self.__nt_headers.FileHeader.NumberOfSections):
            sec_header = py_net_structs.IMAGE_SECTION_HEADER.from_buffer_copy(self.__internal_memory, sec_offset)
            self.__memcpy_internal(buffer, sec_header.PointerToRawData, self.__internal_memory,
                                   sec_header.VirtualAddress, sec_header.SizeOfRawData)
            sec_offset += ctypes.sizeof(py_net_structs.IMAGE_SECTION_HEADER)
        return buffer


cdef class DotNetEmulator:
    """
    This class is capable of emulating most .NET CIL instructions.
    """

    def __init__(self, method_obj, method_params=None, end_method_rid=-1, end_offset=-1, caller=None,
                 break_on_unsupported=False, ignore_security_exceptions=False, dont_execute_cctor=False,
                 force_memory=None, start_offset=0, print_debug_instrs=[],
                 print_debug_rids={}, should_print_callback=None, should_print_callback_param=None, ignore_instrs=list(), app_domain=None):
        """
        Initializes a new DotNetEmulator
        :param method_obj: The MethodDef to emulate.
        :param method_params: A list of parameters to pass to the method.
        All parameters should be either numpy dtypes, NoneType or DotNetObjects for the most part.
        :param end_offset: Should the emulator end emulation at a specific offset?
        :param caller: Used internally by the call instruction.
        :param break_on_unsupported: 
        """

        if not (isinstance(method_obj, net_row_objects.MethodDef) or isinstance(method_obj, net_emu_types.DotNetDynamicMethod)):
            raise net_exceptions.ObjectTypeException
        
        if method_params is None:
            method_params = []
        self.method_obj = method_obj
        self.disasm_obj = self.method_obj.disassemble_method()
        self.method_params = list(method_params)
        self.end_offset = end_offset
        self.static_fields = dict()
        self.stack = DotNetStack(self, self.disasm_obj.max_stack)
        self.localvars = dict()
        self.end_method_rid = end_method_rid
        self.executed_cctors = CctorRegistry()
        if start_offset > -1:
            self.current_eip = self.disasm_obj.get_instr_index_by_offset(start_offset)
        self.current_eip = self.disasm_obj.get_instr_at_offset(start_offset).get_instr_index()
        self.current_offset = start_offset
        self.__last_instr_start = 0
        self.__last_instr_end = 0
        self.caller = caller
        self.end_eip = -1
        self.should_break = False
        self.print_debug = False
        self.print_hex = False
        self.print_debug_children = False
        self.break_on_unsupported = break_on_unsupported
        self.ignore_security_exceptions = ignore_security_exceptions
        self.dont_execute_cctor = dont_execute_cctor
        self.spawned = False
        self.print_debug_offsets = list()
        self.print_debug_methods = list()

        #self.__pre_exec_callback = None
        #self.__post_exec_callback = None
        self.__skip_next_instruction = False
        #self.__callback_param = None
        self.print_debug_instrs = print_debug_instrs
        self.ignore_instrs = ignore_instrs
        if app_domain is None:
            self.app_domain = EmulatorAppDomain(self.method_obj.get_dotnetpe(), self)
        else:
            self.app_domain = app_domain
        numpy.seterr(over='ignore')  # Some obfuscators purposely use overflow math.
        self.print_debug_level = 0
        self.already_init = self.app_domain.get_calling_dotnetpe() is not None

        if not self.already_init:
            self.app_domain.set_calling_dotnetpe(self.method_obj.get_dotnetpe())

        if not self.disasm_obj:
            raise net_exceptions.DisassemblyFailedException

    def set_print_debugging(self, print_debug, print_debug_children, print_debug_instrs=list(), print_debug_offsets=list(), print_debug_methods=list(), print_debug_level=1):
        self.print_debug = print_debug
        self.print_debug_children = print_debug_children
        self.print_debug_instrs = print_debug_instrs
        self.print_debug_offsets = print_debug_offsets
        self.print_debug_methods = print_debug_methods
        self.print_debug_level = print_debug_level

    def get_stack(self):
        """
        Obtain the DotNetStack object associated with this emulator.
        Stacks are per method.  For the most part, DotNetStack operates similar to a python list().
        """
        return self.stack

    def get_method_obj(self):
        """
        Obtain the method object this emulator is executing.
        """
        return self.method_obj

    def get_caller(self):
        """
        Obtain the calling emulator if it exists.
        """
        return self.caller

    cpdef EmulatorAppDomain get_appdomain(self):
        return self.app_domain

    cpdef object get_static_field(self, int idno):
        """
        Obtain a static field from the emulator by id number.
        """
        return self.static_fields[idno]

    cpdef CctorRegistry get_executed_cctors(self):
        """
        Get the CctorRegistry associated with this execution.
        """
        return self.executed_cctors

    cpdef void set_static_field(self, int idno, object val):
        self.static_fields[idno] = val

    cdef object __get_default_value(self, net_utils.TypeSig type_sig):
        cdef net_structs.CorElementType element_type
        cdef net_row_objects.TypeDefOrRef superclass
        cdef net_emu_types.DotNetNull new_obj
        if isinstance(type_sig, net_utils.CorLibTypeSig):
            element_type = type_sig.get_element_type()
            if element_type == net_structs.CorElementType.ELEMENT_TYPE_I:
                return py_net_emu_types.DotNetInt32(self, 0)
            elif element_type == net_structs.CorElementType.ELEMENT_TYPE_I1:
                return py_net_emu_types.DotNetInt8(self, 0)
            elif element_type == net_structs.CorElementType.ELEMENT_TYPE_I2:
                return py_net_emu_types.DotNetInt16(self, 0)
            elif element_type == net_structs.CorElementType.ELEMENT_TYPE_I4:
                return py_net_emu_types.DotNetInt32(self, 0)
            elif element_type == net_structs.CorElementType.ELEMENT_TYPE_I8:
                return py_net_emu_types.DotNetInt64(self, 0)
            elif element_type == net_structs.CorElementType.ELEMENT_TYPE_U:
                return py_net_emu_types.DotNetUInt32(self, 0)
            elif element_type == net_structs.CorElementType.ELEMENT_TYPE_U1:
                return py_net_emu_types.DotNetUInt8(self, 0)
            elif element_type == net_structs.CorElementType.ELEMENT_TYPE_U2:
                return py_net_emu_types.DotNetUInt16(self, 0)
            elif element_type == net_structs.CorElementType.ELEMENT_TYPE_U4:
                return py_net_emu_types.DotNetUInt32(self, 0)
            elif element_type == net_structs.CorElementType.ELEMENT_TYPE_U8:
                return py_net_emu_types.DotNetUInt64(self, 0)
        elif isinstance(type_sig, net_utils.ValueTypeSig):
            # handle System.Enums as a different case
            superclass = type_sig.get_type()
            if superclass.get_full_name() == b'System.Enum':
                return py_net_emu_types.DotNetUInt32(self, 0)
            else:
                superclass = superclass.get_superclass()
                if superclass != None: # if superclass is NULL, should DotNetNull or DotNetObject be returned?
                    if superclass.get_full_name() == b'System.Enum':
                        return py_net_emu_types.DotNetUInt32(self, 0)
        new_obj = net_emu_types.DotNetNull(self)
        return new_obj

    def skip_next_instruction(self):
        self.__skip_next_instruction = True

    def stop_emulator(self):
        self.should_break = True

    cdef void print_string(self, str string, int print_debug_level):
        #threading.Thread(target=print_string_threadfn, args=(string, self.dbg_output_fd)).start()
        if self.print_debug:
            if self.print_debug_level >= print_debug_level or True:
                print(string)

    cpdef net_emu_types.DotNetThread get_current_thread(self):
        return self.running_thread

    cpdef void set_running_thread(self, net_emu_types.DotNetThread thread_obj):
        self.running_thread = thread_obj

    cpdef DotNetEmulator spawn_new_emulator(self, net_row_objects.MethodDef method_obj, list method_params=[], int start_offset=0, int end_offset=-1, DotNetEmulator caller=None,
                           int end_method_rid=0, int end_eip=-1):
        cdef DotNetEmulator new_emu
        new_emu = DotNetEmulator(method_obj, method_params=method_params, start_offset=start_offset,
                                 end_offset=end_offset, caller=caller, app_domain=self.app_domain)
        """
        Use this method to create a new emulator off an existing one.
        For instance, if you are trying to deobfuscate strings, the usual way to do it would be to emulate some cctor method
        and then use spawn_new_emulator() to create emulator objects each time the string decryption method is emulated.
        """
        new_emu.static_fields = self.static_fields
        new_emu.executed_cctors = self.executed_cctors
        new_emu.end_method_rid = end_method_rid
        new_emu.end_eip = end_eip
        new_emu.print_debug_children = self.print_debug_children
        if self.print_debug_children:
            new_emu.print_debug = self.print_debug
        new_emu.ignore_security_exceptions = self.ignore_security_exceptions
        new_emu.break_on_unsupported = self.break_on_unsupported
        if self.end_offset > 0 and self.end_method_rid > 0:
            new_emu.end_offset = self.end_offset
            new_emu.end_method_rid = self.end_method_rid
        new_emu.spawned = True
        new_emu.dont_execute_cctor = self.dont_execute_cctor
        new_emu.print_debug_instrs = self.print_debug_instrs
        new_emu.print_debug_offsets = self.print_debug_offsets
        new_emu.print_debug_rids = self.print_debug_rids
        new_emu.ignore_instrs = self.ignore_instrs
        new_emu.print_debug_methods = self.print_debug_methods
        new_emu.print_debug_level = self.print_debug_level
        new_emu.running_thread = self.running_thread
        return new_emu

    cpdef void print_current_state(self):
        """
        prints the current state of the emulator.
        """
        cdef state_str
        state_str = ''
        if isinstance(self.method_obj, net_row_objects.MethodDef):
            state_str += 'Emulator Method: {}:{}\n'.format(self.method_obj.get_table_name(), self.method_obj.get_rid())
        else:
            state_str += 'Emulator Method: DynamicMethod\n'
        state_str += 'Method Params: {}\n'.format(self.method_params)
        if self.method_obj.method_has_this() and len(self.method_params) >= 1:
            state_str += 'This Object: {}\n'.format(str(self.method_params[0]))
        state_str += 'Printing static variables:\n'
        for key, value in self.static_fields.items():
            if hasattr(value, 'dtype') and self.print_hex:
                state_str += '{}: {}\n'.format(hex(key), hex(value))
            else:
                state_str += '{}: {} - {}\n'.format(hex(key), str(value), type(value))
        state_str += 'Printing local vars:\n'
        for key, value in self.localvars.items():
            if hasattr(value, 'dtype') and self.print_hex:
                state_str += '{}: {}\n'.format(hex(key), hex(value))
            else:
                state_str += '{}: {} - {}\n'.format(hex(key), str(value), type(value))

        state_str += 'Printing stack:\n'
        for value in self.stack:
            if hasattr(value, 'dtype') and self.print_hex:
                state_str += hex(value) + '\n'
            else:
                state_str += '{} - {}\n'.format(str(value), type(value))
        state_str += 'Last Instruction Execution Time (perf_counter_ns): {}\n'.format(
            self.__last_instr_end - self.__last_instr_start)
        state_str += 'Current EIP: {} Current Offset: {}\n'.format(
            hex(self.current_eip), hex(self.current_offset))
        self.print_string(state_str, 1)

    """
    The rest of the functions in this claass are for the most part instruction handlers
    These handlers are meant to emulate specific instructions.
    Instruction handlers return False if the emulator should move to the next instruction
    True is returned if the instruction is a jump and has already jumped to the next instruction.
    """

    cdef bint handle_general_jump(self, net_cil_disas.Instruction instr, Py_ssize_t force_offset) except *:
        cdef Py_ssize_t instr_offset
        cdef Py_ssize_t expected_offset
        if force_offset == 0:
            instr_offset = <Py_ssize_t>instr.get_argument()
            expected_offset = self.current_offset + len(instr) + instr_offset
        else:
            expected_offset = force_offset

        self.current_offset = expected_offset
        self.current_eip = self.disasm_obj.get_instr_index_by_offset(expected_offset)
        return True

    cdef bint handle_brfalse_instruction(self, net_cil_disas.Instruction instr) except *:
        value1 = self.stack.pop()
        if isinstance(value1, net_emu_types.DotNetNull) or (
                not isinstance(value1, net_emu_types.DotNetObject) and not value1):
            return self.handle_general_jump(instr, 0)
        return False

    cdef bint handle_brtrue_instruction(self, net_cil_disas.Instruction instr) except *:
        cdef bint result
        value1 = self.stack.pop()
        if not isinstance(value1, net_emu_types.DotNetNull) and value1:
            result = self.handle_general_jump(instr, 0)
            return result
        return False

    cdef bint handle_call_instruction(self, net_cil_disas.Instruction instr, bint is_virt, bint is_newobj, net_row_objects.MethodDef force_method_obj,
                                str force_extern_type_name) except *:
        cdef net_row_objects.MethodDefOrRef method_obj
        cdef net_row_objects.TypeDefOrRef parent_type
        cdef list method_args
        cdef net_row_objects.MethodDef cctor_method
        cdef DotNetEmulator new_emu
        cdef int amt_params
        cdef net_emu_types.DotNetObject dot_obj
        cdef str type_full_name
        cdef str method_name
        cdef type emulated_type
        cdef bint push_obj_reference
        cdef net_row_objects.ColumnValue params_obj
        
        method_obj = <net_row_objects.MethodDefOrRef>instr.get_argument()
        if force_method_obj:
            method_obj = force_method_obj
        else:

            if method_obj.get_table_name() == 'MethodDef' and not method_obj.has_body() and force_extern_type_name is None:
                if method_obj.get_parent_type():
                    parent_type = <net_row_objects.TypeDefOrRef>method_obj.get_parent_type().get_superclass()
                    if parent_type:
                        return self.handle_call_instruction(instr, is_virt, is_newobj, force_method_obj, parent_type.get_full_name().decode('ascii'))
        if method_obj.get_table_name() == 'MethodDef' and not force_extern_type_name:
            method_args = list()
            if method_obj.get_parent_type():
                cctor_method = method_obj.get_parent_type().get_cctor_method()
                #cctor method should always be MethodDef
                if cctor_method and self.executed_cctors.can_execute(cctor_method):
                    if not self.dont_execute_cctor:
                        new_emu = self.spawn_new_emulator(cctor_method, method_args)
                        new_emu.run_function()

            #crappy fix for the params issue - use whichever is bigger. #More investigation is definitely needed to fix this.
            #see  d18aa5d58656fffd7a2a0a3d7f6f4e011bf0f39b8f89701b0e5263951e1ce90c methods 1365 and 1404
            params_obj = method_obj.get_column('ParamList')
            amt_params = 0
            if params_obj.get_formatted_value() != None:
                amt_params = len(params_obj.get_formatted_value())
            if len(method_obj.get_param_types()) > amt_params:
                amt_params = len(method_obj.get_param_types())

            for x in range(amt_params): #len(method_obj.get_param_types()) seems to be inaccurate sometimes.
                method_args.insert(0, self.stack.pop())
            if method_obj.method_has_this() and method_obj.get_column('Name').get_value() != b'.ctor':
                method_args.insert(0, self.stack.pop())
            if is_newobj:
                dot_obj = net_emu_types.DotNetObject(self)
                dot_obj.initialize_type(method_obj.get_parent_type())
                method_args.insert(0, dot_obj)
            new_emu = self.spawn_new_emulator(method_obj, method_args, caller=self)
            new_emu.run_function()
            # the handler for ret instruction handles cleaning up the stack after this.
        elif method_obj.get_table_name() == 'MemberRef' or force_extern_type_name:
            if isinstance(method_obj.get_parent_type(), net_row_objects.TypeSpec): #generics etc.
                if isinstance(method_obj.get_parent_type().get_type(), net_row_objects.TypeDef):
                    return self.handle_callvirt_instruction(instr, force_virtcall=True, force_virt_type=method_obj.get_parent_type().get_type())
            if force_extern_type_name is None:
                type_full_name = net_emu_types.remove_generics_from_name(method_obj.get_parent_type().get_full_name().decode('ascii'))
                method_name = method_obj.get_column('Name').get_value().decode('ascii')
            else:
                type_full_name = net_emu_types.remove_generics_from_name(force_extern_type_name)
                method_name = method_obj.get_column('Name').get_value().decode('ascii')
            if type_full_name not in net_emu_types.NET_EMULATE_TYPE_REGISTRATIONS:
                raise net_exceptions.EmulatorTypeNotFoundException(type_full_name)
            emulated_type = net_emu_types.NET_EMULATE_TYPE_REGISTRATIONS[type_full_name]
            method_args = list()
            amt_args = len(method_obj.get_param_types())
            push_obj_reference = False
            if method_obj.method_has_this():
                push_obj_reference = True
            for x in range(amt_args):
                method_args.insert(0, self.stack.pop())
            emu_method = None
            obj_ref_initial = None
            obj_ref = None
            if method_name == '.ctor':
                emu_method = emulated_type
            else:
                if push_obj_reference:
                    obj_ref = self.stack.pop()
                    if isinstance(obj_ref, net_emu_types.ArrayAddress):
                        obj_ref_initial = obj_ref
                        obj_ref = obj_ref.get_obj_ref()
                    method_args.insert(0, obj_ref)
                    if is_virt and hasattr(obj_ref, method_name):
                        emu_method = getattr(type(obj_ref), method_name)
                    else:
                        if not hasattr(emulated_type, method_name):
                            raise net_exceptions.EmulatorMethodNotFoundException(method_name)
                        emu_method = getattr(emulated_type, method_name)
                elif hasattr(emulated_type, method_name):
                    emu_method = getattr(emulated_type, method_name)
                else:
                    raise net_exceptions.EmulatorMethodNotFoundException(
                        method_name)

            if not emu_method:
                raise net_exceptions.OperationNotSupportedException
            actual_method_args = list(method_args)
            
            if method_obj.is_static_method():
                actual_method_args.insert(0, self.get_appdomain())

            if is_newobj or method_obj['Name'].get_value() == b'.ctor':
                actual_method_args.insert(0, self)
            ret_val = emu_method(*actual_method_args)
            if obj_ref_initial is not None and obj_ref is not None:
                obj_ref_initial.set_obj_ref(obj_ref)

            if is_newobj:
                if isinstance(ret_val, net_emu_types.DotNetObject):
                    ret_val.initialize_type(method_obj.get_parent_type())
                self.stack.append(ret_val)

            if method_obj.has_return_value() and not is_newobj and method_obj.get_column('Name').get_value() != b'.ctor':
                self.stack.append(ret_val)
        elif method_obj.get_table_name() == 'MethodSpec':
            return self.handle_call_instruction(instr, is_virt, is_newobj,
                                                method_obj.get_column('Method').get_value(), None)
        else:
            raise net_exceptions.EmulatorMethodNotFoundException(
                str(method_obj))
        return False

    cdef bint handle_callvirt_instruction(self, net_cil_disas.Instruction instr, bint force_virtcall=False, net_row_objects.TypeDefOrRef force_virt_type=None) except *:
        # for eazfuscator should get method rid 3 here
        cdef net_row_objects.MethodDefOrRef method_obj
        cdef net_row_objects.TypeDefOrRef parent_type
        cdef int amt_args
        cdef object obj_ref
        cdef net_row_objects.TypeDefOrRef obj_type
        cdef net_row_objects.MethodDefOrRef actual_method_obj
        cdef net_utils.MethodSig initial_method_sig
        cdef net_table_objects.MethodImplTable method_impl_table
        cdef net_row_objects.MethodDef def_method
        cdef net_row_objects.MethodDef curr_method_obj
        method_obj = instr.get_argument()
        if not force_virtcall:
            if isinstance(method_obj, net_row_objects.MemberRef) and isinstance(method_obj.get_parent_type(),
                                                                                net_row_objects.TypeRef):
                return self.handle_call_instruction(instr, True, False, None, None)
            
            if isinstance(method_obj, net_row_objects.MemberRef) and isinstance(method_obj.get_parent_type(), net_row_objects.TypeSpec):
                parent_type = method_obj.get_parent_type()
                if isinstance(parent_type.get_type(), net_row_objects.TypeRef):
                    return self.handle_call_instruction(instr, True, False, None, parent_type.get_type().get_full_name().decode('ascii'))

            if isinstance(method_obj, net_row_objects.MethodDef) and method_obj.has_body():
                return self.handle_call_instruction(instr, True, False, None, None)
        

        if not force_virt_type:
            amt_args = method_obj.get_amt_params() #TODO: amt_args is clearly problematic here - honestly there isnt much of a reason for it anyway.  
            method_params = self.stack[-1 * (amt_args + 1):]
            obj_ref = method_params[0]
            obj_type = obj_ref.get_type_obj()
        else:
            obj_type = force_virt_type
        if not obj_type:
            raise net_exceptions.EmulatorTypeNotFoundException(
                'UNKNOWN PARENT TYPE')
        actual_method_obj = None
        initial_method_sig = method_obj.get_method_signature()
        method_impl_table = method_obj.get_dotnetpe().get_metadata_table('MethodImpl')
        while obj_type and not actual_method_obj:
            if isinstance(obj_type, net_row_objects.TypeDef):
                if method_impl_table is not None:
                    #first check the methodimpl table.
                    def_method = method_impl_table.get_method_definition(method_obj, obj_type)
                    if def_method != None:
                        actual_method_obj = def_method
                        break

                #now check every method based on whether or not its hidebyname or hidebyname + sig
                for curr_method_obj in obj_type.get_methods():
                    if method_obj.is_hidebysig():
                        if curr_method_obj.get_column('Name').get_value() == method_obj.get_column('Name').get_value():
                            if curr_method_obj.get_method_signature() == method_obj.get_method_signature():
                                actual_method_obj = curr_method_obj
                                break
                    else:
                        if curr_method_obj.get_column('Name').get_value() == method_obj.get_column('Name').get_value():
                            if curr_method_obj.has_body():
                                actual_method_obj = curr_method_obj
                                break
            else:
                raise net_exceptions.EmulatorMethodNotFoundException(method_obj.get_full_name())

            if isinstance(obj_type, net_row_objects.TypeDef):
                obj_type = obj_type.get_superclass()
            else:
                break

        if not actual_method_obj:
            raise net_exceptions.EmulatorMethodNotFoundException(
                str(method_obj.get_full_name()))
        return self.handle_call_instruction(instr, True, instr.get_name() == 'newobj', actual_method_obj, None)

    cdef bint handle_ceq_instruction(self, net_cil_disas.Instruction instr) except *:
        # TODO: ceq compares may be broken when comparing DotNetNull objects
        value2 = self.stack.pop()
        value1 = self.stack.pop()
        if value1 == value2:
            self.stack.append(py_net_emu_types.DotNetInt32(self, 1))
        else:
            self.stack.append(py_net_emu_types.DotNetInt32(self, 0))
        return False

    cdef bint handle_cgt_instruction(self, net_cil_disas.Instruction instr) except *:
        value2 = self.stack.pop()
        value1 = self.stack.pop()
        if value1 > value2:
            self.stack.append(py_net_emu_types.DotNetInt32(self, 1))
        else:
            self.stack.append(py_net_emu_types.DotNetInt32(self, 0))
        return False

    cdef bint handle_cgt_un_instruction(self, net_cil_disas.Instruction instr) except *:
        value2 = self.stack.pop()
        value1 = self.stack.pop()
        if value1 == value2 and value2 is None:
            self.stack.append(py_net_emu_types.DotNetInt32(self, 0))
            return False
        #make sure both are converted to unsigned. NOTE: this functionality may not work for floating point stuff.
        if hasattr(value1, 'dtype') and value1.dtype.kind != 'u':
            value1 = value1.astype('u{}'.format(value1.dtype.itemsize), casting='unsafe')
        if hasattr(value2, 'dtype') and value2.dtype.kind != 'u':
            value2 = value2.astype('u{}'.format(value2.dtype.itemsize), casting='unsafe')
        if value1 > value2:
            self.stack.append(py_net_emu_types.DotNetInt32(self, 1))
        else:
            self.stack.append(py_net_emu_types.DotNetInt32(self, 0))
        return False

    cdef bint handle_clt_instruction(self, net_cil_disas.Instruction instr) except *:
        value2 = self.stack.pop()
        value1 = self.stack.pop()
        if value1 < value2:
            self.stack.append(py_net_emu_types.DotNetInt32(self, 1))
        else:
            self.stack.append(py_net_emu_types.DotNetInt32(self, 0))
        return False

    cdef bint handle_clt_un_instruction(self, net_cil_disas.Instruction instr) except *:
        cdef int max_item_size
        value2 = self.stack.pop()
        value1 = self.stack.pop()
        if value1 < value2:
            self.stack.append(py_net_emu_types.DotNetInt32(self, 1))
        else:
            max_item_size = max(value1.itemsize, value2.itemsize)
            if max_item_size == 1:
                un_value1 = py_net_emu_types.DotNetUInt8(self, value1)
                un_value2 = py_net_emu_types.DotNetUInt8(self, value2)
            elif max_item_size == 2:
                un_value1 = py_net_emu_types.DotNetUInt16(self, value1)
                un_value2 = py_net_emu_types.DotNetUInt16(self, value1)
            elif max_item_size == 4:
                un_value1 = py_net_emu_types.DotNetUInt32(self, value1)
                un_value2 = py_net_emu_types.DotNetUInt32(self, value2)
            elif max_item_size == 8:
                un_value1 = py_net_emu_types.DotNetUInt64(self, value1)
                un_value2 = py_net_emu_types.DotNetUInt64(self, value2)
            else:
                raise net_exceptions.InstructionNotSupportedException(instr.get_name())
            if un_value1 < un_value2:
                self.stack.append(py_net_emu_types.DotNetInt32(self, 1))
            else:
                self.stack.append(py_net_emu_types.DotNetInt32(self, 0))
        return False

    cdef bint handle_add_instruction(self, net_cil_disas.Instruction instr) except *:
        value2 = self.stack.pop()
        value1 = self.stack.pop()
        result = value1 + value2
        self.stack.append(result)
        return True

    cdef bint handle_and_instruction(self, net_cil_disas.Instruction instr) except *:
        value2 = self.stack.pop()
        value1 = self.stack.pop()
        result = value1 & value2
        self.stack.append(result)
        return True

    cdef bint handle_conv_i_instruction(self, net_cil_disas.Instruction instr) except *:
        cdef net_opcodes.Opcodes ins_op
        ins_op = instr.get_opcode()
        if ins_op == net_opcodes.Opcodes.Conv_I1:
            self.stack.append(py_net_emu_types.DotNetInt8(self, self.stack.pop()))
        elif ins_op == net_opcodes.Opcodes.Conv_I2:
            self.stack.append(py_net_emu_types.DotNetInt16(self, self.stack.pop()))
        elif ins_op == net_opcodes.Opcodes.Conv_I4:
            self.stack.append(py_net_emu_types.DotNetInt32(self, self.stack.pop()))
        elif ins_op == net_opcodes.Opcodes.Conv_I8:
            self.stack.append(py_net_emu_types.DotNetInt64(self, self.stack.pop()))
        elif ins_op == net_opcodes.Opcodes.Conv_I:
            self.stack.append(py_net_emu_types.DotNetInt32(self, self.stack.pop()))

        return True

    cdef bint handle_conv_r_instruction(self, net_cil_disas.Instruction instr) except *:
        cdef net_opcodes.Opcodes ins_op
        ins_op = instr.get_opcode()
        value1 = self.stack.pop()
        if ins_op == net_opcodes.Opcodes.Conv_R4:
            self.stack.append(value1.astype(py_net_emu_types.DotNetSingle))
        elif ins_op == net_opcodes.Opcodes.Conv_R8:
            self.stack.append(value1.astype(py_net_emu_types.DotNetDouble))
        return True

    cdef bint handle_conv_u_instruction(self, net_cil_disas.Instruction instr) except *:
        cdef net_opcodes.Opcodes ins_op
        ins_op = instr.get_opcode()
        if ins_op == net_opcodes.Opcodes.Conv_U2:
            self.stack.append(py_net_emu_types.DotNetUInt16(self, self.stack.pop()))
        elif ins_op == net_opcodes.Opcodes.Conv_U4:
            self.stack.append(py_net_emu_types.DotNetUInt32(self, self.stack.pop()))
        elif ins_op == net_opcodes.Opcodes.Conv_U8:
            self.stack.append(py_net_emu_types.DotNetUInt64(self, self.stack.pop()))
        elif ins_op == net_opcodes.Opcodes.Conv_U1:
            self.stack.append(py_net_emu_types.DotNetUInt8(self, self.stack.pop()))
        elif ins_op == net_opcodes.Opcodes.Conv_U:
            self.stack.append(py_net_emu_types.DotNetInt32(self, py_net_emu_types.DotNetUInt32(self, self.stack.pop())))
        return True

    cdef bint handle_ldarg_instruction(self, net_cil_disas.Instruction instr) except *:
        cdef net_utils.MethodSig signature_obj
        cdef net_utils.TypeSig param_obj
        cdef int number
        number = instr.get_argument()
        signature_obj = self.method_obj.get_method_signature()
        if self.method_obj.method_has_this() and number == 0:
            self.stack.append(self.method_params[number])
        else:
            sig_param_num = number
            if self.method_obj.method_has_this():
                sig_param_num -= 1
            # account for the case of grabbing the this object in a cctor.
            if self.method_obj.get_column('Name').get_value() == b'.ctor' and sig_param_num == 0:
                self.stack.append(self.method_params[number])
            else:
                param_obj = signature_obj.get_parameters()[sig_param_num]
                if isinstance(param_obj, net_utils.CorLibTypeSig):
                    if param_obj.get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_I1:
                        self.stack.append(py_net_emu_types.DotNetInt8(self, 
                            self.method_params[number]))
                    elif param_obj.get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_I2:
                        self.stack.append(py_net_emu_types.DotNetInt16(self, 
                            self.method_params[number]))
                    elif param_obj.get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_I4:
                        self.stack.append(py_net_emu_types.DotNetInt32(self, 
                            self.method_params[number]))
                    elif param_obj.get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_I8:
                        self.stack.append(py_net_emu_types.DotNetInt64(self, 
                            self.method_params[number]))
                    elif param_obj.get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_U1:
                        self.stack.append(py_net_emu_types.DotNetUInt8(self, self.method_params[number]))
                    elif param_obj.get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_U2:
                        self.stack.append(py_net_emu_types.DotNetUInt16(self, self.method_params[number]))
                    elif param_obj.get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_U4:
                        self.stack.append(py_net_emu_types.DotNetUInt32(self, self.method_params[number]))
                    elif param_obj.get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_U8:
                        self.stack.append(py_net_emu_types.DotNetUInt64(self, self.method_params[number]))
                    else:
                        self.stack.append(self.method_params[number])
                else:
                    self.stack.append(self.method_params[number])
        return True

    cdef bint handle_ldelem_instruction(self, net_cil_disas.Instruction instr) except *:
        cdef net_opcodes.Opcodes ins_op
        cdef net_emu_types.DotNetArray array_obj
        cdef net_emu_types.DotNetObject result_obj
        ins_op = instr.get_opcode()
        index = self.stack.pop()
        array_obj = <net_emu_types.DotNetArray>self.stack.pop()
        if ins_op == net_opcodes.Opcodes.Ldelem:
            result_obj = array_obj[index]
            result_obj.initialize_type(instr.get_argument())
            self.stack.append(result_obj)
        elif ins_op == net_opcodes.Opcodes.Ldelem_I:
            self.stack.append(py_net_emu_types.DotNetInt32(self, array_obj[index]))
        elif ins_op == net_opcodes.Opcodes.Ldelem_I1:
            self.stack.append(py_net_emu_types.DotNetInt32(self, py_net_emu_types.DotNetInt8(self, array_obj[index])))
        elif ins_op == net_opcodes.Opcodes.Ldelem_I2:
            self.stack.append(py_net_emu_types.DotNetInt32(self, py_net_emu_types.DotNetInt16(self, array_obj[index])))
        elif ins_op == net_opcodes.Opcodes.Ldelem_I4:
            self.stack.append(py_net_emu_types.DotNetInt32(self, py_net_emu_types.DotNetInt32(self, array_obj[index])))
        elif ins_op == net_opcodes.Opcodes.Ldelem_I8:
            self.stack.append(py_net_emu_types.DotNetInt64(self, array_obj[index]))
        elif ins_op == net_opcodes.Opcodes.Ldelem_R4:
            self.stack.append(py_net_emu_types.DotNetSingle(self, array_obj[index]))
        elif ins_op == net_opcodes.Opcodes.Ldelem_R8:
            self.stack.append(py_net_emu_types.DotNetDouble(self, array_obj[index]))
        elif ins_op == net_opcodes.Opcodes.Ldelem_U1:
            self.stack.append(py_net_emu_types.DotNetInt32(self, py_net_emu_types.DotNetUInt8(self, array_obj[index])))
        elif ins_op == net_opcodes.Opcodes.Ldelem_U2:
            self.stack.append(py_net_emu_types.DotNetInt32(self, py_net_emu_types.DotNetUInt16(self, array_obj[index])))
        elif ins_op == net_opcodes.Opcodes.Ldelem_U4:
            self.stack.append(py_net_emu_types.DotNetInt32(self, py_net_emu_types.DotNetUInt32(self, array_obj[index])))
        elif ins_op == net_opcodes.Opcodes.Ldelem_Ref:
            self.stack.append(array_obj[index])
        else:
            raise net_exceptions.InstructionNotSupportedException(instr.get_name())
        return True

    cdef bint handle_ldc_i4_instruction(self, net_cil_disas.Instruction instr) except *:
        self.stack.append(py_net_emu_types.DotNetInt32(self, instr.get_argument()))
        return True

    cdef bint handle_ldc_i8_instruction(self, net_cil_disas.Instruction instr) except *:
        self.stack.append(py_net_emu_types.DotNetInt64(self, instr.get_argument()))
        return True

    cdef bint handle_ldc_r4_instruction(self, net_cil_disas.Instruction instr) except *:
        self.stack.append(py_net_emu_types.DotNetSingle(self, instr.get_argument()))
        return True

    cdef bint handle_ldc_r8_instruction(self, net_cil_disas.Instruction instr) except *:
        self.stack.append(py_net_emu_types.DotNetDouble(self, instr.get_argument()))
        return True

    cdef bint handle_ldloc_instruction(self, net_cil_disas.Instruction instr) except *:
        cdef int index
        index = instr.get_argument()
        self.stack.append(self.localvars[index])
        return True

    cdef bint handle_beq_instruction(self, net_cil_disas.Instruction instr) except *:
        value2 = self.stack.pop()
        value1 = self.stack.pop()
        if value1 == value2:
            self.handle_general_jump(instr, 0)
            return False
        return True

    cdef bint handle_bge_instruction(self, net_cil_disas.Instruction instr) except *:
        value2 = self.stack.pop()
        value1 = self.stack.pop()
        if value1 >= value2:
            self.handle_general_jump(instr, 0)
            return False
        return True

    cdef bint handle_bge_un_instruction(self, net_cil_disas.Instruction instr) except *:
        value2 = self.stack.pop()
        self.stack.append(value2)
        if value2.dtype.kind.startswith('f'):
            self.handle_clt_instruction(instr)
            return not self.handle_brfalse_instruction(instr)
        else:
            self.handle_clt_un_instruction(instr)
            return not self.handle_brfalse_instruction(instr)

    cdef bint handle_bgt_instruction(self, net_cil_disas.Instruction instr) except *:
        value2 = self.stack.pop()
        value1 = self.stack.pop()
        if value1 > value2:
            self.handle_general_jump(instr, 0)
            return False
        return True

    cdef bint handle_bgt_un_instruction(self, net_cil_disas.Instruction instr) except *:
        self.handle_cgt_un_instruction(instr)
        return not self.handle_brtrue_instruction(instr)

    cdef bint handle_div_instruction(self, net_cil_disas.Instruction instr) except *:
        value2 = self.stack.pop()
        value1 = self.stack.pop()
        self.stack.append(value1 / value2)
        return True

    cdef bint handle_dup_instruction(self, net_cil_disas.Instruction instr) except *:
        cdef list array
        obj = self.stack.pop()
        if not isinstance(obj, net_emu_types.ArrayAddress):
            copy_obj = copy.copy(obj)  # FIXME: copy.copy on ArrayAddress objects is giving back a non ArrayAddress value.  A temporary fix is given below.
            self.stack.append(obj)
            self.stack.append(copy_obj)
        else:
            self.stack.append(obj)
            array = [obj.get_obj_ref()]
            copy_obj = net_emu_types.ArrayAddress(array, 0)
            self.stack.append(copy_obj)
        return True

    cdef bint handle_ldsfld_instruction(self, net_cil_disas.Instruction instr) except *:
        cdef net_row_objects.RowObject field_obj # can be either MemberRef or Field
        cdef net_row_objects.TypeDefOrRef parent_type
        cdef net_row_objects.MethodDef cctor_method
        cdef list args
        cdef str field_name
        cdef str type_name
        cdef type type_obj
        cdef net_utils.FieldSig sig
        cdef net_row_objects.Field field
        field_obj = instr.get_argument()
        # check if the cctor has been executed.
        parent_type = field_obj.get_parent_type()
        if isinstance(parent_type, net_row_objects.TypeSpec):
            parent_type = parent_type.get_type()
        cctor_method = parent_type.get_cctor_method()
        if cctor_method:
            if self.executed_cctors.can_execute(cctor_method) and not self.dont_execute_cctor:
                new_emu = self.spawn_new_emulator(cctor_method)
                new_emu.run_function()
        if isinstance(field_obj, net_row_objects.MemberRef):
            args = field_obj.get_full_name().split(b'.')
            field_name = args[-1].decode()
            orig_type_name = b'.'.join(args[:-1]).decode()
            type_name = net_emu_types.remove_generics_from_name(orig_type_name)
            if type_name not in net_emu_types.NET_EMULATE_TYPE_REGISTRATIONS:
                parent_type = field_obj.get_parent_type()
                if isinstance(parent_type, net_row_objects.TypeSpec) and isinstance(parent_type.get_type(), net_row_objects.TypeDef):
                    parent_type = parent_type.get_type()
                    for field in parent_type.get_column('FieldList').get_formatted_value():
                        if field.get_column('Name').get_value() == field_obj.get_column('Name').get_value():
                            if field.get_field_signature() == field_obj.get_method_signature():
                                if field.is_static():
                                    if field.get_rid() in self.static_fields:
                                        self.stack.append(self.static_fields[field.get_rid()])
                                    else:
                                        sig = field.get_field_signature()
                                        if isinstance(sig, net_utils.FieldSig):
                                            self.static_fields[field.get_rid()] = self.__get_default_value(sig.get_type_sig())
                                            self.stack.append(self.static_fields[field.get_rid()])
                                        else:
                                            self.static_fields[field.get_rid()] = py_net_emu_types.DotNetInt32(self, 0)
                                            self.stack.append(self.static_fields[field.get_rid()])
                                    break
                else:
                    raise net_exceptions.EmulatorTypeNotFoundException(type_name)
            else:
                type_obj = net_emu_types.NET_EMULATE_TYPE_REGISTRATIONS[type_name]
                if not hasattr(type_obj, field_name):
                    raise net_exceptions.EmulatorMethodNotFoundException(field_obj.get_full_name())
                method_obj = getattr(type_obj, field_name)
                if callable(method_obj):
                    ret_val = method_obj(self.get_appdomain()) #all of these should be python static methods.
                else:
                    ret_val = method_obj
                self.stack.append(ret_val)
        else:
            if not field_obj.is_static():
                raise net_exceptions.ObjectTypeException

            if field_obj.get_rid() in self.static_fields:
                self.stack.append(self.static_fields[field_obj.get_rid()])
            else:
                sig = field_obj.get_field_signature()
                if isinstance(sig, net_utils.FieldSig):
                    self.static_fields[field_obj.get_rid()] = self.__get_default_value(sig.get_type_sig())
                    self.stack.append(self.static_fields[field_obj.get_rid()])
                else:
                    self.static_fields[field_obj.get_rid()] = py_net_emu_types.DotNetInt32(self, 0)
                    self.stack.append(self.static_fields[field_obj.get_rid()])
        return True

    cdef bint handle_ldstr_instruction(self, net_cil_disas.Instruction instr) except *:
        self.stack.append(net_emu_types.DotNetString(self, instr.get_argument(), 'utf-16le'))
        return True

    cdef bint handle_ldtoken_instruction(self, net_cil_disas.Instruction instr) except *:
        self.stack.append(instr.get_argument())
        return True

    cdef bint handle_mul_instruction(self, net_cil_disas.Instruction instr) except *:
        value2 = self.stack.pop()
        value1 = self.stack.pop()
        self.stack.append((value1 * value2).astype(value1.dtype))
        return True
    
    cdef bint handle_neg_instruction(self, net_cil_disas.Instruction instr) except *:
        value1 = self.stack.pop()
        self.stack.append(-value1)
        return True

    cdef bint handle_newarr_instruction(self, net_cil_disas.Instruction instr) except *:
        cdef net_row_objects.TypeDefOrRef type_obj
        type_obj = instr.get_argument()
        amt_of_elem = self.stack.pop()
        value1 = net_emu_types.DotNetArray(self, amt_of_elem, type_obj)
        self.stack.append(value1)
        return True

    cdef bint handle_ble_instruction(self, net_cil_disas.Instruction instr) except *:
        value2 = self.stack.pop()
        value1 = self.stack.pop()
        if value1 <= value2:
            self.handle_general_jump(instr, 0)
            return False
        return True

    cdef bint handle_ble_un_instruction(self, net_cil_disas.Instruction instr) except *:
        value2 = self.stack.pop()
        self.stack.append(value2)
        if value2.dtype.kind.startswith('f'):
            self.handle_cgt_instruction(instr)
            return not self.handle_brfalse_instruction(instr)
        else:
            self.handle_cgt_un_instruction(instr)
            return not self.handle_brfalse_instruction(instr)

    cdef bint handle_blt_instruction(self, net_cil_disas.Instruction instr) except *:
        value2 = self.stack.pop()
        value1 = self.stack.pop()
        if value1 < value2:
            self.handle_general_jump(instr, 0)
            return False
        return True

    cdef bint handle_blt_un_instruction(self, net_cil_disas.Instruction instr) except *:
        self.handle_clt_un_instruction(instr)
        return not self.handle_brtrue_instruction(instr)

    cdef bint handle_bne_un_instruction(self, net_cil_disas.Instruction instr) except *:
        self.handle_ceq_instruction(instr)
        return not self.handle_brfalse_instruction(instr)

    cdef bint handle_ldfld_instruction(self, net_cil_disas.Instruction instr) except *:
        cdef net_row_objects.Field field_obj
        obj_ref = self.stack.pop()
        if isinstance(obj_ref, net_emu_types.ArrayAddress):
            obj_ref = obj_ref.get_obj_ref()
        field_obj = instr.get_argument()
        if not isinstance(obj_ref, net_emu_types.DotNetObject) or field_obj.is_static():
            raise net_exceptions.ObjectTypeException

        self.stack.append(obj_ref.get_field(field_obj.get_rid()))
        return True

    cdef bint handle_or_instruction(self, net_cil_disas.Instruction instr) except *:
        # TODO: Fix this - I think math operations should be result = type of value1.
        value2 = self.stack.pop()
        value1 = self.stack.pop()
        if value1.dtype.kind != value2.dtype.kind:
            if value1.dtype.kind == 'u':
                value1 = value1.astype('i{}'.format(value1.dtype.itemsize), casting='unsafe')
            elif value2.dtype.kind == 'u':
                value2 = value2.astype('i{}'.format(value2.dtype.itemsize), casting='unsafe')
        result = numpy.bitwise_or(value1, value2)
        self.stack.append(py_net_emu_types.DotNetNumber(self, result.dtype, result))
        return True

    cdef bint handle_not_instruction(self, net_cil_disas.Instruction instr) except *:
        value1 = self.stack.pop()
        self.stack.append(~value1)
        return True

    cdef bint handle_ret_instruction(self, net_cil_disas.Instruction instr) except *:
        if self.method_obj.has_return_value():
            if self.caller:
                value1 = self.stack.pop()
                self.caller.stack.append(value1)
        else:
            if self.method_obj.get_column('Name').get_value() == b'.ctor':
                if self.caller:
                    self.caller.stack.append(self.method_params[0])
        return True

    cdef bint handle_shl_instruction(self, net_cil_disas.Instruction instr) except *:
        bits = self.stack.pop()
        value1 = self.stack.pop()  # TODO: fix typing below
        if value1.dtype.kind != bits.dtype.kind:
            new_dtype = numpy.dtype('{}{}'.format(value1.dtype.kind, bits.dtype.itemsize))
            bits = bits.astype(new_dtype)
            bits = DotNetNumber(self, new_dtype, bits)
        res_obj = value1 << bits
        self.stack.append(py_net_emu_types.DotNetNumber(self, res_obj.dtype, res_obj))
        return True

    cdef bint handle_shr_instruction(self, net_cil_disas.Instruction instr) except *:
        bits = self.stack.pop()
        value1 = self.stack.pop()
        res_obj = value1 >> bits
        self.stack.append(py_net_emu_types.DotNetNumber(self, res_obj.dtype, res_obj))
        return True

    cdef bint handle_shr_un_instruction(self, net_cil_disas.Instruction instr) except *:
        cdef int max_item_size
        bits = net_utils.convert_to_uint(self.stack.pop())
        value1 = self.stack.pop()
        max_item_size = value1.itemsize
        if max_item_size == 1:
            un_value1 = py_net_emu_types.DotNetUInt8(self, value1)
        elif max_item_size == 2:
            un_value1 = py_net_emu_types.DotNetUInt16(self, value1)
        elif max_item_size == 4:
            un_value1 = py_net_emu_types.DotNetUInt32(self, value1)
        elif max_item_size == 8:
            un_value1 = py_net_emu_types.DotNetUInt64(self, value1)
        else:
            raise net_exceptions.InstructionNotSupportedException(instr.get_name())
        res_obj = un_value1 >> bits
        self.stack.append(py_net_emu_types.DotNetNumber(self, res_obj.dtype, res_obj))
        return True

    cdef bint handle_stfld_instruction(self, net_cil_disas.Instruction instr) except *:
        cdef net_row_objects.Field field_obj
        cdef net_utils.TypeSig local_type_sig
        cdef net_structs.CorElementType e_type

        value1 = self.stack.pop()
        obj_ref = self.stack.pop()
        field_obj = instr.get_argument()
        if isinstance(obj_ref, net_emu_types.ArrayAddress):
            obj_ref = obj_ref.get_obj_ref()

        if not isinstance(
            obj_ref, net_emu_types.DotNetObject) or field_obj.is_static():
            raise net_exceptions.ObjectTypeException

        local_type_sig = field_obj.get_field_signature().get_type_sig()
        if isinstance(local_type_sig, net_utils.CorLibTypeSig):
            e_type = local_type_sig.get_element_type()
            if e_type == net_structs.CorElementType.ELEMENT_TYPE_I1:
                obj_ref.set_field(field_obj.get_rid(), py_net_emu_types.DotNetInt8(self, value1))
            elif e_type == net_structs.CorElementType.ELEMENT_TYPE_I2:
                obj_ref.set_field(field_obj.get_rid(), py_net_emu_types.DotNetInt16(self, value1))
            elif e_type == net_structs.CorElementType.ELEMENT_TYPE_I4:
                obj_ref.set_field(field_obj.get_rid(), py_net_emu_types.DotNetInt32(self, value1))
            elif e_type == net_structs.CorElementType.ELEMENT_TYPE_I8:
                obj_ref.set_field(field_obj.get_rid(), py_net_emu_types.DotNetInt64(self, value1))
            elif e_type == net_structs.CorElementType.ELEMENT_TYPE_U1:
                obj_ref.set_field(field_obj.get_rid(), py_net_emu_types.DotNetUInt8(self, value1))
            elif e_type == net_structs.CorElementType.ELEMENT_TYPE_U2:
                obj_ref.set_field(field_obj.get_rid(), py_net_emu_types.DotNetUInt16(self, value1))
            elif e_type == net_structs.CorElementType.ELEMENT_TYPE_U4:
                obj_ref.set_field(field_obj.get_rid(), py_net_emu_types.DotNetUInt32(self, value1))
            elif e_type == net_structs.CorElementType.ELEMENT_TYPE_U8:
                obj_ref.set_field(field_obj.get_rid(),  py_net_emu_types.DotNetUInt64(self, value1))
            else:
                obj_ref.set_field(field_obj.get_rid(), value1)
        else:
            if isinstance(value1, net_emu_types.DotNetObject):
                value1.set_type_sig_obj(local_type_sig)
            obj_ref.set_field(field_obj.get_rid(), value1)
        return True

    cdef bint handle_stind_instruction(self, net_cil_disas.Instruction instr) except *:
        cdef net_emu_types.ArrayAddress address_obj
        value_obj = self.stack.pop()
        address_obj = self.stack.pop()
        address_obj.set_obj_ref(value_obj)
        return True

    cdef bint handle_stloc_instruction(self, net_cil_disas.Instruction instr) except *:
        cdef int number
        cdef net_utils.TypeSig local_type_sig
        cdef net_structs.CorElementType e_type
        value1 = self.stack.pop()
        number = instr.get_argument()
        local_type_sig = self.disasm_obj.local_types[number]
        # TODO: change to match statement
        if isinstance(local_type_sig, net_utils.CorLibTypeSig):
            e_type = local_type_sig.get_element_type()
            if e_type == net_structs.CorElementType.ELEMENT_TYPE_I1:
                self.localvars[number] = py_net_emu_types.DotNetInt8(self, value1)
            elif e_type == net_structs.CorElementType.ELEMENT_TYPE_I2:
                self.localvars[number] = py_net_emu_types.DotNetInt16(self, value1)
            elif e_type == net_structs.CorElementType.ELEMENT_TYPE_I4:
                self.localvars[number] = py_net_emu_types.DotNetInt32(self, value1)
            elif e_type == net_structs.CorElementType.ELEMENT_TYPE_I8:
                self.localvars[number] = py_net_emu_types.DotNetInt64(self, value1)
            elif e_type == net_structs.CorElementType.ELEMENT_TYPE_U1:
                self.localvars[number] = py_net_emu_types.DotNetUInt8(self, value1)
            elif e_type == net_structs.CorElementType.ELEMENT_TYPE_U2:
                self.localvars[number] = py_net_emu_types.DotNetUInt16(self, value1)
            elif e_type == net_structs.CorElementType.ELEMENT_TYPE_U4:
                self.localvars[number] = py_net_emu_types.DotNetUInt32(self, value1)
            elif e_type == net_structs.CorElementType.ELEMENT_TYPE_U8:
                self.localvars[number] = py_net_emu_types.DotNetUInt64(self, value1)
            else:
                self.localvars[number] = value1
        else:
            if isinstance(value1, net_emu_types.DotNetObject):
                value1.set_type_sig_obj(local_type_sig)
            self.localvars[number] = value1
        return True

    cdef bint handle_stsfld_instruction(self, net_cil_disas.Instruction instr) except *:
        cdef net_row_objects.RowObject field_obj
        field_obj = instr.get_argument()
        value1 = self.stack.pop()
        self.static_fields[field_obj.get_rid()] = value1
        return True

    cdef bint handle_sub_instruction(self, net_cil_disas.Instruction instr) except *:
        value2 = self.stack.pop()
        value1 = self.stack.pop()
        result = value1 - value2
        self.stack.append(py_net_emu_types.DotNetNumber(self, result.dtype, result))
        return True

    cdef bint handle_switch_instruction(self, net_cil_disas.Instruction instr) except *:
        cdef list targets
        value1 = self.stack.pop()
        targets = instr.get_argument()
        if value1 < len(targets):
            return not self.handle_general_jump(instr, targets[value1])
        else:
            #fallthrough case.  No exception here.
            return True
    
    cdef bint handle_xor_instruction(self, net_cil_disas.Instruction instr) except *:
        # FIXME - uint32 ^ int32 = int64
        value2 = self.stack.pop()
        value1 = self.stack.pop()
        result = (value1 ^ value2).astype(value1.dtype)  # temp fix for above.
        self.stack.append(py_net_emu_types.DotNetNumber(self, result.dtype, result))
        return True

    cdef bint handle_stelem_instruction(self, net_cil_disas.Instruction instr) except *:
        cdef net_opcodes.Opcodes ins_op
        ins_op = instr.get_opcode()
        value1 = self.stack.pop()
        index = self.stack.pop()
        array_obj = self.stack.pop()
        # array_obj[index] = value1
        if ins_op == net_opcodes.Opcodes.Stelem_I:
            array_obj[index] = py_net_emu_types.DotNetInt32(self, value1)
        elif ins_op == net_opcodes.Opcodes.Stelem_I1:
            array_obj[index] = py_net_emu_types.DotNetInt8(self, value1)
        elif ins_op == net_opcodes.Opcodes.Stelem_I2:
            array_obj[index] = py_net_emu_types.DotNetInt16(self, value1)
        elif ins_op == net_opcodes.Opcodes.Stelem_I4:
            array_obj[index] = py_net_emu_types.DotNetInt32(self, value1)
        elif ins_op == net_opcodes.Opcodes.Stelem_I8:
            array_obj[index] = py_net_emu_types.DotNetInt64(self, value1)
        elif ins_op == net_opcodes.Opcodes.Stelem_R4:
            array_obj[index] = py_net_emu_types.DotNetSingle(self, value1)
        elif ins_op == net_opcodes.Opcodes.Stelem_R8:
            array_obj[index] = py_net_emu_types.DotNetDouble(self, value1)
        elif ins_op == net_opcodes.Opcodes.Stelem_Ref:
            array_obj[index] = value1
        elif ins_op == net_opcodes.Opcodes.Stelem:
            array_obj[index] = value1
        return True

    cdef bint handle_rem_instruction(self, net_cil_disas.Instruction instr) except *:
        value2 = self.stack.pop()
        value1 = self.stack.pop()
        result = numpy.fmod(value1, value2)
        self.stack.append(py_net_emu_types.DotNetNumber(self, result.dtype, result))
        return True

    cdef bint handle_rem_un_instruction(self, net_cil_disas.Instruction instr) except *:
        value2 = self.stack.pop()
        value1 = self.stack.pop()
        if value1.dtype.kind == 'i':
            value1 = value1.astype('u{}'.format(value1.dtype.itemsize), casting='unsafe')
        if value2.dtype.kind == 'i':
            value2 = value2.astype('u{}'.format(value2.dtype.itemsize), casting='unsafe')
        result = numpy.fmod(value1, value2)
        self.stack.append(py_net_emu_types.DotNetNumber(self, result.dtype, result))
        return True

    cdef bint handle_ldind_instruction(self, net_cil_disas.Instruction instr) except *:
        # TODO: double check this instr. Add full support
        cdef net_opcodes.Opcodes ins_op
        cdef net_emu_types.ArrayAddress address_obj
        cdef str ins_name
        ins_name = instr.get_name()
        ins_op = instr.get_opcode()
        address_obj = self.stack.pop()
        if ins_op == net_opcodes.Opcodes.Ldind_U4:
            self.stack.append(py_net_emu_types.DotNetInt32(self, 
                address_obj.get_obj_ref()))
        elif ins_op == net_opcodes.Opcodes.Ldind_U1:
            self.stack.append(py_net_emu_types.DotNetInt32(self, py_net_emu_types.DotNetUInt8(self, address_obj.get_obj_ref())))
        else:
            raise net_exceptions.InstructionNotSupportedException(ins_name)
        return True

    cdef bint handle_ldelema_instruction(self, net_cil_disas.Instruction instr) except *:
        index = self.stack.pop()
        array_obj = self.stack.pop()
        self.stack.append(net_emu_types.ArrayAddress(array_obj, index))
        return True

    cdef bint handle_box_instruction(self, net_cil_disas.Instruction instr) except *:
        """
        https://learn.microsoft.com/en-us/dotnet/api/system.reflection.emit.net_opcodes.Opcodes.box?view=net-8.0
        Honestly im not entirely sure how this should be handled.
        I havent really figured out object references I guess, so for now just going to push the object itself.
        """
        cdef net_row_objects.TypeDefOrRef arg_obj
        arg_obj = <net_row_objects.TypeDefOrRef>instr.get_argument()
        if isinstance(arg_obj, net_row_objects.TypeDef):
            value1 = self.stack.pop()
            self.stack.append(value1)
        elif isinstance(arg_obj, net_row_objects.TypeRef):
            #Only do something here if we are boxing to a numpy dtype for now.
            type_name = net_emu_types.remove_generics_from_name(arg_obj.get_full_name().decode())
            emu_type = net_emu_types.NET_EMULATE_TYPE_REGISTRATIONS[type_name]
            value1 = self.stack.pop()
            if hasattr(emu_type, 'dtype'):
                self.stack.append(emu_type(value1))
            else:
                self.stack.append(value1)
                
        else:
            raise net_exceptions.InvalidArgumentsException()
        return True

    cdef bint handle_castclass_instruction(self, net_cil_disas.Instruction instr) except *:
        cdef net_row_objects.TypeDefOrRef class_type
        cdef net_emu_types.DotNetObject ref
        class_type = instr.get_argument()
        obj_ref = self.stack.pop()
        if isinstance(obj_ref, net_emu_types.DotNetObject):
            obj_ref.initialize_type(class_type)
        elif isinstance(obj_ref, net_emu_types.ArrayAddress):
            ref = obj_ref.get_obj_ref()
            if isinstance(ref, net_emu_types.DotNetObject):
                ref.initialize_type(class_type)
        self.stack.append(obj_ref)
        return True

    cdef bint handle_conv_r_un_instruction(self, net_cil_disas.Instruction instr) except *:
        value1 = self.stack.pop()
        # TODO: heres the issue with DotNetReactor.  Does converting this to a float64 instead cause issues?
        self.stack.append(value1.astype(py_net_emu_types.DotNetDouble))
        return True

    cdef bint handle_initobj_instruction(self, net_cil_disas.Instruction instr) except *:
        cdef net_row_objects.TypeDefOrRef type_obj
        obj_ref = self.stack.pop()
        if isinstance(obj_ref, net_emu_types.ArrayAddress):
            if not isinstance(obj_ref.get_obj_ref(), net_emu_types.DotNetObject):
                obj_ref.set_obj_ref(net_emu_types.DotNetObject(self))
            obj_ref = obj_ref.get_obj_ref()
        if not isinstance(obj_ref, net_emu_types.DotNetObject):
            raise net_exceptions.ObjectTypeException
        type_obj = instr.get_argument()
        obj_ref.initialize_type(type_obj)
        return True

    cdef bint handle_isinst_instruction(self, net_cil_disas.Instruction instr) except *:
        #TODO: make sure this instr works.
        cdef net_row_objects.TypeRef instr_arg
        cdef type potential_type
        cdef net_emu_types.DotNetNull null_obj
        obj_ref = self.stack.pop()
        orig_obj_ref = None
        instr_arg = instr.get_argument()
        if isinstance(obj_ref, net_emu_types.ArrayAddress):
            orig_obj_ref = obj_ref
            obj_ref = obj_ref.get_obj_ref()
        if not isinstance(instr_arg, net_row_objects.TypeRef):
            raise net_exceptions.ObjectTypeException
        potential_type = net_emu_types.NET_EMULATE_TYPE_REGISTRATIONS[net_emu_types.remove_generics_from_name(instr_arg.get_full_name().decode('ascii'))]
        if isinstance(obj_ref, potential_type):
            obj_ref.initialize_type(instr_arg)
            self.stack.append(obj_ref)
        else:
            null_obj = net_emu_types.DotNetNull(self)
            self.stack.append(null_obj)
        return True

    cdef bint handle_ldflda_instruction(self, net_cil_disas.Instruction instr) except *:
        cdef net_row_objects.Field field_obj
        obj_ref = self.stack.pop()
        field_obj = instr.get_argument()
        if not isinstance(
            obj_ref, net_emu_types.DotNetObject) or field_obj.is_static():
            raise net_exceptions.ObjectTypeException
        self.stack.append(net_emu_types.ArrayAddress([obj_ref.get_field(field_obj.get_rid())], 0))
        return True

    cdef bint handle_ldlen_instruction(self, net_cil_disas.Instruction instr) except *:
        value_obj = self.stack.pop()
        self.stack.append(py_net_emu_types.DotNetUInt64(self, len(value_obj)))
        return True

    cdef bint handle_ldloca_instruction(self, net_cil_disas.Instruction instr) except *:
        cdef int index
        cdef net_utils.TypeSig local_type
        cdef net_emu_types.DotNetObject new_obj

        index = instr.get_argument()
        local_type = self.disasm_obj.local_types[index]
        if isinstance(local_type, net_utils.ValueTypeSig) and not isinstance(self.localvars[index],
                                                                                net_emu_types.DotNetObject):
            type_obj = local_type.get_type()

            if type_obj.is_valuetype():
                new_obj = net_emu_types.DotNetObject(self)
                new_obj.initialize_type(type_obj)
                self.localvars[index] = new_obj
        self.stack.append(net_emu_types.ArrayAddress([self.localvars[index]], 0))
        return True

    cdef bint handle_ldsflda_instruction(self, net_cil_disas.Instruction instr) except *:
        cdef net_row_objects.MemberRef mref_obj
        cdef net_row_objects.Field field_obj
        cdef net_row_objects.RowObject arg_obj
        cdef list args
        cdef str field_name
        cdef str type_name
        cdef type type_obj
        arg_obj = instr.get_argument()
        if isinstance(arg_obj, net_row_objects.MemberRef):
            mref_obj = <net_row_objects.MemberRef> arg_obj
            args = mref_obj.get_full_name().split(b'.')
            field_name = args[-1].decode()
            type_name = net_emu_types.remove_generics_from_name(b'.'.join(args[:-1]).decode())
            if type_name not in net_emu_types.NET_EMULATE_TYPE_REGISTRATIONS:
                raise net_exceptions.InstructionNotSupportedException(
                    instr.get_name())

            type_obj = net_emu_types.NET_EMULATE_TYPE_REGISTRATIONS[type_name]
            method_obj = getattr(type_obj, field_name)
            ret_val = method_obj()
            self.stack.append(net_emu_types.ArrayAddress([ret_val], 0))
        else:
            field_obj = <net_row_objects.Field>arg_obj
            if field_obj.get_rid() in self.static_fields:
                self.stack.append(net_emu_types.ArrayAddress([self.static_fields[field_obj.get_rid()]], 0))
            else:
                self.static_fields[field_obj.get_rid()] = py_net_emu_types.DotNetInt32(self, 0)
                self.stack.append(net_emu_types.ArrayAddress([self.static_fields[field_obj.get_rid()]], 0))
        return True
    
    cdef bint handle_ldobj_instruction(self, net_cil_disas.Instruction instr) except *:
        cdef net_emu_types.ArrayAddress addr_obj
        addr_obj = self.stack.pop()
        self.stack.append(addr_obj.get_obj_ref())
        return True

    cdef bint handle_leave_instruction(self, net_cil_disas.Instruction instr) except *:
        self.stack.clear()
        self.handle_general_jump(instr, 0)
        return False

    cdef bint handle_starg_instruction(self, net_cil_disas.Instruction instr) except *:
        cdef int number
        number = instr.get_argument()
        value1 = self.stack.pop()
        self.method_params[number] = value1
        return True

    cdef bint handle_stobj_instruction(self, net_cil_disas.Instruction instr) except *:
        cdef net_emu_types.ArrayAddress addr_obj
        value_obj = self.stack.pop()
        addr_obj = self.stack.pop()
        addr_obj.set_obj_ref(value_obj)
        return True

    cdef bint handle_unbox_any_instruction(self, net_cil_disas.Instruction instr) except *:
        boxed_obj = self.stack.pop()
        self.stack.append(boxed_obj) # box doesnt do anything currently so neither should unbox.
        return True

    def print_full_array(self, id_no, is_static):
        if is_static:
            array_obj = self.static_fields[id_no]
        else:
            array_obj = self.localvars[id_no]

        if isinstance(array_obj.internal_array, bytearray) or isinstance(array_obj.internal_array, bytes):
            array_str = str(list(array_obj.internal_array))
        else:
            array_str = str(array_obj.internal_array)

        self.print_string(array_str, 1)

    def print_instr(self, instr):            
        if isinstance(self.method_obj, net_emu_types.DotNetDynamicMethod):
            self.print_string('DynamicMethod: Offset={}, Instr={} {}'.format(hex(self.current_offset), instr.get_name(),
                                                                             instr.get_argument()), 1)
        else:
            self.print_string(
                'Emulator={}:{}, Offset={}, Instr={} {}'.format(self.method_obj.get_table_name(), self.method_obj.get_rid(),
                                                                hex(self.current_offset), instr.get_name(),
                                                                instr.get_argument()), 1)

    cdef void initialize_locals(self):
        cdef net_utils.TypeSig tsig
        cdef int index
        for index in range(len(self.disasm_obj.local_types)):
            tsig = self.disasm_obj.local_types[index]
            self.localvars[index] = self.__get_default_value(tsig)

    cpdef void run_function(self) except *:
        """
        Emulates the method until instructed to end.
        """
        cdef net_opcodes.Opcodes ins_op
        cdef net_cil_disas.Instruction instr
        cdef bint should_print
        cdef str ins_name
        cdef net_emu_types.DotNetNull null_obj
        cdef bint do_normal_offsets
        self.get_appdomain().set_current_emulator(self)
        self.get_appdomain().set_executing_dotnetpe(self.method_obj.get_dotnetpe())
        self.initialize_locals()
        if isinstance(self.method_obj, net_row_objects.MethodDef) and not self.dont_execute_cctor:
            if not self.method_obj.is_static_constructor():
                if self.method_obj.get_parent_type():
                    cctor_method = self.method_obj.get_parent_type().get_cctor_method()
                    if cctor_method and cctor_method.is_static_constructor():
                        if self.executed_cctors.can_execute(cctor_method):
                            emu = self.spawn_new_emulator(cctor_method)
                            emu.run_function()
            else:
                self.executed_cctors.can_execute(self.method_obj)
        if self.caller is not None:
            if self.print_debug:
                self.print_current_state()
        while self.current_eip < len(self.disasm_obj):
            try:
                sig_check()
            except KeyboardInterrupt:
                os._exit(0)
            self.should_break = False
            instr = self.disasm_obj.get_instr_at_offset(self.current_offset)
            if instr == None:
                raise net_exceptions.InvalidArgumentsException()
            if self.end_offset > 0:
                if self.end_method_rid < 0 or (isinstance(self.method_obj,
                                                          net_row_objects.MethodDef) and self.method_obj.get_rid() == self.end_method_rid):
                    if self.current_offset <= self.end_offset < (self.current_offset + len(instr)):
                        break

            if self.print_debug:
                if len(self.print_debug_instrs) == 0 or instr.get_name() in self.print_debug_instrs:
                    should_print = False
                    if len(self.print_debug_offsets) == 0 and len(self.print_debug_methods) == 0:
                        should_print = True
                    else:
                        if isinstance(self.method_obj, net_row_objects.MethodDef):
                            if (self.method_obj.get_rid(), instr.get_instr_offset()) in self.print_debug_offsets:
                                should_print = True
                            if self.method_obj.get_rid() in self.print_debug_methods:
                                should_print = True
                    
                    if should_print:
                        self.print_instr(instr)


            try:
                #if self.__pre_exec_callback:
                #    self.__pre_exec_callback(self, instr, self.__callback_param)
                self.__last_instr_start = time.perf_counter_ns()
                do_normal_offsets = True
                ins_name = instr.get_name()
                ins_op = instr.get_opcode()
                if ins_op == net_opcodes.Opcodes.Add or ins_op == net_opcodes.Opcodes.Add_Ovf or ins_op == net_opcodes.Opcodes.Add_Ovf_Un:
                    self.handle_add_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.And:
                    self.handle_and_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Conv_I or \
                        ins_op == net_opcodes.Opcodes.Conv_I1 or \
                        ins_op == net_opcodes.Opcodes.Conv_I2 or \
                        ins_op == net_opcodes.Opcodes.Conv_I4 or \
                        ins_op == net_opcodes.Opcodes.Conv_I8:
                    self.handle_conv_i_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Conv_R4 or ins_op == net_opcodes.Opcodes.Conv_R8:
                    self.handle_conv_r_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Conv_U or ins_op == net_opcodes.Opcodes.Conv_U1 or ins_op == net_opcodes.Opcodes.Conv_U2 or ins_op == net_opcodes.Opcodes.Conv_U4 or ins_op == net_opcodes.Opcodes.Conv_U8:
                    self.handle_conv_u_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Ldarg or ins_op == net_opcodes.Opcodes.Ldarg_0 or ins_op == net_opcodes.Opcodes.Ldarg_1 or ins_op == net_opcodes.Opcodes.Ldarg_2 or ins_op == net_opcodes.Opcodes.Ldarg_3 or ins_op == net_opcodes.Opcodes.Ldarg_S:
                    self.handle_ldarg_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Ldelem or ins_op == net_opcodes.Opcodes.Ldelem_I or ins_op == net_opcodes.Opcodes.Ldelem_I1 or \
                        ins_op == net_opcodes.Opcodes.Ldelem_I2 or ins_op == net_opcodes.Opcodes.Ldelem_I4 or ins_op == net_opcodes.Opcodes.Ldelem_I8 or ins_op == net_opcodes.Opcodes.Ldelem_Ref or \
                        ins_op == net_opcodes.Opcodes.Ldelem_U1 or ins_op == net_opcodes.Opcodes.Ldelem_U2 or ins_op == net_opcodes.Opcodes.Ldelem_U4:
                    self.handle_ldelem_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Ldc_I4 or ins_op == net_opcodes.Opcodes.Ldc_I4_0 or ins_op == net_opcodes.Opcodes.Ldc_I4_1 or ins_op == net_opcodes.Opcodes.Ldc_I4_2 or \
                        ins_op == net_opcodes.Opcodes.Ldc_I4_3 or ins_op == net_opcodes.Opcodes.Ldc_I4_4 or ins_op == net_opcodes.Opcodes.Ldc_I4_5 or ins_op == net_opcodes.Opcodes.Ldc_I4_6 or \
                        ins_op == net_opcodes.Opcodes.Ldc_I4_7 or ins_op == net_opcodes.Opcodes.Ldc_I4_8 or ins_op == net_opcodes.Opcodes.Ldc_I4_M1 or ins_op == net_opcodes.Opcodes.Ldc_I4_S:
                    self.handle_ldc_i4_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Ldc_I8:
                    self.handle_ldc_i8_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Ldc_R4:
                    self.handle_ldc_r4_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Ldc_R8:
                    self.handle_ldc_r8_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Ldloc or ins_op == net_opcodes.Opcodes.Ldloc_0 or ins_op == net_opcodes.Opcodes.Ldloc_1 or ins_op == net_opcodes.Opcodes.Ldloc_2 or ins_op == net_opcodes.Opcodes.Ldloc_3 or ins_op == net_opcodes.Opcodes.Ldloc_S:
                    self.handle_ldloc_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Beq or ins_op == net_opcodes.Opcodes.Beq_S:
                    do_normal_offsets = self.handle_beq_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Bge or ins_op == net_opcodes.Opcodes.Bge_S:
                    do_normal_offsets = self.handle_bge_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Bge_Un or ins_op == net_opcodes.Opcodes.Bge_Un_S:
                    do_normal_offsets = self.handle_bge_un_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Bgt or ins_op == net_opcodes.Opcodes.Bgt_S:
                    do_normal_offsets = self.handle_bgt_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Bgt_Un or ins_op == net_opcodes.Opcodes.Bgt_Un_S:
                    do_normal_offsets = self.handle_bgt_un_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Div:
                    self.handle_div_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Dup:
                    self.handle_dup_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Ldsfld:
                    self.handle_ldsfld_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Ldstr:
                    self.handle_ldstr_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Ldtoken:
                    self.handle_ldtoken_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Mul or ins_op == net_opcodes.Opcodes.Mul_Ovf or ins_op == net_opcodes.Opcodes.Mul_Ovf_Un:
                    self.handle_mul_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Neg:
                    self.handle_neg_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Newarr:
                    self.handle_newarr_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Ble or ins_op == net_opcodes.Opcodes.Ble_S:
                    do_normal_offsets = self.handle_ble_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Ble_Un or ins_op == net_opcodes.Opcodes.Ble_Un_S:
                    do_normal_offsets = self.handle_ble_un_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Blt or ins_op == net_opcodes.Opcodes.Blt_S:
                    do_normal_offsets = self.handle_blt_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Blt_Un or ins_op == net_opcodes.Opcodes.Blt_Un_S:
                    do_normal_offsets = self.handle_blt_un_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Bne_Un or ins_op == net_opcodes.Opcodes.Bne_Un_S:
                    do_normal_offsets = self.handle_bne_un_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Br or ins_op == net_opcodes.Opcodes.Br_S:
                    do_normal_offsets = not self.handle_general_jump(instr, 0)
                elif ins_op == net_opcodes.Opcodes.Ldfld:
                    self.handle_ldfld_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Or:
                    self.handle_or_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Not:
                    self.handle_not_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Pop:
                    self.stack.pop()
                elif ins_op == net_opcodes.Opcodes.Ret:
                    self.handle_ret_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Shl:
                    self.handle_shl_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Shr:
                    self.handle_shr_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Shr_Un:
                    self.handle_shr_un_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Stfld:
                    self.handle_stfld_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Stind_I or ins_op == net_opcodes.Opcodes.Stind_I1 or ins_op == net_opcodes.Opcodes.Stind_I2 or \
                        ins_op == net_opcodes.Opcodes.Stind_I4 or ins_op == net_opcodes.Opcodes.Stind_I8 or ins_op == net_opcodes.Opcodes.Stind_R4 or \
                        ins_op == net_opcodes.Opcodes.Stind_R8:
                    self.handle_stind_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Stloc or ins_op == net_opcodes.Opcodes.Stloc_0 or ins_op == net_opcodes.Opcodes.Stloc_1 or ins_op == net_opcodes.Opcodes.Stloc_2 or ins_op == net_opcodes.Opcodes.Stloc_3 or ins_op == net_opcodes.Opcodes.Stloc_S:
                    self.handle_stloc_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Stsfld:
                    self.handle_stsfld_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Sub or ins_op == net_opcodes.Opcodes.Sub_Ovf or ins_op == net_opcodes.Opcodes.Sub_Ovf_Un:
                    self.handle_sub_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Switch:
                    do_normal_offsets = self.handle_switch_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Xor:
                    self.handle_xor_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Stelem or ins_op == net_opcodes.Opcodes.Stelem_I or ins_op == net_opcodes.Opcodes.Stelem_I1 or \
                        ins_op == net_opcodes.Opcodes.Stelem_I2 or ins_op == net_opcodes.Opcodes.Stelem_I4 or ins_op == net_opcodes.Opcodes.Stelem_I8 or \
                        ins_op == net_opcodes.Opcodes.Stelem_R4 or ins_op == net_opcodes.Opcodes.Stelem_R8 or ins_op == net_opcodes.Opcodes.Stelem_Ref:
                    self.handle_stelem_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Rem:
                    self.handle_rem_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Rem_Un:
                    self.handle_rem_un_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Ldind_I or ins_op == net_opcodes.Opcodes.Ldind_I1 or ins_op == net_opcodes.Opcodes.Ldind_I2 or \
                        ins_op == net_opcodes.Opcodes.Ldind_I4 or ins_op == net_opcodes.Opcodes.Ldind_I8 or ins_op == net_opcodes.Opcodes.Ldind_R4 or \
                        ins_op == net_opcodes.Opcodes.Ldind_R8 or ins_op == net_opcodes.Opcodes.Ldind_Ref or ins_op == net_opcodes.Opcodes.Ldind_U1 or \
                        ins_op == net_opcodes.Opcodes.Ldind_U2 or ins_op == net_opcodes.Opcodes.Ldind_U4:
                    self.handle_ldind_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Ldelema:  # started here
                    self.handle_ldelema_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Call:
                    self.handle_call_instruction(instr, False, False, None, None)
                elif ins_op == net_opcodes.Opcodes.Callvirt:
                    self.handle_callvirt_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Arglist:
                    raise net_exceptions.InstructionNotSupportedException(instr.get_name())
                elif ins_op == net_opcodes.Opcodes.Box:
                    self.handle_box_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Break:
                    self.should_break = True
                elif ins_op == net_opcodes.Opcodes.Brfalse or ins_op == net_opcodes.Opcodes.Brfalse_S:
                    do_normal_offsets = not self.handle_brfalse_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Brtrue or ins_op == net_opcodes.Opcodes.Brtrue_S:
                    do_normal_offsets = not self.handle_brtrue_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Calli:
                    raise net_exceptions.InstructionNotSupportedException(ins_name)
                elif ins_op == net_opcodes.Opcodes.Castclass:
                    self.handle_castclass_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Ceq:
                    self.handle_ceq_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Cgt:
                    self.handle_cgt_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Cgt_Un:
                    self.handle_cgt_un_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Ckfinite:
                    raise net_exceptions.InstructionNotSupportedException(ins_name)
                elif ins_op == net_opcodes.Opcodes.Clt:
                    self.handle_clt_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Clt_Un:
                    self.handle_clt_un_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Conv_Ovf_I:
                    raise net_exceptions.InstructionNotSupportedException(ins_name)
                elif ins_op == net_opcodes.Opcodes.Conv_Ovf_I_Un or ins_op == net_opcodes.Opcodes.Conv_Ovf_I1_Un or ins_op == net_opcodes.Opcodes.Conv_Ovf_I2_Un or ins_op == net_opcodes.Opcodes.Conv_Ovf_I4_Un or ins_op == net_opcodes.Opcodes.Conv_Ovf_I8_Un:
                    raise net_exceptions.InstructionNotSupportedException(ins_name)
                elif ins_op == net_opcodes.Opcodes.Conv_Ovf_U_Un or ins_op == net_opcodes.Opcodes.Conv_Ovf_U1_Un or ins_op == net_opcodes.Opcodes.Conv_Ovf_U2_Un or ins_op == net_opcodes.Opcodes.Conv_Ovf_U4_Un or ins_op == net_opcodes.Opcodes.Conv_Ovf_U8_Un:
                    raise net_exceptions.InstructionNotSupportedException(ins_name)
                elif ins_op == net_opcodes.Opcodes.Conv_R_Un:
                    self.handle_conv_r_un_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Cpblk:
                    raise net_exceptions.InstructionNotSupportedException(ins_name)
                elif ins_op == net_opcodes.Opcodes.Cpobj:
                    raise net_exceptions.InstructionNotSupportedException(ins_name)
                elif ins_op == net_opcodes.Opcodes.Div_Un:
                    raise net_exceptions.InstructionNotSupportedException(ins_name)
                elif ins_op == net_opcodes.Opcodes.Endfilter:
                    raise net_exceptions.InstructionNotSupportedException(ins_name)
                elif ins_op == net_opcodes.Opcodes.Endfinally:
                    raise net_exceptions.InstructionNotSupportedException(ins_name)
                elif ins_op == net_opcodes.Opcodes.Initblk:
                    raise net_exceptions.InstructionNotSupportedException(ins_name)
                elif ins_op == net_opcodes.Opcodes.Initobj:
                    self.handle_initobj_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Nop:
                    pass
                elif ins_op == net_opcodes.Opcodes.Prefix1 or ins_op == net_opcodes.Opcodes.Prefix2 or ins_op == net_opcodes.Opcodes.Prefix3 or ins_op == net_opcodes.Opcodes.Prefix4 or ins_op == net_opcodes.Opcodes.Prefix5 or ins_op == net_opcodes.Opcodes.Prefix6 or ins_op == net_opcodes.Opcodes.Prefix7 or ins_op == net_opcodes.Opcodes.PrefixRef:
                    raise net_exceptions.InstructionNotSupportedException(ins_name)
                elif ins_op == net_opcodes.Opcodes.Isinst:
                    self.handle_isinst_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Jmp:
                    self.handle_call_instruction(instr, False, False, None, None)  # TODO: check
                elif ins_op == net_opcodes.Opcodes.Ldarga or ins_op == net_opcodes.Opcodes.Ldarga_S:
                    raise net_exceptions.InstructionNotSupportedException(ins_name)
                elif ins_op == net_opcodes.Opcodes.Ldflda:
                    self.handle_ldflda_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Ldftn:
                    self.stack.append(instr.get_argument())
                elif ins_op == net_opcodes.Opcodes.Ldlen:
                    self.handle_ldlen_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Ldloca or ins_op == net_opcodes.Opcodes.Ldloca_S:
                    self.handle_ldloca_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Ldnull:
                    null_obj = net_emu_types.DotNetNull(self)
                    self.stack.append(null_obj)
                elif ins_op == net_opcodes.Opcodes.Ldobj:
                    self.handle_ldobj_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Ldvirtftn:
                    raise net_exceptions.InstructionNotSupportedException(ins_name)
                elif ins_op == net_opcodes.Opcodes.Ldsflda:
                    self.handle_ldsflda_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Leave or ins_op == net_opcodes.Opcodes.Leave_S:
                    do_normal_offsets = self.handle_leave_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Localloc:
                    raise net_exceptions.InstructionNotSupportedException(ins_name)
                elif ins_op == net_opcodes.Opcodes.Mkrefany:
                    raise net_exceptions.InstructionNotSupportedException(ins_name)
                elif ins_op == net_opcodes.Opcodes.Newobj:
                    self.handle_call_instruction(instr, False, True, None, None)
                elif ins_op == net_opcodes.Opcodes.Readonly:
                    raise net_exceptions.InstructionNotSupportedException(ins_name)
                elif ins_op == net_opcodes.Opcodes.Refanytype:
                    raise net_exceptions.InstructionNotSupportedException(ins_name)
                elif ins_op == net_opcodes.Opcodes.Rethrow:
                    raise net_exceptions.InstructionNotSupportedException(ins_name)
                elif ins_op == net_opcodes.Opcodes.Sizeof:
                    raise net_exceptions.InstructionNotSupportedException(ins_name)
                elif ins_op == net_opcodes.Opcodes.Starg or ins_op == net_opcodes.Opcodes.Starg_S:
                    self.handle_starg_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Stind_Ref:
                    raise net_exceptions.InstructionNotSupportedException(ins_name)
                elif ins_op == net_opcodes.Opcodes.Stobj:
                    self.handle_stobj_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Tail:
                    pass
                elif ins_op == net_opcodes.Opcodes.Throw:
                    raise net_exceptions.InstructionNotSupportedException(ins_name)
                elif ins_op == net_opcodes.Opcodes.Unaligned:
                    pass
                elif ins_op == net_opcodes.Opcodes.Unbox:
                    raise net_exceptions.InstructionNotSupportedException(ins_name)
                elif ins_op == net_opcodes.Opcodes.Unbox_Any:
                    self.handle_unbox_any_instruction(instr)
                elif ins_op == net_opcodes.Opcodes.Volatile:
                    pass
                else:
                    raise net_exceptions.InstructionNotSupportedException(ins_name)


                if do_normal_offsets:
                    self.current_eip += 1
                    self.current_offset += len(instr)

                self.__last_instr_end = time.perf_counter_ns()
                #if self.__post_exec_callback:
                #    self.__post_exec_callback(self, instr, self.__callback_param)
            except net_exceptions.InstructionNotSupportedException as e:
                if self.break_on_unsupported:
                    break
                else:
                    if not self.already_init:
                        self.get_appdomain().set_calling_dotnetpe(None)
                    self.print_string('Error on method: {}:{} - Offset: {}'.format(self.method_obj,
                                                                                   hex(self.method_obj.get_token()),
                                                                                   hex(instr.get_instr_offset())), 1)
                    raise e

            except net_exceptions.EmulatorSecurityException as e:
                if self.ignore_security_exceptions:
                    self.current_eip += 1
                    self.current_offset += len(instr)
                    self.print_string('Emulator: Ignoring Security Exception {}'.format(str(e)), 1)
                else:
                    self.print_string('Error on method: {}:{} - Offset: {}'.format(self.method_obj,
                                                                                   hex(self.method_obj.get_token()),
                                                                                   hex(instr.get_instr_offset())), 1)
                    raise e
            except net_exceptions.TooManyMethodParameters as e:
                raise e
            except Exception as e:
                self.print_string('Error on method: {}:{} - Offset: {}'.format(self.method_obj,
                                                                               hex(self.method_obj.get_token()),
                                                                               hex(instr.get_instr_offset())), 1)
                if not self.already_init:
                    self.get_appdomain().set_calling_dotnetpe(None)
                raise e
            if self.print_debug:
                if len(self.print_debug_instrs) == 0 or instr.get_name() in self.print_debug_instrs:
                    should_print = False
                    if len(self.print_debug_offsets) == 0 and len(self.print_debug_methods) == 0:
                        should_print = True
                    else:
                        if isinstance(self.method_obj, net_row_objects.MethodDef):
                            if (self.method_obj.get_rid(), instr.get_instr_offset()) in self.print_debug_offsets:
                                should_print = True
                            if self.method_obj.get_rid() in self.print_debug_methods:
                                should_print = True
                    if should_print:
                        self.print_current_state()



            if ins_op == net_opcodes.Opcodes.Ret or self.should_break:
                # TODO: In theory this supports the break instruction, add a way to insert it.
                break

        if not self.already_init:
            self.get_appdomain().set_calling_dotnetpe(None)
