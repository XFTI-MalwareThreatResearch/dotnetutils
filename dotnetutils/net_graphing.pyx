#cython: language_level=3
#distutils: language=c++
from dotnetutils cimport net_cil_disas, net_emulator, net_cil_disas, net_structs, net_opcodes, net_row_objects, net_emu_types
from dotnetutils.net_opcodes cimport Opcodes

from dotnetutils import net_exceptions

"""
This file is meant to eventually be a grapher and maybe a recompiler + analyzer for method code.
Currently the graphing functionality actually works pretty well.
So far using the graphing functionality I managed to implement a max stack size calculator, which is used for patching methods
Additionally, I was able to implement a math instruction compressor - useful for studying Babel.NET.
Currently working out some of the issues with instruction patching, control flow deobfuscation and stuff so this file isnt really ready for use.
This file will be cythonized once complete.  Its also possible that I may split up the classes into separate files.
Methods and such may change within this file as I continue working on it.
"""

cdef class FunctionBlock:
    def __init__(self, net_row_objects.MethodDef method_object, net_cil_disas.MethodDisassembler disasm_object, FunctionGraph graph):
        """ Setup a new FunctionBlock
        
        Args:
            method_object (net_row_object.MethodDef): The method object the block belongs to.
            disasm_object (net_row_objects.MethodDisassembler): The disassembler object associated with the method (can be None for patching.)
            graph: (FunctionGraph): The graph associated with the block.
        """
        self.__method_object = method_object
        self.__disasm_object = disasm_object
        self.__graph = graph
        self.__instrs = list()
        self.__previous = list()
        self.__next = list()
        self.__start_offset = -1
        self.__start_index = -1
        self.__original_length = 0
        self.__was_cleared = False
        self.__original_cleared = False
        self.__is_junk_block = False
        self.__is_switch_case = False
        self.__was_switch_block = False
        self.__is_block_finished = False
        self.__is_block_try = False
        self.__is_block_catch = False
        self.__is_block_finally = False
        self.__is_block_filter = False
        self.__try_block_offset = -1
        self.__catch_block_offset = -1
        self.__finally_block_offset = -1
        self.__filter_block_offset = -1
        self.__exception_handlers = set()
        self.__new_offset = -1
        self.__new_index = -1

    cpdef bint is_block_start(self):
        cdef int cl_flag = 0
        cdef FunctionBlock blk = None
        if self.__start_offset == 0:
            return True
        for cl_flag, blk in self.__exception_handlers:
            if self.__start_offset == blk.get_start_offset():
                return True
        return False

    cpdef FunctionBlock duplicate(self, FunctionGraph new_graph, dict existing_blocks):
        cdef FunctionBlock new_block = None
        cdef net_cil_disas.Instruction instr = None
        cdef FunctionBlock nxt = None
        cdef tuple exc_block = None
        #Create a deep duplicate of a block.
        if self.get_start_offset() in existing_blocks:
            return existing_blocks[self.get_start_offset()]
        new_block = FunctionBlock(self.__method_object, self.__disasm_object, new_graph)
        existing_blocks[self.get_start_offset()] = new_block
        for instr in self.get_instrs():
            new_block.add_instr(instr.duplicate())
        for nxt in self.get_next():
            new_nxt = nxt.duplicate(new_graph, existing_blocks)
            new_block.add_next(new_nxt)
        new_block.__was_cleared = self.__was_cleared
        new_block.__original_cleared = self.__original_cleared
        new_block.__is_junk_block = self.__is_junk_block
        new_block.__is_switch_case = self.__is_switch_case
        new_block.__was_switch_block = self.__was_switch_block
        new_block.__is_block_finished = self.__is_block_finished
        new_block.__is_block_try = self.__is_block_try
        new_block.__is_block_catch = self.__is_block_catch
        new_block.__is_block_finally = self.__is_block_finally
        new_block.__is_block_filter = self.__is_block_filter
        new_block.__try_block_offset = self.__try_block_offset
        new_block.__catch_block_offset = self.__catch_block_offset
        new_block.__finally_block_offset = self.__finally_block_offset
        new_block.__filter_block_offset = self.__filter_block_offset
        new_block.update_start_offset(self.get_start_offset(), self.get_start_index())
        for exc_block in self.__exception_handlers:
            new_block.__exception_handlers.add((exc_block[0], exc_block[1].duplicate(new_graph, existing_blocks)))
        new_block.__new_offset = self.__new_offset
        new_block.__new_index = self.__new_index
        return new_block

    cpdef int get_start_index(self):
        """ Obtain the index of the first instruction within the block relative to index 0 of the method.

        Returns:
            unsigned int: The start index of the block
        """
        return self.__start_index
    
    cpdef void update_start_offset(self, int start_offset, int start_index):
        """ Updates the stored offset and index for the block.

        Args:
            start_offset (unsigned int): The new start offset.
            start_index (unsigned int): The new start index.
        """
        self.__start_offset = start_offset
        self.__start_index = start_index

    cpdef void setup_new_block_location(self, int new_offset, int new_index):
        """ Updates the stored new offset and index for the block.
        
            Likely to be removed.

        Args:
            start_offset (unsigned int): The new start offset.
            start_index (unsigned int): The new start index.
        """
        self.__new_offset = new_offset
        self.__new_index = new_index

    cpdef void update_size(self, int new_size):
        """ Update the stored byte size of the block.

        Args:
            new_size (unsigned int): The new byte size of the block.
        """
        self.__original_length = new_size 

    cpdef int get_new_offset(self):
        """ Obtains the stored value for the new offset after changes.
            Likely to be removed.
        
        Returns:
            unsigned int: The stored value for the new offset after changes.
        """
        return self.__new_offset
    
    cpdef int get_new_index(self):
        """ Obtains the stored value for the new index after changes.
            Likely to be removed.
        
        Returns:
            unsigned int: The stored value for the new index after changes.
        """
        return self.__new_index

    cpdef set get_exception_handlers(self):
        """ Obtains a single exception handler associated with a block.
            see net_cil_disas for result format.
        
        Returns:
            list: An exception handler associated with the block.
        """
        return self.__exception_handlers
    
    cpdef void add_exception_handler(self, tuple exception_handler):
        """ Sets the block's exception handler.

        Args:
            exception_handler (list): The exception handler to set.
        """
        if exception_handler[1] is None or not isinstance(exception_handler[1], FunctionBlock):
            raise Exception() #Update the docs later etc etc
        self.__exception_handlers.add(exception_handler)

    cpdef void set_filter_block_offset(self, int offset):
        """ Sets the offset of the filter handler associated with the block.

        Args:
            offset (unsigned int): The offset of a filter clause holding the block.
        """
        self.__filter_block_offset = offset

    cpdef void set_try_block_offset(self, int offset):
        """ Sets the offset of the try handler associated with the block.

        Args:
            offset (unsigned int): The offset of a try clause holding the block.
        """
        self.__try_block_offset = offset

    cpdef void set_catch_block_offset(self, int offset):
        """ Sets the offset of the catch handler associated with the block.

        Args:
            offset (unsigned int): The offset of a catch clause holding the block.
        """
        self.__catch_block_offset = offset

    cpdef void set_finally_block_offset(self, int offset):
        """ Sets the offset of the finally handler associated with the block.

        Args:
            offset (unsigned int): The offset of a finally clause holding the block.
        """
        self.__finally_block_offset = offset

    cpdef int get_try_block_offset(self):
        return self.__try_block_offset
    
    cpdef int get_catch_block_offset(self):
        return self.__catch_block_offset
    
    cpdef int get_finally_block_offset(self):
        return self.__finally_block_offset
    
    cpdef int get_filter_block_offset(self):
        return self.__filter_block_offset

    cpdef void mark_block_try(self):
        self.__is_block_try = True

    cpdef void mark_block_catch(self):
        self.__is_block_catch = True

    cpdef void mark_block_finally(self):
        self.__is_block_finally = True

    cpdef void mark_block_filter(self):
        self.__is_block_filter = True

    cpdef bint is_block_try(self):
        return self.__is_block_try
    
    cpdef bint is_block_catch(self):
        return self.__is_block_catch
    
    cpdef bint is_block_finally(self):
        return self.__is_block_finally
    
    cpdef bint is_block_filter(self):
        return self.__is_block_filter

    cpdef void mark_block_finished(self):
        self.__is_block_finished = True

    cpdef void mark_switch_block(self):
        self.__was_switch_block = True

    cpdef bint was_switch_block(self):
        return self.__was_switch_block

    cpdef bint is_block_return(self):
        return self.get_last_instr().get_opcode() == Opcodes.Ret

    def __hash__(self):
        return hash(self.__start_offset)

    cpdef int get_current_size(self):
        cdef int result = 0
        cdef net_cil_disas.Instruction instr = None
        for instr in self.get_instrs():
            result += <int>len(instr)
        return result

    cpdef void mark_switch_case(self):
        self.__is_switch_case = True

    cpdef bint is_switch_case(self):
        return self.__is_switch_case
    
    cpdef int get_instr_index(self, net_cil_disas.Instruction instr):
        cdef Py_ssize_t x = 0
        cdef net_cil_disas.Instruction pt_instr = None
        for x in range(len(self.get_instrs())):
            pt_instr = self.get_instrs()[x]
            if pt_instr.get_instr_offset() == instr.get_instr_offset():
                return <int>x
        return -1
    
    cpdef void mark_junk(self):
        self.__is_junk_block = True

    cpdef bint is_junk_block(self):
        return self.__is_junk_block
    
    cpdef void reverse_next(self):
        self.__next.reverse()

    cpdef bint is_start(self):
        return self.__start_offset == 0

    cpdef int get_original_length(self):
        return self.__original_length

    cpdef bint has_absolute_path_to_zero(self):
        cdef FunctionBlock prev = None
        if self.__start_offset == 0:
            return True
        for prev in self.get_prev():
            if prev.has_absolute_path_to_zero():
                return True
        return False
    
    cpdef bint block_leads_switch(self):
        cdef FunctionBlock usable = None
        if self.is_block_switch():
            return True
        if self.is_block_absolutejmp():
            usable = self
            while len(usable.get_next()) == 1 and usable.is_block_absolutejmp():
                usable = usable.ge_next()[0]
                if usable.is_block_switch():
                    return True
        return False

    cpdef net_cil_disas.Instruction get_instr_at_index(self, int index):
        return self.__instrs[index]

    cpdef void insert_instr(self, int index, net_cil_disas.Instruction instr):
        self.__instrs.insert(index, instr)

    cpdef bint is_block_conditional(self):
        cdef net_cil_disas.Instruction instr = self.get_last_instr()
        if not self.is_block_absolutejmp():
            if instr.get_opcode() != Opcodes.Switch:
                return instr.is_branch()
        return False

    cpdef bint contains_instr(self, str name):
        cdef net_cil_disas.Instruction instr = None
        for instr in self.__instrs:
            if instr.get_name() == name:
                return True
        return False

    cpdef void clear_next(self):
        cdef list nxt = list(self.get_next())
        cdef FunctionBlock n = None
        for n in nxt:
            self.remove_next(n)

    cpdef void clear_prev(self):
        cdef list prv = list(self.get_prev())
        cdef FunctionBlock p = None
        for p in prv:
            self.remove_prev(p)

    cpdef void clear_next_raw(self):
        self.__next.clear()

    cpdef void clear_prev_raw(self):
        self.__previous.clear()

    cpdef void add_next_raw(self, FunctionBlock nxt):
        self.__next.append(nxt)

    cpdef void add_prev_raw(self, FunctionBlock nxt):
        self.__previous.append(nxt)

    cpdef void clear_next_once(self):
        if not self.__was_cleared:
            self.__was_cleared = True
            self.clear_next()

    cpdef bint is_block_switch(self):
        if self.get_last_instr() is None:
            return False
        return self.get_last_instr().get_opcode() == Opcodes.Switch

    cpdef bint is_block_absolutejmp(self):
        cdef net_cil_disas.Instruction instr = self.get_last_instr()
        cdef Opcodes opcode = instr.get_opcode()
        return opcode == Opcodes.Br or opcode == Opcodes.Br_S or opcode == Opcodes.Leave or opcode == Opcodes.Leave_S
    
    cpdef bint is_block_direct(self):
        return not self.is_block_absolutejmp() and not self.is_block_conditional() and not self.get_last_instr().is_branch() and len(self.get_next()) == 1
    
    cpdef void add_instr(self, net_cil_disas.Instruction instr):
        self.__instrs.append(instr)
        if self.__start_offset == -1:
            self.__start_offset = instr.get_instr_offset()
            self.__start_index = instr.get_instr_index()

        self.__original_length += <int>len(instr)

    cpdef void remove_instrs_after_index(self, int index):
        self.__instrs = self.__instrs[:index + 1]

    cpdef void replace_instr(self, int index, net_cil_disas.Instruction instr):
        self.__instrs[index] = instr
    
    cpdef void remove_instrs(self, int start, int end):
        if not 0 <= start < len(self.__instrs) or not 0 <= end <= <int>len(self.__instrs) or start > end:
            raise net_exceptions.InvalidArgumentsException()
        del self.__instrs[start:end]

    cpdef list get_instrs(self):
        return self.__instrs

    cpdef int get_start_offset(self):
        return self.__start_offset

    cpdef net_cil_disas.Instruction get_last_instruction(self):
        if len(self.get_instrs()) == 0:
            return None
        return self.get_instrs()[-1]

    cpdef bint has_prev(self, FunctionBlock block):
        return block in self.__previous

    cpdef void add_next(self, FunctionBlock block):
        if block is None:
            raise Exception()
        self.__next.append(block)
        block.add_prev(self)

    cpdef void add_prev(self, FunctionBlock block):
        if block is None:
            raise Exception()
        if not self.has_prev(block):
            self.__previous.append(block)

    cpdef bint has_next(self, FunctionBlock block):
        return block in self.__next

    cpdef list get_next(self):
        return self.__next

    cpdef list get_prev(self):
        return self.__previous
    
    cpdef void remove_prev(self, FunctionBlock prev):
        prev.__next.remove(self)
        self.__previous.remove(prev)

    cpdef net_cil_disas.Instruction get_last_instr(self):
        if len(self.__instrs) == 0:
            return None
        return self.get_instrs()[-1]

    cpdef bint has_offset(self, int offset):
        cdef net_cil_disas.Instruction instr = None
        if self.__is_block_finished:
            if self.__start_offset <= offset < (self.__start_offset + self.__original_length):
                return True
        for instr in self.get_instrs():
            if instr.get_instr_offset() == offset:
                return True
        return False
    
    cpdef void merge_block(self, FunctionBlock block):
        #merge a block with another.
        cdef bint shouldnt_remove = False
        cdef int cl_flags = 0
        cdef FunctionBlock cl_blk = None
        cdef net_cil_disas.Instruction last_instr = None
        cdef int last_instr_index = 0
        cdef int last_instr_size = 0
        cdef int last_instr_offset = 0
        cdef int new_offset = 0
        cdef int new_length = 0
        cdef int new_index = 0
        cdef net_cil_disas.Instruction instr = None
        cdef int target = 0
        cdef list args = None
        cdef int new_argument = 0


        if block.is_block_try() or block.is_block_catch() or block.is_block_finally() or block.is_block_filter():
            shouldnt_remove = False
            for cl_flags, cl_blk in block.get_exception_handlers():
                if cl_blk == block:
                    shouldnt_remove = True
                    break 
            if shouldnt_remove:
                raise Exception
        last_instr = self.get_last_instr()
        if last_instr is None:
            last_instr_offset = self.__start_offset
            last_instr_size = 0
            last_instr_index = 0
        else:
            last_instr_offset = last_instr.get_instr_offset()
            last_instr_size = <int>len(last_instr)
            last_instr_index = last_instr.get_instr_index()
            
        new_offset = last_instr_offset + last_instr_size
        new_index = last_instr_index
        new_length = self.get_original_length()
        for instr in block.get_instrs():
            if instr.is_absolute_jmp():
                target = instr.get_argument() + <int>len(instr) + instr.get_instr_offset()
                new_argument = target - new_offset - <int>len(instr)
                instr.setup_arguments_from_int32(new_argument)
            elif instr.is_branch():
                if instr.get_opcode() == Opcodes.Switch:
                    args = list()
                    for target in instr.get_argument():
                        new_argument = target - new_offset - <int>len(instr)
                        args.append(new_argument)
                    instr.setup_arguments_from_argslist(args)
                else:
                    target = instr.get_argument() + <int>len(instr) + instr.get_instr_offset()
                    new_argument = target - new_offset - <int>len(instr)
                    instr.setup_arguments_from_int32(new_argument)

            instr.setup_instr_offset(new_offset, new_index)
            new_offset += <int>len(instr)
            new_index += 1
            new_length += <int>len(instr)
            self.add_instr(instr)
        self.__original_length = new_length

    cpdef void validate_block(self) except *:
        cdef net_cil_disas.Instruction last_instr = self.get_last_instr()
        cdef Opcodes opcode = Opcodes.Nop
        cdef FunctionBlock nxt = None
        if last_instr is None:
            if len(self.__next) != 1 and len(self.__next) != 0:
                raise net_exceptions.InvalidBlockException(self)
        else:
            opcode = last_instr.get_opcode()
            if not last_instr.is_branch():
                if opcode == Opcodes.Ret:
                    if not len(self.__next) == 0:
                        raise net_exceptions.InvalidBlockException(self)
                else:
                    if opcode == Opcodes.Throw or opcode == Opcodes.Endfinally or opcode == Opcodes.Rethrow:
                        if len(self.__next) != 0:
                            raise net_exceptions.InvalidBlockException(self)
                    else:
                        if len(self.__next) != 1:
                            raise net_exceptions.InvalidBlockException(self)
            else:
                if opcode == Opcodes.Switch:
                    if len(self.__next) != (len(last_instr.get_argument()) + 1):
                        raise net_exceptions.InvalidBlockException(self)
                elif opcode == Opcodes.Br_S or opcode == Opcodes.Br or opcode == Opcodes.Leave or opcode == Opcodes.Leave_S:
                    if len(self.__next) != 1:
                        raise net_exceptions.InvalidBlockException(self)
                else:
                    if len(self.__next) != 2:
                        raise net_exceptions.InvalidBlockException(self)
                    
                    """if self.__next[0] == self.__next[1]:
                        raise net_exceptions.InvalidBlockException(self)"""
                
        for nxt in self.__next:
            if self not in nxt.get_prev():
                raise net_exceptions.InvalidBlockException(self)

    cpdef FunctionBlock split_block(self, int split_offset):
        cdef list new_instrs = list()
        cdef list split_instrs = list()
        cdef bint start_splitting = False
        cdef int new_size = 0
        cdef FunctionBlock new_block = None
        cdef list exc_handler = None
        cdef net_cil_disas.Instruction instr = None
        cdef list new_next = None
        cdef FunctionBlock nxt = None
        for instr in self.__instrs:
            if instr.get_instr_offset() == split_offset:
                start_splitting = True
            if not start_splitting:
                new_size += <int>len(instr)
                new_instrs.append(instr)
            else:
                split_instrs.append(instr)

        self.__instrs = new_instrs
        self.__original_length = new_size

        new_block = FunctionBlock(self.__method_object, self.__disasm_object, self.__graph)
        if self.__is_block_try:
            new_block.mark_block_try()
        
        if self.__is_block_catch:
            new_block.mark_block_catch()

        if self.__is_block_finally:
            new_block.mark_block_finally()
        
        if self.__is_block_filter:
            new_block.mark_block_filter()
    
        for exc_handler in self.__exception_handlers:
            new_block.add_exception_handler(exc_handler)
        
        for instr in split_instrs:
            new_block.add_instr(instr)

        new_next = list(self.__next)
        for nxt in list(self.__next):
            self.remove_next(nxt)

        for nxt in new_next:
            new_block.add_next(nxt)
        self.__next = list()
        self.add_next(new_block)
        return new_block

    cpdef void remove_next(self, FunctionBlock block):
        if self.has_next(block):
            self.__next.remove(block)
            if self in block.__previous and block not in self.__next:
                block.__previous.remove(self)
    
    cpdef void replace_next(self, FunctionBlock block, FunctionBlock new_block):
        
        cdef bint found = False
        cdef list nxts = list(self.__next)
        cdef Py_ssize_t x = 0
        for x in range(len(nxts)):
            if self.__next[x] == block:
                if block.has_prev(self):
                    block.__previous.remove(self)
                self.__next[x] = new_block
                if not new_block.has_prev(self):
                    new_block.__previous.append(self)
                found = True
        if not found:
            raise Exception()
        
    cpdef void replace_next_index(self, int index, FunctionBlock new_block):
        cdef FunctionBlock old_next = self.__next[index]
        self.__next[index] = new_block
        if old_next not in self.__next:
            if old_next.has_prev(self):
                old_next.__previous.remove(self)
        if not new_block.has_prev(self):
            new_block.__previous.append(self)

    cpdef int get_nstack(self):
        cdef int result = 0
        cdef net_cil_disas.Instruction instr = None
        for instr in self.get_instrs():
            result += instr.get_nstack()
        return result

    def __str__(self):
        return 'Block at offset {}'.format(hex(self.get_start_offset()))
    
    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return isinstance(other, FunctionBlock) and self.get_start_offset() == other.get_start_offset() and self.get_instrs() == other.get_instrs()
"""
For exception blocks:
- Function blocks need to be allowed to take multiple try blocks for handlers - nested handlers.
- __parse_block() needs to use the raw exception handlers to ensure blocks separate when a new try etc is found.
- NEed to make sure compiler happens in a way that nests all the nested blocks together.
"""
cdef class FunctionGraph:
    def __init__(self, net_row_objects.MethodDef method_object, list force_instrs=None, list force_exc_blocks=None, bint init_blocks=True, bint debug_print=False):
        cdef FunctionBlock block = None
        cdef net_cil_disas.Instruction instr = None
        self.__method_object = method_object
        self.__debug_print = debug_print
        self.__disasm_object = None
        self.__instr_offsets = dict()
        self.__instrs = list()
        self.__blocks_start = dict()
        self.__exception_blocks = list()
        self.__raw_exception_blocks = list()

        if force_instrs is None:
            if init_blocks:
                if not self.__method_object.has_body():
                    if not isinstance(self.__method_object, net_row_objects.MethodSpec) or not self.__method_object.get_method().has_body():
                        raise net_exceptions.OperationNotSupportedException
                if not isinstance(self.__method_object, net_row_objects.MethodSpec):
                    self.__disasm_object = method_object.disassemble_method()
                else:
                    self.__disasm_object = method_object.get_method().disassemble_method()
                self.__instrs = self.__disasm_object.get_list_of_instrs()
                self.__raw_exception_blocks = self.__disasm_object.get_exception_blocks()
                for instr in self.__instrs:
                    self.__instr_offsets[instr.get_instr_offset()] = instr
                self.__handle_try_catch_finally_blocks()
                if 0 not in self.__blocks_start:
                    self.__root_block = self.__parse_block(0)
                else:
                    self.__root_block = self.__blocks_start[0]

                for block in self.__blocks_start.values():
                    block.mark_block_finished() #Tell each block that we are done with our initial setup, anything else is a modification.
            else:
                self.__disasm_object = method_object.disassemble_method()
        else:
            if force_exc_blocks is None:
                raise net_exceptions.InvalidArgumentsException()
            self.__instrs = force_instrs
            for instr in self.__instrs:
                self.__instr_offsets[instr.get_instr_offset()] = instr
            self.__raw_exception_blocks = force_exc_blocks
            self.__handle_try_catch_finally_blocks()
            if 0 not in self.__blocks_start:
                self.__root_block = self.__parse_block(0)
            else:
                self.__root_block = self.__blocks_start[0]

            for block in self.__blocks_start.values():
                block.mark_block_finished() #Tell each block that we are done with our initial setup, anything else is a modification.
        self.update_block_handlers()
        self.sort_blocks()
        self.register_exception_handlers()

    cpdef void register_exception_handlers(self):
        cdef int cl_flag = 0
        cdef int try_offset = 0
        cdef int try_length = 0
        cdef int catch_offset = 0
        cdef int catch_length = 0
        cdef object token = 0
        cdef FunctionBlock try_block = None
        cdef FunctionBlock catch_block = None
        for cl_flag, try_offset, try_length, catch_offset, catch_length, token in self.__raw_exception_blocks:
            if cl_flag == net_structs.CorILExceptionClause.Filter:
                token = self.get_block_by_start_offset(token)
            try_block = self.get_block_by_start_offset(try_offset)
            catch_block = self.get_block_by_start_offset(catch_offset)
            self.__exception_blocks.append((cl_flag, try_block, catch_block, token))


    cpdef void update_exc_handlers(self):
        self.__raw_exception_blocks = self.update_raw_exception_clauses()

    cpdef list get_raw_exception_clauses(self):
        return self.__raw_exception_blocks

    cpdef FunctionGraph duplicate(self):
        cdef FunctionGraph new_graph = FunctionGraph(self.__method_object, init_blocks=False)
        cdef dict already_duplicated = dict()
        cdef dict usable_dict = None
        cdef int offset = 0
        cdef FunctionBlock blk = None
        cdef int clause_flags = 0
        cdef FunctionBlock try_block = None
        cdef FunctionBlock catch_block = None
        cdef object filter_block = None
        new_graph.__blocks_start = dict(self.__blocks_start)
        new_graph.__instr_offsets = dict(self.__instr_offsets)
        new_graph.__instrs = list(self.__instrs)
        new_graph.__disasm_object = self.__disasm_object
        new_graph.__debug_print = self.__debug_print
        new_graph.__exception_blocks = list()
        usable_dict = dict(new_graph.__blocks_start)
        new_graph.__blocks_start.clear()
        for offset, blk in usable_dict.items():
            new_graph.__blocks_start[offset] = blk.duplicate(new_graph, already_duplicated)
        new_graph.__root_block = new_graph.get_block_by_offset(0)
        for clause_flags, try_block, catch_block, filter_block in self.__exception_blocks:
            if clause_flags == net_structs.CorILExceptionClause.Filter:
                new_graph.__exception_blocks.append((clause_flags, try_block.duplicate(new_graph, already_duplicated), catch_block.duplicate(new_graph, already_duplicated), filter_block.duplicate(new_graph, already_duplicated)))
            else:
                new_graph.__exception_blocks.append((clause_flags, try_block.duplicate(new_graph, already_duplicated), catch_block.duplicate(new_graph, already_duplicated), filter_block))
        new_graph.__raw_exception_blocks = list(self.__raw_exception_blocks)
        return new_graph

    cpdef void register_block(self, int offset, FunctionBlock block):
        self.__blocks_start[offset] = block

    cdef void __handle_try_block(self, int try_offset, int try_length, int handler_offset, int handler_length):
        self.__parse_block(try_offset, try_offset, try_offset + try_length, True, False, False, False)
        self.__parse_block(handler_offset, handler_offset, handler_offset + handler_length, False, True, False, False)

    cdef void __handle_finally_block(self, int try_offset, int try_length, int handler_offset, int handler_length):
        self.__parse_block(try_offset, try_offset, try_offset + try_length, True, False, False, False)
        self.__parse_block(handler_offset, handler_offset, handler_offset + handler_length, False, False, True, False)

    cdef void __handle_filter_block(self, int try_offset, int try_length, int handler_offset, int handler_length, int filter_offset, int filter_length):
        self.__parse_block(try_offset, try_offset, try_offset + try_length, True, False, False, False)
        self.__parse_block(handler_offset, handler_offset, handler_offset + handler_length, False, True, False, False)
        self.__parse_block(filter_offset, filter_offset, filter_offset + filter_length, False, False, False, True)

    cdef void __handle_try_catch_finally_blocks(self):
        """
        Ensure that try catch finally blocks are treated as their own blocks.  
        """
        cdef tuple exc = None
        cdef net_structs.CorILExceptionClause clause_flags = net_structs.CorILExceptionClause.Exception
        cdef int try_offset = 0
        cdef int try_length = 0
        cdef int handler_offset = 0
        cdef int handler_length = 0
        cdef object class_token = 0
        for exc in self.__raw_exception_blocks:
            clause_flags, try_offset, try_length, handler_offset, handler_length, class_token = exc
            if clause_flags == net_structs.CorILExceptionClause.Exception:
                self.__handle_try_block(try_offset, try_length, handler_offset, handler_length)
            elif clause_flags == net_structs.CorILExceptionClause.Finally:
                self.__handle_finally_block(try_offset, try_length, handler_offset, handler_length)
            elif clause_flags == net_structs.CorILExceptionClause.Fault:
                self.__handle_try_block(try_offset, try_length, handler_offset, handler_length)
            elif clause_flags == net_structs.CorILExceptionClause.Filter:
                filter_size = handler_offset - class_token
                self.__handle_filter_block(try_offset, try_length, handler_offset, handler_length, class_token, filter_size)
            else:
                raise net_exceptions.OperationNotSupportedException()
        self.sort_blocks()

    cpdef list get_exception_blocks(self):
        return self.__exception_blocks

    cpdef net_cil_disas.MethodDisassembler get_disassembler(self):
        return self.__disasm_object

    cpdef void sort_blocks(self):
        cdef list keys = list(self.__blocks_start.keys())
        keys.sort()
        self.__blocks_start = {i: self.__blocks_start[i] for i in keys}
    
    cpdef void enable_debug_printing(self):
        self.__debug_print = True

    cpdef bint debug_printing_enabled(self):
        return self.__debug_print

    cpdef void set_root_block(self, FunctionBlock root_block):
        self.__root_block = root_block

    cpdef FunctionBlock get_root_block(self):
        return self.__root_block

    cpdef FunctionBlock get_block_by_offset(self, int offset):
        cdef FunctionBlock block = None
        for block in self.__blocks_start.values():
            if block.has_offset(offset):
                return block
        return None
    
    cpdef FunctionBlock get_block_by_start_offset(self, int offset):
        cdef FunctionBlock block = None
        for block in self.blocks():
            if block.get_start_offset() == offset:
                return block
        return None
    
    cpdef list get_shortest_path(self, from_offset, to_offset):
        cdef list explored = None
        cdef list queue = None
        cdef list path = None
        cdef FunctionBlock node = None
        cdef FunctionBlock neighbor = None
        cdef list neighbors = None
        if isinstance(to_offset, FunctionBlock) and isinstance(from_offset, FunctionBlock):
            to_block = to_offset
            from_block = from_offset
        else:
            to_block = self.get_block_by_offset(to_offset)
            from_block = self.get_block_by_offset(from_offset)
        if to_block is None or from_block is None:
            raise net_exceptions.OperationNotSupportedException

        explored = []
        queue = [[from_block]]
        if to_block.get_start_offset() == from_block.get_start_offset():
            return [from_block]

        while queue:
            path = queue.pop(0)
            node = path[-1]
            if node not in explored:
                neighbours = node.get_next()
                for neighbor in neighbours:
                    new_path = list(path)
                    new_path.append(neighbor)
                    queue.append(new_path)

                    if neighbor.get_start_offset() == to_block.get_start_offset():
                        return new_path
                explored.append(node)

        return None
    
    cdef int __walk_path_max_stack(self, FunctionBlock block, list already_analyzed):
        cdef int max_value = 0
        cdef int result = 0
        cdef net_cil_disas.Instruction instr = None
        cdef FunctionBlock blk = None
        cdef int next_val = 0
        if block in already_analyzed:
            return 0
        already_analyzed.append(block)
        for instr in block.get_instrs():
            result += instr.get_nstack()
            max_value = max(max_value, result)
        for blk in block.get_next():
            val = self.__walk_path_max_stack(blk, already_analyzed)
            next_val = max(val, next_val)
        return max(max_value, next_val)        
    
    cpdef int calculate_max_stack_size(self):
        cdef int max_val = 0
        cdef list already_analyzed = list()
        cdef FunctionBlock block = None
        for block in self.__blocks_start.values():
            max_val = max(self.__walk_path_max_stack(block, already_analyzed), max_val)
        return max_val

    def get_paths_to_block(self, to_offset, from_offset):
        #TODO: Cythonize this
        to_block = to_offset
        from_block = from_offset
        if not isinstance(to_block, FunctionBlock) or not isinstance(from_block, FunctionBlock):
            to_block = self.get_block_by_offset(to_block)
            from_block = self.get_block_by_offset(from_block)
        def path_checker(one: FunctionBlock, two: FunctionBlock, current_path, paths, visited):
            if one == two:
                paths.append(current_path)
                return
            
            if len(one.get_next()) == 0 or one.is_block_return():
                return
            
            if one.get_start_offset() in visited:
                return
            
            visited.append(one.get_start_offset())
            
            nxt: FunctionBlock
            for nxt in one.get_next():
                if nxt == two:
                    paths.append(current_path + [nxt])
                else:
                    path_checker(nxt, two, current_path + [nxt], paths, visited.copy())

        paths = list()
        visited = list()
        path_checker(to_block, from_block, [to_block], paths, visited)
        return paths
    
    cpdef void update_block_handlers(self):
        cdef net_structs.CorILExceptionClause exc_flags = net_structs.CorILExceptionClause.Exception
        cdef int try_offset = 0
        cdef int try_length = 0
        cdef int catch_offset = 0
        cdef int catch_length = 0
        cdef int token = 0
        cdef int filter_offset = 0
        cdef int filter_length = 0
        cdef FunctionBlock block = None
        for exc_flags, try_offset, try_length, catch_offset, catch_length, token in self.__raw_exception_blocks:
            filter_offset = -1
            filter_length = -1
            if exc_flags == net_structs.CorILExceptionClause.Filter:
                filter_offset = token
                filter_length = catch_offset - token
            for block in self.blocks():
                if try_offset <= block.get_start_offset() < (try_offset + try_length):
                    block.add_exception_handler((exc_flags, self.get_block_by_start_offset(try_offset)))
                if catch_offset <= block.get_start_offset() < (catch_offset + catch_length):
                    block.add_exception_handler((exc_flags, self.get_block_by_start_offset(catch_offset)))
                if filter_offset > 0:
                    if filter_offset <= block.get_start_offset() < (filter_offset + filter_length):
                        block.add_exception_handler((exc_flags, self.get_block_by_start_offset(filter_offset)))

    cdef FunctionBlock __parse_block(self, int start_offset, int clause_start=-1, int max_end_offset=-1, bint is_try=False, bint is_catch=False, bint is_finally=False, bint is_filter=False):
        cdef int usable_offset = start_offset
        cdef bint debug = False
        cdef int x = 0
        cdef FunctionBlock blk = None
        cdef FunctionBlock block = None
        cdef FunctionBlock new_block = None
        cdef net_cil_disas.Instruction instr = None
        cdef Opcodes opcode = Opcodes.Nop
        cdef FunctionBlock usable_block = None
        cdef list targets = None
        cdef int potential_offset = 0
        cdef int potential_offset1 = 0
        cdef int potential_offset2 = 0
        if debug:
            print('calling __parse_block {} {} {} {}'.format(hex(start_offset), is_try, is_catch, is_finally))
        x = self.__instr_offsets[start_offset].get_instr_index()
        if start_offset in self.__blocks_start:
            blk =  self.__blocks_start[start_offset]
            if is_try:
                blk.mark_block_try()
            if is_catch:
                blk.mark_block_catch()
            if is_finally:
                blk.mark_block_finally()
            if is_filter:
                blk.mark_block_filter()
            if max_end_offset != -1:
                if (start_offset + blk.get_original_length()) > max_end_offset:
                    new_block = blk.split_block(max_end_offset)
                    self.__blocks_start[max_end_offset] = new_block
            return blk
        else:
            block = self.get_block_by_offset(start_offset)
            if block is None:
                block = FunctionBlock(self.__method_object, self.__disasm_object, self)
                self.__blocks_start[start_offset] = block
            else:
                new_block = block.split_block(start_offset)
                if is_try:
                    new_block.mark_block_try()
                if is_catch:
                    new_block.mark_block_catch()
                if is_finally:
                    new_block.mark_block_finally()
                if is_filter:
                    new_block.mark_block_filter()
                self.__blocks_start[start_offset] = new_block
                return new_block
        
        if is_finally:
            block.mark_block_finally()

        if is_catch:
            block.mark_block_catch()

        if is_try:
            block.mark_block_try()

        if is_filter:
            block.mark_block_filter()

        while x >= 0 and x < <int>len(self.__instrs):
            if usable_offset in self.__blocks_start and usable_offset != start_offset:
                new_block = self.__blocks_start[usable_offset]
                if not block.has_next(new_block):
                    block.add_next(new_block)
                break
            if max_end_offset != -1 and usable_offset >= max_end_offset:
                break
            instr = self.__instrs[x]
            opcode = instr.get_opcode()
            block.add_instr(instr)
            if instr.is_branch():
                #leave br and br.s are treated as absolute jumps since they basically are.
                if opcode == Opcodes.Br or opcode == Opcodes.Br_S or opcode == Opcodes.Leave or opcode == Opcodes.Leave_S:
                    potential_offset = usable_offset + <int>len(instr) + instr.get_argument()
                    if opcode == Opcodes.Br or opcode == Opcodes.Br_S:
                        new_block = self.__parse_block(potential_offset, clause_start, max_end_offset, is_try, is_catch, is_finally, is_filter)
                    else:
                        if (clause_start == -1 or max_end_offset == -1) or not (clause_start <= potential_offset < max_end_offset):
                            new_block = self.__parse_block(potential_offset, -1, -1, False, False, False, False)
                        else:
                            new_block = self.__parse_block(potential_offset, clause_start, max_end_offset, is_try, is_catch, is_finally, is_filter)

                    usable_block = self.get_block_by_offset(
                        usable_offset)
                    if new_block is None:
                        raise net_exceptions.InvalidBlockException(None)
                    usable_block.add_next(new_block)
                else:
                    if opcode == Opcodes.Switch:
                        targets = instr.get_argument()
                        for target in targets:
                            new_block = self.__parse_block(target, clause_start, max_end_offset, is_try, is_catch, is_finally, is_filter)
                            usable_block = self.get_block_by_offset(
                                usable_offset)
                            usable_block.add_next(new_block)
                            new_block.mark_switch_case()

                        fallthrough_offset = instr.get_instr_offset() + <int>len(instr)
                        new_block = self.__parse_block(
                            fallthrough_offset, clause_start, max_end_offset, is_try, is_catch, is_finally, is_filter)
                        usable_block = self.get_block_by_offset(
                            usable_offset)
                        usable_block.add_next(new_block)
                        new_block.mark_switch_case()
                    else:
                        #this block of code is to handle conditional branches.
                        potential_offset1 = usable_offset + \
                            <int>len(instr) + instr.get_argument()
                        potential_offset2 = usable_offset + <int>len(instr)

                        new_block = self.__parse_block(
                            potential_offset1, clause_start, max_end_offset, is_try, is_catch, is_finally, is_filter)
                        usable_block = self.get_block_by_offset(
                            usable_offset)

                        usable_block.add_next(new_block)
                        new_block = self.__parse_block(
                            potential_offset2, clause_start, max_end_offset, is_try, is_catch, is_finally, is_filter)
                        usable_block = self.get_block_by_offset(
                            usable_offset)
                        usable_block.add_next(new_block)
                break
            else:
                if opcode == Opcodes.Throw or opcode == Opcodes.Rethrow:
                    break

            usable_offset += <int>len(instr)

            if opcode == Opcodes.Ret or opcode == Opcodes.Endfinally:
                break

            if instr.is_branch():
                break
            x = self.__instr_offsets[usable_offset].get_instr_index()
        if block is None:
            raise net_exceptions.InvalidBlockException(None)
        return block
    
    cpdef void validate_blocks(self) except *:
        cdef FunctionBlock blk = None
        cdef FunctionBlock nxt = None
        cdef FunctionBlock prv = None
        for blk in self.blocks():
            blk.validate_block()
            for nxt in blk.get_next():
                if nxt not in self.blocks() or blk not in nxt.get_prev():
                    raise net_exceptions.InvalidBlockException(nxt)

            for prv in blk.get_prev():
                if prv not in self.blocks() or blk not in prv.get_next():
                    if blk not in prv.get_next():
                        print('block {} is a previous of {} but is not in {}'.format(prv, blk, prv.get_next()))
                    raise net_exceptions.InvalidBlockException(prv)
            if blk.get_start_offset() < 0:
                raise net_exceptions.InvalidBlockException(blk)
            
    cpdef void dump_block_relations(self):
        cdef FunctionBlock block = None
        for block in self.blocks():
            print('block {} {}'.format(block, block.get_last_instr()))
            print('block nexts {}'.format(block.get_next()))
            print('block prevs {}'.format(block.get_prev()))

    cpdef void print_root(self):
        cdef set dont_print_again = set()
        print('Printing graph for method {} {}'.format(self.__method_object, hex(self.__method_object.get_token())))
        print('Calculated max stack {}'.format(self.calculate_max_stack_size()))
        self.__print_block(self.__root_block, dont_print_again)
                

    cpdef void debug_print_blocks(self):
        cdef FunctionBlock block = None
        cdef net_cil_disas.Instruction instr = None
        print('debug printing blocks')
        for block in self.__blocks_start.values():
            print('Block {}'.format(hex(block.get_start_offset())))
            for instr in block.get_instrs():
                print('{}: {}'.format(hex(instr.get_instr_offset()), instr.get_name()))

    cpdef void debug_print_nexts(self):
        cdef FunctionBlock block = None
        cdef FunctionBlock nxt = None
        print('Debug printing blocks')
        for block in self.__blocks_start.values():
            print('Block {} is_junk={} is_switch_case={}'.format(hex(block.get_start_offset()), block.is_junk_block(), block.is_switch_case()))
            for nxt in block.get_next():
                print('Next: {}'.format(hex(nxt.get_start_offset())))

    cpdef void update_offsets(self):
        cdef dict blocks = dict(self.__blocks_start)
        cdef int offset = 0
        cdef FunctionBlock block = None
        self.__blocks_start.clear()
        for offset, block in blocks.items():
            self.__blocks_start[block.get_start_offset()] = block

        self.__instr_offsets.clear()
        for offset, block in blocks.items():
            for instr in block.get_instrs():
                self.__instr_offsets[instr.get_instr_offset()] = instr
    
    cpdef void unregister_block(self, int offset) except *:
        cdef net_structs.CorILExceptionClause clause_flags = net_structs.CorILExceptionClause.Exception
        cdef FunctionBlock try_block = None
        cdef FunctionBlock catch_block = None
        cdef object token = None
        for clause_flags, try_block, catch_block, token in self.__exception_blocks:
            if try_block.get_start_offset() == offset or catch_block.get_start_offset() == offset or (isinstance(token, FunctionBlock) and token.get_start_offset() == offset):
                raise Exception()
        del self.__blocks_start[offset]

    cpdef dict get_block_offsets(self):
        return self.__blocks_start
    
    cpdef list blocks(self):
        return list(self.__blocks_start.values())
    
    cdef void __stack_checker(self, FunctionBlock block, int stack_count, list checked):
        cdef int curr_count = stack_count
        cdef net_cil_disas.Instruction instr = None
        cdef int needed = 0
        cdef FunctionBlock nxt = None
        for instr in block.get_instrs():
            needed = instr.get_pstack()
            if curr_count < needed:
                print('error on stack at {} {} {}: not enough elements'.format(hex(instr.get_instr_offset()), instr.get_name(), instr.get_argument()))
                raise Exception()
            curr_count += instr.get_nstack()

        for nxt in block.get_next():
            if (block.get_start_offset(), nxt.get_start_offset()) not in checked:
                checked.append((block.get_start_offset(), nxt.get_start_offset()))
                self.__stack_checker(nxt, curr_count, checked)

    cpdef void stack_checker(self):
        cdef list checked = list()
        self.__stack_checker(self.__blocks_start[0], 0, checked)

    cpdef tuple get_exc_handler_for_block(self, net_structs.CorILExceptionClause flags, FunctionBlock block):
        cdef net_structs.CorILExceptionClause clause_flag = net_structs.CorILExceptionClause.Exception
        cdef FunctionBlock try_block = None
        cdef FunctionBlock catch_block = None
        cdef object token = None
        if block.is_block_try():
            for clause_flag, try_block, catch_block, token in self.get_exception_blocks():
                if flags == clause_flag:
                    if try_block == block:
                        return (clause_flag, try_block, catch_block, token)
        elif block.is_block_catch() or block.is_block_finally():
            for clause_flag, try_block, catch_block, token in self.get_exception_blocks():
                if flags == clause_flag:
                    if catch_block == block:
                        return (clause_flag, try_block, catch_block, token)
        elif block.is_block_filter():
            for clause_flag, try_block, catch_block, token in self.get_exception_blocks():
                if flags == clause_flag:
                    if token == block:
                        return (clause_flag, try_block, catch_block, token)
        return None

    cdef void __print_block(self, FunctionBlock block, set already_printed, int indent=0):
        cdef list instrs = block.get_instrs()
        cdef bint is_block_try = False
        cdef bint is_leave = False
        cdef set exc_handlers = None
        cdef net_cil_disas.Instruction instr = None
        cdef net_structs.CorILExceptionClause cl_flags = net_structs.CorILExceptionClause.Exception
        cdef FunctionBlock cl_blk = None
        cdef FunctionBlock next_block = None
        cdef FunctionBlock exc_block = None
        cdef FunctionBlock finally_block = None
        cdef FunctionBlock catch_block = None

        if block.get_start_offset() not in already_printed:
            print((' ' * indent) + 'Printing block with offset {} size {} num_instrs {} (is junk: {}, is switch case: {}, is_try: {}, is_catch: {}, is_finally: {}, is_filter: {})'.format(
                hex(block.get_start_offset()), hex(block.get_original_length()), len(block.get_instrs()), block.is_junk_block(), block.is_switch_case(), block.is_block_try(), block.is_block_catch(), block.is_block_finally(), block.is_block_filter()))
            exc_handlers = block.get_exception_handlers()
            if block.is_block_try():
                for cl_flags, cl_blk in exc_handlers:
                    if cl_blk == block:
                        is_block_try = True
                        print((' ' * indent) + 'try:')
                        indent += 4
                        break
            elif block.is_block_catch():
                for cl_flags, cl_blk in exc_handlers:
                    if cl_flags != net_structs.CorILExceptionClause.Finally and cl_blk == block:
                        print((' ' * indent) + 'catch:')
                        indent += 4
                        break
            elif block.is_block_finally():
                for cl_flags, cl_blk in exc_handlers:
                    if cl_flags == net_structs.CorILExceptionClause.Finally and cl_blk == block:
                        print((' ' * indent) + 'finally:')
                        indent += 4
                        break
            elif block.is_block_filter():
                for cl_flags, cl_blk in exc_handlers:
                    if cl_flags == net_structs.CorILExceptionClause.Filter and cl_blk == block:
                        print((' ' * indent) + 'filter:')
                        indent += 4
                        break

            already_printed.add(block.get_start_offset())
            for instr in block.get_instrs():
                if instr.is_branch() and not instr.is_absolute_jmp():
                    break
                if instr.is_absolute_jmp():
                    print((' ' * indent) + '{}: jump to {} ({})'.format(hex(instr.get_instr_offset()),
                                                  hex(instr.get_instr_offset() + len(instr) + instr.get_argument()), instr.get_name()))
                else:
                    print((' ' * indent) + '{}: {} {}'.format(hex(instr.get_instr_offset()), instr.get_name(),
                                             instr.get_argument()))
                    
            if block.get_last_instr() is None:
                return

            if instrs[-1].get_opcode() == Opcodes.Switch:
                print((' ' * indent) + 'switch ({}):'.format(hex(instrs[-1].get_instr_offset())))
                x = 0
                for case in instrs[-1].get_argument():
                    print( (' ' * (indent + 4)) +'case {}: ({}:{})'.format(x, hex(case), hex(instrs[-1].get_instr_offset())))
                    self.__print_block(self.get_block_by_offset(case), already_printed, indent + 8)
                    x += 1
                fallthrough = instrs[-1].get_instr_offset() + len(instrs[-1])
                fallthrough = self.get_block_by_offset(fallthrough)
                print((' ' * (indent + 4)) + 'default({}:{}):'.format(hex(fallthrough.get_start_offset()), hex(instrs[-1].get_instr_offset())))
                self.__print_block(fallthrough, already_printed, indent + 8)

            else:
                if instrs[-1].is_branch() and not instrs[-1].is_absolute_jmp():
                    print((' ' * indent) + 'if ({}): {} {}'.format(hex(instrs[-1].get_instr_offset()), instrs[-1].get_name(),instrs[-1].get_argument()))
                    self.__print_block(block.get_next()[0], already_printed, indent + 4)
                    print((' ' * indent ) + 'else ({}):'.format(hex(instrs[-1].get_instr_offset())))
                    if len(block.get_next()) == 1:
                        print((' ' * (indent + 4)) + 'Error: No secondary block!!!!')
                    else:
                        self.__print_block(block.get_next()[1], already_printed, indent + 4)
                else:
                    if instrs[-1].get_opcode() == Opcodes.Leave or instrs[-1].get_opcode() == Opcodes.Leave_S:
                        is_leave = True
                    if is_leave:
                        next_block = block.get_next()[0]

                        if block.is_block_try() and next_block.is_block_try():
                            is_leave = False
                    if not is_leave:
                        if not instrs[-1].is_branch() and len(block.get_next()) == 1:
                            self.__print_block(
                                block.get_next()[0], already_printed, indent)
                        elif instrs[-1].is_absolute_jmp() and instrs[-1].is_branch():
                            self.__print_block(block.get_next()[0], already_printed, indent)
            if is_block_try:
                exc_block = None
                for cl_flag, try_blk, catch_blk, token in self.__exception_blocks:
                    if cl_flag == net_structs.CorILExceptionClause.Exception:
                        if try_blk == block:
                            exc_block = catch_blk
                            break
                if exc_block is None:
                    print((' ' * indent) + 'could not find catch block corresponding to try at offset {}'.format(block))
                else:
                    catch_block = exc_block
                    if not block.is_block_finally():
                        self.__print_block(catch_block, already_printed, indent - 4)
                exc_block = None
                for cl_flag, try_blk, catch_blk, token in self.__exception_blocks:
                    if cl_flag == net_structs.CorILExceptionClause.Finally:
                        if try_blk == block:
                            exc_block = catch_blk
                            break
                if exc_block is not None:
                    finally_block = exc_block
                    self.__print_block(finally_block, already_printed, indent - 4)
            if is_leave:
                next_block = block.get_next()[0]
                if next_block.get_start_offset() not in already_printed:
                    if not instrs[-1].is_branch() and len(block.get_next()) == 1:
                        self.__print_block(next_block, already_printed, indent - 4)
                    elif instrs[-1].is_absolute_jmp() and instrs[-1].is_branch():
                        self.__print_block(next_block, already_printed, indent - 4)
        else:
            print((' ' * indent) + 'goto block {}'.format(hex(block.get_start_offset())))

    cpdef list emit_instructions_as_list(self):
        if self.__disasm_object is None:
            raise Exception('Cant emit a instruction without a disassembler object.')
        cdef int current_offset = 0
        cdef list result = list()
        cdef int current_index = 0
        cdef bint debug = False
        cdef int offset = 0
        cdef FunctionBlock block = None
        cdef net_cil_disas.Instruction instr = None
        for offset, block in self.__blocks_start.items():
            if debug:
                print('emitting block {} {} {} {}'.format(hex(offset), block, block.get_prev(), block.get_next()))
            if current_offset != offset:
                raise Exception('Offset mismatch when emitting instrs {} {}'.format(hex(current_offset), hex(offset)))
            for instr in block.get_instrs():
                if debug:
                    print('emitting instr', instr)
                instr.setup_instr_offset(current_offset, current_index)
                result.append(instr)
                current_offset += <int>len(instr)
                current_index += 1
        return result

    cpdef bint has_block(self, int offset):
        return offset in self.__blocks_start
    
    cpdef list update_raw_exception_clauses(self):
        cdef list result = list()
        cdef net_structs.CorILExceptionClause cl_flag = net_structs.CorILExceptionClause.Exception
        cdef FunctionBlock try_block = None
        cdef FunctionBlock catch_block = None
        cdef object token = None
        cdef int try_offset = 0
        cdef int catch_offset = 0
        cdef int try_size = 0
        cdef int catch_size = 0
        cdef FunctionBlock block
        cdef set exc_clauses = None
        cdef net_structs.CorILExceptionClause exc_flag = net_structs.CorILExceptionClause.Exception
        cdef FunctionBlock blk = None
        for cl_flag, try_block, catch_block, token in self.__exception_blocks:
            try_offset = try_block.get_start_offset()
            catch_offset = catch_block.get_start_offset()
            token = token
            if cl_flag == net_structs.CorILExceptionClause.Filter:
                token = token.get_start_offset()
            try_size = 0
            catch_size = 0
            for block in self.blocks():
                exc_clauses = block.get_exception_handlers()
                for exc_flag, blk in exc_clauses:
                    if blk == try_block and cl_flag == exc_flag:
                        try_size += block.get_original_length()
                    elif blk == catch_block and cl_flag == exc_flag:
                        catch_size += block.get_original_length()
                assert block.get_original_length() == block.get_current_size()
            result.append((cl_flag, try_offset, try_size, catch_offset, catch_size, token))
        return result

    cpdef void repopulate_prevs(self):
        cdef FunctionBlock block = None
        cdef list nxts = None
        cdef FunctionBlock nxt = None
        for block in self.blocks():
            block.clear_prev_raw()
        for block in self.blocks():
            nxts = block.get_next()
            for nxt in nxts:
                nxt.add_prev(block)