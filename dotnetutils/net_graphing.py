from dotnetutils import net_cil_disas, net_emulator, net_cil_disas, net_structs, net_opcodes, net_row_objects, net_exceptions, net_emu_types
from dotnetutils.net_opcodes import Opcodes

"""
This file is meant to eventually be a grapher and maybe a recompiler + analyzer for method code.
Currently the graphing functionality actually works pretty well.
So far using the graphing functionality I managed to implement a max stack size calculator, which is used for patching methods
Additionally, I was able to implement a math instruction compressor - useful for studying Babel.NET.
Currently working out some of the issues with instruction patching, control flow deobfuscation and stuff so this file isnt really ready for use.
This file will be cythonized once complete.  Its also possible that I may split up the classes into separate files.
Methods and such may change within this file as I continue working on it.
"""

class FunctionBlock:
    def __init__(self, method_object, disasm_object, graph):
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

    def is_block_start(self):
        if self.__start_offset == 0:
            return True
        for cl_flag, blk in self.__exception_handlers:
            if self.__start_offset == blk.get_start_offset():
                return True
        return False

    def duplicate(self, new_graph, existing_blocks):
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

    def get_start_index(self):
        """ Obtain the index of the first instruction within the block relative to index 0 of the method.

        Returns:
            unsigned int: The start index of the block
        """
        return self.__start_index
    
    def update_start_offset(self, start_offset, start_index):
        """ Updates the stored offset and index for the block.

        Args:
            start_offset (unsigned int): The new start offset.
            start_index (unsigned int): The new start index.
        """
        self.__start_offset = start_offset
        self.__start_index = start_index

    def setup_new_block_location(self, new_offset, new_index):
        """ Updates the stored new offset and index for the block.
        
            Likely to be removed.

        Args:
            start_offset (unsigned int): The new start offset.
            start_index (unsigned int): The new start index.
        """
        self.__new_offset = new_offset
        self.__new_index = new_index

    def update_size(self, new_size):
        """ Update the stored byte size of the block.

        Args:
            new_size (unsigned int): The new byte size of the block.
        """
        self.__original_length = new_size 

    def get_new_offset(self):
        """ Obtains the stored value for the new offset after changes.
            Likely to be removed.
        
        Returns:
            unsigned int: The stored value for the new offset after changes.
        """
        return self.__new_offset
    
    def get_new_index(self):
        """ Obtains the stored value for the new index after changes.
            Likely to be removed.
        
        Returns:
            unsigned int: The stored value for the new index after changes.
        """
        return self.__new_index

    def get_exception_handlers(self):
        """ Obtains a single exception handler associated with a block.
            see net_cil_disas for result format.
        
        Returns:
            list: An exception handler associated with the block.
        """
        return self.__exception_handlers
    
    def add_exception_handler(self, exception_handler):
        """ Sets the block's exception handler.

        Args:
            exception_handler (list): The exception handler to set.
        """
        if exception_handler[1] is None or not isinstance(exception_handler[1], FunctionBlock):
            raise Exception() #Update the docs later etc etc
        self.__exception_handlers.add(exception_handler)

    def set_filter_block_offset(self, offset):
        """ Sets the offset of the filter handler associated with the block.

        Args:
            offset (unsigned int): The offset of a filter clause holding the block.
        """
        self.__filter_block_offset = offset

    def set_try_block_offset(self, offset):
        """ Sets the offset of the try handler associated with the block.

        Args:
            offset (unsigned int): The offset of a try clause holding the block.
        """
        self.__try_block_offset = offset

    def set_catch_block_offset(self, offset):
        """ Sets the offset of the catch handler associated with the block.

        Args:
            offset (unsigned int): The offset of a catch clause holding the block.
        """
        self.__catch_block_offset = offset

    def set_finally_block_offset(self, offset):
        """ Sets the offset of the finally handler associated with the block.

        Args:
            offset (unsigned int): The offset of a finally clause holding the block.
        """
        self.__finally_block_offset = offset

    def get_try_block_offset(self):
        return self.__try_block_offset
    
    def get_catch_block_offset(self):
        return self.__catch_block_offset
    
    def get_finally_block_offset(self):
        return self.__finally_block_offset
    
    def get_filter_block_offset(self):
        return self.__filter_block_offset

    def mark_block_try(self):
        self.__is_block_try = True

    def mark_block_catch(self):
        self.__is_block_catch = True

    def mark_block_finally(self):
        self.__is_block_finally = True

    def mark_block_filter(self):
        self.__is_block_filter = True

    def is_block_try(self):
        return self.__is_block_try
    
    def is_block_catch(self):
        return self.__is_block_catch
    
    def is_block_finally(self):
        return self.__is_block_finally
    
    def is_block_filter(self):
        return self.__is_block_filter

    def mark_block_finished(self):
        self.__is_block_finished = True

    def mark_switch_block(self):
        self.__was_switch_block = True

    def was_switch_block(self):
        return self.__was_switch_block

    def is_block_return(self):
        return self.get_last_instr().get_opcode() == Opcodes.Ret

    def __hash__(self):
        return hash(self.__start_offset)

    def get_current_size(self):
        result = 0
        for instr in self.get_instrs():
            result += len(instr)
        return result

    def mark_switch_case(self):
        self.__is_switch_case = True

    def is_switch_case(self):
        return self.__is_switch_case
    
    def get_instr_index(self, instr):
        for x in range(len(self.get_instrs())):
            pt_instr = self.get_instrs()[x]
            if pt_instr.get_instr_offset() == instr.get_instr_offset():
                return x
        return -1
    
    def mark_junk(self):
        self.__is_junk_block = True

    def is_junk_block(self):
        return self.__is_junk_block
    
    def reverse_next(self):
        self.__next.reverse()

    def is_start(self):
        return self.__start_offset == 0

    def get_original_length(self):
        return self.__original_length

    def has_absolute_path_to_zero(self):
        if self.__start_offset == 0:
            return prev
        for prev in self.get_prev():
            if prev.has_absolute_path_to_zero():
                return True

        return False
    
    def block_leads_switch(self):
        if self.is_block_switch():
            return True
        if self.is_block_absolutejmp():
            usable = self
            while len(usable.get_next()) == 1 and usable.is_block_absolutejmp():
                usable = usable.ge_next()[0]
                if usable.is_block_switch():
                    return True
        return False

    def get_instr_at_index(self, index):
        return self.__instrs[index]

    def replace_instr(self, index, new_instr):
        self.__instrs[index] = new_instr

    def insert_instr(self, index, instr):
        self.__instrs.insert(index, instr)

    def is_block_conditional(self):
        instr = self.get_last_instr()
        if not self.is_block_absolutejmp():
            if instr.get_opcode() != Opcodes.Switch:
                return instr.is_branch()
        return False

    def contains_instr(self, name):
        for instr in self.__instrs:
            if instr.get_name() == name:
                return True
        return False

    def clear_next(self):
        nxt = list(self.get_next())
        for n in nxt:
            self.remove_next(n)

    def clear_prev(self):
        prv = list(self.get_prev())
        for p in prv:
            self.remove_prev(p)

    def clear_next_raw(self):
        self.__next.clear()

    def clear_prev_raw(self):
        self.__previous.clear()

    def add_next_raw(self, nxt):
        self.__next.append(nxt)

    def add_prev_raw(self, nxt):
        self.__previous.append(nxt)

    def clear_prev_raw(self):
        self.__previous.clear()

    def clear_next_once(self):
        if not self.__was_cleared:
            self.__was_cleared = True
            self.clear_next()

    def is_block_switch(self):
        return self.get_last_instr().get_opcode() == Opcodes.Switch

    def is_block_absolutejmp(self):
        instr = self.get_last_instr()
        opcode = instr.get_opcode()
        return opcode == Opcodes.Br or opcode == Opcodes.Br_S or opcode == Opcodes.Leave or opcode == Opcodes.Leave_S
    
    def is_block_direct(self):
        return not self.is_block_absolutejmp() and not self.is_block_conditional() and not self.get_last_instr().is_branch() and len(self.get_next()) == 1
    
    def add_instr(self, instr):
        self.__instrs.append(instr)
        if self.__start_offset == -1:
            self.__start_offset = instr.get_instr_offset()
            self.__start_index = instr.get_instr_index()

        self.__original_length += len(instr)

    def remove_instrs_after_index(self, index):
        self.__instrs = self.__instrs[:index + 1]

    def replace_instr(self, index, instr):
        self.__instrs[index] = instr
    
    def remove_instrs(self, start, end):
        if not 0 <= start < len(self.__instrs) or not 0 <= end <= len(self.__instrs) or start > end:
            raise net_exceptions.InvalidArgumentsException()
        del self.__instrs[start:end]

    def insert_instr(self, index, instr):
        self.__instrs.insert(index, instr)

    def get_instrs(self):
        return self.__instrs

    def get_start_offset(self):
        return self.__start_offset

    def get_last_instruction(self):
        return self.get_instrs()[-1]

    def has_prev(self, block):
        return block in self.__previous

    def add_next(self, block):
        if block is None:
            raise Exception()
        self.__next.append(block)
        block.add_prev(self)

    def add_prev(self, block):
        if not self.has_prev(block):
            self.__previous.append(block)

    def has_next(self, block):
        return block in self.__next

    def get_next(self):
        return self.__next

    def get_prev(self):
        return self.__previous
    
    def remove_prev(self, prev):
        prev.__next.remove(self)
        self.__previous.remove(prev)

    def get_last_instr(self):
        if len(self.__instrs) == 0:
            return None
        return self.get_instrs()[-1]

    def has_offset(self, offset):
        if self.__is_block_finished:
            if self.__start_offset <= offset < (self.__start_offset + self.__original_length):
                return True
        for instr in self.get_instrs():
            if instr.get_instr_offset() == offset:
                return True
        return False
    
    def merge_block(self, block):
        #merge a block with another.
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
            last_instr_size = len(last_instr)
            last_instr_index = last_instr.get_instr_index()
            
        new_offset = last_instr_offset + last_instr_size
        new_index = last_instr_index
        new_length = self.get_original_length()
        for instr in block.get_instrs():
            if instr.is_absolute_jmp():
                target = instr.get_argument() + len(instr) + instr.get_instr_offset()
                new_argument = target - new_offset - len(instr)
                instr.setup_arguments_from_int32(new_argument)
            elif instr.is_branch():
                if instr.get_opcode() == Opcodes.Switch:
                    args = list()
                    for target in instr.get_argument():
                        new_argument = target - new_offset - len(instr)
                        args.append(new_argument)
                    instr.setup_arguments_from_argslist(args)
                else:
                    target = instr.get_argument() + len(instr) + instr.get_instr_offset()
                    new_argument = target - new_offset - len(instr)
                    instr.setup_arguments_from_int32(new_argument)

            instr.setup_instr_offset(new_offset, new_index)
            new_offset += len(instr)
            new_index += 1
            new_length += len(instr)
            self.add_instr(instr)
        self.__original_length = new_length

    def validate_block(self):
        last_instr = self.get_last_instr()
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
                    
                    if self.__next[0] == self.__next[1]:
                        raise net_exceptions.InvalidBlockException(self)
                
        for nxt in self.__next:
            if self not in nxt.get_prev():
                raise net_exceptions.InvalidBlockException(self)

    def split_block(self, split_offset):
        new_instrs = list()
        split_instrs = list()
        start_splitting = False
        new_size = 0
        for instr in self.__instrs:
            if instr.get_instr_offset() == split_offset:
                start_splitting = True
            if not start_splitting:
                new_size += len(instr)
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

    def remove_next(self, block):
        if self.has_next(block):
            self.__next.remove(block)
            if self in block.__previous and block not in self.__next:
                block.__previous.remove(self)
    
    def replace_next(self, block, new_block):
        found = False
        nxts = list(self.__next)
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
        
    def replace_next_index(self, index, new_block):
        old_next = self.__next[index]
        self.__next[index] = new_block
        if old_next not in self.__next:
            if old_next.has_prev(self):
                old_next.__previous.remove(self)
        if not new_block.has_prev(self):
            new_block.__previous.append(self)

    def get_nstack(self):
        result = 0
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
class FunctionGraph:
    def __init__(self, method_object, force_instrs=None, force_exc_blocks=None, init_blocks=True, debug_print=False):
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

    def register_exception_handlers(self):
        for cl_flag, try_offset, try_length, catch_offset, catch_length, token in self.__raw_exception_blocks:
            if cl_flag == net_structs.CorILExceptionClause.Filter:
                token = self.get_block_by_start_offset(token)
            try_block = self.get_block_by_start_offset(try_offset)
            catch_block = self.get_block_by_start_offset(catch_offset)
            self.__exception_blocks.append((cl_flag, try_block, catch_block, token))


    def update_exc_handlers(self):
        self.__raw_exception_blocks = self.update_raw_exception_clauses()

    def get_raw_exception_clauses(self):
        return self.__raw_exception_blocks

    def duplicate(self):
        new_graph = FunctionGraph(self.__method_object, init_blocks=False)
        new_graph.__blocks_start = dict(self.__blocks_start)
        new_graph.__instr_offsets = dict(self.__instr_offsets)
        new_graph.__instrs = list(self.__instrs)
        new_graph.__disasm_object = self.__disasm_object
        new_graph.__debug_print = self.__debug_print
        new_graph.__exception_blocks = list()
        already_duplicated = dict()
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

    def register_block(self, offset, block):
        self.__blocks_start[offset] = block

    def __handle_try_block(self, try_offset, try_length, handler_offset, handler_length):
        self.__parse_block(try_offset, try_offset, try_offset + try_length, True, False, False, False)
        self.__parse_block(handler_offset, handler_offset, handler_offset + handler_length, False, True, False, False)

    def __handle_finally_block(self, try_offset, try_length, handler_offset, handler_length):
        self.__parse_block(try_offset, try_offset, try_offset + try_length, True, False, False, False)
        self.__parse_block(handler_offset, handler_offset, handler_offset + handler_length, False, False, True, False)

    def __handle_filter_block(self, try_offset, try_length, handler_offset, handler_length, filter_offset, filter_length):
        self.__parse_block(try_offset, try_offset, try_offset + try_length, True, False, False, False)
        self.__parse_block(handler_offset, handler_offset, handler_offset + handler_length, False, True, False, False)
        self.__parse_block(filter_offset, filter_offset, filter_offset + filter_length, False, False, False, True)
    #def __parse_block(self, start_offset, clause_start=-1, max_end_offset=-1, is_try=False, is_catch=False, is_finally=False, is_filter=False)

    def __handle_try_catch_finally_blocks(self):
        """
        Ensure that try catch finally blocks are treated as their own blocks.  
        """
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

    def get_exception_blocks(self):
        return self.__exception_blocks

    def get_disassembler(self):
        return self.__disasm_object

    def sort_blocks(self):
        keys = list(self.__blocks_start.keys())
        keys.sort()
        self.__blocks_start = {i: self.__blocks_start[i] for i in keys}
    
    def enable_debug_printing(self):
        self.__debug_print = True

    def debug_printing_enabled(self):
        return self.__debug_print

    def set_root_block(self, root_block):
        self.__root_block = root_block

    def get_root_block(self):
        return self.__root_block

    def get_block_by_offset(self, offset):
        for block in self.__blocks_start.values():
            if block.has_offset(offset):
                return block
        return None
    
    def get_block_by_start_offset(self, offset):
        for block in self.blocks():
            if block.get_start_offset() == offset:
                return block
        return None
    
    def get_shortest_path(self, from_offset, to_offset):
        if isinstance(to_offset, FunctionBlock) and isinstance(from_offset, FunctionBlock):
            to_block = to_offset
            from_block = from_offset
        else:
            to_block = self.get_block_by_offset(to_offset)
            from_block = self.get_block_by_offset(from_offset)
        if to_block == None or from_block == None:
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
    
    def __walk_path_max_stack(self, block, already_analyzed):
        if block in already_analyzed:
            return 0
        already_analyzed.append(block)
        max_value = 0
        result = 0
        for instr in block.get_instrs():
            result += instr.get_nstack()
            max_value = max(max_value, result)
        next_val = 0
        for blk in block.get_next():
            val = self.__walk_path_max_stack(blk, already_analyzed)
            next_val = max(val, next_val)
        return max(max_value, next_val)        
    
    def calculate_max_stack_size(self):
        max_val = 0
        already_analyzed = list()
        for block in self.__blocks_start.values():
            max_val = max(self.__walk_path_max_stack(block, already_analyzed), max_val)
        return max_val

    def get_paths_to_block(self, to_offset, from_offset):
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
    
    def update_block_handlers(self):
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

    def __parse_block(self, start_offset, clause_start=-1, max_end_offset=-1, is_try=False, is_catch=False, is_finally=False, is_filter=False):
        usable_offset = start_offset
        debug = False
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

        while x >= 0 and x < len(self.__instrs):
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
                    potential_offset = usable_offset + len(instr) + instr.get_argument()
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

                        fallthrough_offset = instr.get_instr_offset() + len(instr)
                        new_block = self.__parse_block(
                            fallthrough_offset, clause_start, max_end_offset, is_try, is_catch, is_finally, is_filter)
                        usable_block = self.get_block_by_offset(
                            usable_offset)
                        usable_block.add_next(new_block)
                        new_block.mark_switch_case()
                    else:
                        #this block of code is to handle conditional branches.
                        potential_offset1 = usable_offset + \
                            len(instr) + instr.get_argument()
                        potential_offset2 = usable_offset + len(instr)

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

            usable_offset += len(instr)

            if opcode == Opcodes.Ret or opcode == Opcodes.Endfinally:
                break

            if instr.is_branch():
                break
            x = self.__instr_offsets[usable_offset].get_instr_index()
        if block is None:
            raise net_exceptions.InvalidBlockException(None)
        return block
    
    def validate_blocks(self):
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
            
    def dump_block_relations(self):
        for block in self.blocks():
            print('block {} {}'.format(block, block.get_last_instr()))
            print('block nexts {}'.format(block.get_next()))
            print('block prevs {}'.format(block.get_prev()))

    def print_root(self):
        dont_print_again = set()
        print('Printing graph for method {} {}'.format(self.__method_object, hex(self.__method_object.get_token())))
        print('Calculated max stack {}'.format(self.calculate_max_stack_size()))
        self.__print_block(self.__root_block, dont_print_again)
                

    def debug_print_blocks(self):
        print('debug printing blocks')
        for block in self.__blocks_start.values():
            print('Block {}'.format(hex(block.get_start_offset())))
            for instr in block.get_instrs():
                print('{}: {}'.format(hex(instr.get_instr_offset()), instr.get_name()))

    def debug_print_nexts(self):
        block: FunctionBlock
        print('Debug printing blocks')
        for block in self.__blocks_start.values():
            print('Block {} is_junk={} is_switch_case={}'.format(hex(block.get_start_offset()), block.is_junk_block(), block.is_switch_case()))
            nxt: FunctionBlock
            for nxt in block.get_next():
                print('Next: {}'.format(hex(nxt.get_start_offset())))

    def update_offsets(self):
        blocks = dict(self.__blocks_start)
        self.__blocks_start.clear()
        for offset, block in blocks.items():
            self.__blocks_start[block.get_start_offset()] = block

        self.__instr_offsets.clear()
        for offset, block in blocks.items():
            for instr in block.get_instrs():
                self.__instr_offsets[instr.get_instr_offset()] = instr
    
    def unregister_block(self, offset):
        for clause_flags, try_block, catch_block, token in self.__exception_blocks:
            if try_block.get_start_offset() == offset or catch_block.get_start_offset() == offset or (isinstance(token, FunctionBlock) and token.get_start_offset() == offset):
                raise Exception()
        del self.__blocks_start[offset]

    def get_block_offsets(self):
        return self.__blocks_start
    
    def blocks(self):
        return self.__blocks_start.values()
    
    def __stack_checker(self, block, stack_count, checked):
        curr_count = stack_count
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

    def stack_checker(self):
        checked = list()
        self.__stack_checker(self.__blocks_start[0], 0, checked)

    def get_exc_handler_for_block(self, flags, block):
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

    def __print_block(self, block, already_printed, indent=0):
        instrs = block.get_instrs()
        is_block_try = False
        is_leave = False

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

    def emit_instructions_as_list(self):
        if self.__disasm_object is None:
            raise Exception('Cant emit a instruction without a disassembler object.')
        current_offset = 0
        result = list()
        current_index = 0
        debug = False
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
                current_offset += len(instr)
                current_index += 1
        return result

    def has_block(self, offset):
        return offset in self.__blocks_start
    
    def update_raw_exception_clauses(self):
        result = list()
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

    def repopulate_prevs(self):
        for block in self.blocks():
            block.clear_prev_raw()
        for block in self.blocks():
            nxts = block.get_next()
            for nxt in nxts:
                nxt.add_prev(block)