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
        for prv in self.get_prev():
            new_prv = prv.duplicate(new_graph, existing_blocks)
            if not new_block.has_prev(new_prv):
                new_block.__previous.append(new_prv)
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
        if block:
            self.__next.append(block)
        if block and not block.has_prev(self):
            block.__previous.append(self)

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
            if len(self.__next) != 1:
                raise net_exceptions.InvalidBlockException(self)
            return
        opcode = last_instr.get_opcode()
        if not last_instr.is_branch():
            if opcode == Opcodes.Ret:
                if not len(self.__next) == 0:
                    raise net_exceptions.InvalidBlockException(self)
            else:
                if opcode == Opcodes.Throw or opcode == Opcodes.Endfinally:
                    #TODO: I think this is correct for endfinally since it doesnt really have a hard transfer, thats handled internally.
                    if len(self.__next) != 0:
                        raise net_exceptions.InvalidBlockException(self)
                else:
                    if len(self.__next) != 1:
                        raise net_exceptions.InvalidBlockException(self)
        else:
            if opcode == Opcodes.Switch:
                if len(self.__next) != (len(last_instr.get_argument()) + 1):
                    print(len(self.__next), len(last_instr.get_argument()))
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
        for nxt in self.__next:
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
    
    def remove_prev(self, prev):
        prev.remove_next(self)

    def replace_next(self, block, new_block):
        if self.has_next(block):
            current_index = self.__next.index(block)
            if current_index == -1:
                raise net_exceptions.InvalidBlockException(self)
            self.remove_next(block)
            if self.has_next(new_block):
                #if the block is already there, in order to preserve order remove it.
                self.remove_next(new_block)

            if not self.has_next(new_block):
                if new_block and not self.has_next(new_block):
                    self.__next.insert(current_index, new_block)
                if new_block and not new_block.has_prev(self):
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
        return isinstance(other, FunctionBlock) and self.get_start_offset() == other.get_start_offset()
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
                    raise net_exceptions.OperationNotSupportedException
                self.__disasm_object = method_object.disassemble_method()
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

    def update_exc_handlers(self):
        self.__raw_exception_blocks = self.get_raw_exception_clauses()

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
                if opcode == Opcodes.Throw:
                    break

            usable_offset += len(instr)

            if opcode == Opcodes.Ret or opcode == Opcodes.Endfinally:
                break

            if instr.is_branch():
                break
            try:
                x = self.__instr_offsets[usable_offset].get_instr_index()
            except:
                print(instr)
                print('error getting index {} {}'.format(hex(usable_offset), block))
                raise Exception
        if block is None:
            raise net_exceptions.InvalidBlockException(None)
        return block
    
    def validate_blocks(self):
        for blk in self.blocks():
            blk.validate_block()

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
                    print((' ' * indent) + '{}: jump to {}'.format(hex(instr.get_instr_offset()),
                                                  hex(instr.get_instr_offset() + len(instr) + instr.get_argument())))
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
                    if cl_flag == net_exceptions.CorILExceptionClause.Exception:
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
                            if cl_flag == net_exceptions.CorILExceptionClause.Finally:
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
        for offset, block in self.__blocks_start.items():
            if offset > current_offset:
                amt_pad = offset - current_offset
                for x in range(amt_pad):
                    #If a branch is just not used, the graph will ignore it.  Account for that here.
                    instr = self.__disasm_object.emit_instruction(0x0)
                    instr.setup_instr_size(1)
                    instr.setup_instr_offset(current_offset, current_index)
                    result.append(instr)
                    current_index += 1
                    current_offset += 1
            if current_offset != offset:
                print(hex(current_offset), hex(offset), block)
                raise Exception()
            for instr in block.get_instrs():
                instr.setup_instr_offset(current_offset, current_index)
                result.append(instr)
                current_offset += len(instr)
                current_index += 1
        return result

    def has_block(self, offset):
        return offset in self.__blocks_start
    
    def get_raw_exception_clauses(self):
        result = list()
        for cl_flag, try_block, catch_block, token in self.__exception_blocks:
            try_offset = try_block.get_start_offset()
            catch_offset = catch_block.get_start_offset()
            token = token
            if cl_flag == net_exceptions.CorILExceptionClause.Filter:
                token = token.get_start_offset()
            try_size = 0
            catch_size = 0
            for block in self.blocks():
                exc_clauses = block.get_exception_handlers()
                for exc_flag, block in exc_clauses:
                    if block == try_offset.get_start_offset() and cl_flag == exc_flag:
                        try_size += block.get_original_length()
                    elif block == catch_offset.get_start_offset() and cl_flag == exc_flag:
                        catch_size += block.get_original_length()
            result.append((cl_flag, try_offset, try_size, catch_offset, catch_size, token))
        return result

class GraphAnalyzer:

    MATH_OPS = [Opcodes.Not, Opcodes.Sub, Opcodes.Add, Opcodes.Neg, Opcodes.Xor, Opcodes.Shr, Opcodes.Shl, Opcodes.Or, Opcodes.Shr_Un, Opcodes.And, Opcodes.Mul, Opcodes.Div, Opcodes.Div_Un, Opcodes.Rem, Opcodes.Rem_Un]
    ALLOWED_STACK_OPS = [Opcodes.Br, Opcodes.Pop, Opcodes.Br_S, Opcodes.Ldc_I4, Opcodes.Ldc_I4_S, Opcodes.Ldloc, Opcodes.Ldloc_S, Opcodes.Dup, Opcodes.Ldc_I4_M1, Opcodes.Ldc_I4_0, Opcodes.Ldc_I4_1, Opcodes.Ldc_I4_2, Opcodes.Ldc_I4_3, Opcodes.Ldc_I4_5, Opcodes.Ldc_I4_6, Opcodes.Ldc_I4_7, Opcodes.Ldc_I4_8]
    BRANCHES = [Opcodes.Brtrue, Opcodes.Brtrue_S, Opcodes.Brfalse, Opcodes.Brfalse_S, Opcodes.Beq, Opcodes.Beq_S, Opcodes.Bne_Un, Opcodes.Bne_Un_S, \
                Opcodes.Bge, Opcodes.Bge_S, Opcodes.Bge_Un, Opcodes.Bge_Un_S, Opcodes.Bgt, Opcodes.Bgt_S, Opcodes.Bgt_Un, Opcodes.Bgt_Un_S, \
                Opcodes.Ble, Opcodes.Ble_S, Opcodes.Ble_Un, Opcodes.Ble_Un_S, Opcodes.Blt, Opcodes.Blt_S, Opcodes.Blt_Un, Opcodes.Blt_Un_S]
    
    def __init__(self, method_obj: net_row_objects.MethodDefOrRef, func_graph: FunctionGraph):
        self.__graph = func_graph
        self.__disasm = self.__graph.get_disassembler()
        self.__method = method_obj


    def __are_additional_instrs_needed(self, block, instrs, start, end):
        if len(instrs) <= 1:
            raise net_exceptions.InvalidArgumentsException()
        #dont allow single instrs blocks, dont allow only checking one instruction.
        amt_on_stack = 0
        first_instr = instrs[start]
        if first_instr.get_pstack() != amt_on_stack:
            return True
        amt_on_stack = first_instr.get_nstack()
        second_instr = instrs[start + 1]
        if second_instr.get_pstack() > amt_on_stack:
            return True
        
        return False
    
    """
    Eventually going to want to move instruction generation out of here but for the prototype
    """
    def emit_branch_instr(self, opcode, offset, target, small):
        #target = argument + instr.size + instr.offset
        #target - instr.size - instr.offset = argument
        instr_one = self.__disasm.emit_instruction(opcode)

        encoded_target = target - offset
        if small:
            if not -126 <= encoded_target <= 129:
                raise net_exceptions.InvalidArgumentsException()
            instr_one.setup_instr_size(2)
            encoded_target -= 2
            instr_one.setup_argument_from_int8(encoded_target)
        else:
            encoded_target -= 5
            instr_one.setup_argument_from_int32(encoded_target)
            instr_one.setup_instr_size(5)
        return instr_one

    def emit_ldc_num(self, number):
        instrs = list()
        use_ldc_i4 = False
        if not isinstance(number, net_emu_types.DotNetNumber):
            raise net_exceptions.InvalidArgumentsException()
        pobj = number.as_python_obj()
        if isinstance(number, net_emu_types.DotNetSingle):
            instr_one = self.__disasm.emit_instruction(0x22)
            instr_one.setup_arguments_from_float(pobj)
            instr_one.setup_instr_size(5)
            instrs.append(instr_one)
        elif isinstance(number, net_emu_types.DotNetDouble):
            instr_one = self.__disasm.emit_instruction(0x23)
            instr_one.setup_instr_size(9)
            instr_one.setup_arguments_from_double(pobj)
            instrs.append(instr_one)
        elif isinstance(number, net_emu_types.DotNetBoolean):
            if pobj:
                instr_one = self.__disasm.emit_instruction(0x17)
            else:
                instr_one = self.__disasm.emit_instruction(0x16)
            instr_one.setup_instr_size(1)
            instrs.append(instr_one)
        else:
            if number.is_signed():
                if pobj == -1:
                    use_ldc_i4 = True
                    instr_one = self.__disasm.emit_instruction(0x15)
                    instr_one.setup_instr_size(1)
                    instrs.append(instr_one)
        if len(instrs) == 0:
            amt_needed = (pobj.bit_length() + 7) // 8
            if amt_needed <= 4 and -2147483648 <= pobj <= 2147483647:
                if 0 <= pobj <= 8:
                    opcode = 0x16 + pobj
                    instr_one = self.__disasm.emit_instruction(opcode)
                    instr_one.setup_instr_size(1)
                    instrs.append(instr_one)
                    use_ldc_i4 = True
                else:
                    if amt_needed == 1 and -128 <= pobj <= 127:
                        instr_one = self.__disasm.emit_instruction(0x1F)
                        instr_one.setup_arguments_from_int8(pobj)
                        instr_one.setup_instr_size(2)
                        instrs.append(instr_one)
                        use_ldc_i4 = True
                    elif amt_needed <= 4:
                        instr_one = self.__disasm.emit_instruction(0x20)
                        instr_one.setup_arguments_from_int32(pobj)
                        instr_one.setup_instr_size(5)
                        instrs.append(instr_one)
                        use_ldc_i4 = True
                    else:
                        raise net_exceptions.InvalidArgumentsException()
            elif amt_needed <= 8:
                instr_one = self.__disasm.emit_instruction(0x1E)
                instr_one.setup_arguments_from_int64(pobj)
                instr_one.setup_instr_size(9)
                instrs.append(instr_one)
            else:
                raise net_exceptions.InvalidArgumentsException()
            
            if isinstance(number, net_emu_types.DotNetUInt32):
                instr_one = self.__disasm.emit_instruction(0x6D)
                instr_one.setup_instr_size(1)
                instrs.append(instr_one)
            elif isinstance(number, net_emu_types.DotNetIntPtr):
                instr_one = self.__disasm.emit_instruction(0xD3)
                instr_one.setup_instr_size(1)
                instrs.append(instr_one)
            elif isinstance(number, net_emu_types.DotNetUIntPtr):
                instr_one = self.__disasm.emit_instruction(0xE0)
                instr_one.setup_instr_size(1)
                instrs.append(instr_one)
            elif isinstance(number, net_emu_types.DotNetInt64) and use_ldc_i4:
                instr_one = self.__disasm.emit_instruction(0x6A)
                instr_one.setup_instr_size(1)
                instrs.append(instr_one)
            elif isinstance(number, net_emu_types.DotNetUInt64):
                instr_one = self.__disasm.emit_instruction(0x6E)
                instr_one.setup_instr_size(1)
                instrs.append(instr_one)
        return instrs
    
    def __handle_math_instrs(self, block, instrs, start_index, end_index, amt_deleted):
        instr = instrs[end_index]
        start_instr = instrs[start_index]
        start_offset = start_instr.get_instr_offset()
        end_offset = instr.get_instr_offset()
        emu_obj = net_emulator.DotNetEmulator(self.__method, start_offset=start_offset, end_offset=end_offset, dont_execute_cctor=True)
        try:
            emu_obj.run_function()
        except net_exceptions.EmulatorEndExecutionException:
            pass
        instrs_result = list()
        for x in range(len(emu_obj.get_stack())):
            result = emu_obj.get_stack().pop_obj()
            instrs_result = self.emit_ldc_num(result) + instrs_result
        amt_instrs = end_index - start_index

        block.remove_instrs(start_index + amt_deleted, end_index + amt_deleted)
        for x in range(len(instrs_result)):
            block.insert_instr(start_index + x + amt_deleted, instrs_result[x])
        return len(instrs_result) - amt_instrs

    """
    An attempt at control flow deobfuscation.
    """

    def __target_walker(self, block, needed, already_checked, stloc_instr, start_offsets, child_addr, bad_instr_offsets, counter=0):
        """
        This method is definitely going to need some testing and work but I mean its okay for now.
        """

        instrs = block.get_instrs()
        debug = False
        if block.get_start_offset() in already_checked:
            if debug:
                print(hex(instr.get_instr_offset()), 0)
            return False
        already_checked.append(block.get_start_offset())
        if debug:
            print('Checking block {} {}'.format(hex(block.get_start_offset()), needed))
        need_local = False
        for x in range(len(instrs) - 1, -1, -1):
            instr = instrs[x]
            ins_op = instr.get_opcode()
            pulled = instr.get_pstack()
            added = instr.get_astack()
            if debug:
                print('Checking instr {} {} {} {} {}'.format(hex(instr.get_instr_offset()), instr.get_name(), needed, added, pulled))
            if ins_op not in (self.MATH_OPS + self.ALLOWED_STACK_OPS + [Opcodes.Switch, Opcodes.Stloc, Opcodes.Stloc_S]):
                if pulled > 0 or added > 0:
                    if debug:
                        print(1, hex(instr.get_instr_offset()))
                    return False
            if ins_op in (Opcodes.Ldloc_S, Opcodes.Ldloc):
                if instr.get_argument() == stloc_instr.get_argument():
                    if needed <= 0:
                        raise Exception()
                    needed -= 1

                    if needed == 0:
                        #Gate this off if theres a stloc above.
                        skip = False
                        if x > 0:
                            if instrs[x-1].get_opcode() in (Opcodes.Stloc, Opcodes.Stloc_S):
                                if instrs[x-1].get_argument() == stloc_instr.get_argument():
                                    bad_instr_offsets.add(instr.get_instr_offset())
                                    needs_local = True
                                    continue
                        elif x == 0:
                            skip = True
                            for prev_blk in block.get_prev():
                                for y in range(len(prev_blk.get_instrs()) - 1, -1, -1):
                                    instr2 = prev_blk.get_instrs()[y]
                                    if instr2.is_absolute_jmp():
                                        continue
                                    if instr2.get_opcode() not in (Opcodes.Stloc, Opcodes.Stloc_S):
                                        skip = False
                                        break
                                    if instr2.get_argument() != stloc_instr.get_argument():
                                        skip = False
                                        break
                                    break
                                        
                                if not skip:
                                    break

                            if skip:
                                needs_local = True
                                bad_instr_offsets.add(instr.get_instr_offset())
                                continue

                        if not skip:
                            bad_instr_offsets.add(instr.get_instr_offset())
                            start_offsets.append((child_addr, instr.get_instr_offset()))
                            if debug:
                                print(2, hex(instr.get_instr_offset()))
                            return True
                    needed += 1
            needed = needed - added + pulled
            if debug:
                print('needed is now 1 {} {} {}'.format(needed, added, pulled))
            if needed < 0:
                needed = 0
            if debug:
                print('needed is now 2 {}'.format(needed))
            if needed == 0:
                bad_instr_offsets.add(instr.get_instr_offset())
                start_offsets.append((child_addr, instr.get_instr_offset()))
                if debug:
                    print(3, hex(instr.get_instr_offset()), hex(child_addr))
                return True
            if ins_op in (Opcodes.Stloc, Opcodes.Stloc_S):
                if instr.get_argument() == stloc_instr.get_argument():
                    continue
                elif instr.get_argument() != stloc_instr.get_argument():
                    if needed == 0:
                        bad_instr_offsets.add(instr.get_instr_offset())
                        start_offsets.append((child_addr, instr.get_instr_offset()))
                        if debug:
                            print(4, hex(instr.get_instr_offset()))
                        return True
                    else:
                        if debug:
                            print(5, hex(instr.get_instr_offset()))
                        return False
            if ins_op not in (self.MATH_OPS + self.ALLOWED_STACK_OPS):
                if counter == 0 and ins_op == Opcodes.Switch:
                    continue
                if debug:
                    print(6, hex(instr.get_instr_offset()))
                return False
            bad_instr_offsets.add(instr.get_instr_offset())
            
        if needed != 0 or needs_local:
            for prev in block.get_prev():
                if debug:
                    print('Checking prev {} {}'.format(hex(prev.get_start_offset()), counter))
                if counter == 0:
                    result = not self.__target_walker(prev, needed, already_checked, stloc_instr, start_offsets, prev.get_start_offset(), bad_instr_offsets, counter=counter+1)
                else:
                    result = not self.__target_walker(prev, needed, already_checked, stloc_instr, start_offsets, child_addr, bad_instr_offsets, counter=counter+1)
                if result:
                    if debug:
                        print(7, hex(instr.get_instr_offset()))
                    return False
        if debug:
            print(8, hex(block.get_start_offset()), hex(child_addr))
        return True

    def __is_target_switch(self, block, start_offsets, bad_instr_offsets):
        #check if all paths have a relatively constant value.
        instrs = block.get_instrs()
        MATH_OPS = [Opcodes.Not, Opcodes.Sub, Opcodes.Add, Opcodes.Neg, Opcodes.Xor, Opcodes.Shr, Opcodes.Shl, Opcodes.Or, Opcodes.Shr_Un, Opcodes.And, Opcodes.Mul, Opcodes.Div, Opcodes.Div_Un, Opcodes.Rem, Opcodes.Rem_Un]
        ALLOWED_STACK_OPS = [Opcodes.Br, Opcodes.Br_S, Opcodes.Ldc_I4, Opcodes.Ldc_I4_S, Opcodes.Stloc, Opcodes.Stloc_S, Opcodes.Ldloc, Opcodes.Ldloc_S, Opcodes.Dup, Opcodes.Ldc_I4_M1, Opcodes.Ldc_I4_0, Opcodes.Ldc_I4_1, Opcodes.Ldc_I4_2, Opcodes.Ldc_I4_3, Opcodes.Ldc_I4_5, Opcodes.Ldc_I4_6, Opcodes.Ldc_I4_7, Opcodes.Ldc_I4_8]
        if len(instrs) < 2:
            return False
        if instrs[-2].get_opcode() not in MATH_OPS:
            return False
        if block.get_last_instr().get_opcode() != Opcodes.Switch:
            return False
        #make sure theres at least one branch thats a fall through or a 1-1 ration
        already_checked = list()
        stloc_instr = None
        for x in range(len(instrs) - 1, -1, -1):
            ins_op = instrs[x].get_opcode()
            bad_instr_offsets.add(instrs[x].get_instr_offset())
            if ins_op == Opcodes.Stloc or ins_op == Opcodes.Stloc_S:
                stloc_instr = instrs[x]
                break
        if stloc_instr is None:
            return False
        start_offsets.clear()
        return self.__target_walker(block, 0, already_checked, stloc_instr, start_offsets, block.get_start_offset(), bad_instr_offsets)
    

    def __switch_block_walker(self, block, switch_instr, offsets_grouped, new_graph, already_handled, initial_emu, base_local_var, stloc_num):
        debug = True
        if block.get_start_offset() in already_handled:
            base_vars = already_handled[block.get_start_offset()]
            if base_local_var.as_python_obj() in base_vars:
                return
        else:
            already_handled[block.get_start_offset()] = list()
        already_handled[block.get_start_offset()].append(base_local_var.as_python_obj())
        if block.get_start_offset() in offsets_grouped:
            if debug:
                print('handling switch block {} with base var {}'.format(block, hex(base_local_var.as_python_obj())))
            offsets = offsets_grouped[block.get_start_offset()]
            for offset in offsets:
                #absolute jmp, it can only go one place.
                if debug:
                    print('Handling offset {}'.format(hex(offset)))
                start_offset = offset
                end_offset = switch_instr.get_instr_offset()
                emu = initial_emu.spawn_new_emulator(self.__method, start_offset=start_offset, end_offset=end_offset)
                emu.set_local_obj(stloc_num, base_local_var)
                emu.setup_method_params([])
                worked = False
                try:
                    emu.run_function()
                except net_exceptions.EmulatorEndExecutionException:
                    worked = True
                if not worked:
                    raise Exception()
                new_target = emu.get_stack().pop_obj()
                if not isinstance(new_target, net_emu_types.DotNetNumber):
                    raise Exception()
                new_local_var = emu.get_local_obj(stloc_num)
                switch_targets = switch_instr.get_argument()
                new_target = new_target.as_python_obj()
                if new_target < 0 or new_target >= len(switch_targets):
                    new_offset = len(switch_instr) + switch_instr.get_instr_offset() 
                else:
                    new_offset = switch_targets[new_target]
                if debug:
                    print('new target {}'.format(hex(new_offset)))
                new_start_block = new_graph.get_block_by_offset(start_offset)
                old_start_block = self.__graph.get_block_by_offset(start_offset)
                new_next_block = new_graph.get_block_by_offset(new_offset)
                if len(old_start_block.get_next()) != 1:
                    print(old_start_block, old_start_block.get_next())
                    raise Exception()
                old_next = old_start_block.get_next()[0]
                new_next = new_graph.get_block_by_offset(old_next.get_start_offset())
                if debug:
                    print('new start block {} new next {} new next block {}'.format(new_start_block, new_next, new_next_block))
                    print('new start block prev nexts {}'.format(new_start_block.get_next()))
                if new_start_block.has_next(new_next): #This line here might be an issue if the function has a legitimate switch statement.  Will need to be careful.
                    new_start_block.remove_next(new_next)
                    new_start_block.add_next(new_next_block) #PROBLEM: because we removed the has_next() check in add_next() to allow for switch instrs to work properly, we need to make sure we arent adding duplicate nexts where they arent needed.
                    if debug:
                        print('new start block new nexts {}'.format(new_start_block.get_next()))
                self.__switch_block_walker(self.__graph.get_block_by_offset(new_offset), switch_instr, offsets_grouped, new_graph, already_handled, initial_emu, new_local_var, stloc_num)
            return
        for nxt in block.get_next():
            #if debug:
            #    print('handling next {}'.format(nxt))
            self.__switch_block_walker(nxt, switch_instr, offsets_grouped, new_graph, already_handled, initial_emu, base_local_var, stloc_num)

    
    def __deobfuscate_switch(self, block, offsets, switch_instr, new_graph, bad_instrs):
        #first group the offsets together.
        offsets_grouped = dict()
        for block_offset, offset in offsets:
            if block_offset not in offsets_grouped:
                offsets_grouped[block_offset] = list()
            offsets_grouped[block_offset].append(offset)

        debug = True
        if debug:
            for block_offset, offsets in offsets_grouped.items():
                for offset in offsets:
                    print('block offset {} -> start {}'.format(hex(block_offset), hex(offset)))
        start_block = None
        for prev in block.get_prev():
            if (prev.get_start_offset() + prev.get_original_length()) == block.get_start_offset():
                start_block = prev
                break
        if start_block is None:
            raise Exception()
        stloc_instr = None
        for instr in reversed(block.get_instrs()):
            if instr.get_opcode() in (Opcodes.Stloc, Opcodes.Stloc_S):
                stloc_instr = instr
                break

        if stloc_instr is None:
            raise Exception()
        needed = 0
        instrs = block.get_instrs()
        for x in range(len(instrs) - 1, -1, -1):
            instr = instrs[x]
            ins_op = instr.get_opcode()
            pulled = instr.get_pstack()
            added = instr.get_astack()
            if ins_op not in (self.MATH_OPS + self.ALLOWED_STACK_OPS + [Opcodes.Switch, Opcodes.Stloc, Opcodes.Stloc_S]):
                raise Exception()
            needed = needed - added + pulled
            if needed == 0:
                break
        dont_use_first = False
        if needed == 0 and block.get_instrs()[0].get_opcode() in (Opcodes.Ldloc, Opcodes.Ldloc_S) and block.get_instrs()[0].get_argument() == stloc_instr.get_argument():
            dont_use_first = True
        if needed == 0 and not dont_use_first:
            first_start_offset = block.get_start_offset()
        else:
            instrs = start_block.get_instrs()
            for x in range(len(instrs) - 1, -1, -1):
                instr = instrs[x]
                ins_op = instr.get_opcode()
                pulled = instr.get_pstack()
                added = instr.get_astack()
                if ins_op not in (self.MATH_OPS + self.ALLOWED_STACK_OPS + [Opcodes.Switch, Opcodes.Stloc, Opcodes.Stloc_S]):
                    raise Exception()
                needed = needed - added + pulled
                bad_instrs.add(instr.get_instr_offset())
                if needed == 0:
                    first_start_offset = instr.get_instr_offset()
                    break
        #get the initial feed value.
        if first_start_offset == -1:
            raise Exception()
        emu = net_emulator.DotNetEmulator(self.__method, start_offset=first_start_offset, end_offset=switch_instr.get_instr_offset(), dont_execute_cctor=True)
        emu.setup_method_params([])
        worked = False
        try:
            emu.run_function()
        except net_exceptions.EmulatorEndExecutionException:
            worked = True
        if not worked:
            raise Exception()
        worked = False
        result = emu.get_stack().pop_obj()
        base_local = emu.get_local_obj(stloc_instr.get_argument())
        if not isinstance(result, net_emu_types.DotNetNumber) or not isinstance(base_local, net_emu_types.DotNetNumber):
            raise Exception()
        result = result.as_python_obj()
        orig_base_local = base_local
        base_local = base_local.as_python_obj()
        switch_targets = switch_instr.get_argument()
        if result < 0 or result >= len(switch_targets):
            starting_offset = switch_instr.get_instr_offset() + len(switch_instr)
        else:
            starting_offset = switch_targets[result]
        #unlink the switch block
        new_switch_block = new_graph.get_block_by_offset(block.get_start_offset())
        new_start_block = new_graph.get_block_by_offset(start_block.get_start_offset())
        new_initial_block = new_graph.get_block_by_offset(starting_offset)
        initial_block = self.__graph.get_block_by_offset(starting_offset)
        if debug:
            print('first start offset {}'.format(hex(first_start_offset)))
            print('new switch block {} new start block {}'.format(new_switch_block, new_start_block))
            print('PRE: new switch block next {} new start block next {}'.format(new_switch_block.get_next(), new_start_block.get_next()))
        new_switch_block.remove_prev(new_start_block)
        new_start_block.add_next(new_initial_block)
        if debug:
            print('POST: new switch block next {} new start block next {}'.format(new_switch_block.get_next(), new_start_block.get_next()))
        already_handled = {new_start_block.get_start_offset(): [base_local]}
        stloc_num = stloc_instr.get_argument()
        self.__switch_block_walker(initial_block, switch_instr, offsets_grouped, new_graph, already_handled, emu, orig_base_local, stloc_num)

        new_switch_block.clear_next()
        new_switch_block.clear_prev()

        for blk in list(new_graph.blocks()):
            if len(blk.get_next()) == 0 and len(blk.get_prev()) == 0 and blk.get_start_offset() != 0:
                new_graph.unregister_block(blk.get_start_offset())
        #now remove any instructions that we know are junk.
        new_graph.validate_blocks()
        for blk in new_graph.blocks():
            amt_deleted = 0
            instrs = list(blk.get_instrs())
            for x in range(len(instrs)):
                instr = instrs[x]
                if instr.get_instr_offset() in bad_instrs and not instr.is_branch() and not instr.is_absolute_jmp():
                    blk.remove_instrs(x - amt_deleted, x - amt_deleted + 1)
                    amt_deleted += 1
        #First remove any useless blocks.
        new_graph.validate_blocks()
        blocks = list(new_graph.blocks())
        #if a block only has one next block and no jump, merge them.
        for blk in blocks:
            last_instr = blk.get_last_instr()
            if last_instr is not None:
                last_op = last_instr.get_opcode()
                instrs = blk.get_instrs()
                if last_op == Opcodes.Ret:
                    continue
                if last_instr.is_branch():
                    continue

                if last_instr.is_absolute_jmp():
                    continue
            if len(blk.get_next()) == len(blk.get_prev()) == len(blk.get_instrs()) == 0:
                if new_graph.has_block(blk.get_start_offset()):
                    new_graph.unregister_block(blk.get_start_offset())
                continue
            nxts = blk.get_next()
            if len(nxts) != 1:
                raise Exception()
            nxt = nxts[0]
            if len(nxt.get_prev()) == 1:
                blk.remove_next(nxt)
                blk.merge_block(nxt)
                blk_nxts = list(nxt.get_next())
                nxt.clear_next()
                for n in blk_nxts:
                    n_last = n.get_last_instr()
                    blk.add_next(n)
                new_graph.unregister_block(nxt.get_start_offset())
            else:
                if not blk.is_block_try() and not blk.is_block_catch() and not blk.is_block_finally() and not blk.is_block_filter():
                    new_instr = self.__disasm.emit_instruction(Opcodes.Br)
                else:
                    new_instr = self.__disasm.emit_instruction(Opcodes.Leave)
                target = nxt.get_start_offset() - (blk.get_start_offset() + blk.get_current_size()) - 5
                new_instr.setup_instr_size(5)
                ins_index = blk.get_start_index()
                if last_instr is not None:
                    ins_index = last_instr.get_instr_index() + 1
                new_instr.setup_instr_offset(blk.get_start_offset() + blk.get_current_size(), ins_index)
                new_instr.setup_arguments_from_int32(target)
                blk.add_instr(new_instr)

        new_graph.validate_blocks()

        #lastly update all the offsets for branches
        for blk in new_graph.blocks():
            last_instr = blk.get_last_instr()
            if last_instr is None:
                continue
            last_op = last_instr.get_opcode()
            if last_instr.is_absolute_jmp():
                if len(blk.get_next()) != 1:
                    raise Exception()
                nxt = blk.get_next()[0]
                argument = nxt.get_start_offset() - last_instr.get_instr_offset() - len(last_instr)
                last_instr.setup_arguments_from_int32(argument)
            else:
                if last_instr.is_branch():
                    if last_instr.get_opcode() == Opcodes.Switch:
                        #TODO: Need to make some changes to FunctionBlock to properly support switches - get_next() is all messed up.
                        args = list()
                        nxts = blk.get_next()
                        for x in range(len(nxts) - 1):
                            target = nxts[x]
                            argument = target.get_start_offset() - last_instr.get_instr_offset() - len(last_instr)
                            args.append(argument)
                        last_instr.setup_arguments_from_argslist(args)
                    else:
                        if len(blk.get_next()) != 2:
                            raise Exception()
                        nxt = blk.get_next()[1]
                        argument = nxt.get_start_offset() - last_instr.get_instr_offset() - len(last_instr)
                        last_instr.setup_arguments_from_int32(argument)
        new_graph.validate_blocks()
        new_graph.sort_blocks()

        new_analyzer = GraphAnalyzer(self.__method, new_graph)
        new_analyzer.repair_blocks()
        new_graph.update_offsets()
        new_graph.sort_blocks()
        new_graph.validate_blocks()

    def simplify_control_flow(self):
        out = self.__graph.duplicate()
        block = self.__graph.get_block_by_offset(0)
        is_obfuscated = False
        for block in self.__graph.blocks():
            #print('checking block {}'.format(hex(block.get_start_offset())))
            start_offsets = list()
            bad_instrs = set()
            if self.__is_target_switch(block, start_offsets, bad_instrs):
                is_obfuscated = True
                self.__deobfuscate_switch(block, start_offsets, block.get_last_instr(), out, bad_instrs)
            else:
                pass
                #print('Block {} is not target switch'.format(hex(block.get_start_offset())))
        if not is_obfuscated:
            return None
        return out
    
    def __emit_small_instr_for_big(self, instr):
        if not instr.is_branch() and not instr.is_absolute_jmp():
            return None
        ins_op = instr.get_opcode()
        new_instr = None
        if ins_op == Opcodes.Br:
            new_instr = self.__disasm.emit_instruction(Opcodes.Br_S)
        elif ins_op == Opcodes.Brfalse:
            new_instr = self.__disasm.emit_instruction(Opcodes.Brfalse_S)
        elif ins_op == Opcodes.Brtrue:
            new_instr = self.__disasm.emit_instruction(Opcodes.Brtrue_S)
        elif ins_op == Opcodes.Beq:
            new_instr = self.__disasm.emit_instruction(Opcodes.Beq_S)
        elif ins_op == Opcodes.Bge:
            new_instr = self.__disasm.emit_instruction(Opcodes.Bge_S)
        elif ins_op == Opcodes.Bgt:
            new_instr = self.__disasm.emit_instruction(Opcodes.Bgt_S)
        elif ins_op == Opcodes.Ble:
            new_instr = self.__disasm.emit_instruction(Opcodes.Ble_S)
        elif ins_op == Opcodes.Blt:
            new_instr = self.__disasm.emit_instruction(Opcodes.Blt_S)
        elif ins_op == Opcodes.Bne_Un:
            new_instr = self.__disasm.emit_instruction(Opcodes.Bne_Un_S)
        elif ins_op == Opcodes.Bge_Un:
            new_instr = self.__disasm.emit_instruction(Opcodes.Bge_Un_S)
        elif ins_op == Opcodes.Bgt_Un:
            new_instr = self.__disasm.emit_instruction(Opcodes.Bgt_Un_S)
        elif ins_op == Opcodes.Ble_Un:
            new_instr = self.__disasm.emit_instruction(Opcodes.Ble_Un_S)
        elif ins_op == Opcodes.Blt_Un:
            new_instr = self.__disasm.emit_instruction(Opcodes.Blt_Un_S)
        elif ins_op == Opcodes.Leave:
            new_instr = self.__disasm.emit_instruction(Opcodes.Leave_S)
        
        if new_instr is None:
            return None
        new_instr.setup_instr_size(2)
        return new_instr
    
    def __emit_big_instr_for_small(self, instr):
        if not instr.is_branch() and not instr.is_absolute_jmp():
            return None
        ins_op = instr.get_opcode()
        new_instr = None
        if ins_op == Opcodes.Br_S:
            new_instr = self.__disasm.emit_instruction(Opcodes.Br)
        elif ins_op == Opcodes.Brfalse_S:
            new_instr = self.__disasm.emit_instruction(Opcodes.Brfalse)
        elif ins_op == Opcodes.Brtrue_S:
            new_instr = self.__disasm.emit_instruction(Opcodes.Brtrue)
        elif ins_op == Opcodes.Beq_S:
            new_instr = self.__disasm.emit_instruction(Opcodes.Beq)
        elif ins_op == Opcodes.Bge_S:
            new_instr = self.__disasm.emit_instruction(Opcodes.Bge)
        elif ins_op == Opcodes.Bgt_S:
            new_instr = self.__disasm.emit_instruction(Opcodes.Bgt)
        elif ins_op == Opcodes.Ble_S:
            new_instr = self.__disasm.emit_instruction(Opcodes.Ble)
        elif ins_op == Opcodes.Blt_S:
            new_instr = self.__disasm.emit_instruction(Opcodes.Blt)
        elif ins_op == Opcodes.Bne_Un_S:
            new_instr = self.__disasm.emit_instruction(Opcodes.Bne_Un)
        elif ins_op == Opcodes.Bge_Un_S:
            new_instr = self.__disasm.emit_instruction(Opcodes.Bge_Un)
        elif ins_op == Opcodes.Bgt_Un_S:
            new_instr = self.__disasm.emit_instruction(Opcodes.Bgt_Un)
        elif ins_op == Opcodes.Ble_Un_S:
            new_instr = self.__disasm.emit_instruction(Opcodes.Ble_Un)
        elif ins_op == Opcodes.Blt_Un_S:
            new_instr = self.__disasm.emit_instruction(Opcodes.Blt_Un)
        elif ins_op == Opcodes.Leave_S:
            new_instr = self.__disasm.emit_instruction(Opcodes.Leave)
        
        if new_instr is None:
            return None
        new_instr.setup_instr_size(5)
        return new_instr
        
    
    def __block_walker(self, block, handled, exc_handlers):
        if block not in handled:
            #The block hasnt been laid out yet.
            handled.append(block) #Goal is to get the layout of blocks in order, then recalculate offsets.
            last_instr = block.get_last_instr()
            last_op = last_instr.get_opcode()
            new_last_instr = self.__emit_big_instr_for_small(last_instr)
            if new_last_instr is not None: #for now normalize all jumps to their big counterparts.
                last_index = len(block.get_instrs()) - 1
                new_last_instr.setup_arguments_from_int32(0)
                new_last_instr.setup_instr_offset(last_instr.get_instr_offset(), last_instr.get_instr_index())
                block.replace_instr(last_index, new_last_instr)
            
            last_instr = block.get_last_instr()
            last_op = last_instr.get_opcode()
            #the fallthrough case is always the last one in the nexts, so theres that.
            blk_next = block.get_next()
            if len(blk_next) > 0:
                self.__block_walker(blk_next[-1], handled, exc_handlers)
            
            if last_instr.is_branch():
                if last_op == Opcodes.Switch:
                    for x in range(0, len(blk_next) - 1):
                        self.__block_walker(blk_next[x], handled, exc_handlers)
                else:
                    self.__block_walker(blk_next[0], handled, exc_handlers)

    def repair_blocks(self):
        #TODO: When stiching together blocks try blocks need to be together, filter clause needs to follow the rules etc.
        self.__graph.validate_blocks()
        for block in list(self.__graph.blocks()):
            block_prev = block.get_prev()
            block_next = block.get_next()
            if len(block_prev) == 1:
                prev = block_prev[0]
                prev_last = prev.get_last_instr()
                if prev_last.get_opcode() in (Opcodes.Br, Opcodes.Br_S):
                    #Remove the jmp on the prev
                    prev_index = len(prev.get_instrs()) - 1
                    prev.remove_instrs(prev_index, prev_index + 1)
                    prev.remove_next(block)
                    prev.merge_block(block)
                    for n in block.get_next():
                        prev.add_next(n)
                    self.__graph.unregister_block(block.get_start_offset())

        self.__graph.validate_blocks()

        blocks_order = list()
        exc_handlers = list()
        for block in self.__graph.blocks():
            self.__block_walker(block, blocks_order, exc_handlers)

        #check over the blocks, make sure theres a jmp if its needed.
        total_compiled = len(blocks_order)
        #Do an initial offset update to ensure the next loop works.
        current_offset = 0
        current_index = 0
        #lay out the offsets
        for x in range(total_compiled):
            block = blocks_order[x]
            block.update_start_offset(current_offset, current_index)
            block.update_size(block.get_current_size())
            current_offset += block.get_original_length()
            current_index += len(block.get_instrs())

        for x in range(total_compiled):
            #check if any jumps need to be added.
            blk = blocks_order[x]
            is_valid_last = True
            last_instr = blk.get_last_instr()
            #I think this should work for try clauses as well but not sure yet.
            if not last_instr.is_absolute_jmp() and not last_instr.is_branch():
                if last_instr.get_opcode() not in (Opcodes.Throw, Opcodes.Ret, Opcodes.Endfinally):
                    is_valid_last = False
            if not is_valid_last:
                if len(blk.get_next()) != 1:
                    raise Exception()
                nxt = blk.get_next()[0]
                if nxt.get_start_offset() != (last_instr.get_instr_offset() + len(last_instr)):
                    new_instr = self.__disasm.emit_instruction(Opcodes.Br)
                    new_instr.setup_instr_size(5)
                    new_instr.setup_instr_offset(last_instr.get_instr_offset() + len(last_instr), last_instr.get_instr_index() + 1)
                    new_instr.setup_arguments_from_int32(nxt.get_start_offset() - len(new_instr) - new_instr.get_instr_offset())
                    blk.add_instr(new_instr)

        current_offset = 0
        current_index = 0
        #lay out the offsets
        for x in range(total_compiled):
            block = blocks_order[x]
            block.update_start_offset(current_offset, current_index)
            block.update_size(block.get_current_size())
            y = 0
            for instr in block.get_instrs():
                ins_op = instr.get_opcode()
                if ins_op in (Opcodes.Br, Opcodes.Br_S) and x < (total_compiled - 1):
                    if block.get_next()[0] == blocks_order[x+1]:
                        block.remove_instrs(y, y+1)
                        continue
                instr.setup_instr_offset(current_offset, current_index)
                current_offset += len(instr)
                current_index += 1
                y += 1

        self.__graph.update_offsets()
        #fixup the branches of any blocks
        for block in self.__graph.blocks():
            last_instr = block.get_last_instr()
            last_op = last_instr.get_opcode()
            blk_next = block.get_next()
            if last_op == Opcodes.Switch:
                args = list()
                for x in range(len(blk_next) - 1):
                    target = blk_next[x].get_start_offset()
                    argument = target - len(last_instr) - last_instr.get_instr_offset()
                    args.append(argument)
                last_instr.setup_arguments_from_argslist(args)
            elif last_instr.is_absolute_jmp() or last_instr.is_branch():
                target = blk_next[0].get_start_offset()
                argument = target - len(last_instr) - last_instr.get_instr_offset()
                last_instr.setup_arguments_from_int32(argument)
        self.__graph.sort_blocks()

    def remove_useless_math(self):
        """ Remove math expressions that compute to a constant value.
        """

        MATH_INSTRS = [Opcodes.Nop, Opcodes.Not, Opcodes.Ldc_I4, Opcodes.Sub, Opcodes.Add, Opcodes.Neg, Opcodes.Xor, \
                       Opcodes.Ldc_I4_M1, Opcodes.Ldc_I4_S, Opcodes.Ldc_I8, Opcodes.Ldc_R4, Opcodes.Ldc_R8, \
                        Opcodes.Ldc_I4_0, Opcodes.Ldc_I4_1, Opcodes.Ldc_I4_2, Opcodes.Ldc_I4_3, Opcodes.Ldc_I4_4, Opcodes.Ldc_I4_5, \
                            Opcodes.Ldc_I4_6, Opcodes.Ldc_I4_7, Opcodes.Ldc_I4_8, Opcodes.Shr, Opcodes.Shl, Opcodes.Or, Opcodes.Shr_Un, Opcodes.And, \
                                Opcodes.Mul, Opcodes.Div, Opcodes.Div_Un, Opcodes.Rem, Opcodes.Rem_Un]
        MATH_OPS = [Opcodes.Not, Opcodes.Sub, Opcodes.Add, Opcodes.Neg, Opcodes.Xor, Opcodes.Shr, Opcodes.Shl, Opcodes.Or, Opcodes.Shr_Un, Opcodes.And, Opcodes.Mul, Opcodes.Div, Opcodes.Div_Un, Opcodes.Rem, Opcodes.Rem_Un]
        was_anything_changed = False
        block: FunctionBlock
        for block in self.__graph.blocks():
            start_index = -1
            end_index = -1
            nstack = 0
            orig_block_instrs = list(block.get_instrs())
            amt_deleted = 0
            for x in range(len(orig_block_instrs)):
                instr = orig_block_instrs[x]
                opcode = instr.get_opcode()
                if opcode not in MATH_INSTRS:
                    y = x
                    end_index = y 
                    nstack = 0
                    if start_index >= 0 and end_index > 0 and (end_index - start_index) > 1:
                        has_math_op = False
                        for z in range(start_index, end_index):
                            instr2 = orig_block_instrs[z]
                            if instr2.get_opcode() in MATH_OPS:
                                has_math_op = True
                                break
                        if has_math_op and not self.__are_additional_instrs_needed(block, orig_block_instrs, start_index, end_index):
                            was_anything_changed = True
                            amt_deleted += self.__handle_math_instrs(block, orig_block_instrs, start_index, end_index, amt_deleted)
                    start_index = -1
                    end_index = -1
                else:
                    if start_index < 0:
                        if instr.get_pstack() > nstack:
                            nstack = 0
                            continue
                        start_index = x
                    else:
                        #Test the instruction for stack consistency.
                        if nstack < instr.get_pstack():
                            y = x
                            end_index = y 
                            nstack = 0
                            if start_index > 0 and (end_index - start_index) > 1 and not self.__are_additional_instrs_needed(block, orig_block_instrs, start_index, end_index):
                                has_math_op = False
                                for z in range(start_index, end_index):
                                    instr2 = orig_block_instrs[z]
                                    if instr2.get_opcode() in MATH_OPS:
                                        has_math_op = True
                                        break
                                if has_math_op:
                                    was_anything_changed = True
                                    amt_deleted += self.__handle_math_instrs(block, orig_block_instrs, start_index, end_index, amt_deleted)
                            start_index = -1
                            end_index = -1
                    nstack += instr.get_nstack()
        return was_anything_changed

class MethodRecompiler:

    def __init__(self, instrs: list, exception_blocks: list=list(), local_var_sig_tok: int=0):
        self.__localvarsigtok = local_var_sig_tok
        self.__exception_blocks = exception_blocks
        self.__instrs = instrs
        self.__code_size = 0
        for instr in self.__instrs:
            self.__code_size += len(instr)

    def compile_method(self):
        use_fat = False
        if self.__code_size > 63:
            use_fat = True
        if self.__localvarsigtok != 0:
            use_fat = True
        if len(self.__exception_blocks) != 0:
            raise Exception()
            use_fat = True

        fgraph = FunctionGraph(None, self.__instrs, self.__exception_blocks)
        calculated_max_stack = fgraph.calculate_max_stack_size()
        if calculated_max_stack > 8:
            use_fat = True
        result = bytearray()
        if not use_fat:
            result.extend(int.to_bytes((self.__code_size << 2) | 0x2, 1, 'little'))
            for instr in self.__instrs:
                result.extend(instr.to_bytes())
            return bytes(result)
        else:
            flags = 0x0003
            if len(self.__exception_blocks) != 0:
                flags |= 0x0008
            
            if self.__localvarsigtok != 0:
                flags |= 0x0010
            flags |= (3 << 12)
            #we need a function graph to calculate the max stack size.
            import binascii
            result.extend(int.to_bytes(flags, 2, 'little'))
            result.extend(int.to_bytes(calculated_max_stack, 2, 'little'))
            result.extend(int.to_bytes(self.__code_size, 4, 'little'))
            result.extend(int.to_bytes(self.__localvarsigtok, 4, 'little'))

            for instr in self.__instrs:
                b = instr.to_bytes()
                result.extend(b)

            if len(self.__exception_blocks) == 0:
                return bytes(result)
            def calc_int_size(num: int):
                return (num.bit_length() + 7) // 8
            
            while len(result) % 4 != 0: 
                result.append(0)
            
            use_fat_exceptions = False

            if len(self.__exception_blocks) > 20:
                use_fat_exceptions = True

            if not use_fat_exceptions:
                for x in range(len(self.__exception_blocks)):
                    clause_flags, try_offset, try_length, handler_offset, handler_length, token = self.__exception_blocks[x]
                    cflags_size = calc_int_size(clause_flags)
                    tryoff_size = calc_int_size(try_offset)
                    trylen_size = calc_int_size(try_length)
                    handleroff_size = calc_int_size(handler_offset)
                    handlerlen_size = calc_int_size(handler_length)

                    if not (cflags_size <= 2 and tryoff_size <= 2 and trylen_size <= 1 and handleroff_size <= 2 and handlerlen_size <= 1):
                        use_fat_exceptions = True
                        break

            if not use_fat_exceptions:
                result.append(net_structs.CorILMethod.Sect_EHTable)
                data_size = (len(self.__exception_blocks) * 12) + 4
                result.extend(int.to_bytes(data_size, 1, 'little'))
                result.append(0)
                result.append(0)
                for exc in self.__exception_blocks:
                    clause_flags, try_offset, try_length, handler_offset, handler_length, token = exc
                    result.extend(int.to_bytes(clause_flags, 2, 'little'))
                    result.extend(int.to_bytes(try_offset, 2, 'little'))
                    result.extend(int.to_bytes(try_length, 1, 'little'))
                    result.extend(int.to_bytes(handler_offset, 2, 'little'))
                    result.extend(int.to_bytes(handler_length, 1, 'little'))
                    result.extend(int.to_bytes(token, 4, 'little'))
            else:
                result.append(net_structs.CorILMethod.Sect_FatFormat | net_structs.CorILMethod.Sect_EHTable)
                data_size = (len(self.__exception_blocks) * 24) + 4
                result.extend(int.to_bytes(data_size, 3, 'little'))
                for exc in self.__exception_blocks:
                    clause_flags, try_offset, try_length, handler_offset, handler_length, token = exc
                    result.extend(int.to_bytes(clause_flags, 4, 'little'))
                    result.extend(int.to_bytes(try_offset, 4, 'little'))
                    result.extend(int.to_bytes(try_length, 4, 'little'))
                    result.extend(int.to_bytes(handler_offset, 4, 'little'))
                    result.extend(int.to_bytes(handler_length, 4, 'little'))
                    result.extend(int.to_bytes(token, 4, 'little'))
            return bytes(result)