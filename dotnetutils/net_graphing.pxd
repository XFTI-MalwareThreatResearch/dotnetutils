#cython: language_level=3
#distutils: language=c++
from dotnetutils cimport net_row_objects, net_cil_disas, net_structs

cdef class FunctionBlock:
    cdef net_row_objects.MethodDef __method_object
    cdef net_cil_disas.MethodDisassembler __disasm_object
    cdef FunctionGraph __graph
    cdef list __instrs
    cdef list __previous
    cdef list __next
    cdef int __start_offset
    cdef int __start_index
    cdef int __original_length
    cdef bint __was_cleared
    cdef bint __original_cleared
    cdef bint __is_junk_block
    cdef bint __is_switch_case
    cdef bint __was_switch_block
    cdef bint __is_block_finished
    cdef bint __is_block_try
    cdef bint __is_block_catch
    cdef bint __is_block_finally
    cdef bint __is_block_filter
    cdef int __try_block_offset
    cdef int __catch_block_offset
    cdef int __finally_block_offset
    cdef int __filter_block_offset
    cdef set __exception_handlers
    cdef int __new_offset
    cdef int __new_index

    cpdef bint is_block_start(self)

    cpdef FunctionBlock duplicate(self, FunctionGraph new_graph, dict existing_blocks)

    cpdef int get_start_index(self)
    
    cpdef void update_start_offset(self, int start_offset, int start_index)

    cpdef void setup_new_block_location(self, int new_offset, int new_index)

    cpdef void update_size(self, int new_size)

    cpdef int get_new_offset(self)
    
    cpdef int get_new_index(self)

    cpdef set get_exception_handlers(self)
    
    cpdef void add_exception_handler(self, tuple exception_handler)

    cpdef void set_filter_block_offset(self, int offset)

    cpdef void set_try_block_offset(self, int offset)

    cpdef void set_catch_block_offset(self, int offset)

    cpdef void set_finally_block_offset(self, int offset)

    cpdef int get_try_block_offset(self)
    
    cpdef int get_catch_block_offset(self)
    
    cpdef int get_finally_block_offset(self)
    
    cpdef int get_filter_block_offset(self)

    cpdef void mark_block_try(self)

    cpdef void mark_block_catch(self)

    cpdef void mark_block_finally(self)

    cpdef void mark_block_filter(self)

    cpdef bint is_block_try(self)
    
    cpdef bint is_block_catch(self)
    
    cpdef bint is_block_finally(self)
    
    cpdef bint is_block_filter(self)

    cpdef void mark_block_finished(self)

    cpdef void mark_switch_block(self)

    cpdef bint was_switch_block(self)

    cpdef bint is_block_return(self)

    cpdef int get_current_size(self)

    cpdef void mark_switch_case(self)

    cpdef bint is_switch_case(self)

    cpdef int get_instr_index(self, net_cil_disas.Instruction instr)
    
    cpdef void mark_junk(self)

    cpdef bint is_junk_block(self)
    
    cpdef void reverse_next(self)

    cpdef bint is_start(self)

    cpdef int get_original_length(self)

    cpdef bint has_absolute_path_to_zero(self)
    
    cpdef bint block_leads_switch(self)

    cpdef net_cil_disas.Instruction get_instr_at_index(self, int index)

    cpdef void insert_instr(self, int index, net_cil_disas.Instruction instr)

    cpdef bint is_block_conditional(self)

    cpdef bint contains_instr(self, str name)

    cpdef void clear_next(self)

    cpdef void clear_prev(self)

    cpdef void clear_next_raw(self)

    cpdef void clear_prev_raw(self)

    cpdef void add_next_raw(self, FunctionBlock nxt)

    cpdef void add_prev_raw(self, FunctionBlock nxt)

    cpdef void clear_next_once(self)

    cpdef bint is_block_switch(self)

    cpdef bint is_block_absolutejmp(self)
    
    cpdef bint is_block_direct(self)
    
    cpdef void add_instr(self, net_cil_disas.Instruction instr)

    cpdef void remove_instrs_after_index(self, int index)

    cpdef void replace_instr(self, int index, net_cil_disas.Instruction instr)
    
    cpdef void remove_instrs(self, int start, int end)

    cpdef list get_instrs(self)

    cpdef int get_start_offset(self)

    cpdef net_cil_disas.Instruction get_last_instruction(self)

    cpdef bint has_prev(self, FunctionBlock block)

    cpdef void add_next(self, FunctionBlock block)

    cpdef void add_prev(self, FunctionBlock block)

    cpdef bint has_next(self, FunctionBlock block)

    cpdef list get_next(self)

    cpdef list get_prev(self)
    
    cpdef void remove_prev(self, FunctionBlock prev)

    cpdef net_cil_disas.Instruction get_last_instr(self)

    cpdef bint has_offset(self, int offset)
    
    cpdef void merge_block(self, FunctionBlock block)

    cpdef void validate_block(self) except *

    cpdef FunctionBlock split_block(self, int split_offset)

    cpdef void remove_next(self, FunctionBlock block)
    
    cpdef void replace_next(self, FunctionBlock block, FunctionBlock new_block)
        
    cpdef void replace_next_index(self, int index, FunctionBlock new_block)

    cpdef int get_nstack(self)


cdef class FunctionGraph:
    cdef net_row_objects.MethodDef __method_object
    cdef bint __debug_print
    cdef net_cil_disas.MethodDisassembler __disasm_object
    cdef dict __instr_offsets
    cdef list __instrs
    cdef dict __blocks_start
    cdef list __exception_blocks
    cdef list __raw_exception_blocks
    cdef FunctionBlock __root_block

    cpdef void register_exception_handlers(self)

    cpdef void update_exc_handlers(self)

    cpdef list get_raw_exception_clauses(self)

    cpdef FunctionGraph duplicate(self)

    cpdef void register_block(self, int offset, FunctionBlock block)

    cdef void __handle_try_block(self, int try_offset, int try_length, int handler_offset, int handler_length)

    cdef void __handle_finally_block(self, int try_offset, int try_length, int handler_offset, int handler_length)

    cdef void __handle_filter_block(self, int try_offset, int try_length, int handler_offset, int handler_length, int filter_offset, int filter_length)

    cdef void __handle_try_catch_finally_blocks(self)

    cpdef list get_exception_blocks(self)

    cpdef net_cil_disas.MethodDisassembler get_disassembler(self)

    cpdef void sort_blocks(self)
    
    cpdef void enable_debug_printing(self)

    cpdef bint debug_printing_enabled(self)

    cpdef void set_root_block(self, FunctionBlock root_block)

    cpdef FunctionBlock get_root_block(self)

    cpdef FunctionBlock get_block_by_offset(self, int offset)
    
    cpdef FunctionBlock get_block_by_start_offset(self, int offset)
    
    cpdef list get_shortest_path(self, from_offset, to_offset)
    
    cdef int __walk_path_max_stack(self, FunctionBlock block, list already_analyzed)
    
    cpdef int calculate_max_stack_size(self)
    
    cpdef void update_block_handlers(self)

    cdef FunctionBlock __parse_block(self, int start_offset, int clause_start=*, int max_end_offset=*, bint is_try=*, bint is_catch=*, bint is_finally=*, bint is_filter=*)
    
    cpdef void validate_blocks(self) except *
            
    cpdef void dump_block_relations(self)

    cpdef void print_root(self)

    cpdef void debug_print_blocks(self)

    cpdef void debug_print_nexts(self)

    cpdef void update_offsets(self)
    
    cpdef void unregister_block(self, int offset) except *

    cpdef dict get_block_offsets(self)
    
    cpdef list blocks(self)
    
    cdef void __stack_checker(self, FunctionBlock block, int stack_count, list checked)

    cpdef void stack_checker(self)

    cpdef tuple get_exc_handler_for_block(self, net_structs.CorILExceptionClause flags, FunctionBlock block)

    cdef void __print_block(self, FunctionBlock block, set already_printed, int indent=*)

    cpdef list emit_instructions_as_list(self)

    cpdef bint has_block(self, int offset)
    
    cpdef list update_raw_exception_clauses(self)

    cpdef void repopulate_prevs(self)