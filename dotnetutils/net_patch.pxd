#cython: language_level=3

cdef int get_fixed_rva(dotnetpefile.PeFile old_pe, bytes new_data, int addr, int old_userstrings_va, int userstrings_difference)