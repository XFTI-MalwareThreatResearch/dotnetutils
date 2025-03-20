#cython: language_level=3

from dotnetutils cimport dotnetpefile

cdef unsigned int get_fixed_rva(dotnetpefile.PeFile old_pe, bytes new_data, int addr, int old_userstrings_va, int userstrings_difference)

cpdef bytes insert_blank_userstrings(dotnetpefile.DotNetPeFile dotnetpe, bytes exe_data)

cpdef bytes apply_pe_fixups(dotnetpefile.PeFile old_pe, bytes old_exe_data, int va_addr, int difference, dotnetpefile.DotNetPeFile dotnetpe, bint in_streams)
