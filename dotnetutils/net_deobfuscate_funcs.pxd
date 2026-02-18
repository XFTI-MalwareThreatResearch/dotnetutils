#cython: language_level=3
#distutils: language=c++

from dotnetutils cimport dotnetpefile
from dotnetutils cimport net_row_objects

cdef void remove_unk_obf_1_junk_loops(dotnetpefile.DotNetPeFile dotnet)

cdef void remove_unk_obf_1_string_obfuscation(dotnetpefile.DotNetPeFile dotnet)

cpdef void remove_unk_obf_1_obfuscation(dotnetpefile.DotNetPeFile dotnet)

cpdef void remove_useless_bytearray_conditionals(dotnetpefile.DotNetPeFile dotnet)

cpdef void remove_useless_conditionals(dotnetpefile.DotNetPeFile dotnet, list target_method_rids=*)

cdef bytes __is_useless_method(dotnetpefile.DotNetPeFile dpe, net_row_objects.MethodDef method_obj)

cdef bint __is_modified_method(dotnetpefile.DotNetPeFile dpe, net_row_objects.MethodDef method_obj)

cdef int __is_junk_method(dotnetpefile.DotNetPeFile dpe, net_row_objects.MethodDef method_obj)

cpdef void remove_useless_functions(dotnetpefile.DotNetPeFile dotnet) except *

cdef bint has_prefix(bytes type_name)

cpdef void cleanup_names(dotnetpefile.DotNetPeFile dotnet,
                  bint change_namespaces=*,
                  bint change_method_names=*,
                  bint change_param_names=*,
                  bint change_module_name=*,
                  bint change_type_names=*,
                  bint change_field_names=*,
                  bint change_property_names=*,
                  bint force_main_method=*,
                  bint change_import_names=*,
                  bint change_events=*) except *

cpdef void deobfuscate_control_flow(dotnetpefile.DotNetPeFile dotnet, list target_rids=*)