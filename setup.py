from setuptools import setup, Extension
from Cython.Build import cythonize
import sys

if sys.platform == 'linux': #Some warnings cant be treated as errors on MSVC because cython generates them.
    #TODO: can we remove no array bounds
    compile_args = ['-g', '-Werror', '-Wno-maybe-uninitialized', '-Wno-unused-but-set-variable', '-Wno-array-bounds'] 
    link_args = ['-g']
elif sys.platform == 'darwin':
    compile_args = ['-g', '-Werror', '-Wno-unreachable-code-fallthrough', '-Wno-unused-but-set-variable']
    link_args = ['-g']
else:
    compile_args = ['/WX', '/wd4551'] 
    link_args = []

# Extension modules
ext_modules = cythonize([
    Extension("dotnetutils.dotnetpefile", ["dotnetutils/dotnetpefile.pyx"], extra_compile_args=compile_args, extra_link_args=link_args),
    Extension("dotnetutils.net_emulator", ["dotnetutils/net_emulator.pyx"], extra_compile_args=compile_args, extra_link_args=link_args),
    Extension("dotnetutils.net_structs", ["dotnetutils/net_structs.pyx"], extra_compile_args=compile_args, extra_link_args=link_args),
    Extension("dotnetutils.net_cil_disas", ["dotnetutils/net_cil_disas.pyx"], extra_compile_args=compile_args, extra_link_args=link_args),
    Extension("dotnetutils.net_metadata", ["dotnetutils/net_metadata.pyx"], extra_compile_args=compile_args, extra_link_args=link_args),
    Extension("dotnetutils.net_table_objects", ["dotnetutils/net_table_objects.pyx"], extra_compile_args=compile_args, extra_link_args=link_args),
    Extension("dotnetutils.net_deobfuscate_funcs", ["dotnetutils/net_deobfuscate_funcs.pyx"], extra_compile_args=compile_args, extra_link_args=link_args),
    Extension("dotnetutils.net_opcodes", ["dotnetutils/net_opcodes.pyx"], extra_compile_args=compile_args, extra_link_args=link_args),
    Extension("dotnetutils.net_tokens", ["dotnetutils/net_tokens.pyx"], extra_compile_args=compile_args, extra_link_args=link_args),
    Extension("dotnetutils.net_processing", ["dotnetutils/net_processing.pyx"], extra_compile_args=compile_args, extra_link_args=link_args),
    Extension("dotnetutils.net_utils", ["dotnetutils/net_utils.pyx"], extra_compile_args=compile_args, extra_link_args=link_args),
    Extension("dotnetutils.net_emu_types", ["dotnetutils/net_emu_types.pyx"], extra_compile_args=compile_args, extra_link_args=link_args),
    Extension("dotnetutils.net_row_objects", ["dotnetutils/net_row_objects.pyx"], extra_compile_args=compile_args, extra_link_args=link_args),
    Extension("dotnetutils.net_patch", ["dotnetutils/net_patch.pyx"], extra_compile_args=compile_args, extra_link_args=link_args),
], annotate=True)

setup(
    ext_modules=ext_modules,
)