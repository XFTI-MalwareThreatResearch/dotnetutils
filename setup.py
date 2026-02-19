from setuptools import setup, Extension
from Cython.Build import cythonize
from Cython.Compiler import Options
import sys

Options.extra_warnings = True
Options.warning_errors = False

if sys.platform == 'linux': #Some warnings cant be treated as errors on MSVC because cython generates them.
    #TODO: can we remove no array bounds
    compile_args = ['-g', '-Werror', '-Wno-maybe-uninitialized', '-Wno-unused-but-set-variable', '-Wno-array-bounds', '-Wno-unused-function'] 
    link_args = ['-g']
elif sys.platform == 'darwin':
    compile_args = ['-g', '-Werror', '-Wno-unreachable-code-fallthrough', '-Wno-unused-but-set-variable', '-Wno-unused-function']
    link_args = ['-g']
else:
    compile_args = ['/DEBUG', '/WX', '/wd4551', '/Zi'] 
    link_args = ['/DEBUG']

def gen_extension(name):
    global compile_args
    global link_args
    if sys.platform == 'win32':
        return Extension('dotnetutils.' + name, ['dotnetutils/{}.pyx'.format(name)], extra_compile_args=compile_args, extra_link_args=link_args + ['/PDB:{}.pdb'.format(name)])
    return Extension('dotnetutils.' + name, ['dotnetutils/{}.pyx'.format(name)], extra_compile_args=compile_args, extra_link_args=link_args)

ext_modules = cythonize([
    gen_extension('dotnetpefile'),
    gen_extension('net_emulator'),
    gen_extension('net_structs'),
    gen_extension('net_cil_disas'),
    gen_extension('net_metadata'),
    gen_extension('net_table_objects'),
    gen_extension('net_deobfuscate_funcs'),
    gen_extension('net_opcodes'),
    gen_extension('net_tokens'),
    gen_extension('net_processing'),
    gen_extension('net_utils'),
    gen_extension('net_emu_types'),
    gen_extension('net_row_objects'),
    gen_extension('net_patch'),
    gen_extension('net_sigs'),
    gen_extension('net_emu_structs')
], annotate=True, gdb_debug=True, show_all_warnings=True, compiler_directives={'embedsignature': True, 'linetrace': True, 'binding': True})

setup(
    ext_modules=ext_modules,
)
