from setuptools import setup, Extension
from Cython.Build import cythonize
import numpy

# Extension modules
ext_modules = cythonize([
    Extension("dotnetutils.dotnetpefile", ["dotnetutils/dotnetpefile.pyx"], include_dirs=[numpy.get_include()], extra_compile_args=['/Zi']),
    Extension("dotnetutils.net_emulator", ["dotnetutils/net_emulator.pyx"], include_dirs=[numpy.get_include()], extra_compile_args=['/Zi']),
    Extension("dotnetutils.net_structs", ["dotnetutils/net_structs.pyx"], include_dirs=[numpy.get_include()], extra_compile_args=['/Zi']),
    Extension("dotnetutils.net_cil_disas", ["dotnetutils/net_cil_disas.pyx"], include_dirs=[numpy.get_include()], extra_compile_args=['/Zi']),
    Extension("dotnetutils.net_metadata", ["dotnetutils/net_metadata.pyx"], include_dirs=[numpy.get_include()], extra_compile_args=['/Zi']),
    Extension("dotnetutils.net_table_objects", ["dotnetutils/net_table_objects.pyx"], include_dirs=[numpy.get_include()], extra_compile_args=['/Zi']),
    Extension("dotnetutils.net_deobfuscate_funcs", ["dotnetutils/net_deobfuscate_funcs.pyx"], include_dirs=[numpy.get_include()], extra_compile_args=['/Zi']),
    Extension("dotnetutils.net_opcodes", ["dotnetutils/net_opcodes.pyx"], include_dirs=[numpy.get_include()], extra_compile_args=['/Zi']),
    Extension("dotnetutils.net_tokens", ["dotnetutils/net_tokens.pyx"], include_dirs=[numpy.get_include()], extra_compile_args=['/Zi']),
    Extension("dotnetutils.net_emu_coretypes", ["dotnetutils/net_emu_coretypes.pyx"], include_dirs=[numpy.get_include()], extra_compile_args=['/Zi']),
    Extension("dotnetutils.net_processing", ["dotnetutils/net_processing.pyx"], include_dirs=[numpy.get_include()], extra_compile_args=['/Zi']),
    Extension("dotnetutils.net_utils", ["dotnetutils/net_utils.pyx"], include_dirs=[numpy.get_include()], extra_compile_args=['/Zi']),
    Extension("dotnetutils.net_emu_types", ["dotnetutils/net_emu_types.pyx"], include_dirs=[numpy.get_include()], extra_compile_args=['/Zi']),
    Extension("dotnetutils.net_row_objects", ["dotnetutils/net_row_objects.pyx"], include_dirs=[numpy.get_include()], extra_compile_args=['/Zi']),
], compiler_directives={'embedsignature': True})

setup(
    ext_modules=ext_modules,
)