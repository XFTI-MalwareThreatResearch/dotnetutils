import os
import sys
from pathlib import Path

# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

ROOT = Path(__file__).resolve().parent

sys.path.insert(0, str(ROOT.parent))

project = 'dotnetutils'
copyright = '2025, IBM'
author = 'Aaron Gdanski, IBM X-Force MTR'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.autosummary',
    'sphinx.ext.napoleon',
    'sphinx.ext.viewcode',
    'sphinx_autodoc_typehints'
]

autosummary_generate = True
autodoc_default_options = {
    "members": True,
    "undoc-members": True,
    "show-inheritance": True,
    "inherited-members": True,
}
autoclass_content = "class"   # <- the one you asked about
add_module_names = False      # <- and this

napoleon_use_ivar = False    

autodoc_mock_imports = []
pkg_dir = ROOT.parent / "dotnetutils"
if pkg_dir.is_dir():
    for p in pkg_dir.rglob("*"):
        if p.suffix in {".pyd", ".so", ".dll"}:
            # turn e.g. dotnetutils/sub/mod.pyd into "dotnetutils.sub.mod"
            rel = p.relative_to(pkg_dir).with_suffix("")
            mod = ".".join(("dotnetutils",) + rel.parts)
            autodoc_mock_imports.append(mod)

templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']



# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'alabaster'
html_static_path = ['_static']
