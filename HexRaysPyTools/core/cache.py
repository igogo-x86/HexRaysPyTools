import collections

import idaapi
import idautils
import idc

import common

# All virtual addresses where imported by module function pointers are stored
imported_ea = set()

# Map from demangled and simplified to C-language compatible names of functions to their addresses
demangled_names = collections.defaultdict(set)

# Functions that went through "touching" decompilation. This is done before Deep Scanning and
# enhance arguments parsing for subroutines called by scanned functions.
touched_functions = set()

# This is where all information about structure being reconstructed stored
# TODO: Make some way to store several structures and switch between them. See issue #22 (3)
temporary_structure = None      # type: temporary_structure.TemporaryStructureModel


def _init_imported_ea():

    def imp_cb(ea, name, ord):
        imported_ea.add(ea - idaapi.get_imagebase())
        # True -> Continue enumeration
        # False -> Stop enumeration
        return True

    print "[Info] Collecting information about imports"
    imported_ea.clear()
    nimps = idaapi.get_import_module_qty()

    for i in xrange(0, nimps):
        name = idaapi.get_import_module_name(i)
        if not name:
            print "[Warning] Failed to get import module name for #%d" % i
            continue

        # print "Walking-> %s" % name
        idaapi.enum_import_names(i, imp_cb)
    print "[Info] Done..."


def _init_demangled_names():
    """
    Creates dictionary of demangled names => set of address, that will be used further when user makes double click
    on methods in Decompiler output.
    """
    demangled_names.clear()
    for address, name in idautils.Names():
        short_name = idc.Demangle(name, idc.INF_SHORT_DN)
        if short_name:
            short_name = common.demangled_name_to_c_str(short_name)
            demangled_names[short_name].add(address - idaapi.get_imagebase())
    print "[DEBUG] Demangled names have been initialized"


def _reset_touched_functions(*args):
    global touched_functions

    touched_functions = set()


def initialize_cache(*args):
    global temporary_structure

    _init_demangled_names()
    _init_imported_ea()
    _reset_touched_functions()
