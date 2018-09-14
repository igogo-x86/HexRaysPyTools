# Information about explored functions
import collections

import idaapi
import idautils
import idc

import common


imported_ea = set()
demangled_names = collections.defaultdict(set)
touched_functions = set()
temporary_structure = None


def init_imported_ea(*args):

    def imp_cb(ea, name, ord):
        imported_ea.add(ea)
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


def init_demangled_names(*args):
    """
    Creates dictionary of demangled names => address, that will be used further at double click on methods got from
    symbols.
    """
    demangled_names.clear()
    for address, name in idautils.Names():
        short_name = idc.Demangle(name, idc.INF_SHORT_DN)
        if short_name:
            short_name = common.demangled_name_to_c_str(short_name)
            demangled_names[short_name].add(address - idaapi.get_imagebase())
    print "[DEBUG] Demangled names have been initialized"


def reset_touched_functions(*args):
    global touched_functions

    touched_functions = set()
