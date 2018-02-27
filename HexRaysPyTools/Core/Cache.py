# Information about explored functions
import re

import idaapi
import idautils
import idc


imported_ea = set()
demangled_names = {}
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
        short_name = idc.Demangle(name, idc.GetLongPrm(idc.INF_SHORT_DN))
        if short_name:
            demangled_names[short_name.split('(')[0]] = address - idaapi.get_imagebase()

            # Names can have templates and should be transformed before creating local type
            name = re.sub(r'[<>]', '_t_', name)

            # Thunk functions with name like "[thunk]:CWarmupHostProvider::Release`adjustor{8}'"
            result = re.search(r"(\[thunk\]:)?([^`]*)(.*\{(\d+)}.*)?", short_name)
            name, adjustor = result.group(2), result.group(4)
            if adjustor:
                demangled_names[name + "_adj_" + adjustor] = address - idaapi.get_imagebase()

    print "[DEBUG] Demangled names have been initialized"


def reset_touched_functions(*args):
    touched_functions = set()
