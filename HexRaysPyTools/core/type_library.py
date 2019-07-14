import ctypes
import sys

import idaapi

import const
import HexRaysPyTools.forms as forms


class til_t(ctypes.Structure):
    pass

til_t._fields_ = [
    ("name", ctypes.c_char_p),
    ("desc", ctypes.c_char_p),
    ("nbases", ctypes.c_int),
    ("base", ctypes.POINTER(ctypes.POINTER(til_t)))
]


def _enable_library_ordinals(library_num):
    idaname = "ida64" if const.EA64 else "ida"
    if sys.platform == "win32":
        dll = ctypes.windll[idaname + ".dll"]
    elif sys.platform == "linux2":
        dll = ctypes.cdll["lib" + idaname + ".so"]
    elif sys.platform == "darwin":
        dll = ctypes.cdll["lib" + idaname + ".dylib"]
    else:
        print "[ERROR] Failed to enable ordinals"
        return

    dll.get_idati.restype = ctypes.POINTER(til_t)
    idati = dll.get_idati()
    dll.enable_numbered_types(idati.contents.base[library_num], True)


def choose_til():
    # type: () -> (idaapi.til_t, int, bool)
    """ Creates a list of loaded libraries, asks user to take one of them and returns it with
    information about max ordinal and whether it's local or imported library """
    idati = idaapi.cvar.idati
    list_type_library = [(idati, idati.name, idati.desc)]
    for idx in xrange(idaapi.cvar.idati.nbases):
        type_library = idaapi.cvar.idati.base(idx)          # type: idaapi.til_t
        list_type_library.append((type_library, type_library.name, type_library.desc))

    library_chooser = forms.MyChoose(
        list(map(lambda x: [x[1], x[2]], list_type_library)),
        "Select Library",
        [["Library", 10 | idaapi.Choose2.CHCOL_PLAIN], ["Description", 30 | idaapi.Choose2.CHCOL_PLAIN]],
        69
    )
    library_num = library_chooser.Show(True)
    if library_num != -1:
        selected_library = list_type_library[library_num][0]    # type: idaapi.til_t
        max_ordinal = idaapi.get_ordinal_qty(selected_library)
        if max_ordinal == idaapi.BADORD:
            _enable_library_ordinals(library_num - 1)
            max_ordinal = idaapi.get_ordinal_qty(selected_library)
        print "[DEBUG] Maximal ordinal of lib {0} = {1}".format(selected_library.name, max_ordinal)
        return selected_library, max_ordinal, library_num == 0


def import_type(library, name):
    if library.name != idaapi.cvar.idati.name:
        last_ordinal = idaapi.get_ordinal_qty(idaapi.cvar.idati)
        type_id = idaapi.import_type(library, -1, name)  # tid_t
        if type_id != idaapi.BADORD:
            return last_ordinal
