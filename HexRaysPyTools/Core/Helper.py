import idaapi
import idautils
import idc

demangled_names = {}


def init_demangled_names(*args):

    demangled_names.clear()
    for address, name in idautils.Names():
        short_name = idc.Demangle(name, idc.GetLongPrm(idc.INF_SHORT_DN))
        if short_name:
            demangled_names[short_name.split('(')[0]] = address
    print "[DEBUG] Demangled names have been initialized"


def get_virtual_func_address(tinfo, offset, name):

    offset *= 8
    address = idc.LocByName(name)
    udt_member = idaapi.udt_member_t()
    while address == idaapi.BADADDR and tinfo.is_struct():
        address = demangled_names.get(tinfo.dstr() + '::' + name, idaapi.BADADDR)
        udt_member.offset = offset
        tinfo.find_udt_member(idaapi.STRMEM_OFFSET, udt_member)
        tinfo = udt_member.type
        offset = offset - udt_member.offset

    return address if address != idaapi.BADADDR else None


def get_func_argument_info(function, expression):
    """
    Function is cexpr with opname == 'cot_call', expression is any son. Returns index of argument and it's type

    :param function: idaapi.cexpr_t
    :param expression: idaapi.cexpr_t
    :return: (int, idaapi.tinfo_t)
    """
    for idx, argument in enumerate(function.a):
        if expression == argument.cexpr:
            return idx, function.x.type.get_nth_arg(idx)
    print "[ERROR] Wrong usage of 'Helper.get_func_argument_info()'"


def get_nice_pointed_object(tinfo):
    """
    Returns nice pointer name (if exist) or None.
    For example if tinfo is PKSPIN_LOCK which is typedef of unsigned int *, then if in local types exist KSPIN_LOCK with
    type unsigned int, this function returns KSPIN_LOCK
    """
    try:
        name = tinfo.dstr()
        if name[0] == 'P':
            pointed_tinfo = idaapi.tinfo_t()
            if pointed_tinfo.get_named_type(idaapi.cvar.idati, name[1:]):
                if tinfo.get_pointed_object().equals_to(pointed_tinfo):
                    return pointed_tinfo
    except TypeError:
        pass
