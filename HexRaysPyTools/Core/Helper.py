import idaapi


def get_func_address_by_name(name):
    """
    Looks through all functions and find the one with the same name. Sigh...

    :param name: str
    :return ea_t or None
    """
    for idx in xrange(idaapi.get_func_qty()):
        function = idaapi.getn_func(idx)
        func_name = idaapi.get_short_name(function.startEA)
        func_name = func_name.split('(')[0].replace("`", '').replace("'", '')
        if func_name == name:
            return function.startEA
    return None


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
