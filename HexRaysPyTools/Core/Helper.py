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
        func_name = func_name.split('(')[0]
        func_name = func_name.replace("`", '').replace("'", '')
        if func_name == name:
            return function.startEA
    return None
