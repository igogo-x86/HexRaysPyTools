import idaapi
import idautils
import idc
import Const

temporary_structure = None
demangled_names = {}


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
    print "[DEBUG] Demangled names have been initialized"


def get_virtual_func_address(tinfo, offset, name):
    """
    :param tinfo: class tinfo
    :param offset: virtual table offset
    :param name: method name
    :return: address of the method
    """

    address = idc.LocByName(name)
    if address != idaapi.BADADDR:
        return address

    offset *= 8
    udt_member = idaapi.udt_member_t()
    while tinfo.is_struct():
        address = demangled_names.get(tinfo.dstr() + '::' + name, idaapi.BADADDR)
        if address != idaapi.BADADDR:
            return address + idaapi.get_imagebase()
        udt_member.offset = offset
        tinfo.find_udt_member(idaapi.STRMEM_OFFSET, udt_member)
        tinfo = udt_member.type
        offset = offset - udt_member.offset


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


def get_fields_at_offset(tinfo, offset):
    """
    Given tinfo and offset of the structure or union, returns list of all tinfo at that offset.
    This function helps to find appropriate structures by type of the offset
    """
    result = []
    if offset == 0:
        result.append(tinfo)
    udt_data = idaapi.udt_type_data_t()
    tinfo.get_udt_details(udt_data)
    udt_member = idaapi.udt_member_t()
    udt_member.offset = offset * 8
    idx = tinfo.find_udt_member(idaapi.STRMEM_OFFSET, udt_member)
    if idx != -1:
        while idx < tinfo.get_udt_nmembers() and udt_data[idx].offset <= offset * 8:
            udt_member = udt_data[idx]
            if udt_member.offset == offset * 8:
                if udt_member.type.is_ptr():
                    result.append(idaapi.get_unk_type(Const.EA_SIZE))
                    result.append(udt_member.type)
                    result.append(idaapi.dummy_ptrtype(Const.EA_SIZE, False))
                elif not udt_member.type.is_udt():
                    result.append(udt_member.type)
            if udt_member.type.is_array():
                if (offset - udt_member.offset / 8) % udt_member.type.get_array_element().get_size() == 0:
                    result.append(udt_member.type.get_array_element())
            elif udt_member.type.is_udt():
                result.extend(get_fields_at_offset(udt_member.type, offset - udt_member.offset / 8))
            idx += 1
    return result


touched_functions = set()


class FunctionTouchVisitor(idaapi.ctree_parentee_t):
    def __init__(self, cfunc):
        super(FunctionTouchVisitor, self).__init__()
        self.functions = set()
        self.cfunc = cfunc

    def visit_expr(self, expression):
        if expression.op == idaapi.cot_call:
            self.functions.add(expression.x.obj_ea)
        return 0

    def touch_all(self):
        for address in self.functions.difference(touched_functions):
            touched_functions.add(address)
            try:
                cfunc = idaapi.decompile(address)
                if cfunc:
                    touch_visitor = FunctionTouchVisitor(cfunc)
                    touch_visitor.apply_to(cfunc.body, None)
                    touch_visitor.touch_all()
            except idaapi.DecompilationFailure:
                print "[ERROR] IDA failed to decompile function at 0x{address:08X}".format(address=address)
        idaapi.decompile(self.cfunc.entry_ea)

    def process(self):
        if self.cfunc.entry_ea not in touched_functions:
            touched_functions.add(self.cfunc.entry_ea)
            self.apply_to(self.cfunc.body, None)
            self.touch_all()
            return True
        return False