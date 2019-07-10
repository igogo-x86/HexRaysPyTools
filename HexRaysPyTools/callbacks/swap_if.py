import idaapi
import idc

import actions
import callbacks


def inverse_if_condition(cif):
    # cexpr_t has become broken but fortunately still exist `assing` method which copies one expr into another
    cit_if_condition = cif.expr
    tmp_cexpr = idaapi.cexpr_t()
    tmp_cexpr.assign(cit_if_condition)
    new_if_condition = idaapi.lnot(tmp_cexpr)
    cif.expr.swap(new_if_condition)
    del cit_if_condition


def inverse_if(cif):
    inverse_if_condition(cif)
    idaapi.qswap(cif.ithen, cif.ielse)


_ARRAY_STORAGE_PREFIX = "$HexRaysPyTools:IfThenElse:"


def has_inverted(func_ea):
    # Find if function has any swapped THEN-ELSE branches
    internal_name = _ARRAY_STORAGE_PREFIX + hex(int(func_ea - idaapi.get_imagebase()))
    internal_id = idc.GetArrayId(internal_name)
    return internal_id != -1


def get_inverted(func_ea):
    # Returns set of relative virtual addresses which are tied to IF and swapped
    internal_name = _ARRAY_STORAGE_PREFIX + hex(int(func_ea - idaapi.get_imagebase()))
    internal_id = idc.GetArrayId(internal_name)
    array = idc.GetArrayElement(idc.AR_STR, internal_id, 0)
    return set(map(int, array.split()))


def invert(func_ea, if_ea):
    # Store information about swaps (affected through actions)
    iv_rva = if_ea - idaapi.get_imagebase()
    func_rva = func_ea - idaapi.get_imagebase()
    internal_name = _ARRAY_STORAGE_PREFIX + hex(int(func_rva))
    internal_id = idc.GetArrayId(internal_name)
    if internal_id == -1:
        internal_id = idc.CreateArray(internal_name)
        idc.SetArrayString(internal_id, 0, str(iv_rva))
    else:
        inverted = get_inverted(func_ea)
        try:
            inverted.remove(iv_rva)
            if not inverted:
                idc.DeleteArray(internal_id)

        except KeyError:
            inverted.add(iv_rva)

        idc.SetArrayString(internal_id, 0, " ".join(map(str, inverted)))


class SwapThenElse(actions.HexRaysPopupAction):
    description = "Swap then/else"
    hotkey = "Shift+S"

    def __init__(self):
        super(SwapThenElse, self).__init__()

    def check(self, hx_view):
        # Checks if we clicked on IF and this if has both THEN and ELSE branches
        if hx_view.item.citype != idaapi.VDI_EXPR:
            return False
        insn = hx_view.item.it.to_specific_type
        if insn.op != idaapi.cit_if or insn.cif.ielse is None:
            return False
        return insn.op == idaapi.cit_if and insn.cif.ielse

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        if self.check(hx_view):
            insn = hx_view.item.it.to_specific_type
            inverse_if(insn.cif)
            hx_view.refresh_ctext()

            invert(hx_view.cfunc.entry_ea, insn.ea)

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


actions.action_manager.register(SwapThenElse())


class SwapThenElseVisitor(idaapi.ctree_parentee_t):
    def __init__(self, inverted):
        super(SwapThenElseVisitor, self).__init__()
        self.__inverted = inverted

    def visit_insn(self, insn):
        if insn.op != idaapi.cit_if or insn.cif.ielse is None:
            return 0

        if insn.ea in self.__inverted:
            inverse_if(insn.cif)

        return 0

    def apply_to(self, *args):
        if self.__inverted:
            super(SwapThenElseVisitor, self).apply_to(*args)


class SpaghettiVisitor(idaapi.ctree_parentee_t):
    def __init__(self):
        super(SpaghettiVisitor, self).__init__()

    def visit_insn(self, instruction):
        if instruction.op != idaapi.cit_block:
            return 0

        while True:
            cblock = instruction.cblock
            size = cblock.size()
            # Find block that has "If" and "return" as last 2 statements
            if size < 2:
                break

            if cblock.at(size - 2).op != idaapi.cit_if:
                break

            cif = cblock.at(size - 2).cif
            if cblock.back().op != idaapi.cit_return or cif.ielse:
                break

            cit_then = cif.ithen

            # Skip if only one (not "if") statement in "then" branch
            if cit_then.cblock.size() == 1 and cit_then.cblock.front().op != idaapi.cit_if:
                return 0

            inverse_if_condition(cif)

            # Take return from list of statements and later put it back
            cit_return = idaapi.cinsn_t()
            cit_return.assign(instruction.cblock.back())
            cit_return.thisown = False
            instruction.cblock.pop_back()

            # Fill main block with statements from "Then" branch
            while cit_then.cblock:
                instruction.cblock.push_back(cit_then.cblock.front())
                cit_then.cblock.pop_front()

            # Put back main return if there's no another return or "GOTO" already
            if instruction.cblock.back().op not in (idaapi.cit_return, idaapi.cit_goto):
                new_return = idaapi.cinsn_t()
                new_return.thisown = False
                new_return.assign(cit_return)
                instruction.cblock.push_back(new_return)

            # Put return into "Then" branch
            cit_then.cblock.push_back(cit_return)
        return 0


class SilentIfSwapper(callbacks.HexRaysEventHandler):

    def __init__(self):
        super(SilentIfSwapper, self).__init__()

    def handle(self, event, *args):
        cfunc, level_of_maturity = args
        if level_of_maturity == idaapi.CMAT_TRANS1 and has_inverted(cfunc.entry_ea):
            # Make RVA from VA of IF instructions that should be inverted
            inverted = map(lambda n: n + idaapi.get_imagebase(), get_inverted(cfunc.entry_ea))
            visitor = SwapThenElseVisitor(inverted)
            visitor.apply_to(cfunc.body, None)
        elif level_of_maturity == idaapi.CMAT_TRANS2:
            visitor = SpaghettiVisitor()
            visitor.apply_to(cfunc.body, None)


callbacks.hx_callback_manager.register(idaapi.hxe_maturity, SilentIfSwapper())
