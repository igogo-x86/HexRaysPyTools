import idaapi
import idc


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


class InversionInfo(object):
    ARRAY_NAME = "$HexRaysPyTools:IfThenElse:"

    def __init__(self, func_ea):
        self.__name = InversionInfo.ARRAY_NAME + hex(int(func_ea))
        self.__id = idc.GetArrayId(self.__name)

    def get_inverted(self):
        if self.__id != -1:
            array = idc.GetArrayElement(idc.AR_STR, self.__id, 0)
            return set(map(int, array.split()))
        return set()

    def switch_inverted(self, address):
        if self.__id == -1:
            self.__id = idc.CreateArray(self.__name)
            idc.SetArrayString(self.__id, 0, str(address))
        else:
            inverted = self.get_inverted()
            try:
                inverted.remove(address)
                if not inverted:
                    idc.DeleteArray(self.__id)

            except KeyError:
                inverted.add(address)

            idc.SetArrayString(self.__id, 0, " ".join(map(str, inverted)))


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


class SwapThenElseVisitor(idaapi.ctree_parentee_t):
    def __init__(self, func_ea):
        super(SwapThenElseVisitor, self).__init__()
        self.__inversion_info = InversionInfo(func_ea)
        self.__inverted = self.__inversion_info.get_inverted()

    def visit_insn(self, insn):
        if insn.op != idaapi.cit_if or insn.cif.ielse is None:
            return 0

        if insn.ea in self.__inverted:
            inverse_if(insn.cif)

        return 0

    def apply_to(self, *args):
        if self.__inverted:
            super(SwapThenElseVisitor, self).apply_to(*args)
