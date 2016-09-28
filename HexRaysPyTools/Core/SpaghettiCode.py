import idaapi


class SpaghettiVisitor(idaapi.ctree_parentee_t):
    def __init__(self):
        super(SpaghettiVisitor, self).__init__()

    def visit_insn(self, instruction):
        if instruction.op == idaapi.cit_block:
            while True:
                cblock = instruction.cblock
                size = cblock.size()
                if size >= 2:
                    # Find block that has "If" and "return" as last 2 statements
                    if cblock.back().op == idaapi.cit_return and \
                                    cblock.at(size - 2).op == idaapi.cit_if and not cblock.at(size - 2).cif.ielse:

                        cit_then = cblock.at(size - 2).cif.ithen

                        # Skip if only one (not "if") statement in "then" branch
                        if cit_then.cblock.size() == 1 and cit_then.cblock.front().op != idaapi.cit_if:
                            return 0

                        # Replacing condition to opposite
                        cit_if_condition = cblock.at(size - 2).cif.expr
                        if cit_if_condition.op == idaapi.cot_lnot:
                            # Ida has following bug:
                            # when return type of call cexpr_t is not signed int, function idaapi.lnot leads to crash
                            new_if_condition = idaapi.cexpr_t(cit_if_condition.x)
                        else:
                            new_if_condition = idaapi.cexpr_t(idaapi.lnot(cit_if_condition))
                        new_if_condition.thisown = False
                        cblock.at(size - 2).cif.expr = new_if_condition
                        del cit_if_condition

                        # Take return from list of statements and later put it back
                        cit_return = idaapi.cinsn_t(instruction.cblock.back())
                        cit_return.thisown = False
                        instruction.cblock.pop_back()

                        # Fill main block with statements from "Then" branch
                        while cit_then.cblock:
                            instruction.cblock.push_back(cit_then.cblock.front())
                            cit_then.cblock.pop_front()

                        # Put back main return if there's no another return or "GOTO" already
                        if instruction.cblock.back().op not in (idaapi.cit_return, idaapi.cit_goto):
                            new_return = idaapi.cinsn_t(cit_return)
                            new_return.thisown = False
                            instruction.cblock.push_back(new_return)

                        # Put return into "Then" branch
                        cit_then.cblock.push_back(cit_return)
                        continue
                break
        return 0