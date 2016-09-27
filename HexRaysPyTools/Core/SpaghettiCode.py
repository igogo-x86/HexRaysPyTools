import idaapi


class SpaghettiVisitor(idaapi.ctree_parentee_t):
    def __init__(self, cfunc):
        super(SpaghettiVisitor, self).__init__()
        self.cfunc = cfunc
        self.result = {}

    def visit_insn(self, instruction):
        print "Instruction", instruction.opname
        return 0

    def visit_expr(self, expression):
        return 0