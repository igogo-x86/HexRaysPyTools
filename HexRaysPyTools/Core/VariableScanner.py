from HexRaysPyTools.Core.TemporaryStructure import *


class CtreeVisitor(idaapi.ctree_parentee_t):
    def __init__(self, function, variable):
        """
        This Class is idaapi.ctree_visitor_t and used for for finding candidates on class membmers.
        Usage: CtreeVisitor.apply_to() and then CtreeVisitor.candidates

        :param function: idaapi.cfunc_t
        :param variable: idaapi.lvart_t
        """
        super(CtreeVisitor, self).__init__()
        self.function = function
        # Dictionary {varuable name => type} of variables that are being scanned
        self.variables = {map(lambda x: x.name, function.get_lvars()).index(variable.name): variable.tif}
        self.convert_citem = lambda x: (x.is_expr() and x.cexpr) or x.cinsn
        self.candidates = []

    def visit_expr(self, expression):
        if expression.op == idaapi.cot_var:
            index = expression.v.idx
            if index in self.variables.keys():
                if len(self.parents) > 3:               # ????
                    result = self.check_member_assignment(self.variables[index])
                    if result:
                        self.candidates.append(result)
        return 0

    def check_member_assignment(self, expression):
        """
        Checks if expression is part of member assignment statement. Returns None if not.

        :param expression: idaapi.cexpr_t
        :return: Structures.Field
        """
        parents_queue = reversed(self.parents)
        parent_generator = lambda: parents_queue.next().cexpr
        parent = parent_generator()

        cast_type = None
        offset = 0
        member_type = None

        if expression.dstr() in ("int", "__int64", "signed __int64"):
            if parent.op == idaapi.cot_add and parent.y.op == idaapi.cot_num:
                offset = parent.y.n.value(idaapi.tinfo_t(idaapi.BT_INT))            # x64
                parent = parent_generator()

            if parent.op == idaapi.cot_cast:
                cast_type = parent.type
                cast_type.remove_ptr_or_array()
                parent = parent_generator()
            else:
                return None

            if parent.op == idaapi.cot_ptr:
                left_son = parent
                parent = parent_generator()
            else:
                return None

            if parent.op == idaapi.cot_asg:
                if left_son == parent.x:
                    right_son = parent.y
                    if right_son.op == idaapi.cot_ref:
                        right_son = right_son.x
                    if right_son.op == idaapi.cot_var:
                        member_type = self.function.get_lvars()[right_son.v.idx].tif
                        print "(Variable) offset: {0:#010X} index: {1}".format(offset, right_son.v.idx)
                    elif right_son.op == idaapi.cot_num:
                        print "(Number) offset: {0:#010X}, value: {1}".format(offset, right_son.n._value)
                        member_type = cast_type
                    elif right_son.op == idaapi.cot_fnum:
                        print "(Float Number) offset: {0:#010X}, value: {1}".format(offset, right_son.fpc._print())
                        member_type = cast_type
                    elif right_son.op == idaapi.cot_obj:
                        member_type = right_son.type
                        if VirtualTable.check_address(right_son.obj_ea):
                            return VirtualTable(offset, right_son.obj_ea)

                        print "(Object) offset: {0:#010X} size: {1}, address: {2:#010X}".format(
                            offset,
                            member_type.get_size(),
                            right_son.obj_ea
                        )
                        member_type.create_ptr(member_type)
                    else:
                        return None
                    return Field(offset, tinfo=member_type)

        return None


