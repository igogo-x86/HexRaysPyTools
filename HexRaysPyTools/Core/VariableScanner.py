from HexRaysPyTools.Core.TemporaryStructure import *


class CtreeVisitor(idaapi.ctree_parentee_t):
    def __init__(self, function, variable, origin=0, index=None):
        """
        This Class is idaapi.ctree_visitor_t and used for for finding candidates on class members.
        Usage: CtreeVisitor.apply_to() and then CtreeVisitor.candidates

        :param function: idaapi.cfunc_t
        :param variable: idaapi.lvar_t
        :param origin: offset in main structure from which scanning is propagating
        """
        super(CtreeVisitor, self).__init__()
        self.function = function
        # Dictionary {variable name => tinfo_t} of variables that are being scanned
        if index:
            self.variables = {index: function.get_lvars()[index].type()}
        else:
            self.variables = {map(lambda x: x.name, function.get_lvars()).index(variable.name): variable.type()}
        self.origin = origin
        self.candidates = []

        self.PVOID_TINFO = idaapi.tinfo_t()
        self.PVOID_TINFO.create_ptr(idaapi.tinfo_t(idaapi.BT_VOID))
        self.CONST_PVOID_TINFO = idaapi.tinfo_t()
        self.CONST_PVOID_TINFO.create_ptr(idaapi.tinfo_t(idaapi.BT_VOID | idaapi.BTM_CONST))

        self.convert_citem = lambda x: (x.is_expr() and x.cexpr) or x.cinsn

    def visit_expr(self, expression):
        if expression.op == idaapi.cot_var:
            index = expression.v.idx
            if index in self.variables.keys():
                if len(self.parents) > 2:               # ????
                    result = self.check_member_assignment(expression, index)
                    if result:
                        self.candidates.append(result)
        return 0

    def check_member_assignment(self, expression, index):
        """
        We are now in cexpr_t == idaapi.cot_var. This function checks if expression is part of member assignment
        statement. Returns None if not.

        :param expression: idaapi.cexpr_t
        :param index: int
        :return: Structures.Field
        """
        parents_queue = reversed(self.parents)
        parent_generator = lambda: parents_queue.next().cexpr
        son = expression
        parent = parent_generator()

        cast_type = None
        offset = 0
        member_type = None

        if self.variables[index].dstr() in ("int", "__int64", "signed __int64"):
            if parent.op == idaapi.cot_add and parent.y.op == idaapi.cot_num:
                offset = parent.y.n.value(idaapi.tinfo_t(idaapi.BT_INT))            # x64
                son = parent
                parent = parent_generator()

            if parent.op == idaapi.cot_cast:
                cast_type = parent.type
                cast_type.remove_ptr_or_array()
                son = parent
                parent = parent_generator()
            elif not parent.op == idaapi.cot_call:
                return None

            if parent.op == idaapi.cot_ptr:
                left_son = parent
                son = parent
                parent = parent_generator()

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
                                return VirtualTable(
                                    offset,
                                    right_son.obj_ea,
                                    ScannedVariable(self.function, self.function.get_lvars()[index]),
                                    self.origin
                                )
                            print "(Object) offset: {0:#010X} name: {1}, size: {2}, address: {3:#010X}".format(
                                offset,
                                member_type.dstr(),
                                member_type.get_size(),
                                right_son.obj_ea
                            )
                            member_type.create_ptr(member_type)
                        elif right_son.op == idaapi.cot_call:
                            member_type = right_son.x.type.get_rettype()
                            print "(Call function) offset: {0:#010X}, type: {1}".format(offset, member_type.dstr())
                        else:
                            member_type = cast_type
                            print "(Call function) offset: {0:#010X}, type: {1}".format(offset, member_type.dstr())
                        return Member(
                            offset,
                            member_type,
                            ScannedVariable(self.function, self.function.get_lvars()[index]),
                            self.origin
                        )

            if parent.op == idaapi.cot_call:
                for argument in parent.a:
                    if argument.cexpr == son:
                        member_type = idaapi.tinfo_t(argument.formal_type)
                        if member_type.equals_to(self.PVOID_TINFO) or member_type.equals_to(self.CONST_PVOID_TINFO):
                            # TODO: if function is memset, than calculate array size
                            member_type = TemporaryStructureModel.BYTE_TINFO
                            print "(Argument) offset: {0:#010X}, type: {1}".format(offset, member_type.dstr())
                            return VoidMember(
                                offset,
                                ScannedVariable(self.function, self.function.get_lvars()[index]),
                                self.origin
                            )
                        else:
                            if member_type.is_ptr():
                                member_type = member_type.get_pointed_object()
                            print "(Argument) offset: {0:#010X}, type: {1}".format(offset, member_type.dstr())
                            return Member(
                                offset,
                                member_type,
                                ScannedVariable(self.function, self.function.get_lvars()[index]),
                                self.origin
                            )
        return None


