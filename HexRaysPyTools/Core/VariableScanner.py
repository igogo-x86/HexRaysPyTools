import HexRaysPyTools.Core.Const as Const
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
        if index is not None:
            self.variables = {index: function.get_lvars()[index].type()}
        else:
            self.variables = {map(lambda x: x.name, function.get_lvars()).index(variable.name): variable.type()}
        self.origin = origin
        self.candidates = []

    def create_member(self, offset, index, tinfo=None, ea=0):
        # Creates appropriate member (VTable, regular member, void *member) depending on input
        if ea:
            if VirtualTable.check_address(ea):
                return VirtualTable(
                    offset,
                    ea,
                    ScannedVariable(self.function, self.function.get_lvars()[index]),
                    self.origin
                )
        if tinfo:
            return Member(
                offset,
                tinfo,
                ScannedVariable(self.function, self.function.get_lvars()[index]),
                self.origin
            )
        else:
            return VoidMember(
                offset,
                ScannedVariable(self.function, self.function.get_lvars()[index]),
                self.origin
            )

    def add_variable(self, index):
        self.variables[index] = self.function.get_lvars()[index].type()

    def visit_expr(self, expression):
        if expression.op == idaapi.cot_var:
            index = expression.v.idx
            if index in self.variables:
                # if len(self.parents) > 2:               # ????
                result = self.new_check_member_assignment(expression, index)
                if result:
                    self.candidates.append(result)
        return 0

    def new_check_member_assignment(self, expression, index):
        """
        We are now in cexpr_t == idaapi.cot_var. This function checks if expression is part of member assignment
        statement. Returns None if not.

        :param expression: idaapi.cexpr_t
        :param index: int
        :return: Structures.AbstractField
        """
        parents_type = map(lambda x: idaapi.get_ctype_name(x.cexpr.op), list(self.parents)[:0:-1])
        parents = map(lambda x: x.cexpr, list(self.parents)[:0:-1])

        # Assignment like (v1 = v2) where v2 is scanned variable
        if parents_type[0:2] == ['asg', 'expr']:
            if parents[0].y == expression:
                if parents[0].x.op == idaapi.cot_var:
                    self.add_variable(parents[0].x.v.idx)
                    return

        # Assignment like v1 = (TYPE) v2 where TYPE is one the supported types
        elif parents_type[0:3] == ['cast', 'asg', 'expr']:
            if parents[1].x.op == idaapi.cot_var:
                if filter(lambda x: x.equals_to(parents[0].type), Const.LEGAL_TYPES):
                    self.add_variable(parents[1].x.v.idx)
                    return

        # --------------------------------------------------------------------------------------------
        # When variable is DWORD, int, __int64 etc
        # --------------------------------------------------------------------------------------------
        if self.variables[index].equals_to(Const.X_WORD_TINFO):
            if parents_type[0] == 'add':
                if parents[0].y.op != idaapi.cot_num:
                    return
                offset = parents.pop(0).y.n._value
                parents_type.pop(0)
            else:
                offset = 0

            # *(TYPE *) (var + x) = object
            if parents_type[0:4] == ['cast', 'ptr', 'asg', 'expr'] and parents[2].x == parents[1]:
                right_child = parents[2].y
                if right_child.op == idaapi.cot_ref:
                    right_child = right_child.x
                if right_child.op == idaapi.cot_obj:
                    member_type = idaapi.tinfo_t(right_child.type)
                    member_type.create_ptr(member_type)
                    return self.create_member(offset, index, member_type, right_child.obj_ea)
                else:
                    return self.create_member(offset, index, right_child.type)

            elif parents_type[0:2] == ['cast', 'call']:
                if parents[0].type.equals_to(Const.PVOID_TINFO) or parents[0].type.equals_to(Const.CONST_PVOID_TINFO):

                    # TODO: Recursion

                    return self.create_member(offset, index)
                else:
                    return self.create_member(offset, index, parents[0].type)

            elif parents_type[0] == 'call':

                arg_index = None
                for arg_index in xrange(len(parents[0].a)):
                    if expression.is_child_of(parents[0].a[arg_index]):
                        break

                new_function = idaapi.decompile(parents[0].x.obj_ea)
                if new_function:
                    scanner = CtreeVisitor(new_function, None, self.origin + offset, arg_index)
                    scanner.apply_to(new_function.body, None)
                    self.candidates.extend(scanner.candidates)
                    return None

            elif parents_type[0] == 'cast':
                return self.create_member(offset, index, parents[0].type)

    # --------------------------------------------------------------------------------------------
    # When variable is DWORD *, QWORD * etc
    # --------------------------------------------------------------------------------------------
        elif self.variables[index].equals_to(Const.PX_WORD_TINFO):
            print "[DEBUG] Parents:", parents_type, "Offset:", None