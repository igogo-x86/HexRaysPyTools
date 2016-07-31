import idaapi

from HexRaysPyTools.Helper.Structures import *


def check_virtual_table(address):
    functions_count = 0
    while True:
        if EA64:
            func_address = idaapi.get_64bit(address)
        else:
            func_address = idaapi.get_32bit(address)
        flags = idaapi.getFlags(func_address)           # flags_t
        if idaapi.isCode(flags):
            functions_count += 1
            address += EA_SIZE
        else:
            break
    return functions_count >= 2


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

        if expression.dstr() == "int":
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
                        if check_virtual_table(right_son.obj_ea):
                            virtual_table = VirtualTable(right_son.obj_ea)
                            return Field(offset, virtual_table=virtual_table)

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


class ActionScanVariable(idaapi.action_handler_t):
    def __init__(self, temporary_structure):
        self.temporary_structure = temporary_structure
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        vu = idaapi.get_tform_vdui(ctx.form)
        variable = vu.item.get_lvar()  # lvar_t
        print "Local variable type: %s" % variable.tif.dstr()
        if variable.tif.dstr() in LEGAL_TYPES:
            scanner = CtreeVisitor(vu.cfunc, variable)
            scanner.apply_to(vu.cfunc.body, None)
            for field in scanner.candidates:
                self.temporary_structure.add_row(field)

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
