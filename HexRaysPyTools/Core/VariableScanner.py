import HexRaysPyTools.Core.Const as Const
import HexRaysPyTools.Core.Helper as Helper
from HexRaysPyTools.Core.TemporaryStructure import *

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
            self.apply_to(self.cfunc.body, None)
            self.touch_all()
            return True
        return False


class CtreeVisitor(idaapi.ctree_parentee_t):
    def __init__(self, function, origin, index):
        """
        This Class is idaapi.ctree_visitor_t and used for for finding candidates on class members.
        Usage: CtreeVisitor.apply_to() and then CtreeVisitor.candidates

        :param function: idaapi.cfunc_t
        :param origin: offset in main structure from which scanning is propagating
        :param index: variable index
        """
        super(CtreeVisitor, self).__init__()
        self.function = function
        # Dictionary {variable name => tinfo_t} of variables that are being scanned

        self.variables = {index: function.get_lvars()[index].type()}
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
        if tinfo and not tinfo.equals_to(Const.VOID_TINFO):
            return Member(
                offset,
                tinfo,
                ScannedVariable(self.function, self.function.get_lvars()[index]),
                self.origin
            )
        else:
            # VoidMember shouldn't have ScannedVariable because after finalizing it can affect on normal functions
            # like `memset`
            return VoidMember(offset, None, self.origin)

    def get_member(self, offset, index, **kwargs):

        # Handling all sorts of functions call
        try:
            call_expr, arg_expr = kwargs['call'], kwargs['arg']
            arg_index, arg_type = Helper.get_func_argument_info(call_expr, arg_expr)
            if arg_type.equals_to(Const.PVOID_TINFO) or arg_type.equals_to(Const.CONST_PVOID_TINFO):
                if not arg_index:
                    self.scan_function(call_expr.x.obj_ea, offset, arg_index)
                return self.create_member(offset, index)
            elif arg_type.equals_to(Const.X_WORD_TINFO) or arg_type.equals_to(Const.PX_WORD_TINFO):
                nice_tinfo = Helper.get_nice_pointed_object(arg_type)
                if nice_tinfo:
                    return self.create_member(offset, index, nice_tinfo)
                if not arg_index:
                    self.scan_function(call_expr.x.obj_ea, offset, arg_index)
                return self.create_member(offset, index)
            arg_type.remove_ptr_or_array()
            return self.create_member(offset, index, arg_type)
        except KeyError:
            pass

        # When we have pointer resolution from the left and expression from the right
        try:
            right_expr = kwargs['object']
            if right_expr.op in (idaapi.cot_ref, idaapi.cot_cast):
                right_expr = right_expr.x
            if right_expr.op == idaapi.cot_obj:
                member_type = idaapi.tinfo_t(right_expr.type)
                member_type.create_ptr(member_type)
                return self.create_member(offset, index, member_type, right_expr.obj_ea)
            return self.create_member(offset, index, right_expr.type)
        except KeyError:
            pass

    def add_variable(self, index):
        self.variables[index] = self.function.get_lvars()[index].type()

    def scan_function(self, ea, offset, arg_index):
        # Function for recursive search structure's members

        print "[Info] Scanning function {name} at 0x{ea:08X}".format(
            name=idaapi.get_short_name(ea),
            ea=ea
        )
        try:
            new_function = idaapi.decompile(ea)
            if new_function:
                scanner = CtreeVisitor(new_function, self.origin + offset, arg_index)
                scanner.apply_to(new_function.body, None)
                self.candidates.extend(scanner.candidates)
        except idaapi.DecompilationFailure:
            print "[ERROR] Ida failed to scan function"

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

        offset = 0

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

        # Universal call with no cast conversion and offsets: call(..., this, ...)
        if parents_type[0] == 'call':
            arg_index = None
            for arg_index in xrange(len(parents[0].a)):
                if parents[0].a[arg_index].op == idaapi.cot_var and parents[0].a[arg_index].v.idx == index:
                    break
            self.scan_function(parents[0].x.obj_ea, 0, arg_index)

        # --------------------------------------------------------------------------------------------
        # When variable is DWORD, int, __int64 etc
        # --------------------------------------------------------------------------------------------
        elif self.variables[index].equals_to(Const.X_WORD_TINFO):

            if parents_type[0:2] == ['add', 'cast']:
                if parents[0].theother(expression).op != idaapi.cot_num:
                    return
                offset = parents[0].theother(expression).numval()

                if parents_type[2] == 'ptr':
                    if parents_type[3] == 'asg' and parents[3].x == parents[2]:
                        # *(TYPE *)(var + x) = ???
                        return self.get_member(offset, index, object=parents[3].y)
                    return self.create_member(offset, index, parents[1].type.get_pointed_object())

                elif parents_type[2] == 'call':
                    # call(..., (TYPE)(var + x), ...)
                    if parents[0].theother(expression).op != idaapi.cot_num:
                        return
                    offset = parents[0].theother(expression).numval()
                    return self.get_member(offset, index, call=parents[2], arg=parents[1])

                cast_type = parents[1].type
                if cast_type.is_ptr():
                    return self.create_member(offset, index, cast_type.get_pointed_object())

            elif parents_type[0:2] == ['cast', 'ptr']:

                if parents_type[2] == 'asg' and parents[2].x == parents[1]:
                    # *(TYPE *)var = ???
                    return self.get_member(0, index, object=parents[2].y)
                return self.create_member(0, index, parents[0].type.get_pointed_object())

            elif parents_type[0:2] == ['cast', 'call']:
                # call(..., (TYPE)(var + x), ...)
                return self.get_member(0, index, call=parents[1], arg=parents[0])

            elif parents_type[0:2] == ['add', 'call']:
                # call(..., var + x, ...)
                if parents[0].theother(expression).op != idaapi.cot_num:
                    return
                offset = parents[0].theother(expression).numval()
                return self.get_member(offset, index, call=parents[1], arg=parents[0])

        # --------------------------------------------------------------------------------------------
        # When variable is void *, PVOID, DWORD *, QWORD * etc
        # --------------------------------------------------------------------------------------------
        else:
            # print "[DEBUG] D* Parents:", parents_type
            offset = 0

            if parents_type[0] == 'idx':
                if parents[0].y.op != idaapi.cot_num:
                    # There's no way to handle with dynamic offset
                    return None
                offset = parents[0].y.numval() * Const.EA_SIZE
                if parents_type[1] == 'asg' and parents[1].x == parents[0]:
                    # var[idx] = ???
                    return self.get_member(offset, index, object=parents[1].y)
                elif parents_type[1] == 'cast':
                    # (TYPE) var[idx]
                    return self.create_member(offset, index, parents[1].type)
                return self.create_member(offset, index, Const.X_WORD_TINFO)
            elif parents_type[0:2] == ['ptr', 'asg']:
                # *var = ???
                return self.get_member(0, index, object=parents[1].y)
            else:
                if parents_type[0:2] == ['cast', 'ptr']:

                    if parents_type[2] == 'call':
                        # call(..., *(TYPE *) var, ...)
                        return self.get_member(0, index, call=parents[2], arg=parents[1])
                    elif parents_type[2] == 'asg' and parents[2].x == parents[1]:
                        # *(TYPE *) var = ???
                        return self.get_member(0, index, object=parents[2].y)

                elif parents_type[0:2] == ['cast', 'add']:
                    if parents[1].theother(parents[0]).op != idaapi.cot_num:
                        return None
                    offset = parents[1].theother(parents[0]).numval()
                    offset *= parents[0].type.get_pointed_object().get_size() if parents[0].type.is_ptr() else 1

                    if parents_type[2] == 'ptr':
                        if parents_type[3] == 'asg' and parents[3].x == parents[2]:
                            # *((TYPE *)var + x) = ???
                            return self.get_member(offset, index, object=parents[3].y)
                        return self.create_member(offset, index, parents[0].type.get_pointed_object())
                    elif parents_type[2] == 'call':
                        # call(..., (TYPE)var + offset, ...)
                        return self.get_member(offset, index, call=parents[2], arg=parents[1])
                    elif parents_type[2] == 'cast' and parents[2].type.is_ptr():
                        # (TYPE *) ((TYPE *)var + x)
                        return self.create_member(offset, index, parents[2].type.get_pointed_object())

                elif parents_type[0:2] == ['add', 'cast']:
                    if parents[0].theother(expression).op != idaapi.cot_num:
                        return None
                    offset = parents[0].theother(expression).numval() * Const.EA_SIZE

                    if parents_type[2] == 'call':
                        # call(..., (TYPE)(var + x), ...)
                        return self.get_member(offset, index, call=parents[2], arg=parents[1])
                    elif parents_type[2] == 'asg' and parents[2].x == parents[1]:
                        # (TYPE)(var + x) = ???
                        return self.get_member(offset, index, object=parents[2].y)
                    else:
                        return self.create_member(offset, index, parents[1].type.get_pointed_object())

                elif parents_type[0:2] == ['add', 'call']:
                    # call(..., var + offset, ...)
                    if parents[0].theother(expression).op != idaapi.cot_num:
                        return None
                    offset = parents[0].theother(expression).numval() * Const.EA_SIZE
                    return self.get_member(offset, index, call=parents[1], arg=parents[0])

                elif parents_type[0:2] == ['cast', 'call']:
                    # call(..., (TYPE) var, ...)
                    return self.get_member(0, index, call=parents[1], arg=parents[0])

        if 'return' not in parents_type[0:2]:
            print "[DEBUG] Unhandled type", self.variables[index].dstr(), \
                "Parents:", parents_type, \
                "Offset:", offset, \
                "Address: 0x{0:08X}".format(expression.ea)
