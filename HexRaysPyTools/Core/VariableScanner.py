import idaapi
import idc
import Const
import Helper
import TemporaryStructure

SCAN_ALL_ARGUMENTS = True
scanned_functions = set()


class ShallowSearchVisitor(idaapi.ctree_parentee_t):
    def __init__(self, function, origin, index=None, global_variable=None):
        """
        This Class is idaapi.ctree_visitor_t and used for for finding candidates on class members.
        Usage: CtreeVisitor.apply_to() and then CtreeVisitor.candidates

        :param function: idaapi.cfunc_t
        :param origin: offset in main structure from which scanning is propagating
        :param index: variable index
        """
        super(ShallowSearchVisitor, self).__init__()
        self.function = function
        # Dictionary {variable name (global) or index (local) => tinfo_t} of variables that are being scanned

        if global_variable:
            index, tinfo = global_variable
            self.variables = {index: tinfo}
        else:
            self.variables = {index: function.get_lvars()[index].type()}
        self.origin = origin
        self.expression_address = idaapi.BADADDR
        self.candidates = []
        if not self.variables[index].equals_to(Const.PVOID_TINFO):
            self.candidates.append(self.create_member(0, index, pvoid_applicable=True))

        self.protected_variables = {index}
        scanned_functions.add((function.entry_ea, index, self.origin))

    def create_member(self, offset, index, tinfo=None, ea=0, pvoid_applicable=False):
        return TemporaryStructure.create_member(
            self.function, self.expression_address, self.origin, offset, index, tinfo, ea, pvoid_applicable
        )

    def get_member(self, offset, index, **kwargs):

        # Handling all sorts of functions call
        try:
            call_expr, arg_expr = kwargs['call'], kwargs['arg']
            arg_index, arg_type = Helper.get_func_argument_info(call_expr, arg_expr)
            if arg_type.equals_to(Const.PVOID_TINFO) or arg_type.equals_to(Const.CONST_PVOID_TINFO):
                if SCAN_ALL_ARGUMENTS or not arg_index:
                    self.scan_function(call_expr.x.obj_ea, offset, arg_index)
                return self.create_member(offset, index)
            elif arg_type.equals_to(Const.X_WORD_TINFO) or arg_type.equals_to(Const.PX_WORD_TINFO) or \
                    arg_type.equals_to(Const.PBYTE_TINFO):
                nice_tinfo = Helper.get_nice_pointed_object(arg_type)
                if nice_tinfo:
                    return self.create_member(offset, index, nice_tinfo)
                if SCAN_ALL_ARGUMENTS or not arg_index:
                    self.scan_function(call_expr.x.obj_ea, offset, arg_index)
                return self.create_member(offset, index, pvoid_applicable=True)
            arg_type.remove_ptr_or_array()
            return self.create_member(offset, index, arg_type)
        except KeyError:
            pass

        # When we have pointer dereference on the left side and expression on the right
        try:
            right_expr, cast_type = kwargs['object'], kwargs['default']
            if right_expr.op in (idaapi.cot_ref, idaapi.cot_cast):
                right_expr = right_expr.x
            if right_expr.op == idaapi.cot_obj:
                member_type = idaapi.tinfo_t(right_expr.type)
                member_type.create_ptr(member_type)
                return self.create_member(offset, index, member_type, right_expr.obj_ea)
            if right_expr.op in Const.COT_ARITHMETIC:
                return self.create_member(offset, index, cast_type)
            return self.create_member(offset, index, right_expr.type)
        except KeyError:
            pass

    def add_variable(self, index):
        self.variables[index] = self.function.get_lvars()[index].type()

    def scan_function(self, ea, offset, arg_index):
        pass

    def visit_expr(self, expression):
        if expression.op == idaapi.cot_var:
            index = expression.v.idx
        elif expression.op == idaapi.cot_obj:
            index = idc.GetTrueName(expression.obj_ea)
        else:
            return 0
        if index in self.variables:
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
        :return: Structures.AbstractField
        """
        parents_type = map(lambda x: idaapi.get_ctype_name(x.cexpr.op), list(self.parents)[:0:-1])
        parents = map(lambda x: x.cexpr, list(self.parents)[:0:-1])

        for parent in parents:
            if parent.ea != idaapi.BADADDR:
                self.expression_address = parent.ea
                break
        else:
            self.expression_address = idaapi.BADADDR

        offset = 0

        if parents_type[0:2] == ['asg', 'expr']:
            if parents[0].y == expression:
                # Assignment like (v1 = v2) where v2 is scanned variable
                if parents[0].x.op == idaapi.cot_var:
                    self.add_variable(parents[0].x.v.idx)
                    return
            else:
                # if expression is (var = something), we have to explore whether continue to scan this variable or not
                if parents[0].y.op != idaapi.cot_num:
                    if parents[0].y.op == idaapi.cot_call:
                        # Check if expression: var = function((TYPE) var, ...) or var = function(var, ...)
                        args = parents[0].y.a
                        if args and (
                            (
                                args[0].op == idaapi.cot_cast and
                                args[0].x.op == idaapi.cot_var and
                                args[0].x.v.idx == index
                            ) or (
                                args[0].op == idaapi.cot_var and
                                args[0].v.idx == index
                            )
                        ):
                            return
                    try:
                        self.protected_variables.remove(index)
                    except KeyError:
                        print "[Info] Remove variable {0} from scan list, address: 0x{1:08X}".format(
                            index, self.expression_address
                        )
                        self.variables.pop(index)
                    return

        # Assignment like v1 = (TYPE) v2 where TYPE is one the supported types
        elif parents_type[0:3] == ['cast', 'asg', 'expr']:
            if parents[1].x.op == idaapi.cot_var:
                if filter(lambda x: x.equals_to(parents[0].type), Const.LEGAL_TYPES):
                    self.add_variable(parents[1].x.v.idx)
                    return

        # Universal call with no cast conversion and offsets: call(..., this, ...)
        if parents_type[0] == 'call':
            arg_index, _ = Helper.get_func_argument_info(parents[0], expression)
            if SCAN_ALL_ARGUMENTS or not arg_index:
                self.scan_function(parents[0].x.obj_ea, 0, arg_index)
            return

        # --------------------------------------------------------------------------------------------
        # When variable is DWORD, int, __int64 etc
        # --------------------------------------------------------------------------------------------
        elif self.variables[index].equals_to(Const.X_WORD_TINFO):

            if parents_type[0:2] == ['add', 'cast']:
                if parents[0].theother(expression).op != idaapi.cot_num:
                    return
                offset = parents[0].theother(expression).numval()

                if parents_type[2] == 'ptr':
                    if parents_type[3] == 'asg':
                        if parents[3].x == parents[2]:
                            # *(TYPE *)(var + x) = ???
                            return self.get_member(
                                offset, index, object=parents[3].y, default=parents[1].type.get_pointed_object()
                            )
                        if parents[3].x.op == idaapi.cot_var:
                            # other_var = *(TYPE *)(var + x)
                            return self.create_member(offset, index, parents[3].x.type)
                    return self.create_member(offset, index, parents[1].type.get_pointed_object())

                elif parents_type[2] == 'call':
                    # call(..., (TYPE)(var + x), ...)
                    if parents[0].theother(expression).op != idaapi.cot_num:
                        return
                    offset = parents[0].theother(expression).numval()
                    return self.get_member(offset, index, call=parents[2], arg=parents[1])

                elif parents_type[2] == 'asg':
                    # other_var = (LEGAL TYPE) (var + offset)
                    if parents[2].y == parents[1] and parents[2].x.op == idaapi.cot_var:
                        if filter(lambda x: x.equals_to(parents[1].type), Const.LEGAL_TYPES):
                            self.scan_function(self.function.entry_ea, offset, parents[2].x.v.idx)
                            return

                cast_type = parents[1].type
                if cast_type.is_ptr():
                    return self.create_member(offset, index, cast_type.get_pointed_object())

            elif parents_type[0:2] == ['cast', 'ptr']:

                if parents_type[2] == 'asg' and parents[2].x == parents[1]:
                    # *(TYPE *)var = ???
                    return self.get_member(0, index, object=parents[2].y, default=parents[0].type.get_pointed_object())
                return self.create_member(0, index, parents[0].type.get_pointed_object())

            elif parents_type[0:2] == ['cast', 'call']:
                # call(..., (TYPE)(var + x), ...)
                return self.get_member(0, index, call=parents[1], arg=parents[0])

            elif parents_type[0] == 'add':
                # call(..., var + x, ...)
                if parents[0].theother(expression).op != idaapi.cot_num:
                    return
                offset = parents[0].theother(expression).numval()

                if parents_type[1] == 'call':
                    return self.get_member(offset, index, call=parents[1], arg=parents[0])

                elif parents_type[1] == 'asg':
                    if parents[1].y == parents[0] and parents[1].x.op == idaapi.cot_var:
                        self.scan_function(self.function.entry_ea, offset, parents[1].x.v.idx)
                        return

            elif parents_type[0] == 'asg':
                # var = (int)&Some_object
                if parents[0].y.op == idaapi.cot_cast and parents[0].y.x.op == idaapi.cot_ref:
                    return self.create_member(0, index, parents[0].y.x.type.get_pointed_object())

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
                offset = parents[0].y.numval() * self.variables[index].get_ptrarr_objsize()
                if parents_type[1] == 'asg' and parents[1].x == parents[0]:
                    # var[idx] = ???
                    return self.get_member(
                        offset, index, object=parents[1].y, default=self.variables[index].get_pointed_object()
                    )
                elif parents_type[1] == 'cast':
                    # (TYPE) var[idx]
                    return self.create_member(offset, index, parents[1].type)
                return self.create_member(offset, index, Const.X_WORD_TINFO)
            elif parents_type[0:2] == ['ptr', 'asg']:
                # *var = ???
                return self.get_member(
                    0, index, object=parents[1].y, default=self.variables[index].get_pointed_object()
                )
            else:
                if parents_type[0:2] == ['cast', 'ptr']:

                    if parents_type[2] == 'call':
                        # call(..., *(TYPE *) var, ...)
                        return self.get_member(0, index, call=parents[2], arg=parents[1])
                    elif parents_type[2] == 'asg' and parents[2].x == parents[1]:
                        # *(TYPE *) var = ???
                        return self.get_member(
                            0, index, object=parents[2].y, default=parents[0].type.get_pointed_object()
                        )

                elif parents_type[0:2] == ['cast', 'add']:
                    if parents[1].theother(parents[0]).op != idaapi.cot_num:
                        return None
                    offset = parents[1].theother(parents[0]).numval()
                    offset *= parents[0].type.get_ptrarr_objsize() if parents[0].type.is_ptr() else 1

                    if parents_type[2] == 'ptr':
                        if parents_type[3] == 'asg' and parents[3].x == parents[2]:
                            # *((TYPE *)var + x) = ???
                            return self.get_member(
                                offset, index, object=parents[3].y, default=parents[0].type.get_pointed_object()
                            )
                        return self.create_member(offset, index, parents[0].type.get_pointed_object())
                    elif parents_type[2] == 'call':
                        # call(..., (TYPE)var + offset, ...)
                        return self.get_member(offset, index, call=parents[2], arg=parents[1])
                    elif parents_type[2] == 'cast' and parents[2].type.is_ptr():
                        if parents_type[3] == 'call':
                            # call(..., (TYPE *) ((TYPE *)var + x), ...)
                            # Where argument type is not the same as cast type. Ida has a bug here choosing sometimes
                            # wrong pointer type
                            idx, tinfo = Helper.get_func_argument_info(parents[3], parents[2])
                            return self.create_member(offset, index, tinfo.get_pointed_object())

                        # (TYPE *) ((TYPE *)var + x)
                        return self.create_member(offset, index, parents[2].type.get_pointed_object())

                elif parents_type[0:2] == ['add', 'cast']:
                    if parents[0].theother(expression).op != idaapi.cot_num:
                        return None
                    offset = parents[0].theother(expression).numval() * self.variables[index].get_ptrarr_objsize()

                    if parents_type[2] == 'call':
                        # call(..., (TYPE)(var + x), ...)
                        return self.get_member(offset, index, call=parents[2], arg=parents[1])
                    elif parents_type[2] == 'asg':
                        if parents[2].y == parents[1] and parents[2].x.op == idaapi.cot_var:
                            if filter(lambda x: x.equals_to(parents[1].type), Const.LEGAL_TYPES):
                                self.scan_function(self.function.entry_ea, offset, parents[2].x.v.idx)
                                return
                    else:
                        return self.create_member(offset, index, parents[1].type.get_pointed_object())

                elif parents_type[0] == 'add':

                    # call(..., var + offset, ...)
                    if parents[0].theother(expression).op != idaapi.cot_num:
                        return None
                    offset = parents[0].theother(expression).numval() * self.variables[index].get_ptrarr_objsize()

                    if parents_type[1] == 'call':
                        return self.get_member(offset, index, call=parents[1], arg=parents[0])

                    if parents_type[1] == 'asg':
                        # other_var = var + offset
                        if parents[1].y == parents[0] and parents[1].x.op == idaapi.cot_var:
                            self.scan_function(self.function.entry_ea, offset, parents[1].x.v.idx)
                            return

                elif parents_type[0:2] == ['cast', 'call']:
                    # call(..., (TYPE) var, ...)
                    return self.get_member(0, index, call=parents[1], arg=parents[0])

                elif parents_type[0] == 'ptr':
                    if parents_type[1] == 'cast':
                        # (TYPE) *var
                        return self.create_member(0, index, parents[0].type)
                    # *var
                    return self.create_member(0, index, self.variables[index].get_pointed_object())

                elif parents_type[0] == 'asg':
                    return

        if 'return' not in parents_type[0:2] and parents_type[0] not in ('if', 'band', 'eq', 'ne', 'cast'):
            print "[DEBUG] Unhandled type", self.variables[index].dstr(), \
                "Index:", index, \
                "Offset:", offset, \
                "Function:", idaapi.get_ea_name(self.function.entry_ea), \
                "Address: 0x{0:08X}".format(expression.ea), \
                "Parents:", parents_type

    def process(self):
        """
        Function that starts recursive search, initializes and clears set of visited functions so that we
        don't wind up in infinite recursion.
        """
        self.apply_to(self.function.body, None)

    @staticmethod
    def clear():
        scanned_functions.clear()


class DeepSearchVisitor(ShallowSearchVisitor):
    def __init__(self, function, origin, index=None, global_variable=None):
        super(DeepSearchVisitor, self).__init__(function, origin, index, global_variable)

    def scan_function(self, ea, offset, arg_index):
        # Function for recursive search structure's members

        if (ea, arg_index, self.origin + offset) in scanned_functions:
            return
        try:
            scanned_functions.add((ea, arg_index, self.origin + offset))
            new_function = idaapi.decompile(ea)
            if new_function:
                print "[Info] Scanning function {name} at 0x{ea:08X}, origin: 0x{origin:04X}".format(
                    name=idaapi.get_short_name(ea), ea=ea, origin=self.origin + offset
                )
                scanner = DeepSearchVisitor(new_function, self.origin + offset, arg_index)
                scanner.apply_to(new_function.body, None)
                self.candidates.extend(scanner.candidates)
        except idaapi.DecompilationFailure:
            print "[ERROR] Ida failed to decompile function at 0x{0:08X}".format(ea)


class VariableLookupVisitor(idaapi.ctree_parentee_t):
    """ Helps to find all variables that are returned by some function placed at func_address """

    def __init__(self, func_address):
        super(VariableLookupVisitor, self).__init__()
        self.func_address = func_address
        self.result = []

    def visit_expr(self, expression):
        # We are looking for expressions like `var = func(...)` or `var = (TYPE) func(...)`
        if expression.op == idaapi.cot_asg and expression.x.op == idaapi.cot_var:
            if expression.y.op == idaapi.cot_call:
                if self.__check_call(expression.y) or \
                        expression.y.op == idaapi.cot_cast and expression.y.x.op == idaapi.cot_call:

                    idx = expression.x.v.idx
                    self.result.append(idx)
        return 0

    def __check_call(self, expression):
        return expression.x.obj_ea == self.func_address
