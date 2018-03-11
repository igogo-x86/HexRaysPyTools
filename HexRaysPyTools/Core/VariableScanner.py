import logging
import idaapi
import idc
import Const
import Helper
import TemporaryStructure
import HexRaysPyTools.Api as Api

logger = logging.getLogger(__name__)

# If disabled then recursion will be triggered only for variable passed as first argument to function
SETTING_SCAN_ALL_ARGUMENTS = True

# Global set which is populated when deep scanning and cleared after completion
scanned_functions = set()
debug_scan_tree = []


class ScannedObject(object):
    def __init__(self, name, expression_address, origin, applicable=True):
        """
        Class for storing object and it's info that have been scanned previously.
        Need to think whether it's better to store address and index, or cfunc_t and lvar_t

        :param function: idaapi.cfunc_t
        :param variable: idaapi.vdui_t
        """
        self.name = name
        self.expression_address = expression_address
        self.func_ea = idc.get_func_attr(self.expression_address, idc.FUNCATTR_START)
        self.origin = origin
        self._applicable = applicable

    @property
    def function_name(self):
        return idaapi.get_short_name(self.func_ea)

    def apply_type(self, tinfo):
        """ Finally apply Class'es tinfo to this variable """
        raise NotImplemented

    @staticmethod
    def create(obj, expression_address, origin, applicable):
        if obj.id == Api.SO_GLOBAL_OBJECT:
            return ScannedGlobalObject(obj.ea. obj.name, expression_address, origin, applicable)
        elif obj.id == Api.SO_LOCAL_VARIABLE:
            return ScannedVariableObject(obj.lvar, obj.name, expression_address, origin, applicable)
        elif obj.id in (Api.SO_STRUCT_REFERENCE, Api.SO_STRUCT_POINTER):
            return ScannedStructureMemberObject(obj.struct_name, obj.offset, expression_address, origin, applicable)
        else:
            raise AssertionError

    def to_list(self):
        """ Creates list that is acceptable to MyChoose2 viewer """
        return [
            "0x{0:04X}".format(self.origin),
            self.function_name,
            self.name,
            Helper.to_hex(self.expression_address)
        ]

    def __eq__(self, other):
        return self.func_ea == other.func_ea and self.name == other.name and \
               self.expression_address == other.expression_address

    def __hash__(self):
        return hash((self.func_ea, self.name, self.expression_address))

    def __repr__(self):
        return "{} : {}".format(self.name, Helper.to_hex(self.expression_address))


class ScannedGlobalObject(ScannedObject):
    def __init__(self, obj_ea, name, expression_address, origin, applicable=True):
        super(ScannedGlobalObject, self).__init__(name, expression_address, origin, applicable)
        self.__obj_ea = obj_ea

    def apply_type(self, tinfo):
        if self._applicable:
            idaapi.set_tinfo2(self.__obj_ea, tinfo)


class ScannedVariableObject(ScannedObject):
    def __init__(self, lvar, name, expression_address, origin, applicable=True):
        super(ScannedVariableObject, self).__init__(name, expression_address, origin, applicable)
        self.__lvar = lvar

    def apply_type(self, tinfo):
        if not self._applicable:
            return

        hx_view = idaapi.open_pseudocode(self.func_ea, -1)
        if hx_view:
            logger.info("Applying tinfo to variable {0} in function {1}".format(self.name, self.function_name))
            # Finding lvar of new window that have the same name that saved one and applying tinfo_t
            lvar = filter(lambda x: x == self.__lvar, hx_view.cfunc.get_lvars())
            if lvar:
                logger.info("Successful")
                hx_view.set_lvar_type(lvar[0], tinfo)
            else:
                logger.warn("Failed to find previously scanned local variable {} from {}".format(
                    self.name, Helper.to_hex(self.expression_address)))


class ScannedStructureMemberObject(ScannedObject):
    def __init__(self, struct_name, struct_offset, name, expression_address, origin, applicable=True):
        super(ScannedStructureMemberObject, self).__init__(name, expression_address, origin, applicable)
        self.__struct_name = struct_name
        self.__struct_offset = struct_offset

    def apply_type(self, tinfo):
        if self._applicable:
            logger.warn("Changing type of structure field is not yet implemented. Address - {}".format(
                Helper.to_hex(self.expression_address)))


class SearchVisitor(Api.ObjectVisitor):
    def __init__(self, cfunc, origin, obj, temporary_structure):
        super(SearchVisitor, self).__init__(cfunc, obj, None, True)
        self.__origin = origin
        self.__temporary_structure = temporary_structure

    def _manipulate(self, cexpr, obj):
        super(SearchVisitor, self)._manipulate(cexpr, obj)
        if not Helper.is_legal_type(obj.tinfo):
            logger.warn("Variable obj.name has weird type at {}".format(self._find_asm_address(cexpr)))
            return
        if obj.tinfo.is_ptr():
            member = self.__extract_member_from_pointer(cexpr, obj)
        else:
            member = self.__extract_member_from_xword(cexpr, obj)
        if member:
            logger.debug("\tCreating member with type {}, {}".format(member.type_name, member.scanned_variables))
            self.__temporary_structure.add_row(member)

    def _get_member(self, offset, cexpr, obj, tinfo=None, obj_ea=None):
        applicable = not self.crippled
        cexpr_ea = self._find_asm_address(cexpr)
        scan_obj = ScannedObject.create(obj, cexpr_ea, self.__origin, applicable)
        if obj_ea:
            if TemporaryStructure.VirtualTable.check_address(obj_ea):
                return TemporaryStructure.VirtualTable(offset, obj_ea, scan_obj, self.__origin)
            if Helper.is_code_ea(obj_ea):
                cfunc = Api.decompile_function(obj_ea)
                if cfunc:
                    tinfo = cfunc.type
                    tinfo.create_ptr(tinfo)
                else:
                    tinfo = Const.DUMMY_FUNC
                return TemporaryStructure.Member(offset, tinfo, scan_obj, self.__origin)
            logger.warn("Want to see this ea - {},".format(Helper.to_hex(cexpr_ea)))

        if not tinfo or tinfo.equals_to(Const.VOID_TINFO):
            return TemporaryStructure.VoidMember(offset, scan_obj, self.__origin)

        if tinfo.equals_to(Const.CHAR_TINFO):
            return TemporaryStructure.VoidMember(offset, scan_obj, self.__origin, char=True)

        if tinfo.equals_to(Const.CONST_PCHAR_TINFO):
            tinfo = Const.PCHAR_TINFO
        elif tinfo.equals_to(Const.CONST_PVOID_TINFO):
            tinfo = Const.PVOID_TINFO
        else:
            tinfo.clr_const()
        return TemporaryStructure.Member(offset, tinfo, scan_obj, self.__origin)

    def _parse_call(self, call_cexpr, arg_cexpr, offset):
        _, tinfo = Helper.get_func_argument_info(call_cexpr, arg_cexpr)
        if tinfo:
            return self.__deref_tinfo(tinfo)
        # TODO: Find example with UTF-16 strings
        return Const.CHAR_TINFO

    def _parse_left_assignee(self, cexpr, offset):
        pass

    def __extract_member_from_pointer(self, cexpr, obj):
        parents_type = map(lambda x: idaapi.get_ctype_name(x.cexpr.op), list(self.parents)[:0:-1])
        parents = map(lambda x: x.cexpr, list(self.parents)[:0:-1])

        logger.debug("Parsing expression {}. Parents - {}".format(obj.name, parents_type))

        # Extracting offset and removing expression parents making this offset
        if parents_type[0] in ('idx', 'add'):
            # `obj[idx]' or `(TYPE *) + x'
            if parents[0].y.op != idaapi.cot_num:
                # There's no way to handle with dynamic offset
                return None
            offset = parents[0].y.numval() * obj.tinfo.get_ptrarr_objsize()
            cexpr = self.parent_expr()
            if parents_type[0] == 'add':
                del parents_type[0]
                del parents[0]
        elif parents_type[0:2] == ['cast', 'add']:
            # (TYPE *)obj + offset
            offset = parents[1].theother(parents[0]).numval() * parents[0].type.get_ptrarr_objsize()
            cexpr = parents[1]
            del parents_type[0:2]
            del parents[0:2]
        else:
            offset = 0

        return self.__extract_member(cexpr, obj, offset, parents, parents_type)

    def __extract_member_from_xword(self, cexpr, obj):
        parents_type = map(lambda x: idaapi.get_ctype_name(x.cexpr.op), list(self.parents)[:0:-1])
        parents = map(lambda x: x.cexpr, list(self.parents)[:0:-1])

        logger.debug("Parsing expression {}. Parents - {}".format(obj.name, parents_type))

        if parents_type[0] == 'add':
            if parents[0].theother(cexpr).op != idaapi.cot_num:
                return
            offset = parents[0].theother(cexpr).numval()
            cexpr = self.parent_expr()
            del parents_type[0]
            del parents[0]
        else:
            offset = 0

        return self.__extract_member(cexpr, obj, offset, parents, parents_type)

    def __extract_member(self, cexpr, obj, offset, parents, parents_type):
        if parents_type[0] == 'cast':
            default_tinfo = parents[0].type
            cexpr = parents[0]
            del parents_type[0]
            del parents[0]
        else:
            default_tinfo = Const.PX_WORD_TINFO

        if parents_type[0] in ('idx', 'ptr'):
            if parents_type[1] == 'cast':
                default_tinfo = parents[1].type
                cexpr = parents[0]
                del parents_type[0]
                del parents[0]
            else:
                default_tinfo = Const.X_WORD_TINFO

            if parents_type[1] == 'asg':
                if parents[1].x == parents[0]:
                    # *(TYPE *)(var + x) = ???
                    obj_ea = self.__extract_obj_ea(parents[1].y)
                    return self._get_member(offset, cexpr, obj, default_tinfo, obj_ea)
                elif parents[1].x.op == idaapi.cot_var:
                    # other_var = *(TYPE *)(var + x)
                    return self._get_member(offset, cexpr, obj, parents[1].x.type)
            elif parents_type[1] == 'call':
                if parents[1].x == parents[0]:
                    # ((type (__some_call *)(..., ..., ...)var[idx])(..., ..., ...)
                    # ((type (__some_call *)(..., ..., ...)*(TYPE *)(var + x))(..., ..., ...)
                    return self._get_member(offset, cexpr, obj, parents[0].type)
                _, tinfo = Helper.get_func_argument_info(parents[1], parents[0])
                if tinfo is None:
                    tinfo = Const.PCHAR_TINFO
                return self._get_member(offset, cexpr, obj, tinfo)
            return self._get_member(offset, cexpr, obj, default_tinfo)

        elif parents_type[0] == 'call':
            # call(..., (TYPE)(var + x), ...)
            tinfo = self._parse_call(parents[0],cexpr, offset)
            return self._get_member(offset, cexpr, obj, tinfo)

        elif parents_type[0] == 'asg':
            if parents[0].y == cexpr:
                # other_obj = (TYPE) (var + offset)
                self._parse_left_assignee(parents[1].x, offset)
        return self._get_member(offset, cexpr, obj, self.__deref_tinfo(default_tinfo))


    @staticmethod
    def __extract_obj_ea(cexpr):
        if cexpr.op == idaapi.cot_ref:
            cexpr = cexpr.x
        if cexpr.op == idaapi.cot_obj:
            if cexpr.obj_ea != idaapi.BADADDR:
                return cexpr.obj_ea

    @staticmethod
    def __deref_tinfo(tinfo):
        if tinfo.is_ptr():
            if tinfo.get_ptrarr_objsize() == 1:
                if tinfo.equals_to(Const.PCHAR_TINFO) or tinfo.equals_to(Const.CONST_PCHAR_TINFO):
                    return Const.CHAR_TINFO
                return None         # Turns into VoidMember
            return tinfo.get_pointed_object()
        return tinfo


class NewShallowSearchVisitor(SearchVisitor, Api.ObjectDownwardsVisitor):
    def __init__(self, cfunc, origin, obj, temporary_structure):
        super(NewShallowSearchVisitor, self).__init__(cfunc, origin, obj, temporary_structure)


class NewDeepSearchVisitor(SearchVisitor,  Api.RecursiveObjectDownwardsVisitor):
    def __init__(self, cfunc, origin, obj, temporary_structure):
        super(NewDeepSearchVisitor, self).__init__(cfunc, origin, obj, temporary_structure)


class ShallowSearchVisitor(idaapi.ctree_parentee_t):
    def __init__(self, cfunc, origin, index=None, global_variable=None, start_ea=0):
        """
        This Class is idaapi.ctree_visitor_t and used for for finding candidates on class members.
        Usage: CtreeVisitor.apply_to() and then CtreeVisitor.candidates

        :param cfunc: idaapi.cfunc_t
        :param origin: offset in main structure from which scanning is propagating
        :param index: variable index
        :param start_ea: From where to start scanning process
        """
        super(ShallowSearchVisitor, self).__init__()
        self.function = cfunc
        # Dictionary {variable name (global) or index (local) => tinfo_t} of variables that are being scanned

        if global_variable:
            index, tinfo = global_variable
            self.variables = {index: tinfo}
        else:
            self.variables = {index: cfunc.get_lvars()[index].type()}
        self.origin = origin
        self.expression_address = idaapi.BADADDR

        # All extracted Members
        self.candidates = []

        # Save information about parents of analyze expression to print it when debugging and simplify process of
        # problems identification
        self.__parents_type = None

        if not self.variables[index].equals_to(Const.PVOID_TINFO):
            self.candidates.append(self.create_member(0, index, pvoid_applicable=True))

        # Dirty but haven't found out better way. Need to not allow deleting variables when faced to
        # `var = new Constructor()`. Scanner by default stops scanning variable when happens situation like `var = ...`
        # First variable will be deleted from protected variables. Than, after it's empty it will be removed form
        # self.variables.
        if cfunc.lvars[index].is_arg_var:
            self.__protected_variables = set()
        else:
            self.__protected_variables = {index}

        # If start_ea is specified than scanner will start processing expressions only when expression with address
        # greater or equal then start_ea has been visited
        self.__skip = True if start_ea else False
        self.__start_scan_ea = start_ea

    def create_member(self, offset, index, tinfo=None, ea=0, pvoid_applicable=False):
        logger.debug("\tCreating member with type: {}, parents: {}".format(str(tinfo), self.__parents_type))
        return TemporaryStructure.create_member(
            self.function, self.expression_address, self.origin, offset, index, tinfo, ea, pvoid_applicable
        )

    def get_member(self, offset, index, **kwargs):
        # Handling all sorts of functions call
        try:
            call_expr, arg_expr = kwargs['call'], kwargs['arg']
            arg_index, arg_type = Helper.get_func_argument_info(call_expr, arg_expr)

            if arg_type is None:
                # When function has variable amount of arguments and our argument is after determined amount of args
                return self.create_member(offset, index)

            elif arg_type.equals_to(Const.PVOID_TINFO) or arg_type.equals_to(Const.CONST_PVOID_TINFO):
                if SETTING_SCAN_ALL_ARGUMENTS or not arg_index:
                    self.scan_function(call_expr.x.obj_ea, offset, arg_index)
                return self.create_member(offset, index)

            elif arg_type.equals_to(Const.X_WORD_TINFO) or arg_type.equals_to(Const.PX_WORD_TINFO) or \
                    arg_type.equals_to(Const.PBYTE_TINFO):
                nice_tinfo = Helper.get_nice_pointed_object(arg_type)
                if nice_tinfo:
                    return self.create_member(offset, index, nice_tinfo)
                if SETTING_SCAN_ALL_ARGUMENTS or not arg_index:
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
                # TODO: Check if it's really correct
                if not member_type.is_funcptr():
                    member_type.create_ptr(member_type)
                return self.create_member(offset, index, member_type, right_expr.obj_ea)
            if right_expr.op in Const.COT_ARITHMETIC:
                return self.create_member(offset, index, cast_type)
            return self.create_member(offset, index, right_expr.type)
        except KeyError:
            pass

    def add_variable(self, index):
        lvar = self.function.lvars[index]
        logger.debug("Adding variable {} to scan list".format(lvar.name))
        self.variables[index] = lvar.type()

    def scan_function(self, ea, offset, arg_index):
        pass

    def visit_expr(self, expression):
        # Check if we have already started scanning
        if self.__skip:
            if expression.ea != idaapi.BADADDR and expression.ea >= self.__start_scan_ea:
                self.__skip = False
            else:
                return 0

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
        self.__parents_type = parents_type
        parents = map(lambda x: x.cexpr, list(self.parents)[:0:-1])

        self.expression_address = self._find_asm_address(expression)
        offset = 0

        logger.debug("Parsing expression at %s, Index: %s", Helper.to_hex(self.expression_address), index)

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
                    self._remove_scan_variable(index)
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
            if SETTING_SCAN_ALL_ARGUMENTS or not arg_index:
                self.scan_function(parents[0].x.obj_ea, 0, arg_index)
            return

        # In situation call(..., (TYPE) &var, ...) there's great probability that var is no longer original pointer
        if parents_type[0:3] == ['ref', 'cast', 'call']:
            self._remove_scan_variable(index)
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
                    cast_type = parents[1].type
                    if cast_type.is_ptr() and cast_type.get_ptrarr_objsize() == 1:
                        return self.create_member(offset, index, cast_type.get_pointed_object())
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
            logger.debug(
                "Unhandled type `%s`, Index: %s, Offset: %s, Function: %s, Address: %s, Parents: %s",
                str(self.variables[index]),
                index,
                offset,
                idaapi.get_ea_name(self.function.entry_ea),
                Helper.to_hex(self.expression_address),
                parents_type
            )

    def process(self):
        """
        Function that starts recursive search, initializes and clears set of visited functions so that we
        don't wind up in infinite recursion.
        """
        self.apply_to(self.function.body, None)

    def _remove_scan_variable(self, index):
        try:
            self.__protected_variables.remove(index)
        except KeyError:
            logger.info("Remove variable {0} from scan list, address: 0x{1:08X}".format(
                index, self.expression_address
            ))
            self.variables.pop(index)


class DeepSearchVisitor(ShallowSearchVisitor):
    def __init__(self, cfunc, origin, index=None, global_variable=None, start_ea=0, level=0):
        super(DeepSearchVisitor, self).__init__(cfunc, origin, index, global_variable, start_ea)
        self.__level = level
        self.__add_scan_tree_info(idaapi.get_short_name(cfunc.entry_ea), index, self.origin)
        scanned_functions.add((cfunc.entry_ea, index, self.origin))

    def scan_function(self, ea, offset, arg_index):
        # Function for recursive search structure's members
        if Helper.is_imported_ea(ea):
            return
        if (ea, arg_index, self.origin + offset) in scanned_functions:
            return
        try:
            scanned_functions.add((ea, arg_index, self.origin + offset))
            new_function = idaapi.decompile(ea)

            if new_function:
                func_name = idaapi.get_short_name(ea)

                # Check if scanned variable is really an argument, otherwise it can be part of format expression
                if ea != self.function.entry_ea and not self.__is_func_arg(new_function, arg_index):
                    logger.warning("Seems like we're scanning format argument at {}, function: {}, index: {}".format(
                        Helper.to_hex(self.expression_address),
                        func_name,
                        arg_index
                    ))
                    return

                logger.info("Scanning function {name} at {ea}, origin: 0x{origin:04X}, index: {idx}".format(
                    name=func_name,
                    ea=Helper.to_hex(self.expression_address),
                    origin=self.origin + offset,
                    idx=arg_index
                ))

                # If we are scanning the same function but different variable, then start this process from
                # current expression and not from the beginning of the function
                if ea == self.function.entry_ea:
                    start_ea = self.expression_address
                else:
                    start_ea = 0

                scanner = DeepSearchVisitor(
                    new_function, self.origin + offset, arg_index, start_ea=start_ea, level=self.__level + 1
                )
                scanner.apply_to(new_function.body, None)
                self.candidates.extend(scanner.candidates)
                logger.info("Finished scanning function {}".format(func_name))

        except idaapi.DecompilationFailure:
            logger.warning("Ida failed to decompile function at {}".format(Helper.to_hex(ea)))
        debug_scan_tree = []

    def __add_scan_tree_info(self, func_name, arg_index, offset):
        prefix = " | " * (self.__level - 1) + " |_" if self.__level else ""
        debug_scan_tree.append("{}{} {} {}".format(prefix, func_name, arg_index, offset))

    @staticmethod
    def clear():
        global debug_scan_tree

        scanned_functions.clear()
        DeepSearchVisitor.dump_scan_tree()
        debug_scan_tree = []

    @staticmethod
    def __is_func_arg(cfunc, index):
        return index < len(cfunc.lvars) and cfunc.lvars[index].is_arg_var

    @staticmethod
    def dump_scan_tree():
        global debug_scan_tree

        logger.debug("\n--- Scan Tree---\n{}\n----------------".format("\n".join(debug_scan_tree)))


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
