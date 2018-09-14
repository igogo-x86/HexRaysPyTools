import logging
import idaapi
import idc
import const
import helper
import temporary_structure
import HexRaysPyTools.api as api

logger = logging.getLogger(__name__)

# If disabled then recursion will be triggered only for variable passed as first argument to function
SETTING_SCAN_ALL_ARGUMENTS = True

# Global set which is populated when deep scanning and cleared after completion
scanned_functions = set()
debug_scan_tree = []


class ScannedObject(object):
    def __init__(self, name, expression_address, origin, applicable=True):
        """
        :param name: Object name
        :param expression_address: ea_t
        :param origin: which offset had structure at scan moment
        :param applicable: whether to apply type after creating structure
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
        """ Creates suitable instance of ScannedObject depending on obj """
        if obj.id == api.SO_GLOBAL_OBJECT:
            return ScannedGlobalObject(obj.ea, obj.name, expression_address, origin, applicable)
        elif obj.id == api.SO_LOCAL_VARIABLE:
            return ScannedVariableObject(obj.lvar, obj.name, expression_address, origin, applicable)
        elif obj.id in (api.SO_STRUCT_REFERENCE, api.SO_STRUCT_POINTER):
            return ScannedStructureMemberObject(obj.struct_name, obj.offset, expression_address, origin, applicable)
        else:
            raise AssertionError

    def to_list(self):
        """ Creates list that is acceptable to MyChoose2 viewer """
        return [
            "0x{0:04X}".format(self.origin),
            self.function_name,
            self.name,
            helper.to_hex(self.expression_address)
        ]

    def __eq__(self, other):
        return self.func_ea == other.func_ea and self.name == other.name and \
               self.expression_address == other.expression_address

    def __hash__(self):
        return hash((self.func_ea, self.name, self.expression_address))

    def __repr__(self):
        return "{} : {}".format(self.name, helper.to_hex(self.expression_address))


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
        self.__lvar = idaapi.lvar_locator_t(lvar.location, lvar.defea)

    def apply_type(self, tinfo):
        if not self._applicable:
            return

        hx_view = idaapi.open_pseudocode(self.func_ea, -1)
        if hx_view:
            logger.debug("Applying tinfo to variable {0} in function {1}".format(self.name, self.function_name))
            # Finding lvar of new window that have the same name that saved one and applying tinfo_t
            lvar = filter(lambda x: x == self.__lvar, hx_view.cfunc.get_lvars())
            if lvar:
                logger.debug("Successful")
                hx_view.set_lvar_type(lvar[0], tinfo)
            else:
                logger.warn("Failed to find previously scanned local variable {} from {}".format(
                    self.name, helper.to_hex(self.expression_address)))


class ScannedStructureMemberObject(ScannedObject):
    def __init__(self, struct_name, struct_offset, name, expression_address, origin, applicable=True):
        super(ScannedStructureMemberObject, self).__init__(name, expression_address, origin, applicable)
        self.__struct_name = struct_name
        self.__struct_offset = struct_offset

    def apply_type(self, tinfo):
        if self._applicable:
            logger.warn("Changing type of structure field is not yet implemented. Address - {}".format(
                helper.to_hex(self.expression_address)))


class SearchVisitor(api.ObjectVisitor):
    def __init__(self, cfunc, origin, obj, temporary_structure):
        super(SearchVisitor, self).__init__(cfunc, obj, None, True)
        self.__origin = origin
        self.__temporary_structure = temporary_structure

    def _manipulate(self, cexpr, obj):
        super(SearchVisitor, self)._manipulate(cexpr, obj)

        if obj.tinfo and not helper.is_legal_type(obj.tinfo):
            logger.warn("Variable obj.name has weird type at {}".format(helper.to_hex(self._find_asm_address(cexpr))))
            return
        if cexpr.type.is_ptr():
            member = self.__extract_member_from_pointer(cexpr, obj)
        else:
            member = self.__extract_member_from_xword(cexpr, obj)
        if member:
            logger.debug("\tCreating member with type {}, {}, offset - {}".format(
                member.type_name, member.scanned_variables, member.offset))
            self.__temporary_structure.add_row(member)

    def _get_member(self, offset, cexpr, obj, tinfo=None, obj_ea=None):
        if offset < 0:
            logger.error("Considered to be imposible: offset - {}, obj - {}".format(
                offset, helper.to_hex(self._find_asm_address(cexpr))))
            raise AssertionError

        applicable = not self.crippled
        cexpr_ea = self._find_asm_address(cexpr)
        scan_obj = ScannedObject.create(obj, cexpr_ea, self.__origin, applicable)
        if obj_ea:
            if temporary_structure.VirtualTable.check_address(obj_ea):
                return temporary_structure.VirtualTable(offset, obj_ea, scan_obj, self.__origin)
            if helper.is_code_ea(obj_ea):
                cfunc = helper.decompile_function(obj_ea)
                if cfunc:
                    tinfo = cfunc.type
                    tinfo.create_ptr(tinfo)
                else:
                    tinfo = const.DUMMY_FUNC
                return temporary_structure.Member(offset, tinfo, scan_obj, self.__origin)
            # logger.warn("Want to see this ea - {},".format(Helper.to_hex(cexpr_ea)))

        if not tinfo or tinfo.equals_to(const.VOID_TINFO) or tinfo.equals_to(const.CONST_VOID_TINFO):
            return temporary_structure.VoidMember(offset, scan_obj, self.__origin)

        if tinfo.equals_to(const.CHAR_TINFO):
            return temporary_structure.VoidMember(offset, scan_obj, self.__origin, char=True)

        if tinfo.equals_to(const.CONST_PCHAR_TINFO):
            tinfo = const.PCHAR_TINFO
        elif tinfo.equals_to(const.CONST_PVOID_TINFO):
            tinfo = const.PVOID_TINFO
        else:
            tinfo.clr_const()
        return temporary_structure.Member(offset, tinfo, scan_obj, self.__origin)

    def _parse_call(self, call_cexpr, arg_cexpr, offset):
        _, tinfo = helper.get_func_argument_info(call_cexpr, arg_cexpr)
        if tinfo:
            return self.__deref_tinfo(tinfo)
        # TODO: Find example with UTF-16 strings
        return const.CHAR_TINFO

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
                return
            offset = parents[0].y.numval() * cexpr.type.get_ptrarr_objsize()
            cexpr = self.parent_expr()
            if parents_type[0] == 'add':
                del parents_type[0]
                del parents[0]
        elif parents_type[0:2] == ['cast', 'add']:
            # (TYPE *)obj + offset or (TYPE)obj + offset
            if parents[1].y.op != idaapi.cot_num:
                return
            if parents[0].type.is_ptr():
                size = parents[0].type.get_ptrarr_objsize()
            else:
                size = 1
            offset = parents[1].theother(parents[0]).numval() * size
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
            default_tinfo = const.PX_WORD_TINFO

        if parents_type[0] in ('idx', 'ptr'):
            if parents_type[1] == 'cast':
                default_tinfo = parents[1].type
                cexpr = parents[0]
                del parents_type[0]
                del parents[0]
            else:
                default_tinfo = self.__deref_tinfo(default_tinfo)

            if parents_type[1] == 'asg':
                if parents[1].x == parents[0]:
                    # *(TYPE *)(var + x) = ???
                    obj_ea = self.__extract_obj_ea(parents[1].y)
                    return self._get_member(offset, cexpr, obj, parents[1].y.type, obj_ea)
                return self._get_member(offset, cexpr, obj, parents[1].x.type)
            elif parents_type[1] == 'call':
                if parents[1].x == parents[0]:
                    # ((type (__some_call *)(..., ..., ...)var[idx])(..., ..., ...)
                    # ((type (__some_call *)(..., ..., ...)*(TYPE *)(var + x))(..., ..., ...)
                    return self._get_member(offset, cexpr, obj, parents[0].type)
                _, tinfo = helper.get_func_argument_info(parents[1], parents[0])
                if tinfo is None:
                    tinfo = const.PCHAR_TINFO
                return self._get_member(offset, cexpr, obj, tinfo)
            return self._get_member(offset, cexpr, obj, default_tinfo)

        elif parents_type[0] == 'call':
            # call(..., (TYPE)(var + x), ...)
            tinfo = self._parse_call(parents[0], cexpr, offset)
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
                if tinfo.equals_to(const.PCHAR_TINFO) or tinfo.equals_to(const.CONST_PCHAR_TINFO):
                    return const.CHAR_TINFO
                return None         # Turns into VoidMember
            return tinfo.get_pointed_object()
        return tinfo


class NewShallowSearchVisitor(SearchVisitor, api.ObjectDownwardsVisitor):
    def __init__(self, cfunc, origin, obj, temporary_structure):
        super(NewShallowSearchVisitor, self).__init__(cfunc, origin, obj, temporary_structure)


class NewDeepSearchVisitor(SearchVisitor, api.RecursiveObjectDownwardsVisitor):
    def __init__(self, cfunc, origin, obj, temporary_structure):
        super(NewDeepSearchVisitor, self).__init__(cfunc, origin, obj, temporary_structure)


class DeepReturnVisitor(NewDeepSearchVisitor):
    def __init__(self, cfunc, origin, obj, temporary_structure):
        super(DeepReturnVisitor, self).__init__(cfunc, origin, obj, temporary_structure)
        self.__callers_ea = helper.get_funcs_calling_address(cfunc.entry_ea)
        self.__call_obj = obj

    def _start(self):
        for ea in self.__callers_ea:
            self._add_scan_tree_info(ea, -1)
        assert self.__prepare_scanner()

    def _finish(self):
        if self.__prepare_scanner():
            self._recursive_process()

    def __prepare_scanner(self):
        try:
            cfunc = self.__iter_callers().next()
        except StopIteration:
            return False

        self.prepare_new_scan(cfunc, -1, self.__call_obj)
        return True

    def __iter_callers(self):
        for ea in self.__callers_ea:
            cfunc = helper.decompile_function(ea)
            if cfunc:
                yield cfunc
