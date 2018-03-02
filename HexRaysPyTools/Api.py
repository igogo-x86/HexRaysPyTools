import logging
import idaapi
import idc
from Core.Helper import to_hex, get_member_name

logger = logging.getLogger(__name__)


SETTING_START_FROM_CURRENT_EXPR = True


class ScanObject(object):
    def __init__(self):
        self.ea = idaapi.BADADDR
        self.name = None
        self.depth = 0
        self.block_ea = idaapi.BADADDR

    @staticmethod
    def create(cfunc, arg):
        # Creates object suitable for scaning either from cexpr_t or ctree_item_t
        if isinstance(arg, idaapi.ctree_item_t):
            lvar = arg.get_lvar()
            if lvar:
                index = list(cfunc.get_lvars()).index(lvar)
                result = VariableObject(index)
                result.name = lvar.name
                return result
            cexpr = arg.e
        else:
            cexpr = arg

        if cexpr.op == idaapi.cot_var:
            result = VariableObject(cexpr.v.idx)
            result.name = cfunc.get_lvars()[cexpr.v.idx].name
        elif cexpr.op == idaapi.cot_memptr:
            t = cexpr.x.type.get_pointed_object()
            result = StructPtrObject(t.dstr(), cexpr.m)
            result.name = get_member_name(t, cexpr.m)
        elif cexpr.op == idaapi.cot_memref:
            t = cexpr.x.type
            result = StructRefObject(t.dstr(), cexpr.m)
            result.name = get_member_name(t, cexpr.m)
        elif cexpr.op == idaapi.cot_obj:
            result = GlobalVariableObject(cexpr.obj_ea)
            result.name = idaapi.get_short_name(cexpr.obj_ea)
        else:
            return
        result.ea = ScanObject.get_expression_address(cfunc, cexpr)
        result.depth = ScanObject.get_expression_depth(cfunc, cexpr)
        result.block_ea = ScanObject.get_expression_block_ea(cfunc, cexpr)
        return result

    @staticmethod
    def get_expression_block_ea(cfunc, cexpr):
        expr = cexpr
        while expr and expr.op != idaapi.cit_block:
            expr = cfunc.body.find_parent_of(expr.to_specific_type)
        return expr.ea

    @staticmethod
    def get_expression_depth(cfunc, cexpr):
        expr = cexpr
        idx = 0
        while expr:
            expr = cfunc.body.find_parent_of(expr.to_specific_type)
            idx += 1
        return idx

    @staticmethod
    def get_expression_address(cfunc, cexpr):
        expr = cexpr

        while expr and expr.ea == idaapi.BADADDR:
            expr = expr.to_specific_type
            expr = cfunc.body.find_parent_of(expr)

        assert expr is not None
        return expr.ea

SO_LOCAL_VARIABLE = 1       # cexpr.op == idaapi.cot_var
SO_STRUCT_POINTER = 2       # cexpr.op == idaapi.cot_memptr
SO_STRUCT_REFERENCE = 3     # cexpr.op == idaapi.cot_memref
SO_GLOBAL_OBJECT = 4        # cexpr.op == idaapi.cot_obj


class VariableObject(ScanObject):
    # Represents `var` expression
    def __init__(self, index):
        super(VariableObject, self).__init__()
        self.__index = index
        self.id = SO_LOCAL_VARIABLE

    def is_target(self, cexpr):
        return cexpr.op == idaapi.cot_var and cexpr.v.idx == self.__index


class StructPtrObject(ScanObject):
    # Represents `x->m` expression
    def __init__(self, struct_name, offset):
        super(StructPtrObject, self).__init__()
        self.__struct_name = struct_name
        self.__offset = offset
        self.id = SO_STRUCT_POINTER

    def is_target(self, cexpr):
        return cexpr.op == idaapi.cot_memptr and cexpr.m == self.__offset and \
               cexpr.x.type.get_pointed_object().dstr() == self.__struct_name


class StructRefObject(ScanObject):
    # Represents `x.m` expression
    def __init__(self, struct_name, offset):
        super(StructRefObject, self).__init__()
        self.__struct_name = struct_name
        self.__offset = offset
        self.id = SO_STRUCT_REFERENCE

    def is_target(self, cexpr):
        return cexpr.op == idaapi.cot_memref and cexpr.m == self.__offset and \
               cexpr.x.type.dstr() == self.__struct_name


class GlobalVariableObject(ScanObject):
    # Represents global object
    def __init__(self, object_address):
        super(GlobalVariableObject, self).__init__()
        self.__obj_ea = object_address
        self.id = SO_GLOBAL_OBJECT

    def is_target(self, cexpr):
        return cexpr.op == idaapi.cot_obj and self.__obj_ea == cexpr.obj_ea


ASSIGNMENT_RIGHT = 1
ASSIGNMENT_LEFT = 2


class ObjectDownwardsVisitor(idaapi.ctree_parentee_t):
    def __init__(self, cfunc, obj, data=None, skip_until_object=False):
        self._cfunc = cfunc
        self._objects = [obj]
        self._data = data
        self.__start_ea = obj.ea
        self.__skip = skip_until_object
        super(ObjectDownwardsVisitor, self).__init__()

    def visit_expr(self, cexpr):
        if self.__skip:
            if self._objects[0].is_target(cexpr) and self._find_asm_address(cexpr) == self.__start_ea:
                self.__skip = False
            return 0

        for obj in self._objects:
            if not obj.is_target(cexpr):
                continue
            code = self.__check_assignment(cexpr)
            if code == ASSIGNMENT_RIGHT:
                e = self.__extract_left_expression()
                new_obj = ScanObject.create(self._cfunc, e)
                if new_obj:
                    self._objects.append(new_obj)
                    self.manipulate(e, new_obj.id)
            elif code == ASSIGNMENT_LEFT:
                if self.__is_object_overwritten(obj, cexpr):
                    logger.info("Removed object from scanning at {}".format(to_hex(self._find_asm_address(cexpr))))
                    self._objects.remove(obj)
                    return 0
            self.manipulate(cexpr, obj.id)
        return 0

    def process(self):
        self.apply_to(self._cfunc.body, None)

    def __check_assignment(self, cexpr):
        size = self.parents.size()
        parent = self.parents.at(size - 1)
        if parent.op == idaapi.cot_asg:
            if parent.cexpr.y == cexpr:
                return ASSIGNMENT_RIGHT
            return ASSIGNMENT_LEFT
        elif parent.op == idaapi.cot_cast and self.parents.at(size - 2).op == idaapi.cot_asg:
            return ASSIGNMENT_RIGHT

    def __extract_left_expression(self):
        size = self.parents.size()
        if self.parents.at(size - 1).op == idaapi.cot_asg:
            return self.parents.at(size - 1).cexpr.x
        return self.parents.at(size - 2).cexpr.x

    def __is_object_overwritten(self, obj, cexpr):
        size = self.parents.size()
        if size < obj.depth:
            return True
        elif size == obj.depth:
            if obj.ea != self._find_asm_address(cexpr):
                return ScanObject.get_expression_block_ea(self._cfunc, cexpr) == obj.block_ea
        return False

    def manipulate(self, cexpr, obj_id):
        """
        Method called for every object having assignment relationship with starter object. This method should be
        reimplemented in order to something useful

        :param cexpr: idaapi_cexpr_t
        :param id: one of the SO_* constants
        :return: None
        """
        logger.info("Expression {} at {}".format(cexpr.opname, to_hex(self._find_asm_address(cexpr))))

    def set_manipulator(self, func):
        self.manipulate = func.__get__(self, ObjectDownwardsVisitor)

    def __get_line(self):
        for p in reversed(self.parents):
            if not p.is_expr():
                return idaapi.tag_remove(p.print1(self._cfunc))
        AssertionError("Parent instruction is not found")
