import logging
import idaapi
import idc
from Core.Helper import to_hex, get_member_name, get_func_argument_info

logger = logging.getLogger(__name__)


SETTING_START_FROM_CURRENT_EXPR = True


def decompile_function(address):
    try:
        cfunc = idaapi.decompile(address)
        if cfunc:
            return cfunc
    except idaapi.DecompilationFailure:
        pass
    print logger.warn("IDA failed to decompile function at 0x{address:08X}".format(address=address))


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
        super(ObjectDownwardsVisitor, self).__init__()
        self._cfunc = cfunc
        self._objects = [obj]
        self._data = data
        self.__start_ea = obj.ea
        self._skip = skip_until_object

    def visit_expr(self, cexpr):
        if self._skip:
            if self._objects[0].is_target(cexpr) and self._find_asm_address(cexpr) == self.__start_ea:
                self._skip = False
            return 0

        for obj in self._objects:
            if not obj.is_target(cexpr):
                continue
            code = self._check_assignment(cexpr)
            if code == ASSIGNMENT_RIGHT:
                e = self._extract_left_expression()
                new_obj = ScanObject.create(self._cfunc, e)
                if new_obj:
                    self._objects.append(new_obj)
                    self._manipulate(e, new_obj.id)
            elif code == ASSIGNMENT_LEFT:
                if self._is_object_overwritten(obj, cexpr):
                    logger.info("Removed object from scanning at {}".format(to_hex(self._find_asm_address(cexpr))))
                    self._objects.remove(obj)
                    return 0
            self._manipulate(cexpr, obj.id)
            return 0
        return 0

    def set_callbacks(self, manipulate=None):
        if manipulate:
            self.__manipulate = manipulate.__get__(self, ObjectDownwardsVisitor)

    def process(self):
        self.apply_to(self._cfunc.body, None)

    def _check_assignment(self, cexpr):
        size = self.parents.size()
        parent = self.parents.at(size - 1)
        if parent.op == idaapi.cot_asg:
            if parent.cexpr.y == cexpr:
                return ASSIGNMENT_RIGHT
            return ASSIGNMENT_LEFT
        elif parent.op == idaapi.cot_cast and self.parents.at(size - 2).op == idaapi.cot_asg:
            return ASSIGNMENT_RIGHT

    def _extract_left_expression(self):
        size = self.parents.size()
        if self.parents.at(size - 1).op == idaapi.cot_asg:
            return self.parents.at(size - 1).cexpr.x
        return self.parents.at(size - 2).cexpr.x

    def _extract_right_expression(self):
        parent = self.parent_expr()
        assert parent.op == idaapi.cot_asg
        if parent.x.op == idaapi.cot_cast:
            return parent.x.y
        return parent.y

    def _is_object_overwritten(self, obj, cexpr):
        size = self.parents.size()
        if size < obj.depth:
            return True
        elif size == obj.depth:
            if obj.ea != self._find_asm_address(cexpr):
                return ScanObject.get_expression_block_ea(self._cfunc, cexpr) == obj.block_ea
        return False

    def _manipulate(self, cexpr, obj_id):
        """
        Method called for every object having assignment relationship with starter object. This method should be
        reimplemented in order to do something useful

        :param cexpr: idaapi_cexpr_t
        :param id: one of the SO_* constants
        :return: None
        """
        logger.info("Expression {} at {}. Id - {}".format(cexpr.opname, to_hex(self._find_asm_address(cexpr)), obj_id))

    def _manipulate(self, cexpr, obj_id):
        self.__manipulate(cexpr, obj_id)

    def __get_line(self):
        for p in reversed(self.parents):
            if not p.is_expr():
                return idaapi.tag_remove(p.print1(self._cfunc))
        AssertionError("Parent instruction is not found")


class ObjectUpwardsVisitor(ObjectDownwardsVisitor):
    def __init__(self, cfunc, obj, data=None, skip_until_object=False):
        super(ObjectUpwardsVisitor, self).__init__(cfunc, obj, data, skip_until_object)
        self.cv_flags |= idaapi.CV_POST

    def leave_expr(self, cexpr):
        if self._skip:
            if self._objects[0].is_target(cexpr) and self._find_asm_address(cexpr) == self.__start_ea:
                self._skip = False
            else:
                return 0

        for obj in self._objects:
            if not obj.is_target(cexpr):
                continue
            code = self._check_assignment(cexpr)
            self._manipulate(cexpr, obj.id)
            if code == ASSIGNMENT_LEFT:
                e = self._extract_right_expression()
                self._objects.remove(obj)
                new_obj = ScanObject.create(self._cfunc, e)
                if new_obj:
                    self._objects.append(new_obj)
                    self._manipulate(e, new_obj.id)
                elif len(self._objects) == 0:
                    return 1
            return 0
        return 0


class RecursiveObjectDownwardsVisitor(ObjectDownwardsVisitor):
    def __init__(self, cfunc, obj, data=None, skip_until_object=False, visited=None):
        super(RecursiveObjectDownwardsVisitor, self).__init__(cfunc, obj, data, skip_until_object)
        self.__visited = visited if visited else set()
        self.__new_for_visit = set()
        self.crippled = self.__is_func_crippled()

    def visit_expr(self, cexpr):
        return super(RecursiveObjectDownwardsVisitor, self).visit_expr(cexpr)

    def set_callbacks(self, manipulate=None, start=None, start_iteration=None, finish=None, finish_iteration=None):
        super(RecursiveObjectDownwardsVisitor, self).set_callbacks(manipulate)
        if start:
            self.__start = start.__get__(self, RecursiveObjectDownwardsVisitor)
        if start_iteration:
            self.__start_iteration = start_iteration.__get__(self, RecursiveObjectDownwardsVisitor)
        if finish:
            self.__finish = finish.__get__(self, RecursiveObjectDownwardsVisitor)
        if finish_iteration:
            self.__finish_iteration = finish_iteration.__get__(self, RecursiveObjectDownwardsVisitor)

    def prepare_new_scan(self, cfunc, obj):
        self._cfunc = cfunc
        self._objects = [obj]
        self.__start_ea = obj.ea
        self.crippled = self.__is_func_crippled()

    def process(self):
        self.__start()
        self.__recursive_process()
        self.__finish()

    def __recursive_process(self):
        self.__start_iteration()
        super(RecursiveObjectDownwardsVisitor, self).process()
        self.__finish_iteration()

        while self.__new_for_visit:
            func_ea, arg_idx = self.__new_for_visit.pop()
            cfunc = decompile_function(func_ea)
            if cfunc:
                obj = VariableObject(arg_idx)
                self.prepare_new_scan(cfunc, obj)
                self.process()

    def _manipulate(self, cexpr, obj_id):
        self.__check_call(cexpr)
        super(RecursiveObjectDownwardsVisitor, self)._manipulate(cexpr, obj_id)

    def __check_call(self, cexpr):
        parent = self.parent_expr()
        grandparent = self.parents.at(self.parents.size() - 2)
        if parent.op == idaapi.cot_call:
            call_cexpr = parent
            idx, _ = get_func_argument_info(call_cexpr, cexpr)
            self.__add_visit(call_cexpr.x.obj_ea, idx)
        elif parent.op == idaapi.cot_cast and grandparent.op == idaapi.cot_call:
            call_cexpr = grandparent.cexpr
            idx, _ = get_func_argument_info(call_cexpr, parent)
            self.__add_visit(call_cexpr.x.obj_ea, idx)

    def __add_visit(self, func_ea, arg_idx):
        if (func_ea, arg_idx) not in self.__visited:
            self.__visited.add((func_ea, arg_idx))
            self.__new_for_visit.add((func_ea, arg_idx))

    def __start(self):
        pass

    def __start_iteration(self):
        pass

    def __finish(self):
        pass

    def __finish_iteration(self):
        pass

    def __is_func_crippled(self):
        # Check if function is just call to another function
        b = self._cfunc.body.cblock
        if b.size() == 1:
            e = b.at(0)
            return e.op == idaapi.cit_return or (e.op == idaapi.cit_expr and e.cexpr.op == idaapi.cot_call)
        return False
