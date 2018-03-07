import logging
import idaapi
import idc
from Core.Helper import to_hex, get_member_name, get_func_argument_info, get_funcs_calling_address

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
        self.tinfo = None
        self.depth = 0
        self.block_ea = idaapi.BADADDR
        self.id = 0

    @staticmethod
    def create(cfunc, arg):
        # Creates object suitable for scaning either from cexpr_t or ctree_item_t
        if isinstance(arg, idaapi.ctree_item_t):
            lvar = arg.get_lvar()
            if lvar:
                index = list(cfunc.get_lvars()).index(lvar)
                result = VariableObject(index)
                if arg.e:
                    result.ea = ScanObject.get_expression_address(cfunc, arg.e)
                result.name = lvar.name
                result.tinfo = lvar.type()
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
        result.type = cexpr.type
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

    def __hash__(self):
        return hash((self.id, self.name))

    def __eq__(self, other):
        return self.id == other.id and self.name == other.name

    def __repr__(self):
        return self.name

SO_LOCAL_VARIABLE = 1       # cexpr.op == idaapi.cot_var
SO_STRUCT_POINTER = 2       # cexpr.op == idaapi.cot_memptr
SO_STRUCT_REFERENCE = 3     # cexpr.op == idaapi.cot_memref
SO_GLOBAL_OBJECT = 4        # cexpr.op == idaapi.cot_obj
SO_CALL_ARGUMENT = 5        # cexpr.op == idaapi.cot_call
SO_MEMORY_ALLOCATOR = 6


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
        return cexpr.op == idaapi.cot_memref and cexpr.m == self.__offset and cexpr.x.type.dstr() == self.__struct_name


class GlobalVariableObject(ScanObject):
    # Represents global object
    def __init__(self, object_address):
        super(GlobalVariableObject, self).__init__()
        self.__obj_ea = object_address
        self.id = SO_GLOBAL_OBJECT

    def is_target(self, cexpr):
        return cexpr.op == idaapi.cot_obj and self.__obj_ea == cexpr.obj_ea


class CallArgObject(ScanObject):
    # Represents call of function and specified argument
    def __init__(self, func_address, arg_idx):
        super(CallArgObject, self).__init__()
        self.__func_ea = func_address
        self.__arg_idx = arg_idx
        self.name = idaapi.get_short_name(func_address)
        self.id = SO_CALL_ARGUMENT

    def is_target(self, cexpr):
        return cexpr.op == idaapi.cot_call and cexpr.x.obj_ea == self.__func_ea

    def create_arg_obj(self, cfunc, cexpr):
        e = cexpr.a[self.__arg_idx]
        while e.op in (idaapi.cot_cast, idaapi.cot_ref, idaapi.cot_add, idaapi.cot_sub, idaapi.cot_idx):
            e = e.x
        return ScanObject.create(cfunc, e)


class MemoryAllocationObject(ScanObject):
    # Represents `operator new()' or `malloc'
    def __init__(self, name, size):
        super(MemoryAllocationObject, self).__init__()
        self.name = name
        self.size = size
        self.id = SO_MEMORY_ALLOCATOR

    @staticmethod
    def create(cfunc, cexpr):
        if cexpr.op == idaapi.cot_call:
            e = cexpr
        elif cexpr.op == idaapi.cot_cast and cexpr.x.op == idaapi.cot_call:
            e = cexpr.x
        else:
            return

        func_name = idaapi.get_short_name(e.x.obj_ea)
        if "malloc" in func_name or "operator new" in func_name:
            carg = e.a[0]
            if carg.op == idaapi.cot_num:
                size = carg.numval()
            else:
                size = 0
            result = MemoryAllocationObject(func_name, size)
            result.ea = ScanObject.get_expression_address(cfunc, e)
            return result


ASSIGNMENT_RIGHT = 1
ASSIGNMENT_LEFT = 2


class ObjectVisitor(idaapi.ctree_parentee_t):
    def __init__(self, cfunc, obj, data, skip_until_object):
        super(ObjectVisitor, self).__init__()
        self._cfunc = cfunc
        self._objects = [obj]
        self._init_obj = obj
        self._data = data
        self._start_ea = obj.ea
        self._skip = skip_until_object if self._start_ea != idaapi.BADADDR else False

    def process(self):
        self.apply_to(self._cfunc.body, None)

    def set_callbacks(self, manipulate=None):
        if manipulate:
            self.__manipulate = manipulate.__get__(self, ObjectDownwardsVisitor)

    def check_assignment(self, cexpr):
        size = self.parents.size()
        parent = self.parents.at(size - 1)
        if parent.op == idaapi.cot_asg:
            if parent.cexpr.y == cexpr:
                return ASSIGNMENT_RIGHT
            return ASSIGNMENT_LEFT
        elif parent.op == idaapi.cot_cast and self.parents.at(size - 2).op == idaapi.cot_asg:
            return ASSIGNMENT_RIGHT

    def extract_left_expression(self):
        size = self.parents.size()
        if self.parents.at(size - 1).op == idaapi.cot_asg:
            return self.parents.at(size - 1).cexpr.x
        return self.parents.at(size - 2).cexpr.x

    def extract_right_expression(self):
        parent = self.parent_expr()
        assert parent.op == idaapi.cot_asg
        if parent.x.op == idaapi.cot_cast:
            return parent.x.y
        return parent.y

    def _is_initial_object(self, cexpr):
        return self._init_obj.is_target(cexpr) and self._find_asm_address(cexpr) == self._start_ea

    def _get_line(self):
        for p in reversed(self.parents):
            if not p.is_expr():
                return idaapi.tag_remove(p.print1(self._cfunc.__ref__()))
        AssertionError("Parent instruction is not found")

    def _manipulate(self, cexpr, obj):
        self.__manipulate(cexpr, obj)

    def __manipulate(self, cexpr, obj):
        """
        Method called for every object having assignment relationship with starter object. This method should be
        reimplemented in order to do something useful

        :param cexpr: idaapi_cexpr_t
        :param id: one of the SO_* constants
        :return: None
        """
        logger.info("Expression {} at {} Id - {}".format(cexpr.opname, to_hex(self._find_asm_address(cexpr)), obj_id))


class ObjectDownwardsVisitor(ObjectVisitor):
    def __init__(self, cfunc, obj, data=None, skip_until_object=False):
        super(ObjectDownwardsVisitor, self).__init__(cfunc, obj, data, skip_until_object)

    def visit_expr(self, cexpr):
        if self._skip:
            if self._is_initial_object(cexpr):
                self._skip = False
            else:
                return 0

        for obj in self._objects:
            if not obj.is_target(cexpr):
                continue
            code = self.check_assignment(cexpr)
            if code == ASSIGNMENT_RIGHT:
                e = self.extract_left_expression()
                new_obj = ScanObject.create(self._cfunc, e)
                if new_obj:
                    self._objects.append(new_obj)
                    self._manipulate(e, new_obj)
            elif code == ASSIGNMENT_LEFT:
                if self._is_object_overwritten(obj, cexpr):
                    logger.info("Removed object from scanning at {}".format(to_hex(self._find_asm_address(cexpr))))
                    self._objects.remove(obj)
                    return 0
            self._manipulate(cexpr, obj)
            return 0
        return 0

    def _is_object_overwritten(self, obj, cexpr):
        size = self.parents.size()
        if size < obj.depth:
            return True
        elif size == obj.depth:
            if obj.ea != self._find_asm_address(cexpr):
                return ScanObject.get_expression_block_ea(self._cfunc, cexpr) == obj.block_ea
        return False


class ObjectUpwardsVisitor(ObjectVisitor):
    STAGE_PREPARE = 1
    STAGE_PARSING = 2

    def __init__(self, cfunc, obj, data=None, skip_after_object=False):
        super(ObjectUpwardsVisitor, self).__init__(cfunc, obj, data, skip_after_object)
        self._stage = self.STAGE_PREPARE
        self._tree = {}
        self._call_obj = obj if obj.id == SO_CALL_ARGUMENT else None

    def visit_expr(self, cexpr):
        if self._stage == self.STAGE_PARSING:
            return 0

        if self._call_obj and self._call_obj.is_target(cexpr):
            obj = self._call_obj.create_arg_obj(self._cfunc, cexpr)
            if obj:
                self._objects.append(obj)

        obj = ScanObject.create(self._cfunc, cexpr)
        if obj:
            code = self.check_assignment(cexpr)
            if code == ASSIGNMENT_LEFT:
                left_obj = obj
                right_cexpr = self.extract_right_expression()
                right_obj = ScanObject.create(self._cfunc, right_cexpr)
                if right_obj:
                    self.__add_object_assignment(left_obj, right_obj)

        if self._skip and self._is_initial_object(cexpr):
            return 1
        return 0

    def leave_expr(self, cexpr):
        if self._stage == self.STAGE_PREPARE:
            return 0

        if self._skip and self._is_initial_object(cexpr):
            self._manipulate(cexpr, self._init_obj)
            return 1

        for obj in self._objects:
            if obj.is_target(cexpr):
                self._manipulate(cexpr, obj)
                return 0
        return 0

    def process(self):
        self._stage = self.STAGE_PREPARE
        self.cv_flags &= ~idaapi.CV_POST
        super(ObjectUpwardsVisitor, self).process()
        self._stage = self.STAGE_PARSING
        self.cv_flags |= idaapi.CV_POST
        self.__prepare()
        super(ObjectUpwardsVisitor, self).process()

    def __add_object_assignment(self, from_obj, to_obj):
        if from_obj in self._tree:
            self._tree[from_obj].add(to_obj)
        else:
            self._tree[from_obj] = {to_obj}

    def __prepare(self):
        result = set()
        todo = set(self._objects)
        while todo:
            obj = todo.pop()
            result.add(obj)
            if obj.id == SO_CALL_ARGUMENT or obj not in self._tree:
                continue
            o = self._tree[obj]
            todo |= o - result
            result |= o
        self._objects = list(result)


class RecursiveObjectVisitor(ObjectVisitor):
    def __init__(self, cfunc, obj, data=None, skip_until_object=False, visited=None):
        super(RecursiveObjectVisitor, self).__init__(cfunc, obj, data, skip_until_object)
        self._visited = visited if visited else set()
        self._new_for_visit = set()
        self.crippled = self.__is_func_crippled()

    def visit_expr(self, cexpr):
        return super(RecursiveObjectVisitor, self).visit_expr(cexpr)

    def set_callbacks(self, manipulate=None, start=None, start_iteration=None, finish=None, finish_iteration=None):
        super(RecursiveObjectVisitor, self).set_callbacks(manipulate)
        if start:
            self.__start = start.__get__(self, RecursiveObjectDownwardsVisitor)
        if start_iteration:
            self.__start_iteration = start_iteration.__get__(self, RecursiveObjectDownwardsVisitor)
        if finish:
            self.__finish = finish.__get__(self, RecursiveObjectDownwardsVisitor)
        if finish_iteration:
            self.__finish_iteration = finish_iteration.__get__(self, RecursiveObjectDownwardsVisitor)

    def prepare_new_scan(self, cfunc, obj, skip=False):
        self._cfunc = cfunc
        self._objects = [obj]
        self._init_obj = obj
        self._skip = False
        self.crippled = self.__is_func_crippled()

    def process(self):
        self.__start()
        self._recursive_process()
        self.__finish()

    def _recursive_process(self):
        self.__start_iteration()
        super(RecursiveObjectVisitor, self).process()
        self.__finish_iteration()

    def _manipulate(self, cexpr, obj):
        self._check_call(cexpr)
        super(RecursiveObjectVisitor, self)._manipulate(cexpr, obj)

    def _check_call(self, cexpr):
        raise NotImplemented

    def _add_visit(self, func_ea, arg_idx):
        if (func_ea, arg_idx) not in self._visited:
            self._visited.add((func_ea, arg_idx))
            self._new_for_visit.add((func_ea, arg_idx))

    def __start(self):
        """ Called at the beginning of visiting """
        pass

    def __start_iteration(self):
        """ Called every time new function visiting started """
        pass

    def __finish(self):
        """ Called after all visiting happened """
        pass

    def __finish_iteration(self):
        """ Called every time new function visiting finished """
        pass

    def __is_func_crippled(self):
        # Check if function is just call to another function
        b = self._cfunc.body.cblock
        if b.size() == 1:
            e = b.at(0)
            return e.op == idaapi.cit_return or (e.op == idaapi.cit_expr and e.cexpr.op == idaapi.cot_call)
        return False


class RecursiveObjectDownwardsVisitor(RecursiveObjectVisitor, ObjectDownwardsVisitor):
    def __init__(self, cfunc, obj, data=None, skip_until_object=False, visited=None):
        super(RecursiveObjectDownwardsVisitor, self).__init__(cfunc, obj, data, skip_until_object, visited)

    def _check_call(self, cexpr):
        parent = self.parent_expr()
        grandparent = self.parents.at(self.parents.size() - 2)
        if parent.op == idaapi.cot_call:
            call_cexpr = parent
            idx, _ = get_func_argument_info(call_cexpr, cexpr)
            self._add_visit(call_cexpr.x.obj_ea, idx)
        elif parent.op == idaapi.cot_cast and grandparent.op == idaapi.cot_call:
            call_cexpr = grandparent.cexpr
            idx, _ = get_func_argument_info(call_cexpr, parent)
            self._add_visit(call_cexpr.x.obj_ea, idx)

    def _recursive_process(self):
        super(RecursiveObjectVisitor, self).process()

        while self._new_for_visit:
            func_ea, arg_idx = self._new_for_visit.pop()
            cfunc = decompile_function(func_ea)
            if cfunc:
                obj = VariableObject(arg_idx)
                self.prepare_new_scan(cfunc, obj)
                self._recursive_process()


class RecursiveObjectUpwardsVisitor(RecursiveObjectVisitor, ObjectUpwardsVisitor):
    def __init__(self, cfunc, obj, data=None, skip_after_object=False, visited=None):
        super(RecursiveObjectUpwardsVisitor, self).__init__(cfunc, obj, data, skip_after_object, visited)

    def prepare_new_scan(self, cfunc, obj, skip=False):
        super(RecursiveObjectUpwardsVisitor, self).prepare_new_scan(cfunc, obj, skip)
        self._call_obj = obj if obj.id == SO_CALL_ARGUMENT else None

    def _check_call(self, cexpr):
        if cexpr.op == idaapi.cot_var and self._cfunc.get_lvars()[cexpr.v.idx].is_arg_var:
            self._add_visit(self._cfunc.entry_ea, cexpr.v.idx)

    def _recursive_process(self):
        super(RecursiveObjectUpwardsVisitor, self)._recursive_process()

        while self._new_for_visit:
            func_ea, arg_idx = self._new_for_visit.pop()
            funcs = get_funcs_calling_address(func_ea)
            obj = CallArgObject(func_ea, arg_idx)
            for callee_ea in funcs:
                cfunc = decompile_function(callee_ea)
                if cfunc:
                    self.prepare_new_scan(cfunc, obj, False)
                    self._recursive_process()
