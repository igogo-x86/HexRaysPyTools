import logging
import idaapi
import idc
from core.helper import to_hex
import core.helper as helper

logger = logging.getLogger(__name__)


SETTING_START_FROM_CURRENT_EXPR = True


class ScanObject(object):
    def __init__(self):
        self.ea = idaapi.BADADDR
        self.name = None
        self.tinfo = None
        self.id = 0

    @staticmethod
    def create(cfunc, arg):
        # Creates object suitable for scaning either from cexpr_t or ctree_item_t
        if isinstance(arg, idaapi.ctree_item_t):
            lvar = arg.get_lvar()
            if lvar:
                index = list(cfunc.get_lvars()).index(lvar)
                result = VariableObject(lvar, index)
                if arg.e:
                    result.ea = ScanObject.get_expression_address(cfunc, arg.e)
                return result
            cexpr = arg.e
        else:
            cexpr = arg

        if cexpr.op == idaapi.cot_var:
            lvar = cfunc.get_lvars()[cexpr.v.idx]
            result = VariableObject(lvar, cexpr.v.idx)
            result.ea = ScanObject.get_expression_address(cfunc, cexpr)
            return result
        elif cexpr.op == idaapi.cot_memptr:
            t = cexpr.x.type.get_pointed_object()
            result = StructPtrObject(t.dstr(), cexpr.m)
            result.name = helper.get_member_name(t, cexpr.m)
        elif cexpr.op == idaapi.cot_memref:
            t = cexpr.x.type
            result = StructRefObject(t.dstr(), cexpr.m)
            result.name = helper.get_member_name(t, cexpr.m)
        elif cexpr.op == idaapi.cot_obj:
            result = GlobalVariableObject(cexpr.obj_ea)
            result.name = idaapi.get_short_name(cexpr.obj_ea)
        else:
            return
        result.tinfo = cexpr.type
        result.ea = ScanObject.get_expression_address(cfunc, cexpr)
        return result

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
SO_RETURNED_OBJECT = 7


class VariableObject(ScanObject):
    # Represents `var` expression
    def __init__(self, lvar, index):
        super(VariableObject, self).__init__()
        self.lvar = lvar
        self.tinfo = lvar.type()
        self.name = lvar.name
        self.index = index
        self.id = SO_LOCAL_VARIABLE

    def is_target(self, cexpr):
        return cexpr.op == idaapi.cot_var and cexpr.v.idx == self.index


class StructPtrObject(ScanObject):
    # Represents `x->m` expression
    def __init__(self, struct_name, offset):
        super(StructPtrObject, self).__init__()
        self.struct_name = struct_name
        self.offset = offset
        self.id = SO_STRUCT_POINTER

    def is_target(self, cexpr):
        return cexpr.op == idaapi.cot_memptr and cexpr.m == self.offset and \
               cexpr.x.type.get_pointed_object().dstr() == self.struct_name


class StructRefObject(ScanObject):
    # Represents `x.m` expression
    def __init__(self, struct_name, offset):
        super(StructRefObject, self).__init__()
        self.struct_name = struct_name
        self.offset = offset
        self.id = SO_STRUCT_REFERENCE

    def is_target(self, cexpr):
        return cexpr.op == idaapi.cot_memref and cexpr.m == self.offset and cexpr.x.type.dstr() == self.struct_name


class GlobalVariableObject(ScanObject):
    # Represents global object
    def __init__(self, object_address):
        super(GlobalVariableObject, self).__init__()
        self.obj_ea = object_address
        self.id = SO_GLOBAL_OBJECT

    def is_target(self, cexpr):
        return cexpr.op == idaapi.cot_obj and self.obj_ea == cexpr.obj_ea


class CallArgObject(ScanObject):
    # Represents call of a function and argument index
    def __init__(self, func_address, arg_idx):
        super(CallArgObject, self).__init__()
        self.func_ea = func_address
        self.arg_idx = arg_idx
        self.id = SO_CALL_ARGUMENT

    def is_target(self, cexpr):
        return cexpr.op == idaapi.cot_call and cexpr.x.obj_ea == self.func_ea

    def create_scan_obj(self, cfunc, cexpr):
        e = cexpr.a[self.arg_idx]
        while e.op in (idaapi.cot_cast, idaapi.cot_ref, idaapi.cot_add, idaapi.cot_sub, idaapi.cot_idx):
            e = e.x
        return ScanObject.create(cfunc, e)

    @staticmethod
    def create(cfunc, arg_idx):
        result = CallArgObject(cfunc.entry_ea, arg_idx)
        result.name = cfunc.get_lvars()[arg_idx].name
        result.tinfo = cfunc.type
        return result

    def __repr__(self):
        return "{}"


class ReturnedObject(ScanObject):
    # Represents value returned by function
    def __init__(self, func_address):
        super(ReturnedObject, self).__init__()
        self.__func_ea = func_address
        self.id = SO_RETURNED_OBJECT

    def is_target(self, cexpr):
        return cexpr.op == idaapi.cot_call and cexpr.x.obj_ea == self.__func_ea


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
        self.crippled = False

    def process(self):
        self.apply_to(self._cfunc.body, None)

    def set_callbacks(self, manipulate=None):
        if manipulate:
            self.__manipulate = manipulate.__get__(self, ObjectDownwardsVisitor)

    def _get_line(self):
        for p in reversed(self.parents):
            if not p.is_expr():
                return idaapi.tag_remove(p.print1(self._cfunc.__ref__()))
        AssertionError("Parent instruction is not found")

    def _manipulate(self, cexpr, obj):
        """
        Method called for every object having assignment relationship with starter object. This method should be
        reimplemented in order to do something useful

        :param cexpr: idaapi_cexpr_t
        :param id: one of the SO_* constants
        :return: None
        """
        self.__manipulate(cexpr, obj)

    def __manipulate(self, cexpr, obj):
        logger.debug("Expression {} at {} Id - {}".format(cexpr.opname, to_hex(self._find_asm_address(cexpr)), obj.id))


class ObjectDownwardsVisitor(ObjectVisitor):
    def __init__(self, cfunc, obj, data=None, skip_until_object=False):
        super(ObjectDownwardsVisitor, self).__init__(cfunc, obj, data, skip_until_object)
        self.cv_flags |= idaapi.CV_POST

    def visit_expr(self, cexpr):
        if self._skip:
            if self._is_initial_object(cexpr):
                self._skip = False
            else:
                return 0

        if cexpr.op != idaapi.cot_asg:
            return 0

        x_cexpr = cexpr.x
        if cexpr.y.op == idaapi.cot_cast:
            y_cexpr = cexpr.y.x
        else:
            y_cexpr = cexpr.y

        for obj in self._objects:
            if obj.is_target(x_cexpr):
                if self.__is_object_overwritten(x_cexpr, obj, y_cexpr):
                    logger.info("Removed object {} from scanning at {}".format(
                        obj, to_hex(self._find_asm_address(x_cexpr))))
                    self._objects.remove(obj)
                return 0
            elif obj.is_target(y_cexpr):
                new_obj = ScanObject.create(self._cfunc, x_cexpr)
                if new_obj:
                    self._objects.append(new_obj)
                return 0
        return 0

    def leave_expr(self, cexpr):
        if self._skip:
            return 0

        for obj in self._objects:
            if obj.is_target(cexpr) and obj.id != SO_RETURNED_OBJECT:
                self._manipulate(cexpr, obj)
                return 0
        return 0

    def _is_initial_object(self, cexpr):
        if cexpr.op == idaapi.cot_asg:
            cexpr = cexpr.y
            if cexpr.op == idaapi.cot_cast:
                cexpr = cexpr.x
        return self._init_obj.is_target(cexpr) and self._find_asm_address(cexpr) == self._start_ea

    def __is_object_overwritten(self, x_cexpr, obj, y_cexpr):
        if len(self._objects) < 2:
            return False

        if y_cexpr.op == idaapi.cot_cast:
            e = y_cexpr.x
        else:
            e = y_cexpr

        if e.op != idaapi.cot_call or len(e.a) == 0:
            return True

        for obj in self._objects:
            if obj.is_target(e. a[0]):
                return False
        return True


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
            obj = self._call_obj.create_scan_obj(self._cfunc, cexpr)
            if obj:
                self._objects.append(obj)
            return 0

        if cexpr.op != idaapi.cot_asg:
            return 0

        x_cexpr = cexpr.x
        if cexpr.y.op == idaapi.cot_cast:
            y_cexpr = cexpr.y.x
        else:
            y_cexpr = cexpr.y

        obj_left = ScanObject.create(self._cfunc, x_cexpr)
        obj_right = ScanObject.create(self._cfunc, y_cexpr)
        if obj_left and obj_right:
            self.__add_object_assignment(obj_left, obj_right)

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

    def _is_initial_object(self, cexpr):
        return self._init_obj.is_target(cexpr) and self._find_asm_address(cexpr) == self._start_ea

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
        self._tree.clear()


class RecursiveObjectVisitor(ObjectVisitor):
    def __init__(self, cfunc, obj, data=None, skip_until_object=False, visited=None):
        super(RecursiveObjectVisitor, self).__init__(cfunc, obj, data, skip_until_object)
        self._visited = visited if visited else set()
        self._new_for_visit = set()
        self.crippled = False
        self._arg_idx = -1
        self._debug_scan_tree = {}
        self.__debug_scan_tree_root = idc.Name(self._cfunc.entry_ea)
        self.__debug_message = []

    def visit_expr(self, cexpr):
        return super(RecursiveObjectVisitor, self).visit_expr(cexpr)

    def set_callbacks(self, manipulate=None, start=None, start_iteration=None, finish=None, finish_iteration=None):
        super(RecursiveObjectVisitor, self).set_callbacks(manipulate)
        if start:
            self._start = start.__get__(self, RecursiveObjectDownwardsVisitor)
        if start_iteration:
            self._start_iteration = start_iteration.__get__(self, RecursiveObjectDownwardsVisitor)
        if finish:
            self._finish = finish.__get__(self, RecursiveObjectDownwardsVisitor)
        if finish_iteration:
            self._finish_iteration = finish_iteration.__get__(self, RecursiveObjectDownwardsVisitor)

    def prepare_new_scan(self, cfunc, arg_idx, obj, skip=False):
        self._cfunc = cfunc
        self._arg_idx = arg_idx
        self._objects = [obj]
        self._init_obj = obj
        self._skip = False
        self.crippled = self.__is_func_crippled()

    def process(self):
        self._start()
        self._recursive_process()
        self._finish()
        self.dump_scan_tree()

    def dump_scan_tree(self):
        self.__prepare_debug_message()
        logger.info("{}\n---------------".format("\n".join(self.__debug_message)))

    def __prepare_debug_message(self, key=None, level=1):
        if key is None:
            key = (self.__debug_scan_tree_root, -1)
            self.__debug_message.append("--- Scan Tree---\n{}".format(self.__debug_scan_tree_root))
        if key in self._debug_scan_tree:
            for func_name, arg_idx in self._debug_scan_tree[key]:
                prefix = " | " * (level - 1) + " |_ "
                self.__debug_message.append("{}{} (idx: {})".format(prefix, func_name, arg_idx))
                self.__prepare_debug_message((func_name, arg_idx), level + 1)

    def _recursive_process(self):
        self._start_iteration()
        super(RecursiveObjectVisitor, self).process()
        self._finish_iteration()

    def _manipulate(self, cexpr, obj):
        self._check_call(cexpr)
        super(RecursiveObjectVisitor, self)._manipulate(cexpr, obj)

    def _check_call(self, cexpr):
        raise NotImplemented

    def _add_visit(self, func_ea, arg_idx):
        if (func_ea, arg_idx) not in self._visited:
            self._visited.add((func_ea, arg_idx))
            self._new_for_visit.add((func_ea, arg_idx))
            return True
        return False

    def _add_scan_tree_info(self, func_ea, arg_idx):
        head_node = (idc.Name(self._cfunc.entry_ea), self._arg_idx)
        tail_node = (idc.Name(func_ea), arg_idx)
        if head_node in self._debug_scan_tree:
            self._debug_scan_tree[head_node].add(tail_node)
        else:
            self._debug_scan_tree[head_node] = {tail_node}

    def _start(self):
        """ Called at the beginning of visiting """
        pass

    def _start_iteration(self):
        """ Called every time new function visiting started """
        pass

    def _finish(self):
        """ Called after all visiting happened """
        pass

    def _finish_iteration(self):
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
            arg_cexpr = cexpr
        elif parent.op == idaapi.cot_cast and grandparent.op == idaapi.cot_call:
            call_cexpr = grandparent.cexpr
            arg_cexpr = parent
        else:
            return
        idx, _ = helper.get_func_argument_info(call_cexpr, arg_cexpr)
        func_ea = call_cexpr.x.obj_ea
        if func_ea == idaapi.BADADDR:
            return
        if self._add_visit(func_ea, idx):
            self._add_scan_tree_info(func_ea, idx)

    def _recursive_process(self):
        super(RecursiveObjectDownwardsVisitor, self)._recursive_process()

        while self._new_for_visit:
            func_ea, arg_idx = self._new_for_visit.pop()
            if helper.is_imported_ea(func_ea):
                continue
            cfunc = helper.decompile_function(func_ea)
            if cfunc:
                assert arg_idx < len(cfunc.get_lvars()), "Wrong argument at func {}".format(to_hex(func_ea))
                obj = VariableObject(cfunc.get_lvars()[arg_idx], arg_idx)
                self.prepare_new_scan(cfunc, arg_idx, obj)
                self._recursive_process()


class RecursiveObjectUpwardsVisitor(RecursiveObjectVisitor, ObjectUpwardsVisitor):
    def __init__(self, cfunc, obj, data=None, skip_after_object=False, visited=None):
        super(RecursiveObjectUpwardsVisitor, self).__init__(cfunc, obj, data, skip_after_object, visited)

    def prepare_new_scan(self, cfunc, arg_idx, obj, skip=False):
        super(RecursiveObjectUpwardsVisitor, self).prepare_new_scan(cfunc, arg_idx, obj, skip)
        self._call_obj = obj if obj.id == SO_CALL_ARGUMENT else None

    def _check_call(self, cexpr):
        if cexpr.op == idaapi.cot_var and self._cfunc.get_lvars()[cexpr.v.idx].is_arg_var:
            func_ea = self._cfunc.entry_ea
            arg_idx = cexpr.v.idx
            if self._add_visit(func_ea, arg_idx):
                for callee_ea in helper.get_funcs_calling_address(func_ea):
                    self._add_scan_tree_info(callee_ea, arg_idx)

    def _recursive_process(self):
        super(RecursiveObjectUpwardsVisitor, self)._recursive_process()

        while self._new_for_visit:
            new_visit = list(self._new_for_visit)
            self._new_for_visit.clear()
            for func_ea, arg_idx in new_visit:
                funcs = helper.get_funcs_calling_address(func_ea)
                obj = CallArgObject.create(idaapi.decompile(func_ea), arg_idx)
                for callee_ea in funcs:
                    cfunc = helper.decompile_function(callee_ea)
                    if cfunc:
                        self.prepare_new_scan(cfunc, arg_idx, obj, False)
                        super(RecursiveObjectUpwardsVisitor, self)._recursive_process()
