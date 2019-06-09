from collections import namedtuple
import idaapi
import actions
import HexRaysPyTools.core.helper as helper


RecastLocalVariable = namedtuple('RecastLocalVariable', ['recast_tinfo', 'local_variable'])
RecastGlobalVariable = namedtuple('RecastGlobalVariable', ['recast_tinfo', 'global_variable_ea'])
RecastArgument = namedtuple('RecastArgument', ['recast_tinfo', 'arg_idx', 'func_ea', 'func_tinfo'])
RecastReturn = namedtuple('RecastReturn', ['recast_tinfo', 'func_ea'])
RecastStructure = namedtuple('RecastStructure', ['recast_tinfo', 'structure_name', 'field_offset'])


class RecastItemLeft(actions.HexRaysPopupAction):

    description = "Recast Item"
    hotkey = "Shift+L"

    def __init__(self):
        super(RecastItemLeft, self).__init__()

    def extract_recast_info(self, cfunc, ctree_item):
        # type: (idaapi.cfunc_t, idaapi.ctree_item_t) -> namedtuple
        # Returns one of the Recast... namedtuple or None if nothing was found

        if ctree_item.citype != idaapi.VDI_EXPR:
            return

        expression = ctree_item.it.to_specific_type
        child = None

        # Look through parents until we found Return, Assignment or Call
        while expression and expression.op not in (idaapi.cot_asg, idaapi.cit_return, idaapi.cot_call):
            child = expression.to_specific_type
            expression = cfunc.body.find_parent_of(expression)
        if not expression:
            return

        expression = expression.to_specific_type
        if expression.op == idaapi.cot_asg:

            if expression.x.opname not in ('var', 'obj', 'memptr', 'memref'):
                return

            right_expr = expression.y
            right_tinfo = right_expr.x.type if right_expr.op == idaapi.cot_cast else right_expr.type

            # Check if both left and right parts of expression are of the same types.
            # If not then we can recast then.
            if right_tinfo.dstr() == expression.x.type.dstr():
                return

            if expression.x.op == idaapi.cot_var:
                # var = (TYPE ) ...;
                variable = cfunc.get_lvars()[expression.x.v.idx]
                return RecastLocalVariable(right_tinfo, variable)

            elif expression.x.op == idaapi.cot_obj:
                # g_var = (TYPE ) ...;
                return RecastGlobalVariable(right_tinfo, expression.x.obj_ea)

            elif expression.x.op == idaapi.cot_memptr:
                # struct->member = (TYPE ) ...;
                struct_name = expression.x.x.type.get_pointed_object().dstr()
                struct_offset = expression.x.m
                return RecastStructure(right_tinfo, struct_name, struct_offset)

            elif expression.x.op == idaapi.cot_memref:
                # struct.member = (TYPE ) ...;
                struct_name = expression.x.x.type.dstr()
                struct_offset = expression.x.m
                return RecastStructure(right_tinfo, struct_name, struct_offset)

        elif expression.op == idaapi.cit_return:
            child = child or expression.creturn.expr
            if child.op == idaapi.cot_cast:
                # return (TYPE) ...;
                return RecastReturn(child.x.type, cfunc.entry_ea)

            func_tinfo = idaapi.tinfo_t()
            cfunc.get_func_type(func_tinfo)
            rettype = func_tinfo.get_rettype()
            if rettype.dstr() != child.type.dstr():
                # return ...;
                # This's possible when returned type and value are both pointers to different types
                return RecastReturn(child.type, cfunc.entry_ea)

        elif expression.op == idaapi.cot_call:
            if expression.x == child:
                return
            func_ea = expression.x.obj_ea
            arg_index, param_tinfo = helper.get_func_argument_info(expression, child)
            if expression.x.op == idaapi.cot_memptr:
                if child.op == idaapi.cot_cast:
                    # struct_ptr->func(..., (TYPE) var, ...);
                    arg_tinfo = child.x.type
                else:
                    # struct_ptr->func(..., var, ...); When `var` and `arg` are different pointers
                    if param_tinfo.equals_to(child.type):
                        return
                    arg_tinfo = child.type

                struct_tinfo = expression.x.x.type.get_pointed_object()
                funcptr_tinfo = expression.x.type
                helper.set_funcptr_argument(funcptr_tinfo, arg_index, arg_tinfo)
                return RecastStructure(funcptr_tinfo, struct_tinfo.dstr(), expression.x.m)

            if child.op == idaapi.cot_ref:
                if child.x.op == idaapi.cot_memref and child.x.m == 0:
                    # func(..., &struct.field_0, ...)
                    arg_tinfo = idaapi.tinfo_t()
                    arg_tinfo.create_ptr(child.x.x.type)
                elif child.x.op == idaapi.cot_memptr and child.x.m == 0:
                    # func(..., &struct->field_0, ...)
                    arg_tinfo = child.x.x.type
                else:
                    # func(..., &var, ...)
                    arg_tinfo = child.type
            elif child.op == idaapi.cot_cast:
                arg_tinfo = child.x.type
            else:
                arg_tinfo = child.type

            func_tinfo = expression.x.type.get_pointed_object()
            return RecastArgument(arg_tinfo, arg_index, func_ea, func_tinfo)

    def set_label(self, label):
        idaapi.update_action_label(self.name, label)

    def check(self, hx_view):
        cfunc, ctree_item = hx_view.cfunc, hx_view.item

        ri = self.extract_recast_info(cfunc, ctree_item)
        if not ri:
            return False

        if isinstance(ri, RecastLocalVariable):
            self.set_label('Recast Variable "{0}" to {1}'.format(ri.local_variable.name, ri.recast_tinfo.dstr()))
        elif isinstance(ri, RecastGlobalVariable):
            gvar_name = idaapi.get_name(ri.global_variable_ea)
            self.set_label('Recast Global Variable "{0}" to {1}'.format(gvar_name, ri.recast_tinfo.dstr()))
        elif isinstance(ri, RecastArgument):
            self.set_label("Recast Argument")
        elif isinstance(ri, RecastStructure):
            self.set_label("Recast Field of {0} structure".format(ri.structure_name))
        elif isinstance(ri, RecastReturn):
            self.set_label("Recast Return to ".format(ri.recast_tinfo.dstr()))
        else:
            raise NotImplementedError
        return True

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        ri = self.extract_recast_info(hx_view.cfunc, hx_view.item)
        if not ri:
            return 0

        if isinstance(ri, RecastLocalVariable):
            hx_view.set_lvar_type(ri.local_variable, ri.recast_tinfo)

        elif isinstance(ri, RecastGlobalVariable):
            idaapi.apply_tinfo2(ri.global_variable_ea, ri.recast_tinfo, idaapi.TINFO_DEFINITE)

        elif isinstance(ri, RecastArgument):
            if ri.recast_tinfo.is_array():
                ri.recast_tinfo.convert_array_to_ptr()
            helper.set_func_argument(ri.func_tinfo, ri.arg_idx, ri.recast_tinfo)
            idaapi.apply_tinfo2(ri.func_ea, ri.func_tinfo, idaapi.TINFO_DEFINITE)

        elif isinstance(ri, RecastReturn):
            cfunc = helper.decompile_function(ri.func_ea)
            if not cfunc:
                return 0

            func_tinfo = idaapi.tinfo_t()
            cfunc.get_func_type(func_tinfo)
            helper.set_func_return(func_tinfo, ri.recast_tinfo)
            idaapi.apply_tinfo2(cfunc.entry_ea, func_tinfo, idaapi.TINFO_DEFINITE)

        elif isinstance(ri, RecastStructure):
            tinfo = idaapi.tinfo_t()
            tinfo.get_named_type(idaapi.cvar.idati, ri.structure_name)
            ordinal = idaapi.get_type_ordinal(idaapi.cvar.idati, ri.structure_name)
            if ordinal == 0:
                return 0

            udt_member = idaapi.udt_member_t()
            udt_member.offset = ri.field_offset * 8
            idx = tinfo.find_udt_member(idaapi.STRMEM_OFFSET, udt_member)
            if udt_member.offset != ri.field_offset * 8:
                print "[Info] Can't handle with arrays yet"
            elif udt_member.type.get_size() != ri.recast_tinfo.get_size():
                print "[Info] Can't recast different sizes yet"
            else:
                udt_data = idaapi.udt_type_data_t()
                tinfo.get_udt_details(udt_data)
                udt_data[idx].type = ri.recast_tinfo
                tinfo.create_udt(udt_data, idaapi.BTF_STRUCT)
                tinfo.set_numbered_type(idaapi.cvar.idati, ordinal, idaapi.NTF_REPLACE, ri.structure_name)
        else:
            raise NotImplementedError

        hx_view.refresh_view(True)
        return 0


class RecastItemRight(RecastItemLeft):

    name = "my:RecastItemRight"
    description = "Recast Item"
    hotkey = "Shift+R"

    def __init__(self):
        super(RecastItemRight, self).__init__()

    def extract_recast_info(self, cfunc, ctree_item):
        if ctree_item.citype != idaapi.VDI_EXPR:
            return

        expression = ctree_item.it
        result = RecastItemRight._check_potential_array(cfunc, expression)
        if result:
            return result

        # Look through parents until we found Cast
        while expression and expression.op != idaapi.cot_cast:
            expression = expression.to_specific_type
            expression = cfunc.body.find_parent_of(expression)
        if not expression:
            return

        expression = expression.to_specific_type

        # Find `(TYPE) something;` or `(TYPE *) &something;` and calculate appropriate type for recast
        if expression.x.op == idaapi.cot_ref:
            tinfo = expression.type.get_pointed_object()
            expression = expression.x
        else:
            tinfo = expression.type

        if expression.x.op == idaapi.cot_var:
            # (TYPE) var;
            variable = cfunc.get_lvars()[expression.x.v.idx]
            return RecastLocalVariable(tinfo, variable)

        elif expression.x.op == idaapi.cot_obj:
            # (TYPE) g_var;
            if helper.is_code_ea(expression.x.obj_ea) and tinfo.is_funcptr():
                # (TYPE) sub_XXXXXX;
                tinfo = tinfo.get_pointed_object()
            gvar_ea = expression.x.obj_ea
            return RecastGlobalVariable(tinfo, gvar_ea)

        elif expression.x.op == idaapi.cot_call:
            # (TYPE) call();
            idaapi.update_action_label(RecastItemRight.name, "Recast Return")
            func_ea = expression.x.x.obj_ea
            return RecastReturn(tinfo, func_ea)

        elif expression.x.op == idaapi.cot_memptr:
            # (TYPE) var->member;
            idaapi.update_action_label(RecastItemRight.name, "Recast Field")
            struct_name = expression.x.x.type.get_pointed_object().dstr()
            struct_offset = expression.x.m
            return RecastStructure(tinfo, struct_name, struct_offset)

    @staticmethod
    def _check_potential_array(cfunc, expr):
        """ Checks `call(..., &buffer, ..., number)` and returns information for recasting """
        if expr.op != idaapi.cot_var:
            return

        var_expr = expr.to_specific_type
        parent = cfunc.body.find_parent_of(expr)
        if parent.op != idaapi.cot_ref:
            return

        parent = cfunc.body.find_parent_of(parent)
        if parent.op != idaapi.cot_call:
            return

        call_expr = parent.to_specific_type
        for arg_expr in call_expr.a:
            if arg_expr.op == idaapi.cot_num:
                number = arg_expr.numval()
                if number:
                    variable = cfunc.lvars[var_expr.v.idx]
                    char_array_tinfo = idaapi.tinfo_t()
                    char_array_tinfo.create_array(idaapi.tinfo_t(idaapi.BTF_CHAR), number)
                    idaapi.update_action_label(RecastItemRight.name, 'Recast Variable "{}" to "{}"'.format(
                        variable.name, char_array_tinfo.dstr()
                    ))
                    return RecastLocalVariable(char_array_tinfo, variable)


actions.action_manager.register(RecastItemLeft())
actions.action_manager.register(RecastItemRight())
