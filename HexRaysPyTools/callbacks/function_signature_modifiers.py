import idaapi
import actions
import HexRaysPyTools.core.const as const


class ConvertToUsercall(actions.HexRaysPopupAction):
    description = "Convert to __usercall"

    def __init__(self):
        super(ConvertToUsercall, self).__init__()

    def check(self, hx_view):
        return hx_view.item.citype == idaapi.VDI_FUNC

    def activate(self, ctx):
        vu = idaapi.get_widget_vdui(ctx.widget)
        function_tinfo = idaapi.tinfo_t()
        if not vu.cfunc.get_func_type(function_tinfo):
            return
        function_details = idaapi.func_type_data_t()
        function_tinfo.get_func_details(function_details)
        convention = idaapi.CM_CC_MASK & function_details.cc
        if convention == idaapi.CM_CC_CDECL:
            function_details.cc = idaapi.CM_CC_SPECIAL
        elif convention in (idaapi.CM_CC_STDCALL, idaapi.CM_CC_FASTCALL, idaapi.CM_CC_PASCAL, idaapi.CM_CC_THISCALL):
            function_details.cc = idaapi.CM_CC_SPECIALP
        elif convention == idaapi.CM_CC_ELLIPSIS:
            function_details.cc = idaapi.CM_CC_SPECIALE
        else:
            return
        function_tinfo.create_func(function_details)
        idaapi.apply_tinfo2(vu.cfunc.entry_ea, function_tinfo, idaapi.TINFO_DEFINITE)
        vu.refresh_view(True)


class AddRemoveReturn(actions.HexRaysPopupAction):
    description = "Add/Remove Return"

    def __init__(self):
        super(AddRemoveReturn, self).__init__()

    def check(self, hx_view):
        return hx_view.item.citype == idaapi.VDI_FUNC

    def activate(self, ctx):
        vu = idaapi.get_widget_vdui(ctx.widget)
        function_tinfo = idaapi.tinfo_t()
        if not vu.cfunc.get_func_type(function_tinfo):
            return
        function_details = idaapi.func_type_data_t()
        function_tinfo.get_func_details(function_details)
        if function_details.rettype.equals_to(const.VOID_TINFO):
            function_details.rettype = idaapi.tinfo_t(const.PVOID_TINFO)
        else:
            function_details.rettype = idaapi.tinfo_t(idaapi.BT_VOID)
        function_tinfo.create_func(function_details)
        idaapi.apply_tinfo2(vu.cfunc.entry_ea, function_tinfo, idaapi.TINFO_DEFINITE)
        vu.refresh_view(True)


class RemoveArgument(actions.HexRaysPopupAction):
    description = "Remove Argument"

    def __init__(self):
        super(RemoveArgument, self).__init__()

    def check(self, hx_view):
        if hx_view.item.citype != idaapi.VDI_LVAR:
            return False
        local_variable = hx_view.item.get_lvar()          # type:idaapi.lvar_t
        return local_variable.is_arg_var

    def activate(self, ctx):
        vu = idaapi.get_widget_vdui(ctx.widget)
        function_tinfo = idaapi.tinfo_t()
        if not vu.cfunc.get_func_type(function_tinfo):
            return
        function_details = idaapi.func_type_data_t()
        function_tinfo.get_func_details(function_details)
        del_arg = vu.item.get_lvar()

        function_details.erase(filter(lambda x: x.name == del_arg.name, function_details)[0])

        function_tinfo.create_func(function_details)
        idaapi.apply_tinfo2(vu.cfunc.entry_ea, function_tinfo, idaapi.TINFO_DEFINITE)
        vu.refresh_view(True)


actions.action_manager.register(ConvertToUsercall())
actions.action_manager.register(AddRemoveReturn())
actions.action_manager.register(RemoveArgument())
