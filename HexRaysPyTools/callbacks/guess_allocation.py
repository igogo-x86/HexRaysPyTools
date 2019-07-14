import idaapi

import actions
import HexRaysPyTools.api as api
import HexRaysPyTools.forms as forms
import HexRaysPyTools.core.helper as helper


class _StructAllocChoose(forms.MyChoose):
    def __init__(self, items):
        forms.MyChoose.__init__(
            self, items, "Possible structure allocations",
            [["Function", 30], ["Variable", 10], ["Line", 50], ["Type", 10]]
        )

    def OnSelectLine(self, n):
        idaapi.jumpto(self.items[n][0])

    def OnGetLine(self, n):
        func_ea, var, line, alloc_type = self.items[n]
        return [helper.to_nice_str(func_ea), var, line, alloc_type]


class _GuessAllocationVisitor(api.RecursiveObjectUpwardsVisitor):
    def __init__(self, cfunc, obj):
        super(_GuessAllocationVisitor, self).__init__(cfunc, obj, skip_after_object=True)
        self._data = []

    def _manipulate(self, cexpr, obj):
        if obj.id == api.SO_LOCAL_VARIABLE:
            parent = self.parent_expr()
            if parent.op == idaapi.cot_asg:
                alloc_obj = api.MemoryAllocationObject.create(self._cfunc, self.parent_expr().y)
                if alloc_obj:
                    self._data.append([alloc_obj.ea, obj.name, self._get_line(), "HEAP"])
            elif self.parent_expr().op == idaapi.cot_ref:
                self._data.append([helper.find_asm_address(cexpr, self.parents), obj.name, self._get_line(), "STACK"])
        elif obj.id == api.SO_GLOBAL_OBJECT:
            self._data.append([helper.find_asm_address(cexpr, self.parents), obj.name, self._get_line(), "GLOBAL"])

    def _finish(self):
        chooser = _StructAllocChoose(self._data)
        chooser.Show(False)


class GuessAllocation(actions.HexRaysPopupAction):
    description = "Guess allocation"
    hotkey = None

    def __init__(self):
        super(GuessAllocation, self).__init__()

    def check(self, hx_view):
        if hx_view.item.citype != idaapi.VDI_EXPR:
            return False
        return api.ScanObject.create(hx_view.cfunc, hx_view.item) is not None

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        obj = api.ScanObject.create(hx_view.cfunc, hx_view.item)
        if obj:
            visitor = _GuessAllocationVisitor(hx_view.cfunc, obj)
            visitor.process()

actions.action_manager.register(GuessAllocation())
