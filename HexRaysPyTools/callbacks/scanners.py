import idaapi
from . import actions
import HexRaysPyTools.api as api
import HexRaysPyTools.core.cache as cache
import HexRaysPyTools.core.helper as helper
from ..core.variable_scanner import NewShallowSearchVisitor, NewDeepSearchVisitor, DeepReturnVisitor
from ..core.temporary_structure import TemporaryStructureModel


class Scanner(actions.HexRaysPopupAction):
    """
    Abstract class containing common check of whether object can be scanned or not.
    Concrete class implement actual scan process in activate method
    """
    def __init__(self):
        super(Scanner, self).__init__()

    def _can_be_scanned(self, cfunc, ctree_item):
        obj = api.ScanObject.create(cfunc, ctree_item)
        return obj and helper.is_legal_type(obj.tinfo)

    def check(self, hx_view):
        cfunc, ctree_item = hx_view.cfunc, hx_view.item
        return self._can_be_scanned(cfunc, ctree_item)


class ShallowScanVariable(Scanner):
    description = "Scan Variable"
    hotkey = "F"

    def __init__(self):
        super(ShallowScanVariable, self).__init__()

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        cfunc = hx_view.cfunc
        origin = cache.temporary_structure.main_offset

        if self._can_be_scanned(cfunc, hx_view.item):
            obj = api.ScanObject.create(cfunc, hx_view.item)
            visitor = NewShallowSearchVisitor(cfunc, origin, obj, cache.temporary_structure)
            visitor.process()


class DeepScanVariable(Scanner):
    description = "Deep Scan Variable"
    hotkey = "shift+F"

    def __init__(self):
        super(DeepScanVariable, self).__init__()

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        cfunc = hx_view.cfunc
        origin = cache.temporary_structure.main_offset

        if self._can_be_scanned(cfunc, hx_view.item):
            obj = api.ScanObject.create(cfunc, hx_view.item)
            if helper.FunctionTouchVisitor(cfunc).process():
                hx_view.refresh_view(True)
            visitor = NewDeepSearchVisitor(hx_view.cfunc, origin, obj, cache.temporary_structure)
            visitor.process()


class RecognizeShape(Scanner):
    description = "Recognize Shape"

    def __init__(self):
        super(RecognizeShape, self).__init__()

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        cfunc = hx_view.cfunc

        if not self._can_be_scanned(cfunc, hx_view.item):
            return

        obj = api.ScanObject.create(cfunc, hx_view.item)
        tmp_struct = TemporaryStructureModel()
        visitor = NewShallowSearchVisitor(cfunc, 0, obj, tmp_struct)
        visitor.process()
        tinfo = tmp_struct.get_recognized_shape()
        if tinfo:
            tinfo.create_ptr(tinfo)
            if obj.id == api.SO_LOCAL_VARIABLE:
                hx_view.set_lvar_type(obj.lvar, tinfo)
            elif obj.id == api.SO_GLOBAL_OBJECT:
                idaapi.apply_tinfo(obj.obj_ea, tinfo, idaapi.TINFO_DEFINITE)
            hx_view.refresh_view(True)


class DeepScanReturn(Scanner):
    description = "Deep Scan Returned Variables"

    def __init__(self):
        super(DeepScanReturn, self).__init__()

    def check(self, hx_view):
        cfunc, ctree_item = hx_view.cfunc, hx_view.item
        if ctree_item.citype != idaapi.VDI_FUNC:
            return False
        tinfo = idaapi.tinfo_t()
        hx_view.cfunc.get_func_type(tinfo)
        return helper.is_legal_type(tinfo.get_rettype())

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        func_ea = hx_view.cfunc.entry_ea
        obj = api.ReturnedObject(func_ea)
        origin = cache.temporary_structure.main_offset
        visitor = DeepReturnVisitor(hx_view.cfunc, origin, obj, cache.temporary_structure)
        visitor.process()


class DeepScanFunctions(actions.Action):
    description = "Scan First Argument"

    def __init__(self):
        super(DeepScanFunctions, self).__init__()

    def activate(self, ctx):
        for idx in ctx.chooser_selection:
            func_ea = idaapi.getn_func(idx - 1).start_ea
            cfunc = helper.decompile_function(func_ea)
            obj = api.VariableObject(cfunc.get_lvars()[0], 0)
            if cfunc:
                NewDeepSearchVisitor(cfunc, 0, obj, cache.temporary_structure).process()

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_FUNCS:
            idaapi.attach_action_to_popup(ctx.widget, None, self.name)
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET


actions.action_manager.register(ShallowScanVariable())
actions.action_manager.register(DeepScanVariable())
actions.action_manager.register(RecognizeShape())
actions.action_manager.register(DeepScanReturn())
actions.action_manager.register(DeepScanFunctions())
