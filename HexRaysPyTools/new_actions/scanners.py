import idaapi
import actions
import HexRaysPyTools.api as api
import HexRaysPyTools.core.cache as cache
import HexRaysPyTools.core.helper as helper
from ..core.variable_scanner import NewShallowSearchVisitor, NewDeepSearchVisitor


def _can_be_scanned(cfunc, ctree_item):
    obj = api.ScanObject.create(cfunc, ctree_item)
    return obj and helper.is_legal_type(obj.tinfo)


class ShallowScanVariable(actions.PopupAction):
    description = "Scan Variable"
    hotkey = "F"

    def __init__(self):
        super(ShallowScanVariable, self).__init__()

    def check(self, *args):
        form, popup, hx_view = args
        cfunc, ctree_item = hx_view.cfunc, hx_view.item
        return _can_be_scanned(cfunc, ctree_item)

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        cfunc = hx_view.cfunc
        origin = cache.temporary_structure.main_offset

        if _can_be_scanned(cfunc, hx_view.item):
            obj = api.ScanObject.create(cfunc, hx_view.item)
            visitor = NewShallowSearchVisitor(cfunc, origin, obj, cache.temporary_structure)
            visitor.process()

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class DeepScanVariable(actions.PopupAction):
    description = "Deep Scan Variable"
    hotkey = "shift+F"

    def __init__(self):
        super(DeepScanVariable, self).__init__()

    def check(self, *args):
        form, popup, hx_view = args
        cfunc, ctree_item = hx_view.cfunc, hx_view.item
        return _can_be_scanned(cfunc, ctree_item)

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        cfunc = hx_view.cfunc
        origin = cache.temporary_structure.main_offset

        if _can_be_scanned(cfunc, hx_view.item):
            obj = api.ScanObject.create(cfunc, hx_view.item)
            if helper.FunctionTouchVisitor(cfunc).process():
                hx_view.refresh_view(True)
            visitor = NewDeepSearchVisitor(hx_view.cfunc, origin, obj, cache.temporary_structure)
            visitor.process()

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


actions.action_manager.register(ShallowScanVariable())
actions.action_manager.register(DeepScanVariable())
