import idaapi

import actions
import HexRaysPyTools.core.helper as helper
import HexRaysPyTools.core.struct_xrefs as struct_xrefs
import HexRaysPyTools.forms as forms


class FindFieldXrefs(actions.HexRaysPopupAction):
    description = "Field Xrefs"
    hotkey = "Ctrl+X"

    def __init__(self):
        super(FindFieldXrefs, self).__init__()

    def check(self, hx_view):
        return hx_view.item.citype == idaapi.VDI_EXPR and \
               hx_view.item.it.to_specific_type.op in (idaapi.cot_memptr, idaapi.cot_memref)

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        if not self.check(hx_view):
            return

        data = []
        offset = hx_view.item.e.m
        struct_type = idaapi.remove_pointer(hx_view.item.e.x.type)
        ordinal = helper.get_ordinal(struct_type)
        result = struct_xrefs.XrefStorage().get_structure_info(ordinal, offset)
        for xref_info in result:
            data.append([
                idaapi.get_short_name(xref_info.func_ea) + "+" + hex(int(xref_info.offset)),
                xref_info.type,
                xref_info.line
            ])

        field_name = helper.get_member_name(struct_type, offset)
        chooser = forms.MyChoose(
            data,
            "Cross-references to {0}::{1}".format(struct_type.dstr(), field_name),
            [["Function", 20 | idaapi.Choose2.CHCOL_PLAIN],
             ["Type", 2 | idaapi.Choose2.CHCOL_PLAIN],
             ["Line", 40 | idaapi.Choose2.CHCOL_PLAIN]]
        )
        idx = chooser.Show(True)
        if idx == -1:
            return

        xref = result[idx]
        idaapi.open_pseudocode(xref.func_ea + xref.offset, False)

actions.action_manager.register(FindFieldXrefs())
