# encoding:utf-8
import idaapi
import ida_struct

from . import actions
import HexRaysPyTools.core.helper as helper
import HexRaysPyTools.core.struct_xrefs as struct_xrefs
import HexRaysPyTools.forms as forms


class FindFieldXrefs(actions.HexRaysXrefAction):
    description = "Field Xrefs"
    hotkey = "Ctrl+X"

    def __init__(self):
        super(FindFieldXrefs, self).__init__()

    #def check(self, hx_view):#old
    #    return hx_view.item.citype == idaapi.VDI_EXPR and \
    #           hx_view.item.it.to_specific_type.op in (idaapi.cot_memptr, idaapi.cot_memref)

    def check(self,ctree_item):
        return ctree_item.citype == idaapi.VDI_EXPR and \
               ctree_item.it.to_specific_type.op in (idaapi.cot_memptr, idaapi.cot_memref)

    def activate(self, ctx):
        ordinal = 0
        offset = 0
        data = []
        struct_name=''
        field_name=''
        
        
        #print('activate widget_type: ',ctx.widget_type)

        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:# pseudocode window
            hx_view = idaapi.get_widget_vdui(ctx.widget)#vdui_t
            item = hx_view.item
            if not self.check(item):
                return
            offset = item.e.m
            #print (item.e.x.type
            #print (dir(item.e.x.type);
            struct_type = idaapi.remove_pointer(item.e.x.type)
            #print (struct_type
            #print (dir(struct_type);
            ordinal = helper.get_ordinal(struct_type)#ordinal Id
            struct_name=struct_type.dstr()
            field_name=helper.get_member_name(struct_type, offset)
        
        if ctx.widget_type == idaapi.BWN_STRUCTS:#struct window ctrl+x
            #print (dir(ctx));
            #print (dir(ctx.chooser_selection));
            #print (dir(ctx.cur_struc));#struc_t *
            #print (type(ctx.cur_struc))
            #print (dir(ctx.cur_strmem));#member_t *  the current structure member
            ordinal= ctx.cur_struc.ordinal
            offset= ctx.cur_strmem.soff
            struct_name = ida_struct.get_struc_name(ctx.cur_struc.id)
            field_name = ida_struct.get_member_name(ctx.cur_strmem.id)


        result = struct_xrefs.XrefStorage().get_structure_info(ordinal, offset)
        for xref_info in result:
            data.append([
                idaapi.get_short_name(xref_info.func_ea) + "+" + hex(int(xref_info.offset)),
                xref_info.type,
                xref_info.line
            ])

        chooser = forms.MyChoose(
            data,
            "Cross-references to {0}::{1}".format(struct_name, field_name),
            [["Function", 20 | idaapi.Choose.CHCOL_PLAIN],
             ["Type", 2 | idaapi.Choose.CHCOL_PLAIN],
             ["Line", 40 | idaapi.Choose.CHCOL_PLAIN]]
        )
        idx = chooser.Show(True)
        if idx == -1:
            return

        xref = result[idx]
        idaapi.open_pseudocode(xref.func_ea + xref.offset, False)

actions.action_manager.register(FindFieldXrefs())
