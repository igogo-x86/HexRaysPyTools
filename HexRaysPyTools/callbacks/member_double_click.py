import idaapi

import callbacks
import HexRaysPyTools.core.helper as helper


class MemberDoubleClick(callbacks.HexRaysEventHandler):
    def __init__(self):
        super(MemberDoubleClick, self).__init__()

    def handle(self, event, *args):
        hx_view = args[0]
        item = hx_view.item
        if item.citype == idaapi.VDI_EXPR and item.e.op in (idaapi.cot_memptr, idaapi.cot_memref):
            # Look if we double clicked on expression that is member pointer. Then get tinfo_t of  the structure.
            # After that remove pointer and get member name with the same offset
            if item.e.x.op == idaapi.cot_memref and item.e.x.x.op == idaapi.cot_memptr:
                vtable_tinfo = item.e.x.type.get_pointed_object()
                method_offset = item.e.m
                class_tinfo = item.e.x.x.x.type.get_pointed_object()
                vtable_offset = item.e.x.x.m
            elif item.e.x.op == idaapi.cot_memptr:
                vtable_tinfo = item.e.x.type
                if vtable_tinfo.is_ptr():
                    vtable_tinfo = vtable_tinfo.get_pointed_object()
                method_offset = item.e.m
                class_tinfo = item.e.x.x.type.get_pointed_object()
                vtable_offset = item.e.x.m
            else:
                func_offset = item.e.m
                struct_tinfo = item.e.x.type.get_pointed_object()
                func_ea = helper.choose_virtual_func_address(helper.get_member_name(struct_tinfo, func_offset))
                if func_ea:
                    idaapi.jumpto(func_ea)
                return 0

            func_name = helper.get_member_name(vtable_tinfo, method_offset)
            func_ea = helper.choose_virtual_func_address(func_name, class_tinfo, vtable_offset)
            if func_ea:
                idaapi.open_pseudocode(func_ea, 0)
                return 1

callbacks.hx_callback_manager.register(idaapi.hxe_double_click, MemberDoubleClick())
