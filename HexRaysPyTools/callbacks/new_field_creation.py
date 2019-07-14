import logging
import re

import idaapi
import idc

import actions
import HexRaysPyTools.core.helper as helper
import HexRaysPyTools.core.const as const

logger = logging.getLogger(__name__)


def _is_gap_field(cexpr):
    if cexpr.op not in (idaapi.cot_memptr, idaapi.cot_memref):
        return False
    struct_type = cexpr.x.type
    struct_type.remove_ptr_or_array()
    return helper.get_member_name(struct_type, cexpr.m)[0:3] == "gap"


class CreateNewField(actions.HexRaysPopupAction):
    description = "Create New Field"
    hotkey = "Ctrl+F"

    def __init__(self):
        super(CreateNewField, self).__init__()

    def check(self, hx_view):
        if hx_view.item.citype != idaapi.VDI_EXPR:
            return False

        return _is_gap_field(hx_view.item.it.to_specific_type)

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        if not self.check(hx_view):
            return

        item = hx_view.item.it.to_specific_type
        parent = hx_view.cfunc.body.find_parent_of(item).to_specific_type
        if parent.op != idaapi.cot_idx or parent.y.op != idaapi.cot_num:
            idx = 0
        else:
            idx = parent.y.numval()

        struct_tinfo = item.x.type
        struct_tinfo.remove_ptr_or_array()

        offset = item.m
        ordinal = struct_tinfo.get_ordinal()
        struct_name = struct_tinfo.dstr()

        if (offset + idx) % 2:
            default_field_type = "_BYTE"
        elif (offset + idx) % 4:
            default_field_type = "_WORD"
        elif (offset + idx) % 8:
            default_field_type = "_DWORD"
        else:
            default_field_type = "_QWORD" if const.EA64 else "_DWORD"

        declaration = idaapi.asktext(
            0x10000, "{0} field_{1:X}".format(default_field_type, offset + idx), "Enter new structure member:"
        )
        if declaration is None:
            return

        result = self.parse_declaration(declaration)
        if result is None:
            logger.warn("Bad member declaration")
            return

        field_tinfo, field_name = result
        field_size = field_tinfo.get_size()
        udt_data = idaapi.udt_type_data_t()
        udt_member = idaapi.udt_member_t()

        struct_tinfo.get_udt_details(udt_data)
        udt_member.offset = offset * 8
        struct_tinfo.find_udt_member(idaapi.STRMEM_OFFSET, udt_member)
        gap_size = udt_member.size // 8

        gap_leftover = gap_size - idx - field_size

        if gap_leftover < 0:
            logger.error("Too big size for the field. Type with maximum {0} bytes can be used".format(gap_size - idx))
            return

        iterator = udt_data.find(udt_member)
        iterator = udt_data.erase(iterator)

        if gap_leftover > 0:
            udt_data.insert(iterator, helper.create_padding_udt_member(offset + idx + field_size, gap_leftover))

        udt_member = idaapi.udt_member_t()
        udt_member.offset = offset * 8 + idx
        udt_member.name = field_name
        udt_member.type = field_tinfo
        udt_member.size = field_size

        iterator = udt_data.insert(iterator, udt_member)

        if idx > 0:
            udt_data.insert(iterator, helper.create_padding_udt_member(offset, idx))

        struct_tinfo.create_udt(udt_data, idaapi.BTF_STRUCT)
        struct_tinfo.set_numbered_type(idaapi.cvar.idati, ordinal, idaapi.BTF_STRUCT, struct_name)
        hx_view.refresh_view(True)

    @staticmethod
    def parse_declaration(declaration):
        m = re.search(r"^(\w+[ *]+)(\w+)(\[(\d+)\])?$", declaration)
        if m is None:
            logger.error("Member declaration should be like `TYPE_NAME NAME[SIZE]` (Array is optional)")
            return

        type_name, field_name, _, arr_size = m.groups()
        if field_name[0].isdigit():
            logger.error("Bad field name")
            return

        result = idc.ParseType(type_name, 0)
        if result is None:
            logger.error("Failed to parse member type. It should be like `TYPE_NAME NAME[SIZE]` (Array is optional)")
            return

        _, tp, fld = result
        tinfo = idaapi.tinfo_t()
        tinfo.deserialize(idaapi.cvar.idati, tp, fld, None)
        if arr_size:
            assert tinfo.create_array(tinfo, int(arr_size))
        return tinfo, field_name

actions.action_manager.register(CreateNewField())

# TODO: All this stuff can be done automatically when we either use ctrl+F5 or regular F5
