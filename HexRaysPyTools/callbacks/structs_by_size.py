import idaapi

import actions
import HexRaysPyTools.forms as forms
import HexRaysPyTools.core.type_library as type_library


def _choose_structure_by_size(size):
    result = type_library.choose_til()
    if result:
        selected_library, max_ordinal, is_local_type = result
        matched_types = []
        tinfo = idaapi.tinfo_t()
        for ordinal in xrange(1, max_ordinal):
            tinfo.create_typedef(selected_library, ordinal)
            if tinfo.get_size() == size:
                name = tinfo.dstr()
                description = idaapi.print_tinfo(None, 0, 0, idaapi.PRTYPE_DEF, tinfo, None, None)
                matched_types.append([str(ordinal), name, description])

        type_chooser = forms.MyChoose(
            matched_types,
            "Select Type",
            [["Ordinal", 5 | idaapi.Choose2.CHCOL_HEX], ["Type Name", 25], ["Declaration", 50]],
            165
        )
        selected_type = type_chooser.Show(True)
        if selected_type != -1:
            if is_local_type:
                return int(matched_types[selected_type][0])
            return type_library.import_type(selected_library, matched_types[selected_type][1])
    return None


class GetStructureBySize(actions.HexRaysPopupAction):
    # TODO: apply type automatically if expression like `var = new(size)`
    description = "Structures with this size"

    def __init__(self):
        super(GetStructureBySize, self).__init__()

    def check(self, hx_view):
        return hx_view.item.citype == idaapi.VDI_EXPR and hx_view.item.e.op == idaapi.cot_num

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        if not self.check(hx_view):
            return
        ea = ctx.cur_ea
        c_number = hx_view.item.e
        number_value = c_number.numval()
        ordinal = _choose_structure_by_size(number_value)
        if ordinal:
            number_format_old = c_number.n.nf
            number_format_new = idaapi.number_format_t()
            number_format_new.flags = idaapi.FF_1STRO | idaapi.FF_0STRO
            operand_number = number_format_old.opnum
            number_format_new.opnum = operand_number
            number_format_new.props = number_format_old.props
            number_format_new.type_name = idaapi.create_numbered_type_name(ordinal)

            c_function = hx_view.cfunc
            number_formats = c_function.numforms    # type: idaapi.user_numforms_t
            # print "(number) flags: {0:#010X}, type_name: {1}, opnum: {2}".format(
            #     number_format.flags,
            #     number_format.type_name,
            #     number_format.opnum
            # )
            operand_locator = idaapi.operand_locator_t(ea, ord(operand_number) if operand_number else 0)
            if operand_locator in number_formats:
                del number_formats[operand_locator]

            number_formats[operand_locator] = number_format_new
            c_function.save_user_numforms()
            hx_view.refresh_view(True)

actions.action_manager.register(GetStructureBySize())
