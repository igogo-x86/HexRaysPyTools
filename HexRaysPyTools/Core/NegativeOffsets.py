import re

import idaapi

import idc
EA64 = idc.__EA64__
EA_SIZE = 8 if EA64 else 4


def check_ida_bug(tinfo, offset):
    udt_data = idaapi.udt_type_data_t()
    tinfo.get_udt_details(udt_data)
    return False if filter(lambda x: x.offset == offset * 8, udt_data) else True


def parse_lvar_comment(lvar):
    if lvar.type().is_ptr():
        m = re.search('```(.+)```', lvar.cmt)
        if m:
            name, offset = m.group(1).split('+')
            offset = int(offset)
            parent_tinfo = idaapi.tinfo_t()
            if not parent_tinfo.get_named_type(idaapi.cvar.idati, name):
                return None
            udt_data = idaapi.udt_type_data_t()
            parent_tinfo.get_udt_details(udt_data)
            udt_member = filter(lambda x: x.offset == offset*8, udt_data)
            if udt_member:
                member_name = udt_member[0].name
                return NegativeLocalInfo(lvar.type(), parent_tinfo, offset, member_name)
    return None


class NegativeLocalInfo:
    def __init__(self, tinfo, parent_tinfo, offset, member_name):
        self.tinfo = tinfo
        tmp_tinfo = self.tinfo.get_pointed_object()
        self.size = tmp_tinfo.get_size() if tmp_tinfo.is_udt else 0
        self.parent_tinfo = parent_tinfo
        self.offset = offset
        self.member_name = member_name

    def __repr__(self):
        return "Type - {0}, parent type - {1}, offset - {2}, member_name - {3}".format(
            self.tinfo.dstr(),
            self.parent_tinfo.dstr(),
            self.offset,
            self.member_name
        )


class ReplaceVisitor(idaapi.ctree_parentee_t):
    del_list = []

    def __init__(self, negative_lvars):
        super(ReplaceVisitor, self).__init__()
        self.negative_lvars = negative_lvars
        self.pvoid_tinfo = idaapi.tinfo_t(idaapi.BT_VOID)
        self.pvoid_tinfo.create_ptr(self.pvoid_tinfo)

    def visit_expr(self, expression):
        if expression.op == idaapi.cot_add and expression.x.op == idaapi.cot_var and expression.y.op == idaapi.cot_num:
            # print "ADD TYPE", expression.type.dstr()
            index = expression.x.v.idx
            if index in self.negative_lvars:
                offset = expression.y.n.value(idaapi.tinfo_t(idaapi.BT_INT))
                if offset < self.negative_lvars[index].size:
                    self.create_containing_record(expression, index, offset)
        elif expression.op == idaapi.cot_sub and expression.x.op == idaapi.cot_var and expression.y.op == idaapi.cot_num:
            # print "SUB TYPE", expression.type.dstr(), expression.x.type.dstr()
            index = expression.x.v.idx
            if index in self.negative_lvars:
                offset = -expression.y.n.value(idaapi.tinfo_t(idaapi.BT_INT))
                self.create_containing_record(expression, index, offset)
        # elif expression.op == idaapi.cot_var:
        #     index = expression.v.idx
        #     if index in self.negative_lvars:
        #         self.create_containing_record(expression, index, 0)
        return 0

    def create_containing_record(self, expression, index, offset):

        negative_lvar = self.negative_lvars[index]
        print "[DEBUG] Rebuilding negative offset", negative_lvar.offset, offset, negative_lvar.parent_tinfo.dstr()
        diff = negative_lvar.offset + offset

        if check_ida_bug(negative_lvar.parent_tinfo, diff):
            print "[IDA ERROR] Try another member pointer in CONTAINING_RECORD macro"
            return
        # if diff:
        #     return

        arg_address = idaapi.carg_t()
        if expression.op == idaapi.cot_var:
            arg_address.consume_cexpr(expression)
        else:
            arg_address.consume_cexpr(expression.x)

        arg_type = idaapi.carg_t()
        cexpr_helper = idaapi.create_helper(
            True,
            self.pvoid_tinfo,
            negative_lvar.parent_tinfo.dstr()
        )
        arg_type.consume_cexpr(cexpr_helper)

        arg_field = idaapi.carg_t()
        cexpr_helper = idaapi.create_helper(
            True,
            self.pvoid_tinfo,
            negative_lvar.member_name
        )
        arg_field.consume_cexpr(cexpr_helper)
        return_tinfo = idaapi.tinfo_t(negative_lvar.parent_tinfo)
        return_tinfo.create_ptr(return_tinfo)
        call_helper = idaapi.call_helper(return_tinfo, None, "CONTAINING_RECORD")
        call_helper.a.push_back(arg_address)
        call_helper.a.push_back(arg_type)
        call_helper.a.push_back(arg_field)
        call_helper.ea = expression.ea
        call_helper.x.ea = expression.ea

        if diff:
            number = idaapi.make_num(diff)
            add_helper = idaapi.cexpr_t(idaapi.cot_add, call_helper, number)
            add_helper.type = return_tinfo
            # print len(self.parents)
            # print "PARENTS", idaapi.get_ctype_name(reversed(self.parents).next().op)
            # if reversed(self.parents).next().op == idaapi.cot_ref:
            # if True:
            #     cast_helper = idaapi.cexpr_t(idaapi.cot_cast, add_helper)
            #     cast_helper.type = idaapi.dummy_ptrtype(EA_SIZE, 0)
            #     ReplaceVisitor.del_list.append(cast_helper)
            #     ReplaceVisitor.del_list.append(add_helper)
            #     expression.replace_by(cast_helper)
            # else:

            ReplaceVisitor.del_list.append(add_helper)
            expression.replace_by(add_helper)
            # if expression.op == idaapi.cot_sub:
            #     expression.op = idaapi.cot_add
            #     expression.type = call_helper.type
            #     expression.x.replace_by(call_helper)
            #     expression.y.replace_by(number)
            # expression.replace_by(add_helper)
        else:
            expression.replace_by(call_helper)


class SearchVisitor(idaapi.ctree_parentee_t):
    def __init__(self, cfunc):
        super(SearchVisitor, self).__init__()
        self.cfunc = cfunc
        self.result = {}

    def visit_expr(self, expression):
        if expression.op == idaapi.cot_call and expression.x.op == idaapi.cot_helper and len(expression.a) == 3:
            if expression.x.helper == "CONTAINING_RECORD":
                if expression.a[0].op == idaapi.cot_var:
                    idx = expression.a[0].v.idx
                    if expression.a[1].op == idaapi.cot_helper and expression.a[2].op == idaapi.cot_helper:
                        parent_name = expression.a[1].helper
                        member_name = expression.a[2].helper
                        parent_tinfo = idaapi.tinfo_t()
                        if not parent_tinfo.get_named_type(idaapi.cvar.idati, parent_name):
                            return None
                        udt_data = idaapi.udt_type_data_t()
                        parent_tinfo.get_udt_details(udt_data)
                        udt_member = filter(lambda x: x.name == member_name, udt_data)
                        if udt_member:
                            tinfo = udt_member[0].type
                            tinfo.create_ptr(tinfo)
                            self.result[idx] = NegativeLocalInfo(
                                tinfo,
                                parent_tinfo,
                                udt_member[0].offset / 8,
                                member_name
                            )
                            return 1
        return 0
