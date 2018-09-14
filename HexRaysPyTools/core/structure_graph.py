import logging

import idaapi
import idc

logger = logging.getLogger(__name__)


class LocalType:
    def __init__(self, name, members_ordinals, hint, is_selected=False, is_typedef=False, is_enum=False, is_union=False):
        self.name = name
        self.members_ordinals = members_ordinals
        self.hint = hint
        self.is_selected = is_selected
        self.is_typedef = is_typedef
        self.is_enum = is_enum
        self.is_union = is_union

    def __call__(self):
        return self.name, self.members_ordinals

    def __str__(self):
        return "<{0}, {1}>".format(self.name, self.members_ordinals)

    def __repr__(self):
        return self.__str__()

    @property
    def name_and_color(self):
        if self.is_selected:
            return self.name, 0x0000FF
        elif self.is_typedef:
            return self.name, 0x99FFFF
        elif self.is_enum:
            return self.name, 0x33FF33
        elif self.is_union:
            return self.name, 0xCCCC00
        return self.name, 0xffdd99


class StructureGraph:
    # TODO:Enum types display
    def __init__(self, ordinal_list=None):
        self.ordinal_list = ordinal_list if ordinal_list else xrange(1, idc.GetMaxLocalType())
        self.local_types = {}
        self.edges = []
        self.final_edges = []
        self.visited_downward = []
        self.visited_upward = []
        self.downward_edges = {}
        self.upward_edges = {}
        self.initialize_nodes()
        self.calculate_edges()

    def change_selected(self, selected):
        self.visited_downward = []
        self.visited_upward = []
        self.final_edges = []
        for ordinal in self.ordinal_list:
            self.local_types[ordinal].is_selected = False
        self.ordinal_list = set(self.local_types).intersection(selected)
        for ordinal in self.ordinal_list:
            self.local_types[ordinal].is_selected = True

    @staticmethod
    def get_ordinal(tinfo):
        while tinfo.is_ptr() or tinfo.is_array():
            tinfo.remove_ptr_or_array()
        if tinfo.is_udt():
            return tinfo.get_ordinal()
        elif tinfo.is_enum():
            return tinfo.get_ordinal()
        elif tinfo.is_typeref():
            typeref_ordinal = tinfo.get_ordinal()
            if typeref_ordinal:
                typeref_tinfo = StructureGraph.get_tinfo_by_ordinal(typeref_ordinal)
                if typeref_tinfo is None:
                    logger.warn("You have dependencies of deleted %s type", tinfo.dstr())
                    return 0

                if typeref_tinfo.is_typeref() or typeref_tinfo.is_udt() or typeref_tinfo.is_ptr():
                    return typeref_ordinal
        return 0

    @staticmethod
    def get_members_ordinals(tinfo):
        ordinals = []
        if tinfo.is_udt():
            udt_data = idaapi.udt_type_data_t()
            tinfo.get_udt_details(udt_data)
            for udt_member in udt_data:
                ordinal = StructureGraph.get_ordinal(udt_member.type)
                if ordinal:
                    ordinals.append(ordinal)
        return ordinals

    @staticmethod
    def get_tinfo_by_ordinal(ordinal):
        local_typestring = idc.GetLocalTinfo(ordinal)
        if local_typestring:
            p_type, fields = local_typestring
            local_tinfo = idaapi.tinfo_t()
            local_tinfo.deserialize(idaapi.cvar.idati, p_type, fields)
            return local_tinfo
        return None

    def initialize_nodes(self):
        for ordinal in xrange(1, idc.GetMaxLocalType()):
            # if ordinal == 15:
            #     import pydevd
            #     pydevd.settrace("localhost", port=12345, stdoutToServer=True, stderrToServer=True)

            local_tinfo = StructureGraph.get_tinfo_by_ordinal(ordinal)
            if not local_tinfo:
                continue
            name = idc.GetLocalTypeName(ordinal)

            if local_tinfo.is_typeref():
                typeref_ordinal = local_tinfo.get_ordinal()
                members_ordinals = []
                if typeref_ordinal:
                    typeref_tinfo = StructureGraph.get_tinfo_by_ordinal(typeref_ordinal)
                    if typeref_tinfo.is_typeref() or typeref_tinfo.is_udt() or typeref_tinfo.is_ptr():
                        members_ordinals = [typeref_ordinal]
                cdecl_typedef = idaapi.print_tinfo(None, 4, 5, 0x3, local_tinfo, None, None)
                self.local_types[ordinal] = LocalType(name, members_ordinals, cdecl_typedef, is_typedef=True)
            elif local_tinfo.is_udt():
                # udt_data = idaapi.udt_type_data_t()
                # local_tinfo.get_udt_details(udt_data)
                members_ordinals = StructureGraph.get_members_ordinals(local_tinfo)
                cdecl_typedef = idaapi.print_tinfo(None, 4, 5, 0x1, local_tinfo, None, None)
                self.local_types[ordinal] = LocalType(name, members_ordinals, cdecl_typedef, is_union=local_tinfo.is_union())
            elif local_tinfo.is_ptr():
                typeref_ordinal = StructureGraph.get_ordinal(local_tinfo)
                members_ordinals = [typeref_ordinal] if typeref_ordinal else []
                cdecl_typedef = idaapi.print_tinfo(None, 4, 5, 0x2, local_tinfo, None, None)
                self.local_types[ordinal] = LocalType(
                    name,
                    members_ordinals,
                    cdecl_typedef + ' *',
                    is_typedef=True
                )
            elif local_tinfo.is_enum():
                cdecl_typedef = idaapi.print_tinfo(None, 4, 5, 0x21, local_tinfo, None, None)
                self.local_types[ordinal] = LocalType(name, [], cdecl_typedef, is_enum=True)

        self.ordinal_list = set(self.ordinal_list).intersection(self.local_types)
        for ordinal in self.ordinal_list:
            self.local_types[ordinal].is_selected = True

    def calculate_edges(self):
        for first in self.local_types.keys():
            for second in self.local_types[first].members_ordinals:
                self.edges.append((first, second))

        self.downward_edges = {key: [] for key in self.local_types.keys()}
        self.upward_edges = {key: [] for key in self.local_types.keys()}

        for key, value in self.edges:
            self.downward_edges[key].append(value)
            self.upward_edges[value].append(key)

    def generate_final_edges_down(self, node):
        if node not in self.visited_downward:
            self.visited_downward.append(node)
        else:
            return
        for next_node in self.downward_edges[node]:
            self.final_edges.append((node, next_node))
        for next_node in self.downward_edges[node]:
            self.generate_final_edges_down(next_node)

    def generate_final_edges_up(self, node):
        if node not in self.visited_upward:
            self.visited_upward.append(node)
        else:
            return
        for next_node in self.upward_edges[node]:
            self.final_edges.append((next_node, node))
        for next_node in self.upward_edges[node]:
            self.generate_final_edges_up(next_node)

    def get_nodes(self):
        for ordinal in self.ordinal_list:
            if ordinal in self.local_types:
                self.generate_final_edges_down(ordinal)
                self.generate_final_edges_up(ordinal)
        return set([node for nodes in self.final_edges for node in nodes])

    def get_edges(self):
        return self.final_edges
