import idaapi
import idc


class StructureGraphViewer(idaapi.GraphViewer):
    def __init__(self, title, graph):
        idaapi.GraphViewer.__init__(self, title)
        self.graph = graph

    def OnRefresh(self):
        self.Clear()
        nodes_id = {}
        for node in self.graph.get_nodes():
            nodes_id[node] = self.AddNode(node)
        for first, second in self.graph.get_edges():
            self.AddEdge(nodes_id[first], nodes_id[second])
        return True

    def OnGetText(self, node_id):
        return self.graph.local_types[self[node_id]].name_and_color

    def OnHint(self, node_id):
        try:
            ordinal = self[node_id]
            return self.graph.local_types[ordinal].hint
        except KeyError:
            return

    def OnDblClick(self, node_id):
        self.graph.change_selected([self[node_id]])
        self.Refresh()


class LocalType:
    def __init__(self, name, members_ordinals, hint, selected=False, is_typedef=False):
        self.name = name
        self.members_ordinals = members_ordinals
        self.hint = hint
        self.selected = selected
        self.is_typedef = is_typedef

    def __call__(self):
        return self.name, self.members_ordinals

    def __str__(self):
        return "<{0}, {1}>".format(self.name, self.members_ordinals)

    def __repr__(self):
        return self.__str__()

    @property
    def name_and_color(self):
        return self.name, 0x0000FF if self.selected else 0x99FFFF if self.is_typedef else 0xffdd99


class StructureGraph:
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
            self.local_types[ordinal].selected = False
        self.ordinal_list = set(self.local_types).intersection(selected)
        for ordinal in self.ordinal_list:
            self.local_types[ordinal].selected = True

    @staticmethod
    def get_ordinal(tinfo):
        while tinfo.is_ptr() or tinfo.is_array():
            tinfo.remove_ptr_or_array()
        if tinfo.is_udt():
            return tinfo.get_ordinal()
        else:
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

    def initialize_nodes(self):
        for ordinal in xrange(1, idc.GetMaxLocalType()):
            local_typestring = idc.GetLocalTinfo(ordinal)
            if local_typestring:
                type, fields = local_typestring
                name = idc.GetLocalTypeName(ordinal)
                local_tinfo = idaapi.tinfo_t()
                local_tinfo.deserialize(idaapi.cvar.idati, type, fields)
                if local_tinfo.is_typeref():
                    typeref_ordinal = local_tinfo.get_ordinal()
                    if typeref_ordinal:
                        cdecl_typedef = idaapi.print_tinfo(None, 4, 5, 0x3, local_tinfo, None, None)
                        self.local_types[ordinal] = LocalType(name, [typeref_ordinal], cdecl_typedef, is_typedef=True)
                elif local_tinfo.is_udt():
                    udt_data = idaapi.udt_type_data_t()
                    local_tinfo.get_udt_details(udt_data)
                    members_ordinals = StructureGraph.get_members_ordinals(local_tinfo)
                    cdecl_typedef = idaapi.print_tinfo(None, 4, 5, 0x1, local_tinfo, None, None)
                    self.local_types[ordinal] = LocalType(name, members_ordinals, cdecl_typedef)
                elif local_tinfo.is_ptr():
                    typeref_ordinal = StructureGraph.get_ordinal(local_tinfo)
                    if typeref_ordinal:
                        cdecl_typedef = idaapi.print_tinfo(None, 4, 5, 0x2, local_tinfo, None, None)
                        print cdecl_typedef, local_tinfo.dstr()
                        self.local_types[ordinal] = LocalType(name, [typeref_ordinal], cdecl_typedef + ' *', is_typedef=True)

        self.ordinal_list = set(self.ordinal_list).intersection(self.local_types)
        for ordinal in self.ordinal_list:
            self.local_types[ordinal].selected = True

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


class ActionShowGraph(idaapi.action_handler_t):
    name = "my:ShowGraph"
    description = "Show graph"
    hotkey = "G"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        self.graph = None
        self.graph_view = None

    @staticmethod
    def generate():
        return idaapi.action_desc_t(
            ActionShowGraph.name,
            ActionShowGraph.description,
            ActionShowGraph(),
            ActionShowGraph.hotkey
        )

    def activate(self, ctx):
        """
        :param ctx: idaapi.action_activation_ctx_t
        :return:    None
        """
        form = self.graph_view.GetTForm() if self.graph_view else None
        if form:
            self.graph.change_selected(list(ctx.chooser_selection))
            self.graph_view.Refresh()
        else:
            self.graph = StructureGraph(list(ctx.chooser_selection))
            self.graph_view = StructureGraphViewer("Structure Graph", self.graph)
            self.graph_view.Show()

    def update(self, ctx):
        if ctx.form_type == idaapi.BWN_LOCTYPS:
            idaapi.attach_action_to_popup(ctx.form, None, self.name)
            return idaapi.AST_ENABLE_FOR_FORM
        else:
            return idaapi.AST_DISABLE_FOR_FORM
