from gi.repository import Gdk, Gtk

try:
    from ns3.visualizer.base import InformationWindow
except ModuleNotFoundError:
    from visualizer.base import InformationWindow


## ShowOlsrRoutingTable class
class ShowOlsrRoutingTable(InformationWindow):
    ## @var win
    #  window
    ## @var visualizer
    #  visualizer
    ## @var node_index
    #  node index
    ## @var table_model
    #  table model
    ## @var _response_cb
    #  _response_cb function
    ## @var COLUMN_DESTINATION
    #  COLUMN_DESTINATION constant
    ## @var COLUMN_NEXT_HOP
    #  COLUMN_NEXT_HOP constant
    ## @var COLUMN_INTERFACE
    #  COLUMN_INTERFACE constant
    ## @var COLUMN_NUM_HOPS
    #  COLUMN_NUM_HOPS constant
    (
        COLUMN_DESTINATION,
        COLUMN_NEXT_HOP,
        COLUMN_INTERFACE,
        COLUMN_NUM_HOPS,
    ) = range(4)

    def __init__(self, visualizer, node_index):
        """!
        Initializer
        @param self this object
        @param visualizer visualizer object
        @param node_index the node index
        """
        InformationWindow.__init__(self)
        self.win = Gtk.Dialog(
            parent=visualizer.window,
            flags=Gtk.DialogFlags.DESTROY_WITH_PARENT,
            buttons=("_Close", Gtk.ResponseType.CLOSE),
        )
        self.win.set_default_size(Gdk.Screen.width() / 2, Gdk.Screen.height() / 2)
        self.win.connect("response", self._response_cb)
        self.win.set_title("OLSR routing table for node %i" % node_index)
        self.visualizer = visualizer
        self.node_index = node_index

        self.table_model = Gtk.ListStore(str, str, str, int)

        treeview = Gtk.TreeView(self.table_model)
        treeview.show()
        sw = Gtk.ScrolledWindow()
        sw.set_properties(
            hscrollbar_policy=Gtk.PolicyType.AUTOMATIC, vscrollbar_policy=Gtk.PolicyType.AUTOMATIC
        )
        sw.show()
        sw.add(treeview)
        self.win.vbox.add(sw)

        # Dest.
        column = Gtk.TreeViewColumn(
            "Destination", Gtk.CellRendererText(), text=self.COLUMN_DESTINATION
        )
        treeview.append_column(column)

        # Next hop
        column = Gtk.TreeViewColumn("Next hop", Gtk.CellRendererText(), text=self.COLUMN_NEXT_HOP)
        treeview.append_column(column)

        # Interface
        column = Gtk.TreeViewColumn("Interface", Gtk.CellRendererText(), text=self.COLUMN_INTERFACE)
        treeview.append_column(column)

        # Num. Hops
        column = Gtk.TreeViewColumn("Num. Hops", Gtk.CellRendererText(), text=self.COLUMN_NUM_HOPS)
        treeview.append_column(column)

        self.visualizer.add_information_window(self)
        self.win.show()

    def _response_cb(self, win, response):
        """!
        Initializer
        @param self this object
        @param win the window
        @param response the response
        @return none
        """
        self.win.destroy()
        self.visualizer.remove_information_window(self)

    def update(self):
        """!
        Update function
        @param self this object
        @return none
        """
        node = ns.NodeList.GetNode(self.node_index)
        ipv4 = node.GetObject(ns.Ipv4.GetTypeId())
        if not ns.cppyy.gbl.hasOlsr(ns3_node):
            return
        olsr = ns.cppyy.gbl.getNodeOlsr(node)

        self.table_model.clear()
        for route in olsr.GetRoutingTableEntries():
            tree_iter = self.table_model.append()
            netdevice = ipv4.GetNetDevice(route.interface)
            if netdevice is None:
                interface_name = "lo"
            else:
                interface_name = ns.Names.FindName(netdevice)
                if not interface_name:
                    interface_name = "(interface %i)" % route.interface
            self.table_model.set(
                tree_iter,
                self.COLUMN_DESTINATION,
                str(route.destAddr),
                self.COLUMN_NEXT_HOP,
                str(route.nextAddr),
                self.COLUMN_INTERFACE,
                interface_name,
                self.COLUMN_NUM_HOPS,
                route.distance,
            )


def populate_node_menu(viz, node, menu):
    ns3_node = ns.NodeList.GetNode(node.node_index)
    if not ns.cppyy.gbl.hasOlsr(ns3_node):
        print("No OLSR")
        return

    menu_item = Gtk.MenuItem("Show OLSR Routing Table")
    menu_item.show()

    def _show_ipv4_routing_table(dummy_menu_item):
        ShowOlsrRoutingTable(viz, node.node_index)

    menu_item.connect("activate", _show_ipv4_routing_table)
    menu.add(menu_item)


def register(viz):
    viz.connect("populate-node-menu", populate_node_menu)
