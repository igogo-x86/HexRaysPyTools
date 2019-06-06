from collections import defaultdict
import idaapi


class EventManager(object):
    def __init__(self):
        self.__handlers = defaultdict(list)

    def register_handler(self, event, handler):
        self.__handlers[event].append(handler)

    def handle(self, event, *args):
        for handler in self.__handlers[event]:
            handler.handle(event, *args)
        # IDA expects zero
        return 0

    def initialize(self):
        raise NotImplementedError

    def finalize(self):
        raise NotImplementedError


class HexRaysEventManager(EventManager):
    def __init__(self):
        super(HexRaysEventManager, self).__init__()

    def initialize(self):
        """ This method should be called only after HexRays plugin was initialized """
        idaapi.install_hexrays_callback(self.handle)

    def finalize(self):
        idaapi.remove_hexrays_callback(self.handle)


hx_event_manager = HexRaysEventManager()


class DataBaseEventManager(EventManager):
    flags = idaapi.NW_OPENIDB | idaapi.NW_CLOSEIDB | idaapi.NW_INITIDA | idaapi.NW_REMOVE | idaapi.NW_TERMIDA

    def initialize(self):
        idaapi.notify_when(self.flags, database_event_manager.handle)

    def finalize(self):
        idaapi.notify_when(self.flags | idaapi.NW_REMOVE)


database_event_manager = DataBaseEventManager()


class EventHandler(object):
    """
    Abstract class for event callback. You should inherent it, implement `handle` method and register in
    EventHandlerManager.
    """
    def __init__(self):
        super(EventHandler, self).__init__()

    def handle(self, event, *args):
        raise NotImplementedError("This is an abstract class")


class PopupRequestHandler(EventHandler):
    """
    This is wrapper around PopupAction which allows to dynamically decide whether to add Action to popup menu or not.
    Register this in EventHandlerManager with event=idaapi.hxe_populating_popup.
    """
    def __init__(self, action):
        super(PopupRequestHandler, self).__init__()
        self.__action = action

    def handle(self, event, *args):
        if self.__action.check(*args):
            form, popup = args[0:2]
            idaapi.attach_action_to_popup(form, popup, self.__action.name, None)
        return 0
