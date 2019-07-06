from collections import defaultdict
import idaapi


class CallbackManager(object):
    __flags = idaapi.NW_OPENIDB | idaapi.NW_CLOSEIDB | idaapi.NW_INITIDA | idaapi.NW_REMOVE | idaapi.NW_TERMIDA

    def __init__(self):
        self.__hexrays_event_handlers = defaultdict(list)
        self.__database_event_handlers = defaultdict(list)

    def initialize(self):
        idaapi.install_hexrays_callback(self.__handle_hexrays_event)
        idaapi.notify_when(self.__flags, self.__handle_database_event)

    def finalize(self):
        idaapi.remove_hexrays_callback(self.__handle_hexrays_event)
        idaapi.notify_when(self.__flags, idaapi.NW_REMOVE)

    def register(self, event, handler):
        if isinstance(handler, DatabaseEventHandler):
            self.__database_event_handlers[event].append(handler)
        elif isinstance(handler, HexRaysEventHandler):
            self.__hexrays_event_handlers[event].append(handler)

    def __handle_hexrays_event(self, event, *args):
        for handler in self.__hexrays_event_handlers[event]:
            handler.handle(event, *args)
        # IDA expects zero
        return 0

    def __handle_database_event(self, event, *args):
        for handler in self.__database_event_handlers[event]:
            handler.handle(event, *args)
        # IDA expects zero
        return 0


callback_manager = CallbackManager()


class EventHandler(object):
    """
    Abstract class for event callback. You should inherent it, implement `handle` method and register in
    EventHandlerManager.
    """
    def __init__(self):
        super(EventHandler, self).__init__()

    def handle(self, event, *args):
        raise NotImplementedError("This is an abstract class")


class DatabaseEventHandler(EventHandler):
    def __init__(self):
        super(DatabaseEventHandler, self).__init__()

    def handle(self, event, *args):
        raise NotImplementedError("This is an abstract class")


class HexRaysEventHandler(EventHandler):
    def __init__(self):
        super(HexRaysEventHandler, self).__init__()

    def handle(self, event, *args):
        raise NotImplementedError("This is an abstract class")
