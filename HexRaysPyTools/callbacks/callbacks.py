from collections import defaultdict
import idaapi


class HexRaysCallbackManager(object):
    def __init__(self):
        self.__hexrays_event_handlers = defaultdict(list)

    def initialize(self):
        idaapi.install_hexrays_callback(self.__handle)

    def finalize(self):
        idaapi.remove_hexrays_callback(self.__handle)

    def register(self, event, handler):
        self.__hexrays_event_handlers[event].append(handler)

    def __handle(self, event, *args):
        for handler in self.__hexrays_event_handlers[event]:
            handler.handle(event, *args)
        # IDA expects zero
        return 0


hx_callback_manager = HexRaysCallbackManager()


class HexRaysEventHandler(object):
    def __init__(self):
        super(HexRaysEventHandler, self).__init__()

    def handle(self, event, *args):
        raise NotImplementedError("This is an abstract class")
