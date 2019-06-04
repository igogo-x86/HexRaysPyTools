from collections import defaultdict
import idaapi


class EventMediator(object):
    def __init__(self):
        self.__handlers = defaultdict(list)
        self.__popup_actions = list()

    def register_handler(self, event, handler):
        self.__handlers[event].append(handler)

    def register_popup_action(self, event, action):
        self.__handlers[event].append(PopupRequestHandler(action))
        self.__popup_actions.append(action)

    def handle(self, event, *args):
        for handler in self.__handlers[event]:
            handler.handle(event, *args)
        return 0

    def initialize(self):
        for action in self.__popup_actions:
            idaapi.register_action(
                idaapi.action_desc_t(action.name, action.description, action, action.hotkey)
            )
        idaapi.install_hexrays_callback(self.handle)

    def finalize(self):
        for action in self.__popup_actions:
            idaapi.unregister_action(action.name)
        # FIXME: Do we really need it here? May be we should just install callback in constructor?
        idaapi.remove_hexrays_callback(self.handle)


event_mediator = EventMediator()


class EventHandler(object):

    def __init__(self):
        super(EventHandler, self).__init__()

    def handle(self, event, *args):
        raise NotImplementedError


class PopupRequestHandler(EventHandler):
    description = "No description provided"
    hotkey = None

    def __init__(self, action):
        super(PopupRequestHandler, self).__init__()
        self.__action = action

    def handle(self, event, *args):
        if self.__action.check(*args):
            form, popup = args[0:2]
            idaapi.attach_action_to_popup(form, popup, self.__action.name, None)
        return 0


class Action(idaapi.action_handler_t):
    description = "No description provided"
    hotkey = None

    def __init__(self):
        super(Action, self).__init__()

    @property
    def name(self):
        return "HexRaysPyTools:" + type(self).__name__

    def check(self, *args):
        raise NotImplementedError

    def activate(self, ctx):
        raise NotImplementedError

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
