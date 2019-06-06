import idaapi
from ..callbacks import hx_event_manager, PopupRequestHandler


class ActionManager(object):
    def __init__(self):
        self.__actions = []

    def register(self, action):
        self.__actions.append(action)
        if isinstance(action, PopupAction):
            hx_event_manager.register_handler(idaapi.hxe_populating_popup, PopupRequestHandler(action))

    def initialize(self):
        for action in self.__actions:
            idaapi.register_action(
                idaapi.action_desc_t(action.name, action.description, action, action.hotkey)
            )

    def finalize(self):
        for action in self.__actions:
            idaapi.unregister_action(action.name)


action_manager = ActionManager()


class Action(idaapi.action_handler_t):
    """
    Wrapper which has `check
    """

    def __init__(self):
        super(Action, self).__init__()

    @property
    def name(self):
        return "HexRaysPyTools:" + type(self).__name__

    def activate(self, ctx):
        raise NotImplementedError

    def update(self, ctx):
        raise NotImplementedError


class PopupAction(Action):
    """
    Wrapper which has `check
    """

    def __init__(self):
        super(PopupAction, self).__init__()

    def check(self, *args):
        raise NotImplementedError
