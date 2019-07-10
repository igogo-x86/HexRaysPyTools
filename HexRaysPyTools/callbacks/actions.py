import idaapi

from .callbacks import hx_callback_manager, HexRaysEventHandler


class ActionManager(object):
    def __init__(self):
        self.__actions = []

    def register(self, action):
        self.__actions.append(action)
        if isinstance(action, HexRaysPopupAction):
            hx_callback_manager.register(idaapi.hxe_populating_popup, HexRaysPopupRequestHandler(action))

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
    Convenience wrapper with name property allowing to be registered in IDA using ActionManager
    """
    description = None
    hotkey = None

    def __init__(self):
        super(Action, self).__init__()

    @property
    def name(self):
        return "HexRaysPyTools:" + type(self).__name__

    def activate(self, ctx):
        # type: (idaapi.action_activation_ctx_t) -> None
        raise NotImplementedError

    def update(self, ctx):
        # type: (idaapi.action_activation_ctx_t) -> None
        raise NotImplementedError


class HexRaysPopupAction(Action):
    """
    Wrapper around Action. Represents Action which can be added to menu after right-clicking in Decompile window.
    Has `check` method that should tell whether Action should be added to popup menu when different items
    are right-clicked.
    Children of this class can also be fired by hot-key without right-clicking if one provided in `hotkey`
    static member.
    """

    def __init__(self):
        super(HexRaysPopupAction, self).__init__()

    def activate(self, ctx):
        # type: (idaapi.action_activation_ctx_t) -> None
        raise NotImplementedError

    def check(self, hx_view):
        # type: (idaapi.vdui_t) -> bool
        raise NotImplementedError

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class HexRaysPopupRequestHandler(HexRaysEventHandler):
    """
    This is wrapper around HexRaysPopupAction which allows to dynamically decide whether to add Action to popup
    menu or not.
    Register this in CallbackManager.
    """
    def __init__(self, action):
        super(HexRaysPopupRequestHandler, self).__init__()
        self.__action = action

    def handle(self, event, *args):
        form, popup, hx_view = args
        if self.__action.check(hx_view):
            idaapi.attach_action_to_popup(form, popup, self.__action.name, None)
        return 0
