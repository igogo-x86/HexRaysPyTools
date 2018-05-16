import logging
import Settings

Settings.load_settings()
logging.basicConfig(format='[%(levelname)s] %(message)s\t(%(module)s:%(funcName)s)')
logging.root.setLevel(Settings.DEBUG_MESSAGE_LEVEL)

