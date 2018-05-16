import os
import ConfigParser
import idc

import logging

CONFIG_FILE_PATH = os.path.join(idc.GetIdaDirectory(), 'cfg', 'HexRaysPyTools.cfg')

DEBUG_MESSAGE_LEVEL = logging.INFO
# Whether propagate names (Propagate name feature) through all names or only defaults like v11, a3, this, field_4
PROPAGATE_THROUGH_ALL_NAMES = False
# Store Xref information in database. I don't know how much size it consumes yet
STORE_XREFS = True


def add_default_settings(config):
    if not config.has_option("DEFAULT", "DEBUG_MESSAGE_LEVEL"):
        config.set(None, 'DEBUG_MESSAGE_LEVEL', logging.INFO)
    if not config.has_option("DEFAULT", "PROPAGATE_THROUGH_ALL_NAMES"):
        config.set(None, 'PROPAGATE_THROUGH_ALL_NAMES', False)
    if not config.has_option("DEFAULT", "STORE_XREFS"):
        config.set(None, 'STORE_XREFS', True)
    with open(CONFIG_FILE_PATH, "w") as f:
        config.write(f)


def load_settings():
    global DEBUG_MESSAGE_LEVEL, PROPAGATE_THROUGH_ALL_NAMES, STORE_XREFS

    config = ConfigParser.ConfigParser()
    if os.path.isfile(CONFIG_FILE_PATH):
        config.read(CONFIG_FILE_PATH)

    add_default_settings(config)

    DEBUG_MESSAGE_LEVEL = config.getint("DEFAULT", 'DEBUG_MESSAGE_LEVEL')
    PROPAGATE_THROUGH_ALL_NAMES = config.getboolean("DEFAULT", 'PROPAGATE_THROUGH_ALL_NAMES')
    STORE_XREFS = config.getboolean("DEFAULT", 'STORE_XREFS')
