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
# There're some types that can be pointers to structures like int, PVOID etc and by default plugin scans only them
# Full list can be found in `Const.LEGAL_TYPES`.
# But if set this option to True than variable of every type could be possible to scan
SCAN_ANY_TYPE = False


def add_default_settings(config):
    updated = False
    if not config.has_option("DEFAULT", "DEBUG_MESSAGE_LEVEL"):
        print DEBUG_MESSAGE_LEVEL
        config.set(None, 'DEBUG_MESSAGE_LEVEL', str(DEBUG_MESSAGE_LEVEL))
        updated = True
    if not config.has_option("DEFAULT", "PROPAGATE_THROUGH_ALL_NAMES"):
        config.set(None, 'PROPAGATE_THROUGH_ALL_NAMES', str(PROPAGATE_THROUGH_ALL_NAMES))
        updated = True
    if not config.has_option("DEFAULT", "STORE_XREFS"):
        config.set(None, 'STORE_XREFS', str(STORE_XREFS))
        updated = True
    if not config.has_option("DEFAULT", "SCAN_ANY_TYPE"):
        config.set(None, 'SCAN_ANY_TYPE', str(SCAN_ANY_TYPE))
        updated = True

    if updated:
        try:
            with open(CONFIG_FILE_PATH, "w") as f:
                config.write(f)
        except IOError:
            print "[ERROR] Failed to write or update config file at {}. Default settings will be used instead.\n" \
                  "Consider running IDA Pro under administrator once".format(CONFIG_FILE_PATH)


def load_settings():
    global DEBUG_MESSAGE_LEVEL, PROPAGATE_THROUGH_ALL_NAMES, STORE_XREFS, SCAN_ANY_TYPE

    config = ConfigParser.ConfigParser()
    if os.path.isfile(CONFIG_FILE_PATH):
        config.read(CONFIG_FILE_PATH)

    add_default_settings(config)

    DEBUG_MESSAGE_LEVEL = config.getint("DEFAULT", 'DEBUG_MESSAGE_LEVEL')
    PROPAGATE_THROUGH_ALL_NAMES = config.getboolean("DEFAULT", 'PROPAGATE_THROUGH_ALL_NAMES')
    STORE_XREFS = config.getboolean("DEFAULT", 'STORE_XREFS')
    SCAN_ANY_TYPE = config.getboolean("DEFAULT", 'SCAN_ANY_TYPE')
