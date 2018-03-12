import logging

# TODO: Move this settings to separate `.config` file

DEBUG_MESSAGE_LEVEL = logging.DEBUG
# Whether propagate names (Propagate name feature) through all names or only defaults like v11, a3, this, field_4
PROPAGATE_THROUGH_ALL_NAMES = True
# Store Xref information in database. I don't know how much size it consumes yet
STORE_XREFS = True
