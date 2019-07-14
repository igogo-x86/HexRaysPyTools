from collections import namedtuple, defaultdict
import json
import logging

import idaapi
import helper
import HexRaysPyTools.settings as settings

logger = logging.getLogger(__name__)

XrefInfo = namedtuple('XrefInfo', ['func_ea', 'offset', 'line', 'type'])


def singleton(cls):
    instances = {}

    def get_instance():
        if cls not in instances:
            instances[cls] = cls()
        return instances[cls]
    return get_instance


@singleton
class XrefStorage(object):
    ARRAY_NAME = "$HexRaysPyTools:XrefStorage"

    def __init__(self):
        """
        storage - {ordinal: {func_offset: (code_offset, line, usage_type)}}
        __delete_items_helper - {func_offset: set(ordinals)}
        """
        self.storage = None
        self.__delete_items_helper = defaultdict(set)

    def open(self):
        if not settings.STORE_XREFS:
            self.storage = {}
            return

        result = helper.load_long_str_from_idb(self.ARRAY_NAME)
        if result:
            try:
                self.storage = json.loads(result, object_hook=self.json_keys_to_str)
                self.__init_delete_helper()
                return
            except ValueError:
                logger.error("Failed to read previous info about Xrefs. Try Ctrl+F5 to cache data")
        self.storage = {}

    def close(self):
        self.save()
        self.storage = None
        self.__delete_items_helper = defaultdict(set)

    def save(self):
        if not settings.STORE_XREFS:
            return

        if self.storage:
            helper.save_long_str_to_idb(self.ARRAY_NAME, json.dumps(self.storage))

    def update(self, function_offset, data):
        """ data - {ordinal : (code_offset, line, usage_type)} """
        for ordinal, info in data.items():
            self.__update_ordinal_info(ordinal, function_offset, info)

        deleted_ordinals = self.__delete_items_helper[function_offset].difference(data.keys())
        for ordinal in deleted_ordinals:
            self.__remove_ordinal_info(ordinal, function_offset)

    def get_structure_info(self, ordinal, struct_offset):
        """ By given ordinal and offset within a structure returns dictionary {func_address -> list(offsets)} """
        result = []

        if ordinal not in self.storage:
            return result

        for func_offset, info in self.storage[ordinal].items():
            if struct_offset in info:
                func_ea = func_offset + idaapi.get_imagebase()
                for xref_info in info[struct_offset]:
                    offset, line, usage_type = xref_info
                    result.append(XrefInfo(func_ea, offset, line, usage_type))
        return result

    @staticmethod
    def json_keys_to_str(x):
        if isinstance(x, dict):
            return {int(k): v for k, v in x.items()}
        return x

    def __len__(self):
        return len(str(self.storage))

    def __init_delete_helper(self):
        for ordinal, data in self.storage.items():
            for func_offset in data:
                self.__delete_items_helper[func_offset].add(ordinal)

    def __remove_ordinal_info(self, ordinal, function_offset):
        del self.storage[ordinal][function_offset]
        self.__delete_items_helper[function_offset].remove(ordinal)

    def __update_ordinal_info(self, ordinal, function_offset, info):
        if ordinal not in self.storage:
            self.storage[ordinal] = {}
        self.storage[ordinal][function_offset] = info
        self.__delete_items_helper[function_offset].add(ordinal)
