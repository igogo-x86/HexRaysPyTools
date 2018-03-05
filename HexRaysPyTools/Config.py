import HexRaysPyTools.Actions as Actions
import HexRaysPyTools.Forms as Forms
import ConfigParser
import idc
import os.path
import ida_kernwin
import ida_diskio

hex_pytools_config = None

class Config(object):

    def __init__(self):
        global hex_pytools_config
        self.section = "HexRaysPyTools features"
        self.file_path = os.path.join(ida_diskio.idadir(""),"cfg", "HexRaysPyTools.cfg")
        self.reader = ConfigParser.SafeConfigParser()
        self.reader.optionxform = str
        self.actions, self.action_names = self.GetDefActions()
        self.actions_refs = self.GetActionsRefs()
        hex_pytools_config = self
        try:
            f = open(self.file_path, "ab")
            f.close()
        except:
            print("Cannot open config file.")
            self.file_path = os.path.join(os.environ["APPDATA"],"IDA Pro","cfg", "HexRaysPyTools.cfg")
            if not os.path.exists(os.path.join(os.environ["APPDATA"], "IDA Pro", "cfg")):
                os.makedirs(os.path.join(os.environ["APPDATA"], "IDA Pro", "cfg"))
            f = open(self.file_path, "ab")
            f.close()
        try:
            f = open(self.file_path, "rb")
            self.reader.readfp(f)
            f.close()
            fRewrite = False
            for ac in self.actions:
                if self.reader.has_option(self.section,ac):
                    self.actions[ac] = self.reader.getboolean(self.section,ac)
                else:
                    fRewrite = True
            if fRewrite:
                self.write_config()

        except ConfigParser.NoSectionError:
            self.actions, self.action_names = self.GetDefActions()
            del self.reader
            self.reader = ConfigParser.SafeConfigParser()
            self.reader.optionxform = str
            self.reader.add_section(self.section)
            for ac in self.actions:
                self.reader.set(self.section, ac, "true" if self.actions[ac] else "false")
            f = open(self.file_path, "wb")
            self.reader.write(f)
            f.close()

    def __getitem__(self, item):
        if item in self.action_names:
            return self.actions[self.action_names[item]]
        if item in self.actions:
            return self.actions[item]
        return False

    def write_config(self):
        for ac in self.actions:
            self.reader.set(self.section, ac, "true" if self.actions[ac] else "false")
        f = open(self.file_path, "w+b")
        self.reader.write(f)
        f.close()

    def update(self, vals):
        for key in vals:
            if key in self.action_names:
                self.actions[self.action_names[key]] = vals[key]
            if key in self.actions:
                self.actions[key] = vals[key]
        self.write_config()

    def modify(self):
        f = Forms.ConfigFeatures(self)
        f.Do()
        f.Free()

    def GetActionsRefs(self):
        ret = {}
        md = Actions.__dict__
        for c in md:
            if isinstance(md[c], type) and md[c].__module__ == Actions.__name__ and (md[c].__base__ == ida_kernwin.action_handler_t or md[c].__base__.__base__ == ida_kernwin.action_handler_t):
                ret[c] = md[c]
        return ret

    @staticmethod
    def GetDefActions():
        md = Actions.__dict__
        ret = {}
        ret2 = {}
        for c in md:
            if isinstance(md[c], type) and md[c].__module__ == Actions.__name__ and (md[c].__base__ == ida_kernwin.action_handler_t or md[c].__base__.__base__ == ida_kernwin.action_handler_t):
                ret[c] = True
                ret2[md[c].name] = c
        return (ret,ret2)