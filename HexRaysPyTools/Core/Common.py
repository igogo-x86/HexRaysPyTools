import re


BAD_C_NAME_PATTERN = re.compile('[^a-zA-Z_0-9:]')


def demangled_name_to_c_str(name):
    """
    Removes or replaces characters from demangled symbol so that it was possible to create legal C structure from it
    """
    if not BAD_C_NAME_PATTERN.findall(name):
        return name

    name = name.replace("~", "DESTRUCTOR_")
    name = name.replace("*", "_PTR")
    name = name.replace("<", "_t_")
    name = name.replace(">", "_t_")

    name = "_".join(filter(len, BAD_C_NAME_PATTERN.split(name)))
    return name
