import os


def get_roles(directory):
    roles = []

    _rolesdir = "%s/roles/" % directory
    for _role in os.listdir(_rolesdir):
        _roledir = "%s/%s" % (_rolesdir, _role)
        if not os.path.isdir(_roledir) or \
           not os.path.isdir("%s/meta" % _roledir) or \
           not os.path.isdir("%s/tasks" % _roledir):
            continue
        roles.append(_role)

    return sorted(roles)


def get_modules(directory):
    management_modules = []
    roles_modules = []

    for root, _dirs, files in os.walk(directory):
        if not root.startswith("%s/plugins/" % directory) and \
           not root.startswith("%s/roles/" % directory):
            continue
        for _file in files:
            if _file.endswith(".py"):
                if root == "%s/plugins/modules" % directory:
                    management_modules.append(_file[:-3])
                elif root.startswith("%s/roles/" % directory):
                    if root.endswith("/library"):
                        roles_modules.append(_file[:-3])

    return sorted(management_modules), sorted(roles_modules)


BASE_DIR = os.path.abspath(os.path.dirname(__file__) + "/..")
ROLES = get_roles(BASE_DIR)
MANAGEMENT_MODULES, ROLES_MODULES = get_modules(BASE_DIR)
ALL_MODULES = sorted(MANAGEMENT_MODULES + ROLES_MODULES)
