import sys
import yaml
from facts import MANAGEMENT_MODULES


def create_action_group(yml_file, project_prefix):
    yaml_data = None
    with open(yml_file) as f_in:
        yaml_data = yaml.safe_load(f_in)

    yaml_data.setdefault("action_groups", {})[
        "%s.modules" % project_prefix
    ] = MANAGEMENT_MODULES

    with open(yml_file, 'w') as f_out:
        yaml.safe_dump(yaml_data, f_out, default_flow_style=False,
                       explicit_start=True)


if len(sys.argv) != 3:
    print("Usage: %s <runtime file> <collection prefix>" % sys.argv[0])
    sys.exit(-1)

create_action_group(sys.argv[1], sys.argv[2])
