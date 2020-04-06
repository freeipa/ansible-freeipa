import sys
import re


def galaxify_playbook(playbook_in, project_prefix, collection_prefix):
    p1 = re.compile('(%s.*:)$' % project_prefix)
    p2 = re.compile('(.*:) (%s.*)$' % project_prefix)
    lines = []

    pattern1 = r'%s.\1' % collection_prefix
    pattern2 = r'\1 %s.\2' % collection_prefix

    with open(playbook_in) as in_f:
        changed = False
        changeable = False
        include_role = False
        for line in in_f:
            stripped = line.strip()
            if stripped.startswith("- name:") or \
               stripped.startswith("- block:"):
                changeable = True
            elif stripped in ["set_fact:", "vars:"]:
                changeable = False
                include_role = False
            elif stripped.startswith("include_role:"):
                include_role = True
            elif include_role and stripped.startswith("name:"):
                line = p2.sub(pattern2, line)
                changed = True
            elif changeable and stripped.startswith("- role:"):
                line = p2.sub(pattern2, line)
                changed = True
            elif changeable and not stripped.startswith(collection_prefix):
                line = p1.sub(pattern1, line)
                changed = True

            lines.append(line)

    if changed:
        with open(playbook_in, "w") as out_f:
            for line in lines:
                out_f.write(line)


galaxify_playbook(sys.argv[1], sys.argv[2], sys.argv[3])
