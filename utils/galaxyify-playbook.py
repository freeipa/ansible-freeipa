import sys
import re


def galaxify_playbook(playbook_in):
    p1 = re.compile('(ipa.*:)$')
    p2 = re.compile('(.*:) (ipa.*)$')
    lines = []

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
                line = p2.sub(r'\1 freeipa.ansible_freeipa.\2', line)
                changed = True
            elif changeable and stripped.startswith("- role:"):
                line = p2.sub(r'\1 freeipa.ansible_freeipa.\2', line)
                changed = True
            elif changeable and not stripped.startswith(
                    "freeipa.ansible_freeipa."):
                line = p1.sub(r'freeipa.ansible_freeipa.\1', line)
                changed = True

            lines.append(line)

    if changed:
        with open(playbook_in, "w") as out_f:
            for line in lines:
                out_f.write(line)


galaxify_playbook(sys.argv[1])
