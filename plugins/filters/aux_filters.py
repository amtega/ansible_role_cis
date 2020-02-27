"""
Filters: good_rsyslog_perms.

Filters:
    good_rsyslog_perms: Auxiliary function for check 4.2.1.3
"""
from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

from ansible.errors import AnsibleFilterError
from ansible.utils import helpers


def good_rsyslog_perms(grep_stdout_lines):
    """
        Auxiliary function for check 4.2.1.3

        Parses the output of:
        grep "^\\$FileCreateMode" /etc/rsyslog.conf /etc/rsyslog.d/*.conf
        and checks that permission is 0640 or more restrictive
    """
    if not grep_stdout_lines:
        return False

    result = True
    for line in grep_stdout_lines:
        line_fields = line.split()
        permission = int(line_fields[1], 8)
        bad_permission = bool(permission & ~  0o0640)
        print("{} {}".format(permission, bad_permission))
        result = result and not bad_permission

    return result

# ---- Ansible filters ----
class FilterModule(object):
    def filters(self):
        return {"good_rsyslog_perms": good_rsyslog_perms}
