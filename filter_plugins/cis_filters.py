# Make coding more python3-ish
from __future__ import absolute_import, division, print_function

__metaclass__ = type


def cis_script_variable_value(variable_declarations):
    """Parses script variable declaration lines and returns value

    Args:
        variable_declarations (string): string with variable declaration lines
            formated VAR=VALUE

    Returns:
        string: last value declared
    """

    if variable_declarations:
        return variable_declarations.split("\n")[-1].split("=")[1]
    else:
        return ""


class FilterModule(object):
    """Ansible win_domain_ous filters."""

    def filters(self):
        return {
            "cis_script_variable_value": cis_script_variable_value,
        }
