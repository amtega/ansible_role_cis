# Make coding more python3-ish
"""
Tests: cis_search_words, good_rsyslog_perms.

Tests:
    cis_search_words: Test if given words compose a string
    good_rsyslog_perms: Auxiliary function for check 4.2.1.3
"""
from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.utils.display import Display

DISPLAY = Display()


def cis_search_words(string, words):
    """Test if given words compose a string.

    Args:
        string (string): string to search in
        words (string): strings with the words to search

    Returns:
        bool: true if all words are present or false if any word is missing
                or any string component is not in words.
    """
    set_string = set(string.split(" "))
    set_words = set(words.split(" "))
    return set_string == set_words


def all_at_least_restrictive_as(find_list, reference_permission):
    """
        Auxiliary function for check 4.2.4

        Compares two permission strings and returns True when the reference
        octal permission is equally or more restrictive
    """
    result = True
    for found_file in find_list:
        path = found_file["path"]
        mode = found_file["mode"]
        regular_file = found_file["isreg"]
        if not regular_file or at_least_restrictive_as(mode, reference_permission):
            continue
        else:
            DISPLAY.warning(
                'check 4.2.4: Insecure permission (%s %s)' % (mode, path))
            result = False
    return result


def at_least_restrictive_as(str_permission, str_reference_permission):
    """
        Auxiliary function for "all_at_least_restrictive_as"

        Compares two permission strings and returns True when the reference is
        equally or more restrictive
    """
    def str_to_perm(str_perm):
        """Convert a permission in string format to binary"""
        return int(str_perm, 8)

    permission = str_to_perm(str_permission)
    reference_permission = str_to_perm(str_reference_permission)
    is_more_permissive = bool(permission & ~ reference_permission)
    return not is_more_permissive


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


def iptables_contains_ports(iptables_stdout_lines, open_ports):
    """
        Auxiliary function for check 3.6.5

        Parses the output of:
        iptables -L -v -n
        and checks that any ports that have been opened on non-loopback
        addresses need firewall rules to govern traffic.
    """

    def parse_multiport(ports_to_parse):
        # Example: 1500:1501,1552:1553,1581
        ports_parsed = []
        chunks = ports_to_parse.split(',')
        for chunk in chunks:
            if ':' in chunk:
                begin, end = map(int, chunk.split(':'))
                ports_parsed.extend(range(begin, end + 1))
            else:
                ports_parsed.append(int(chunk))
        return ports_parsed

    open_port_set = set()
    for port in open_ports:
        if (port["address"] == '::1' or port["address"].startswith('127.')):
            continue  # Exclude loopback
        open_port_set |= set([(port["protocol"], port["port"])])

    iptables_port_set = set()
    for line in iptables_stdout_lines:
        if ('dpt' in line or 'dports' in line):
            split_line = line.split()
            protocol = split_line[3]
            if 'dpt' in line:
                port = int(split_line[-1].split(':')[1])
                iptables_port_set |= set([(protocol, port)])
            else:
                ports = parse_multiport(split_line[-1])
                for port in ports:
                    iptables_port_set |= set([(protocol, port)])
    return (open_port_set - iptables_port_set) == set()


def user_system_not_login(etc_passwd_lines):
    """
        Auxiliary function for check 5.4.2

        Parses /etc/passwd lines and checks that system accounts are non-login
    """
    result = True
    for line in etc_passwd_lines.split('\n'):
        if line == "":
            continue
        line_split = line.split(':')
        if len(line_split) != 7:
            DISPLAY.warning(
                'user_system_not_login:Strange /etc/passwd line:\n%s' % (line))
            continue
        (login, _passw, uid, _gid, _gecos, _directory, shell) = line_split
        uid = int(uid)
        shell = shell.strip()
        if login.startswith('+') or login in ['root', 'sync', 'shutdown',
                                              'halt']:
            continue
        elif uid >= 1000:
            continue
        elif shell in ['/sbin/nologin', '/bin/false']:
            continue
        else:
            DISPLAY.warning('check 5.4.2: Sytem user %s have shell %s' % (login, shell))
            result = False
    return result


def passwd_field_not_empty(etc_passwd_lines):
    """
        Auxiliary function for check 6.2.1

        Parses /etc/passwd lines and checks that password fields are not empty
    """
    result = True
    for line in etc_passwd_lines.split('\n'):
        if line == "":
            continue
        line_split = line.split(':')
        if len(line_split) != 7:
            DISPLAY.warning(
                'passwd_field_not_empty:Strange /etc/passwd line:\n%s' % (line))
            continue
        (login, passw, _uid, _gid, _gecos, _directory, _shell) = line_split
        if passw == "":
            DISPLAY.warning('check 6.2.1: User without password: %s' % (login))
            result = False
    return result


class TestModule:
    """ Ansible tests """

    def tests(self):
        return {
            "all_at_least_restrictive_as": all_at_least_restrictive_as,
            "cis_search_words": cis_search_words,
            'good_rsyslog_perms': good_rsyslog_perms,
            'iptables_contains_ports': iptables_contains_ports,
            'passwd_field_not_empty': passwd_field_not_empty,
            'user_system_not_login': user_system_not_login,
            }
