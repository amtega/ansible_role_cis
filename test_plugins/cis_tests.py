# Make coding more python3-ish
"""
Tests: cis_search_words, cis_good_rsyslog_perms.

Tests:
    cis_search_words: Test if given words compose a string
    cis_good_rsyslog_perms: Auxiliary function for check 4.2.1.3
"""
from __future__ import absolute_import, division, print_function
import re

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


def cis_all_cis_at_least_restrictive_as(find_list, reference_permission):
    """Test permissions of a list files.

    Args:
        find_list (list): dicts result of the find module
        reference_permission (string): string with octal permission

    Returns:
        bool: true when the reference octal permission of all specified files
        is equally or more restrictive that the reference permission.
    """
    result = True
    for found_file in find_list:
        path = found_file["path"]
        mode = found_file["mode"]
        regular_file = found_file["isreg"]
        if not regular_file \
           or cis_at_least_restrictive_as(mode, reference_permission):
            continue
        else:
            DISPLAY.warning("check 4.2.4: Insecure permission (%s %s)"
                            % (mode, path))
            result = False
    return result


def cis_at_least_restrictive_as(str_permission, str_reference_permission):
    """Test two octal permissions.

    Args:
        str_permission (string): dicts result of the find module
        str_reference_permission (string): string with otcal permission

    Returns:
        bool: returns true when the reference is equally or more restrictive
    """

    permission = octal_str_to_int(str_permission)
    reference_permission = octal_str_to_int(str_reference_permission)
    is_more_permissive = bool(permission & ~reference_permission)
    return not is_more_permissive


def octal_str_to_int(str_perm):
    """Convert a octal permission in string format to integer

    Args:
        str_perm (string): octal string representing a file permission

    Returns:
        int: returns the permissions as int (it's bynary representation)
    """
    return int(str_perm, 8)


def cis_umasks_at_least_restrictive_as(commands, str_reference_permission):
    """Compare a list of umask commands against a reference octal permission.

    Args:
        commands (string list): umask commands in script
        str_reference_permission (string): reference umask

    Returns:
        bool: returns true when the reference is equally or more restrictive
    """

    def is_restrictive_enough(str_permission):
        """Check one umask against the reference"""
        permission = octal_str_to_int(str_permission)
        reference_permission = octal_str_to_int(str_reference_permission)
        if permission == reference_permission:
            return True
        is_more_permissive = bool(~permission & reference_permission)
        return not is_more_permissive

    return all(
        is_restrictive_enough(
            command.strip().split()[1]) for command in commands)


def cis_good_rsyslog_perms(grep_stdout_lines):
    """Parses FileCreateMode from rsyslog config.

    Args:
        grep_stdout_lines (list): strings with FileCreateMode settings

    Returns:
        bool: returns true when permission is 0640 or more restrictive
    """
    if not grep_stdout_lines:
        return False

    result = True
    for line in grep_stdout_lines:
        line_fields = line.split()
        permission = int(line_fields[1], 8)
        bad_permission = bool(permission & ~0o0640)
        print("{} {}".format(permission, bad_permission))
        result = result and not bad_permission

    return result


def cis_iptables_contains_ports(iptables_stdout_lines, open_ports):
    """Parses iptables -L -v -n output.

    Args:
        iptables_stdout_lines (list): strings with iptables -L -v -n output
        open_ports (dict): output of listen_ports_facts module

    Returns:
        bool: returns true when there ar firewall rules to govern traffic on
        any ports that have been opened on non-loopback addresses
    """

    def parse_multiport(ports_to_parse):
        # Example: 1500:1501,1552:1553,1581
        ports_parsed = []
        chunks = ports_to_parse.split(",")
        for chunk in chunks:
            if ":" in chunk:
                begin, end = map(int, chunk.split(":"))
                ports_parsed.extend(range(begin, end + 1))
            else:
                ports_parsed.append(int(chunk))
        return ports_parsed

    open_port_set = set()
    for port in open_ports:
        if port["address"] == "::1" or port["address"].startswith("127."):
            continue  # Exclude loopback
        open_port_set |= set([(port["protocol"], port["port"])])

    iptables_port_set = set()
    for line in iptables_stdout_lines:
        if "dpt" in line or "dports" in line:
            split_line = line.split()
            protocol = split_line[3]
            if "dpt" in line:
                port = int(split_line[-1].split(":")[1])
                iptables_port_set |= set([(protocol, port)])
            else:
                ports = parse_multiport(split_line[-1])
                for port in ports:
                    iptables_port_set |= set([(protocol, port)])
    return (open_port_set - iptables_port_set) == set()


def cis_user_system_not_login(etc_passwd_lines, exclude_logins=[]):
    """Parses /etc/passwd lines.

    Args:
        etc_passwd_lines (list): strings with /etc/passwd content
        exclude_logins (list): strings with usernames allowed to login

    Returns:
        bool: returns true when system accounts are non-login.
    """
    result = True
    for line in etc_passwd_lines.split("\n"):
        if line == "":
            continue
        line_split = line.split(":")
        if len(line_split) != 7:
            DISPLAY.warning(
                "cis_user_system_not_login:Strange /etc/passwd line:\n%s"
                % (line)
            )
            continue
        (login, _passw, uid, _gid, _gecos, _directory, shell) = line_split
        uid = int(uid)
        shell = shell.strip()
        if login.startswith("+") \
           or login in ["root", "sync", "shutdown", "halt"]:
            continue
        elif uid >= 1000:
            continue
        elif shell in ["/sbin/nologin", "/bin/false"]:
            continue
        elif login in exclude_logins:
            continue
        else:
            DISPLAY.warning("check 5.4.2: Sytem user %s have shell %s"
                            % (login, shell))
            result = False
    return result


def cis_passwd_field_not_empty(etc_passwd_lines):
    """Parses /etc/passwd lines.

    Args:
        etc_passwd_lines (list): strings with /etc/passwd content

    Returns:
        bool: returns true when password fields are not empty.
    """
    result = True
    for line in etc_passwd_lines.split("\n"):
        if line == "":
            continue
        line_split = line.split(":")
        if len(line_split) != 7:
            DISPLAY.warning(
                "cis_passwd_field_not_empty:Strange /etc/passwd line:\n%s"
                % (line)
            )
            continue
        (login, passw, _uid, _gid, _gecos, _directory, _shell) = line_split
        if passw == "":
            DISPLAY.warning("check 6.2.1: User without password: %s" % (login))
            result = False
    return result


def cis_check_5_3_3_compliant(output):
    """Parses check 5.3.3 commands outputs.

    Args:
      output (list): List of strings output of:
        egrep '^password\\s+sufficient\\s+pam_unix.so' /etc/pam.d/password-auth
        egrep '^password\\s+sufficient\\s+pam_unix.so' /etc/pam.d/system-auth
        or:
        egrep '^password\\s+required\\s+pam_pwhistory.so' \
              /etc/pam.d/password-auth
        egrep '^password\\s+required\\s+pam_pwhistory.so' \
              /etc/pam.d/system-auth

    Returns:
        bool: returns true when 'remember'>=5 in all 'sufficient' or
              'required' outputs
    """

    def remember_enough(line):
        if "remember=" not in line:
            return False
        match = re.search(r"^.*\sremember=(\d+).*$", line, flags=re.M)
        if not match:
            return False
        remember_times = int(match.group(1))
        is_enough = 5 <= remember_times
        return is_enough

    return all(remember_enough(lines) for lines in output)


class TestModule:
    """ Ansible tests """

    def tests(self):
        return {
            "cis_all_cis_at_least_restrictive_as":
                cis_all_cis_at_least_restrictive_as,
            "cis_search_words":
                cis_search_words,
            "cis_good_rsyslog_perms":
                cis_good_rsyslog_perms,
            "cis_iptables_contains_ports":
                cis_iptables_contains_ports,
            "cis_passwd_field_not_empty":
                cis_passwd_field_not_empty,
            "cis_user_system_not_login":
                cis_user_system_not_login,
            "cis_check_5_3_3_compliant":
                cis_check_5_3_3_compliant,
            "cis_umasks_at_least_restrictive_as":
                cis_umasks_at_least_restrictive_as,
        }
