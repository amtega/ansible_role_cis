# Make coding more python3-ish
"""
Tests: cis_search_words, good_rsyslog_perms.

Tests:
    cis_search_words: Test if given words compose a string
    good_rsyslog_perms: Auxiliary function for check 4.2.1.3
"""
from __future__ import absolute_import, division, print_function

__metaclass__ = type


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
                begin, end = map(int,chunk.split(':'))
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

class TestModule:
    """ Ansible tests """

    def tests(self):
        return {
            "cis_search_words": cis_search_words,
            'good_rsyslog_perms': good_rsyslog_perms,
            'iptables_contains_ports': iptables_contains_ports,
            }
