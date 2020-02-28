# Make coding more python3-ish
"""
Tests: cis_search_words, good_rsyslog_perms.

Tests:
    cis_search_words: Test if given words compose a string
    good_rsyslog_perms: Auxiliary function for check 4.2.1.3
"""
from __future__ import absolute_import, division, print_function

__metaclass__ = type

from crypt import crypt


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


class TestModule:
    """ Ansible tests """

    def tests(self):
        return {
            "cis_search_words": cis_search_words,
            'good_rsyslog_perms': good_rsyslog_perms,
            }
