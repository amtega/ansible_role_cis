# Make coding more python3-ish
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


class TestModule:
    """ Ansible tests """

    def tests(self):
        return {"cis_search_words": cis_search_words}
