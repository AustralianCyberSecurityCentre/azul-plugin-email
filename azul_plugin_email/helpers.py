"""Helper utilities, reusable by different mail plugins."""

import csv


def get_words(bodies, filename=None):
    """Given a list of mail text bodies, create a password dictionary list.

    @param bodies: List of str
    @param filename: str of filename to include in list
    @return: byte stream of new-line separated words
    """
    words = set()
    # split the text from the body into words, preserving quoted, space-separated strings
    for b in bodies:
        for row in csv.reader(b.decode("utf-8").replace("\t", " ").splitlines(), delimiter=" "):
            words = words.union((s.strip(",.()[]:;'\" ") for s in row))
    # some phishing says to use the filename as the pw
    if filename:
        words.add(filename)
        words.add(filename.rsplit(".")[0])  # try without ext too
    # ensure we sort to get deterministic output
    return b"\n".join((s.encode("utf-8") for s in sorted(words) if len(s) > 2 and len(s) < 20))
