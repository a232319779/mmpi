# -*- coding: utf-8 -*-
# @Time    : 2020/12/23 01:57:36 
# @Author  : ddvv
# @Site    : https://ddvvmmzz.github.io
# @File    : abstracts.py 
# @Software: Visual Studio Code


import re
import logging

log = logging.getLogger(__name__)


class Processing(object):
    """Base abstract class for processing module."""
    order = 1
    enabled = True

    def __init__(self):
        self.file_type = None
        self.file_content = None
        self.results = None

    @classmethod
    def init_once(cls):
        pass

    def set_type(self, file_type):
        """Set str.
        @param file_type: file type.
        """
        self.file_type = file_type

    def set_content(self, file_content):
        """Set object.
        @param file_content: file object.
        """
        self.file_content = file_content

    def set_results(self, results):
        """Set the results - the fat dictionary."""
        self.results = results

    def run(self):
        """Start processing.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError


class Signature(object):
    """Base class signatures."""
    name = ""
    description = ""
    severity = 1
    order = 1
    categories = []
    families = []
    authors = []
    references = []
    platform = None
    alert = False
    enabled = True

    # Maximum amount of marks to record.
    markcount = 50

    # Basic filters to reduce the amount of events sent to this signature.
    filter_apinames = []
    filter_categories = []

    # If no on_call() handler is present and this field has been set, then
    # dispatch on a per-API basis to the accompanying API. That is, rather
    # than calling the generic on_call(), call, e.g., on_call_CreateFile().
    on_call_dispatch = False

    def __init__(self, caller):
        """
        @param caller: calling object. Stores results in caller.results
        """
        self.marks = []
        self.matched = False
        self._caller = caller

        # These are set by the caller, they represent the process identifier
        # and call index respectively.
        self.pid = None
        self.cid = None
        self.call = None

    @classmethod
    def init_once(cls):
        pass

    def _check_value(self, pattern, subject, regex=False, all=False):
        """Checks a pattern against a given subject.
        @param pattern: string or expression to check for.
        @param subject: target of the check.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @return: boolean with the result of the check.
        """
        ret = set()
        if regex:
            exp = re.compile(pattern, re.IGNORECASE)
            if isinstance(subject, list):
                for item in subject:
                    if exp.match(item):
                        ret.add(item)
            else:
                if exp.match(subject):
                    ret.add(subject)
        else:
            if isinstance(subject, list):
                for item in subject:
                    if item.lower() == pattern.lower():
                        ret.add(item)
            else:
                if subject == pattern:
                    ret.add(subject)

        # Return all elements.
        if all:
            return list(ret)
        # Return only the first element, if available. Otherwise return None.
        elif ret:
            return ret.pop()

    def get_results(self, key=None, default=None):
        if key:
            return self._caller.results.get(key, default)

        return self._caller.results

    def init(self):
        """Allow signatures to initialize themselves."""

    def mark_ioc(self, category, ioc, description=None):
        """Mark an IOC as explanation as to why the current signature
        matched."""
        mark = {
            "type": "ioc",
            "category": category,
            "ioc": ioc,
            "description": description,
        }

        # Prevent duplicates.
        if mark not in self.marks:
            self.marks.append(mark)

    def mark(self, **kwargs):
        """Mark arbitrary data."""
        mark = {
            "type": "generic",
        }
        mark.update(kwargs)
        self.marks.append(mark)

    def has_marks(self, count=None):
        """Returns true if this signature has one or more marks."""
        if count is not None:
            return len(self.marks) >= count
        return not not self.marks

    def on_signature(self, signature):
        """Event yielded when another signatures has matched. Some signatures
        only take effect when one or more other signatures have matched as
        well.

        @param signature: The signature that just matched
        """

    def on_process(self, process):
        """Called on process change.

        Can be used for cleanup of flags, re-activation of the signature, etc.

        @param process: dictionary describing this process
        """

    def on_yara(self, category, filepath, match):
        """Called on YARA match.
        @param category: yara match category
        @param filepath: path to the file that matched
        @param match: yara match information

        The Yara match category can be one of the following.
          extracted: an extracted PE image from a process memory dump
          procmem: a process memory dump
          dropped: a dropped file
        """

    def on_complete(self):
        """Signature is notified when all API calls have been processed."""

    def results(self):
        """Turn this signature into actionable results."""
        return dict(name=self.name,
                    description=self.description,
                    severity=self.severity,
                    marks=self.marks[:self.markcount],
                    markcount=len(self.marks))

    @property
    def cfgextr(self):
        return self._caller.c
