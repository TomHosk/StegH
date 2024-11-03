"""custom_errors.py

Written by Thomas Hosking (z3253935) <z3253935@student.unsw.edu.au> on
October 27 2024.

This module contains custom error class definitions.
"""


class InvalidFileError(Exception):
    """Exception for errors where the provided file is not of suitable
    format.
    """
    pass


class CapacityError(Exception):
    """Exception for errors where the provided file does not have
    sufficient capcity to encode a message.
    """
    pass
