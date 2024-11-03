"""byte_tools.py

Written by Thomas Hosking (z3253935) <z3253935@student.unsw.edu.au> on
October 27 2024.

This module contains functions related to manipulation of bits and
bytestrings.
"""
BITS_PER_BYTE = 8


# converts a given number of bytes in a bytestring at a given offset to
# an integer using little endian encoding
def read_int(data, offset, num_bytes):
    """Converts a given number of bytes in a bytestring at a given
    offset to an integer using little endian encoding.

    Arguments:
        data: bytestring
            A bytestring containing the byte representation of the
            integer as a substring.
        offset: integer
            The offset of the start of the integer substring,
        num_bytes: integer
            The number of bytes in the integer substring.
    Returns:
        Integer converted from the integer substring.
    """
    int_as_bytes = data[offset:(offset + num_bytes)]
    return int.from_bytes(int_as_bytes, byteorder="little")


def read_int_big(data, offset, num_bytes):
    """Converts a given number of bytes in a bytestring at a given
    offset to an integer using big endian encoding.

    Arguments:
        data: bytestring
            A bytestring containing the byte representation of the
            integer as a substring.
        offset: integer
            The offset of the start of the integer substring,
        num_bytes: integer
            The number of bytes in the integer substring.
    Returns:
        Integer converted from the integer substring.
    """
    int_as_bytes = data[offset:(offset + num_bytes)]
    return int.from_bytes(int_as_bytes, byteorder="big")


def split_bytes(byte_string, interval):
    """Splits a bytestring into a list of bytestrings with a given
    maximum length.

    Arguments:
        byte_string: bytestring
            The bytestring to split.
        interval: integer
            The maximum length of the split bytestrings.
    Returns:
        List of bytestrings.
    """
    chunks = []
    for i in range(0, len(byte_string), interval):
        chunk = byte_string[i:i + interval]
        chunks.append(chunk)
    return chunks


def bits_from_bytes(byte_string):
    """Converts a bytestring into a list of bits.

    Arguments:
        byte_string: bytestring
            The bytestring to convert to bits.
    Returns:
        List of integers (0 or 1) representing bits of the bytestring.
    """
    bits = []
    for byte_val in list(byte_string):
        for i in range(BITS_PER_BYTE):
            mask = 0b1 << (7 - i)
            bit = (mask & byte_val) >> (7 - i)
            bits.append(bit)
    return bits


def bytes_from_bits(bits):
    """Converts a list of integer bits (0 or 1) into a bytestring.

    Arguments:
        bits: list
            A list of integers (0 or 1) to convert.
    Returns:
        Bytestring converted from the bits.
    """
    message_bytes = []
    assert (len(bits) % 8 == 0)
    msg_len = len(bits) // 8
    for i in range(msg_len):
        byte_val = 0
        for j in range(BITS_PER_BYTE):
            mask = 0b1 << (7 - j)
            byte_val += bits[i * 8 + j] * mask
        message_bytes.append(byte_val.to_bytes(1, byteorder='big'))
    return b''.join(message_bytes)
