"""jpeg.py

Written by Thomas Hosking (z3253935) <z3253935@student.unsw.edu.au> on
October 27 2024.

This module contains functions related to steganography of jpeg files.
"""

import re
from modules.custom_errors import InvalidFileError
from modules.byte_tools import read_int_big
from modules.byte_tools import split_bytes

MARKER_SOI = b"\xff\xd8"
MARKER_APP0 = b"\xff\xe0"
MARKER_SOS = b"\xff\xda"
MARKER_EOI = b"\xff\xd9"
MARKER_COM = b"\xff\xfe"
APP0_JFIF_ID = b"JFIF\x00"
APP0_EXIF_ID = b"EXIF\x00"
MARKER_LEN = 2
LENGTH_LEN = 2
APPO_OFFSET = 2
APPO_LEN_OFFSET = 4
MAX_COM_LEN = 65533
END_OF_IMAGE = 'eoi'
METADATA = 'metadata'
# 2nd byte of markers which should be ignored when parsing the
# compressed image section, ie pad marker and reset markers
IGNORE_MARKER_BYTES = (b'\x00', b'\xd0', b'\xd1', b'\xd2', b'\xd3',
                       b'\xd4', b'\xd5', b'\xd6', b'\xd7')
SIGNATURE = b'STEGH\x00'


def encode_jpg(data, message, steg_flags, show_sections):
    """Creates modified jpeg contents with the message encoded using
    the method specified in encoding flags.

    Arguments:
        data: bytestring
            The contents of the jpeg file as a bytestring.
        message: bytestring
            The contents of the message to encode in the jpeg.
        steg_flags: dictionary
            Dictionary with boolean values for each jpeg encoding
            flag.
    Returns:
        Bytestring of the modified jpeg contents
    """
    validate_jpeg(data)
    sections = decompose_jpeg(data)
    if show_sections:
        print('JPEG sections prior to encoding (first 20 bytes of '
              'each):')
        print_start(sections, 20)

    if steg_flags[END_OF_IMAGE]:
        sections = insert_eoi(sections, message)
    elif steg_flags[METADATA]:
        sections = insert_comment(sections, message)
    else:
        raise ValueError('At least one encoding mode in steg_flags must be '
                         'True')
    if show_sections:
        print('JPEG sections after encoding (first 20 bytes of each):')
        print_start(sections, 20)

    return b''.join(sections)


# Checks that the provided file is a jpeg file
def validate_jpeg(data):
    """Confirms a file is a valid and supported jpeg, or raises an
    exception.

    Arguments:
        data: bytestring
            The contents of the jpeg file as a bytestring.
    Returns:
        nothing
    """
    if not data[:MARKER_LEN] == MARKER_SOI:
        raise InvalidFileError('File not a valid jpeg file')


# spiit the file contents into sections at beginning of jpeg markers
def decompose_jpeg(data):
    """Splits the contents of a jpeg file into a list of its component
    sections, defined by jpeg markers. Any data after the end of a jpeg
    file is included in a single section at the end of the list.

    Arguments:
        data: bytestring
            The contents of the jpeg file as a bytestring.
    Returns:
        List of bytestrings of each jpeg section.
    """
    # extract each section before the start of scan marker
    sections = sections_until_marker(data, 0, MARKER_SOS)
    # extract the scan section
    sos_start = sum([len(x) for x in sections])
    sos_section = extract_scan_section(data, sos_start)
    sections.append(sos_section)
    # extract the sections between the scan section and the end of image
    # marker
    sos_end = sum([len(x) for x in sections])
    after_scan = sections_until_marker(data, sos_end, MARKER_EOI)
    sections.extend(after_scan)
    # extract the end of image marker
    eoi_start = sum([len(x) for x in sections])
    eoi_end = eoi_start + MARKER_LEN
    sections.append(data[eoi_start:eoi_end])
    # extract anything after the end of image marker
    sections.append(data[eoi_end:])

    return sections


def sections_until_marker(data, start_offset, end_marker):
    """Splits the sections of a jpeg file between a start offset until
     a particular end marker is seen.

    Arguments:
        data: bytestring
            The contents of the jpeg file as a bytestring.
        start_offset: integer
            The offset to start splitting sections from. Must correspond
            with the start of a section marker.
        end_marker:
            A jpeg marker which will halt section splitting if seen.
    Returns:
        List of bytestrings of each jpeg section.
    """
    sections = []
    sect_start = start_offset
    while (marker := data[sect_start:sect_start + MARKER_LEN]) != end_marker:
        if marker == MARKER_SOI:
            length = 0
        else:
            length = section_length(data, sect_start)
        sect_end = sect_start + MARKER_LEN + length
        sections.append(data[sect_start:sect_end])
        sect_start = sect_end
    return sections


def section_length(data, sect_start):
    """Returns the length of a jpeg section.

    Arguments:
        data: bytestring
            The contents of the jpeg file as a bytestring.
        sect_start: integer
            The offset of the start of the section. Must correspond
            with the start of a section marker.

    Returns:
        Integer of the length of the section (in bytes), not including
        the section marker.
    """
    if (data[sect_start:sect_start + 1] != b'\xff'):
        raise InvalidFileError('Chosen JPEG file is not supported')
    length_offset = sect_start + MARKER_LEN
    return read_int_big(data, length_offset, LENGTH_LEN)


def extract_scan_section(data, sos_offset):
    """Extracts data from the scan section of a jpeg.

    Arguments:
        data: bytestring
            The contents of the jpeg file as a bytestring.
        sos_offset: integer
            The offset of the SOS (Start of Scan) section marker.
    Returns:
        Bytestring of the scan section of the jpeg, including marker.
    """
    length = section_length(data, sos_offset)
    scan_start = sos_offset + MARKER_LEN + length
    i = scan_start
    # look for the first marker after the compressed image
    while ((data[i:i + 1] != b'\xff') or
           (data[i + 1: i + 2] in IGNORE_MARKER_BYTES)):
        i += 1
    scan_end = i
    return data[sos_offset:scan_end]


def insert_eoi(sections, secret):
    """Modifies a sections list to include the secret bytestring after
    the end of image. Overwrites any existing data after the end of
    image marker.

    Arguments:
        sections: list
            A list of section bytestrings, with the last entry being
            data after the end of image marker.
        secret: bytestring
            A secret message to encode.
    Returns:
        List of section bytestrings, with message encoded after the end
        of image marker.
    """
    assert (sections[-2] == MARKER_EOI)
    sections[-1] = secret
    return sections


def insert_comment(sections, secret):
    """Modifies a sections list to include new comment section(s) in
    the metadata, containing the secret message.

    Arguments:
        sections: list
            A list of section bytestrings.
        secret: bytestring
            A secret message to encode.
    Returns:
        List of section bytestrings, with message encoded as new
        comment sections inserted before the start of image marker.
    """
    max_chunk_size = MAX_COM_LEN - LENGTH_LEN - len(SIGNATURE)
    chunks = split_bytes(secret, max_chunk_size)
    comments = [make_comment(x) for x in chunks]

    sos_index = get_marker_index(sections, MARKER_SOS)
    assert (sos_index is not None)
    return (sections[:sos_index] + comments + sections[sos_index:])


def make_comment(byte_string):
    """Generates a new comment section from a bytestring.

    Arguments:
        byte_string: bytestring
            A bytestring to include as the comment contents
    Returns:
        Bytestring of a jpeg comment section including marker, length
        and byte_string contents.
    """
    size = len(byte_string) + LENGTH_LEN + len(SIGNATURE)
    size_bytes = size.to_bytes(LENGTH_LEN, byteorder='big')
    return MARKER_COM + size_bytes + SIGNATURE + byte_string


def get_marker_index(section_list, marker):
    """Returns the section index of the first instance of a given
    marker.

    Arguments:
        section_list: list
            A list of section bytestrings.
        marker: bytestring
            The marker to search for the first instance of.
    Returns:
        Integer of the section index of the first instance of the marker
        in the jpeg file. Returns None if not present in the file.
    """
    index = None
    for i, row in enumerate(section_list):
        if row[:MARKER_LEN] == marker:
            index = i
            break
    return index


def decode_jpg(data, steg_flags, show_sections):
    """Decodes a message which is encoded in a jpeg file, using the
    method specified in encoding flags.

    Arguments:
        data: bytestring
            The contents of the jpeg file as a bytestring.
        steg_flags: dictionary
            Dictionary with boolean values for each jpeg encoding
            flag.
    Returns:
        Bytestring of the recovered message.
    """
    validate_jpeg(data)
    sections = decompose_jpeg(data)
    if show_sections:
        print('JPEG sections (first 20 bytes of each):')
        print_start(sections, 20)

    if steg_flags[END_OF_IMAGE]:
        secret = extract_eoi(sections)
        if len(secret := extract_eoi(sections)) == 0:
            raise InvalidFileError('No decodable message found in file after '
                                   'the End of Image')
    elif steg_flags[METADATA]:
        if (secret := extract_comment(sections, SIGNATURE)) is None:
            raise InvalidFileError('No decodable message found in file '
                                   'metadata')
    else:
        raise ValueError('At least one encoding mode in steg_flags must be '
                         'True')

    return secret


def extract_eoi(sections):
    """Extracts any data after the end of image marker in a jpeg.

    Arguments:
        sections: list
            A list of section bytestrings, with the last entry being
            data after the end of image marker.
    Returns:
        Bytestring of the data after the end of image marker.
    """
    assert (sections[-2] == MARKER_EOI)
    secret = sections[-1]
    return secret


def extract_comment(sections, signature=b''):
    """Extracts any data encoded in comment sections headed by a given
    signature.

    Arguments:
        sections: list
            A list of section bytestrings.
    Returns:
        Bytestring of the extracted and recombined comment data.
    """
    comment_pattern = re.compile(MARKER_COM + rb".{2}" + signature)
    comments = list(filter(lambda x: comment_pattern.match(x), sections))
    if len(comments) == 0:
        return None
    com_header_len = MARKER_LEN + LENGTH_LEN + len(signature)

    return b''.join([x[com_header_len:] for x in comments])


def detect_steg_jpg(data, show_sections):
    """Detects and returns steganographically encoded data found after
    the end of image marker or in jpeg comments.

    Arguments:
        data: bytestring
            The contents of the jpeg file as a bytestring.
    Returns:
        List of tuples representing detected steganographic data, in the
        form (description_string, data_bytestring). Empty list if no
        steganography detected.
    """
    validate_jpeg(data)
    sections = decompose_jpeg(data)
    if show_sections:
        print('JPEG sections (first 20 bytes of each):')
        print_start(sections, 20)

    secrets = []
    if len(steg_eoi := extract_eoi(sections)) > 0:
        secrets.append(('after end of image', steg_eoi))
    if (steg_meta := extract_comment(sections)) is not None:
        secrets.append(('in metadata', steg_meta))
    return secrets


def print_start(string_list, max):
    """Prints each element of a bytestring list, up to a maximum number
    of bytes for each element.

    Arguments:
        string_list: list
            A list of bytestrings.
        max: integer
            The maximum number of bytes to print for each element
    Returns:
        nothing
    """
    for i in range(len(string_list)):
        print(string_list[i][:max])
    print()
