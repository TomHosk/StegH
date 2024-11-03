"""bitmap.py

Written by Thomas Hosking (z3253935) <z3253935@student.unsw.edu.au> on
October 27 2024.

This module contains functions related to steganography of bitmap files.
"""
import pprint
from math import ceil
from modules.custom_errors import InvalidFileError
from modules.custom_errors import CapacityError
from modules.byte_tools import read_int
from modules.byte_tools import split_bytes
from modules.byte_tools import bits_from_bytes
from modules.byte_tools import bytes_from_bits
from modules.byte_tools import BITS_PER_BYTE

OFFSET_ID = 0x00
OFFSET_PIXEL_ARRAY_OFFSET = 0x0A
OFFSET_IMG_WIDTH = 0X12
OFFSET_IMG_HEIGHT = 0X16
OFFSET_BITS_PER_PIXEL = 0x1c
OFFSET_COMPRESSION_METHOD = 0x1E
OFFSET_BITFIELD_RED = 0x36
OFFSET_BITFIELD_GREEN = 0x3A
OFFSET_BITFIELD_BLUE = 0x3E
OFFSET_BITFIELD_ALPHA = 0x42
SIZE_ID = 2
SIZE_PIXEL_ARRAY_OFFSET = 4
SIZE_IMG_WIDTH = 4
SIZE_IMG_HEIGHT = 4
SIZE_BITS_PER_PIXEL = 2
SIZE_COMPRESSION_METHOD = 2
SIZE_BITFIELD_RED = 4
SIZE_BITFIELD_GREEN = 4
SIZE_BITFIELD_BLUE = 4
SIZE_BITFIELD_ALPHA = 4
COMPRESSION_RGB = 0
COMPRESSION_BI_BITFIELDS = 3
MASK_R_16 = 0x7C00
MASK_G_16 = 0x03E0
MASK_B_16 = 0x001F
MASK_R_24 = 0xFF0000
MASK_G_24 = 0x00FF00
MASK_B_24 = 0x0000FF
MASK_R_32 = 0xFF0000
MASK_G_32 = 0x00FF00
MASK_B_32 = 0x0000FF
PIXEL_PADDING = 'pixel_pad'
LEAST_SIGNIFICANT_BIT = 'lsb'
END_OF_ROW_PADDING = 'end_row_pad'
SUPPORTED_BIT_DEPTHS = (16, 24, 32)
SUPOPORTED_COMPRESSION = (COMPRESSION_RGB, COMPRESSION_BI_BITFIELDS)
SIZE_STEG_HEADER = 4


def get_capacity(data, steg_flags, detailed):
    """Returns the maximum size of file which can be steganographically
    encoded in the given bitmap file when using the given encoding
    flags.

    Arguments:
        data: bytestring
            The contents of the bitmap file as a bytestring.
        steg_flags: dictionary
            Dictionary with boolean values for each bitmap encoding
            flag.
        detailed: boolean
            Boolean of if image and steg details should be printed.
    Returns:
        Integer of the number of bytes which the bitmap file can store
        as a secret.
    """
    bmp_info = process_bmp(data)
    steg_info = get_steg_info(bmp_info, steg_flags)
    if detailed:
        detailed_print(bmp_info, steg_info)
    if steg_info['max_bytes_secret'] <= 0:
        raise CapacityError('BMP has insufficient capacity to encode any data '
                            'with selected steg method(s)')
    return steg_info['max_bytes_secret']


def process_bmp(data):
    """Confirms a bitmap file is valid and supported, and extracts its
    metadata.

    Arguments:
        data: bytestring
            The contents of the bitmap file as a bytestring.
    Returns:
        Dictionary containing image metadata information.
    """
    if not is_bmp(data):
        raise InvalidFileError('File is not a bitmap file')
    try:
        bmp_info = extract_metadata(data)
    except IndexError:
        raise InvalidFileError('BMP file is incorrectly formatted')
    validate_supported_bmp(bmp_info)
    return bmp_info


def is_bmp(data):
    """Validates a file has the correct bitmap header.

    Arguments:
        data: bytestring
            The contents of the bitmap file as a bytestring.
    Returns:
        Boolean value of if file has a bitmap header.
    """
    return data[OFFSET_ID: OFFSET_ID + SIZE_ID] == b"BM"


def extract_metadata(data):
    """Creates a dictionary of relevant metadata from a given bitmap.

    Arguments:
        data: bytestring
            The contents of the bitmap file as a bytestring.
    Returns:
        Dictionary containing bitmap metadata.
    """
    info = {}
    info["offset_array_start"] = read_int(data, OFFSET_PIXEL_ARRAY_OFFSET,
                                          SIZE_PIXEL_ARRAY_OFFSET)
    info["width"] = read_int(data, OFFSET_IMG_WIDTH, SIZE_IMG_WIDTH)
    info["height"] = read_int(data, OFFSET_IMG_HEIGHT, SIZE_IMG_HEIGHT)
    info["bit_depth"] = read_int(data, OFFSET_BITS_PER_PIXEL,
                                 SIZE_BITS_PER_PIXEL)
    info["compression"] = read_int(data, OFFSET_COMPRESSION_METHOD,
                                   SIZE_COMPRESSION_METHOD)

    if info["compression"] == COMPRESSION_BI_BITFIELDS:
        info["mask_red"] = read_int(data, OFFSET_BITFIELD_RED,
                                    SIZE_BITFIELD_RED)
        info["mask_green"] = read_int(data, OFFSET_BITFIELD_GREEN,
                                      SIZE_BITFIELD_GREEN)
        info["mask_blue"] = read_int(data, OFFSET_BITFIELD_BLUE,
                                     SIZE_BITFIELD_BLUE)
        info["mask_alpha"] = read_int(data, OFFSET_BITFIELD_ALPHA,
                                      SIZE_BITFIELD_ALPHA)

    info["bytes_per_row"] = int(info["width"] * info["bit_depth"] /
                                BITS_PER_BYTE)
    info["padded_bytes_per_row"] = 4 * ceil(info["bytes_per_row"] / 4)
    info["pad_per_row"] = info["padded_bytes_per_row"] - info["bytes_per_row"]
    info["num_pixels"] = info["width"] * info["height"]
    return info


def validate_supported_bmp(info):
    """Raises exception if bitmap file is of a type which is not
    supported.

    Arguments:
        data: bytestring
            The contents of the bitmap file as a bytestring.
    Returns:
        nothing
    """
    if info["bit_depth"] not in SUPPORTED_BIT_DEPTHS:
        raise InvalidFileError('BMP file has unsupported bit depth')
    elif info["compression"] not in SUPOPORTED_COMPRESSION:
        raise InvalidFileError('BMP file has unsupported compression type')


def get_steg_info(bmp_info, steg_flags):
    """Creates a dictionary containing information related to
    steganographic capacity of a given bitmap, given the provided
    encoding flags.

    Arguments:
        data: bytestring
            The contents of the bitmap file as a bytestring.
        steg_flags: dictionary
            Dictionary with boolean values for each bitmap encoding
            flag.
    Returns:
        Dictionary containing steganography data.
    """
    steg_info = {}
    rgba_masks = get_rgba_masks(bmp_info)
    steg_info["steg_header_bits"] = SIZE_STEG_HEADER * BITS_PER_BYTE
    # Info about pixels steg, including lsb and pixel padding.
    steg_info['bitmasks'] = get_bitmasks(rgba_masks, bmp_info["bit_depth"],
                                         steg_flags)
    steg_info["bits_per_pixel"] = len(steg_info['bitmasks'])
    steg_info["pix_bits_per_row"] = (steg_info["bits_per_pixel"] *
                                     bmp_info["width"])
    # Info about end of row padding steg.
    if steg_flags[END_OF_ROW_PADDING]:
        steg_info["end_pad_bits_per_row"] = (bmp_info["pad_per_row"] *
                                             BITS_PER_BYTE)
    else:
        steg_info["end_pad_bits_per_row"] = 0
    # Total secret storage space.
    steg_info["bits_secret_per_row"] = (steg_info["pix_bits_per_row"] +
                                        steg_info["end_pad_bits_per_row"])
    steg_info["max_bits_secret"] = (steg_info["bits_secret_per_row"] *
                                    bmp_info["height"] -
                                    steg_info["steg_header_bits"])
    steg_info["max_bytes_secret"] = (steg_info["max_bits_secret"] //
                                     BITS_PER_BYTE)
    return steg_info


def get_rgba_masks(bmp_info):
    """Creates a list of used red, green, blue and alpha channel
    bitfields of a bitmap.

    Arguments:
        bmp_info: dictionary
            The bmp_info dict for the bitmap.
    Returns:
        List of int values representing the bitfields of the channels
        used by the bitmap.
    """
    if bmp_info["compression"] == COMPRESSION_RGB:
        if bmp_info["bit_depth"] == 32:
            return (MASK_R_32, MASK_G_32, MASK_B_32)
        elif bmp_info["bit_depth"] == 24:
            return (MASK_R_24, MASK_G_24, MASK_B_24)
        elif bmp_info["bit_depth"] == 16:
            return (MASK_R_16, MASK_G_16, MASK_B_16)
    elif bmp_info["compression"] == COMPRESSION_BI_BITFIELDS:
        mask_r = bmp_info["mask_red"]
        mask_g = bmp_info["mask_green"]
        mask_b = bmp_info["mask_blue"]
        mask_a = bmp_info["mask_alpha"]
        return [x for x in (mask_r, mask_g, mask_b, mask_a) if x != 0]


def get_bitmasks(rgba_masks, bit_depth, steg_flags):
    """Creates a list of bitmasks with each representing a pixel bit
    which can store steganographic data, given the provided encoding
    flags.

    Arguments:
        rgba_masks: list
            List of rgba bitfields of channels used by the bitmap, as
            integers.
        bit_depth: integer
            The bit depth of the bitmap.
        steg_flags: dictionary
            Dictionary with boolean values for each bitmap encoding
            flag.
    Returns:
        List of bitmasks for each modifiable pixel bit, as integers.
    """
    bitmasks = []
    if steg_flags[LEAST_SIGNIFICANT_BIT]:
        lsb_masks = get_lsb_masks(rgba_masks)
        assert len(lsb_masks) > 0
        bitmasks.extend(lsb_masks)
    if steg_flags[PIXEL_PADDING]:
        pad_masks = get_pad_masks(rgba_masks, bit_depth)
        bitmasks.extend(pad_masks)
        bitmasks.sort(reverse=True)
    return bitmasks


def get_lsb_masks(rgba_masks):
    """Creates a list of bitmasks with each representing the least
    significant bit of one of the rgba channels of a bitmap.

    Arguments:
        rgba_masks: list
            List of rgba bitfields of channels used by the bitmap, as
            integers.
    Returns:
        List of bitmasks for each least significant bit, as integers.
    """
    lsb_masks = []
    for mask in rgba_masks:
        if mask == 0:
            continue
        bit = 1
        while bit & mask == 0:
            bit = bit << 1
        lsb_masks.append(bit)
    return lsb_masks


def get_pad_masks(rgba_masks, bit_depth):
    """Creates a list of bitmasks with each representing a padding bit
    within the pixel.

    Arguments:
        rgba_masks: list
            List of rgba bitfields of channels used by the bitmap, as
            integers.
        bit_depth: integer
            The bit depth of the bitmap.
    Returns:
        List of bitmasks for each pixel padding bit, as integers.
    """
    pad_masks = []
    rgba_mask = 0
    for mask in rgba_masks:
        rgba_mask ^= mask
    for i in range(bit_depth):
        bitmask = 1 << i
        if bitmask & rgba_mask == 0:
            pad_masks.append(bitmask)
    return pad_masks


def detailed_print(bmp_info, steg_info):
    """Prints bitmap and steganography details to stdout.

    Arguments:
        bmp_info: dictionary
            The bmp_info dict for the bitmap.
        steg_info: dictionary
            The steg_info dict for the bitmap.
    Returns:
        nothing
    """
    print('Bitmap file details:')
    pprint.pprint(bmp_info)
    print()
    print('Bitmap steganography details:')
    pprint.pprint(steg_info)
    print()


def encode_message(data, message, steg_flags, detailed):
    """Creates modified bitmap contents with the message encoded using
    the method(s) specified in encoding flags.

    Arguments:
        data: bytestring
            The contents of the bitmap file as a bytestring.
        message: bytestring
            The contents of the message to encode in the bitmap.
        steg_flags: dictionary
            Dictionary with boolean values for each bitmap encoding
            flag.
        detailed: boolean
            Boolean of if image and steg details should be printed.
    Returns:
        Bytestring of the modified bitmap contents
    """
    bmp_info = process_bmp(data)
    steg_info = get_steg_info(bmp_info, steg_flags)
    if detailed:
        detailed_print(bmp_info, steg_info)

    # The message must be smaller than the capacity of the given file
    if steg_info['max_bytes_secret'] <= 0:
        raise CapacityError('BMP has insufficient capacity to encode any data '
                            'with selected steg method(s)')
    elif steg_info['max_bytes_secret'] < len(message):
        raise CapacityError(f"BMP has insufficient capacity for message. The "
                            f"max message size for this BMP is "
                            f"{steg_info['max_bytes_secret']} bytes")

    # Split the bmp array data into a list of rows, with each including
    # pixel and padding data.
    row_data = extract_row_data(data, bmp_info)
    message_bits = bits_from_bytes(message)
    assert (len(message_bits) % 8 == 0)

    # Append size of message to the start of the message
    message_len_bytes = len(message_bits).to_bytes(SIZE_STEG_HEADER,
                                                   byteorder='little')
    message_len_bits = bits_from_bytes(message_len_bytes)
    message_bits = message_len_bits + message_bits

    for i, row in enumerate(row_data):
        m_start = steg_info["bits_secret_per_row"] * i
        m_end = m_start + steg_info["bits_secret_per_row"]
        message_chunk = message_bits[m_start:m_end]
        # End when encoding is complete
        if len(message_chunk) == 0:
            break
        row_data[i] = encode_row(row, bmp_info, steg_info, message_chunk)
    array_data = b''.join(row_data)
    data = data[:bmp_info['offset_array_start']] + array_data

    return data


def extract_row_data(data, bmp_info):
    """Generates a list of data for each row in a bitmap file,
    including pixel and padding data.

    Arguments:
        data: bytestring
            The contents of the bitmap file as a bytestring.
        bmp_info: dictionary
            The bmp_info dict for the bitmap.
    Returns:
        List of bytestrings, with each representing the data from a row
        of the bitmap.
    """
    start = bmp_info["offset_array_start"]
    step = bmp_info["padded_bytes_per_row"]
    return split_bytes(data[start:], step)


def encode_row(row_bytes, bmp_info, steg_info, message_bits):
    """Encodes a message into the pixels and/or padding of a row.

    Arguments:
        row_bytes: bytstring
            Data of the row to encode message into.
        bmp_info: dictionary
            The bmp_info dict for the bitmap.
        steg_info: dictionary
            The steg_info dict for the bitmap.
        message_bits: list
            List of integers (1 or 0) representing the bits of the
            message to encode.
    Returns:
        Bytestring of the modified row data.
    """
    # Encode secret within pixel padding and least significant bits
    pixel_bytes = row_bytes[:bmp_info['bytes_per_row']]
    pixel_chunk = message_bits[:steg_info['pix_bits_per_row']]
    if len(pixel_chunk) > 0:
        pixel_bytes = encode_pixels(pixel_bytes, bmp_info, steg_info,
                                    pixel_chunk)
    # Encode secret within end of line padding
    end_pad_bytes = row_bytes[bmp_info['bytes_per_row']:]
    end_pad_chunk = message_bits[steg_info['pix_bits_per_row']:]
    if len(end_pad_chunk) > 0:
        end_pad_bytes = encode_end_pad(end_pad_bytes, bmp_info, end_pad_chunk)

    return pixel_bytes + end_pad_bytes


def encode_pixels(pixel_bytes, bmp_info, steg_info, message_bits):
    """Encodes a message into the pixels of a row.

    Arguments:
        pixel_bytes: bytstring
            Pixel data of the row, without end padding.
        bmp_info: dictionary
            The bmp_info dict for the bitmap.
        steg_info: dictionary
            The steg_info dict for the bitmap.
        message_bits: list
            List of integers (1 or 0) representing the bits of the
            message to encode.
    Returns:
        Bytestring of the modified pixel row data.
    """
    bytes_per_pixel = bmp_info['bit_depth'] // BITS_PER_BYTE
    pixel_values = list_pixel_vals(pixel_bytes, bytes_per_pixel)

    # modify bits of each pixel value to encode message
    curr_pixel = 0
    msg_bits_per_pixel = steg_info['bits_per_pixel']
    i = 0
    while i < len(message_bits):
        write_bits = message_bits[i:i + msg_bits_per_pixel]
        pixel_values[curr_pixel] = set_bits(pixel_values[curr_pixel], 32,
                                            steg_info['bitmasks'], write_bits)
        i += msg_bits_per_pixel
        curr_pixel += 1

    # Reform bytestring from modified pixel values
    return b''.join([x.to_bytes(4, byteorder='little')[:bytes_per_pixel]
                     for x in pixel_values])


def set_bits(pixel, bit_depth, bitmasks, message_bits):
    """Encodes bits into the pixels of a row, at locations defined by
    bitmasks.

    Arguments:
        pixel: bytstring
            Pixel data to modify.
        bit_depth: integer
            The bit depth of the bitmap.
        bitmasks: list
            List of integers representing bitmasks of bits to modify.
        message_bits: list
            List of integers (1 or 0) representing the bits of the
            message to encode.
    Returns:
        Bytestring of the modified pixel data.
    """
    assert (len(message_bits) <= len(bitmasks))
    for i, bit in enumerate(message_bits):
        assert bit in (0, 1)
        mask = (2 ** bit_depth - 1) - bitmasks[i]
        pixel = (pixel & mask) ^ (bitmasks[i] * bit)
    return pixel


def list_pixel_vals(byte_string, bytes_per_pixel):
    """Converts a bytesting of pixel data into a list of integer values
    representing those pixels.

    Arguments:
        pixel: bytstring
            Pixel data to convert
        bytes_per_pixel: integer
            The number of bytes of data for each pixel of the bitmap.
    Returns:
        List of interger values of pixels.
    """
    assert (len(byte_string) % bytes_per_pixel == 0)
    pixel_list = []
    for col in range(len(byte_string) // bytes_per_pixel):
        start_offset = col * bytes_per_pixel
        pixel_bytes = byte_string[start_offset:start_offset + bytes_per_pixel]
        pixel_bytes = pixel_bytes + b'\x00' * (4 - bytes_per_pixel)
        pixel_list.append(int.from_bytes(pixel_bytes, byteorder='little'))
    return pixel_list


def encode_end_pad(end_pad_bytes, bmp_info, message_bits):
    """Encodes bits into the end padding row.

    Arguments:
        end_pad_bytes: bytstring
            End pad data to modify
        bmp_info: dictionary
            The bmp_info dict for the bitmap.
        message_bits: list
            List of integers (1 or 0) representing the bits of the
            message to encode.
    Returns:
        Bytestring of modified row end padding.
    """
    # If no bits to encode in end pad, leave bytes as is
    if message_bits == 0:
        return end_pad_bytes
    else:
        # In event the message ends partway through the end pad, pad
        # the message with additional bits
        while len(message_bits) < (bmp_info['pad_per_row'] * BITS_PER_BYTE):
            message_bits.append(0)
        return bytes_from_bits(message_bits)


def decode_message(data, steg_flags, detailed):
    """Decodes a message which is encoded in a bitmap file, using the
    method(s) specified in encoding flags.

    Arguments:
        data: bytestring
            The contents of the encoded bitmap file as a bytestring.
        steg_flags: dictionary
            Dictionary with boolean values for each bitmap encoding
            flag.
        detailed: boolean
            Boolean of if image and steg details should be printed.
    Returns:
        Bytestring of the recovered message.
    """
    bmp_info = process_bmp(data)
    steg_info = get_steg_info(bmp_info, steg_flags)
    if detailed:
        detailed_print(bmp_info, steg_info)
    if steg_info['max_bytes_secret'] <= 0:
        raise CapacityError('BMP is too small to contain encoded data')

    row_data = extract_row_data(data, bmp_info)

    msg_len_bytes = read_message(row_data, bmp_info, steg_info,
                                 SIZE_STEG_HEADER * 8)
    msg_len = int.from_bytes(msg_len_bytes, byteorder='little')
    # Need to include the size of the header to ensure full message is read
    full_msg_len = msg_len + SIZE_STEG_HEADER * 8
    if full_msg_len > steg_info['max_bits_secret'] + SIZE_STEG_HEADER * 8:
        raise InvalidFileError('File does not contain a valid message')

    message_bytes = read_message(row_data, bmp_info, steg_info, full_msg_len)
    return message_bytes[SIZE_STEG_HEADER:]


def read_message(row_data, bmp_info, steg_info, msg_len):
    """Decodes a message bytestring of a given length from row data,
    using specified encoding methods.

    Arguments:
        row_data: list
            List of bytestrings of data of each row, including pixels
            and end padding.
        bmp_info: dictionary
            The contents of the encoded bitmap file as a bytestring.
        steg_info: dictionary
            The steg_info dict for the bitmap.
        msg_len: integer
            The length of the message to decode, in bits.
    Returns:
        Bytestring of the recovered message.
    """
    message_bits = read_message_bits(row_data, bmp_info, steg_info, msg_len)
    return bytes_from_bits(message_bits)


def read_message_bits(row_data, bmp_info, steg_info, msg_len):
    """Extracts a given number of message bits from row data, using
    specified encoding methods.

    Arguments:
        row_data: list
            List of bytestrings of data of each row, including pixels
            and end padding.
        bmp_info: dictionary
            The contents of the encoded bitmap file as a bytestring.
        steg_info: dictionary
            The steg_info dict for the bitmap.
        msg_len: integer
            The length of the message to decode, in bits.
    Returns:
        List of bits of the extracted message, as integers (0 or 1).
    """
    msg_bits = []
    i = 0
    while msg_len > 0:
        row_msg_len = min(msg_len, steg_info["bits_secret_per_row"])
        row_bits = decode_row(row_data[i], bmp_info, steg_info, row_msg_len)
        msg_bits.extend(row_bits)
        msg_len -= row_msg_len
        i += 1
    return msg_bits


def decode_row(row_bytes, bmp_info, steg_info, num_bits):
    """Extracts a given number of message bits from row data, using
    specified encoding methods.

    Arguments:
        row_bytes: list
            Bytestring of data of the row to decode message from,
            including pixels and end padding.
        bmp_info: dictionary
            The contents of the encoded bitmap file as a bytestring.
        steg_info: dictionary
            The steg_info dict for the bitmap.
        num_bits: integer
            The total number of bits to decode from the row.
    Returns:
        List of bits of the extracted message, as integers (0 or 1).
    """
    # Decode secret within pixel padding and least significant bits.
    pixel_bytes = row_bytes[:bmp_info['bytes_per_row']]
    pix_msg_len = min(steg_info['pix_bits_per_row'], num_bits)
    pix_msg = []
    if pix_msg_len > 0:
        pix_msg = decode_pixels(pixel_bytes, bmp_info, steg_info, pix_msg_len)
    # Decode secret within end of line padding.
    end_pad_bytes = row_bytes[bmp_info['bytes_per_row']:]
    end_pad_msg_len = num_bits - pix_msg_len
    end_pad_msg = []
    if end_pad_msg_len > 0:
        end_pad_msg = decode_end_pad(end_pad_bytes, end_pad_msg_len)

    return pix_msg + end_pad_msg


def decode_pixels(pixel_bytes, bmp_info, steg_info, msg_len):
    """Extracts a given number of message bits from row pixel data,
    using specified encoding methods.

    Arguments:
        pixel_bytes: bytestring
            Bytestring of pixel data of the row to decode message from,
            excluding end padding.
        bmp_info: dictionary
            The contents of the encoded bitmap file as a bytestring.
        steg_info: dictionary
            The steg_info dict for the bitmap.
        msg_len: integer
            The length of the message to decode, in bits.
    Returns:
        List of bits of the extracted message, as integers (0 or 1).
    """
    bytes_per_pixel = bmp_info['bit_depth'] // BITS_PER_BYTE
    pixel_values = list_pixel_vals(pixel_bytes, bytes_per_pixel)

    pix_bits = []
    curr_pixel = 0
    i = msg_len
    while i > 0:
        num_bits = min(steg_info['bits_per_pixel'], i)
        bits = get_pixel_bits(pixel_values[curr_pixel], steg_info['bitmasks'],
                              num_bits)
        pix_bits.extend(bits)
        i -= num_bits
        curr_pixel += 1

    # Reform bytestring from modified pixel values.
    return pix_bits


def get_pixel_bits(pixel, bitmasks, num_bits):
    """Extracts a given number of message bits from the data of a single
    pixel, using specified encoding methods.

    Arguments:
        pixel: bytestring
            Bytestring of the single pixel's data.
        bitmasks: list
            List of integers representing bitmasks of bits to extract.
        num_bits: integer
            The number of bits to decode from the pixel.
    Returns:
        List of bits of the extracted message, as integers (0 or 1).
    """
    assert (num_bits <= len(bitmasks))
    bits = []
    for i in range(num_bits):
        bits.append(int((pixel & bitmasks[i]) != 0))
    return bits


def decode_end_pad(end_pad_bytes, msg_len):
    """Extracts bits from the end padding of a row.

    Arguments:
        end_pad_bytes: bytstring
            End pad data to extract bits from.
        bmp_info: dictionary
            The bmp_info dict for the bitmap.
        msg_len: integer
            The length of the message to decode, in bits.
    Returns:
        List of bits of the extracted message, as integers (0 or 1).
    """
    end_pad_bits = bits_from_bytes(end_pad_bytes)
    # In event the message ends partway through the end pad, return
    # a truncated bit list.
    return end_pad_bits[:msg_len]


def detect_steg(data):
    """Detects and returns steganographically encoded data in pixel and
    end row padding from a bitmap.

    Arguments:
        data: bytestring
            The contents of the bitmap file as a bytestring.
    Returns:
        List of tuples representing detected steganographic data, in the
        form (description_string, data_bytestring). Empty list if no
        steganography detected.
    """
    detections = []
    bmp_info = process_bmp(data)
    row_data = extract_row_data(data, bmp_info)

    # Extract all pixel padding data.
    steg_flags = {PIXEL_PADDING: True, END_OF_ROW_PADDING: False,
                  LEAST_SIGNIFICANT_BIT: False}
    steg_info = get_steg_info(bmp_info, steg_flags)
    msg_len = steg_info['pix_bits_per_row'] * bmp_info['height']
    pix_pad_bits = read_message_bits(row_data, bmp_info, steg_info, msg_len)
    if len(set(pix_pad_bits)) > 1:
        # Add padding bits to data to bring to a multiple of 8,
        # otherwise unable to convert all extracted data to bytes.
        while (len(pix_pad_bits) % BITS_PER_BYTE != 0):
            pix_pad_bits.append(0)
        pix_pad_bytes = bytes_from_bits(pix_pad_bits)
        detections.append(('in pixel padding', pix_pad_bytes))

    # Extract all row padding data.
    steg_flags = {PIXEL_PADDING: False, END_OF_ROW_PADDING: True,
                  LEAST_SIGNIFICANT_BIT: False}
    steg_info = get_steg_info(bmp_info, steg_flags)
    msg_len = steg_info['end_pad_bits_per_row'] * bmp_info['height']
    row_pad_bytes = read_message(row_data, bmp_info, steg_info, msg_len)
    if len(set(row_pad_bytes)) > 1:
        detections.append(('in end-of-row padding', row_pad_bytes))

    return detections
