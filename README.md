# STEGH

STEGH provides various commands to encode, decode and detect
steganographic data in jpg and bmp files.

STEGH currently supports all types of jpeg files, as well as 16, 24 and
32 bit colour bitmap files, with or without alpha channels.

## Commands:
### stegh capacity
    Description: Analyse bmp file to determine maximum size for of
                 secret able to be encoded.
    Usage:  stegh capacity [-h] [-l] [-x] [-p] [--detailed] infile
            -h:         display help
            -l:         use least significant bit encoding
            -x:         use pixel padding bit encoding
            -p:         use end of row padding bit encoding
            --detailed: display detailed image information
            infile:     bmp file to analyse

### stegh encode-bmp
    Description: Stegonographically encodes a given secret file into a
                 given bitmap file. Encoding can be performed using
                 pixel padding bits, end of row padding bytes, least
                 significant bit encoding in colour and alpha channels,
                 or any combination of these. If no encoding options are
                 provided, defaults to using all available options.
    Usage:  stegh encode-bmp [-h] [-l] [-x] [-p] [--detailed] infile secret outfile
            -h:         display help
            -l:         use least significant bit encoding
            -x:         use pixel padding bit encoding
            -p:         use end of row padding bit encoding
            --detailed: display detailed image information
            infile:     bmp file to encode secret into
            secret:     file to stegonographically encode into infile
            outfile:    filepath to save encoded bmp file

### stegh decode-bmp
    Description: Decodes a secret file from an encoded bitmap file.
                 Decoding must use the same encoding options used to
                 encode the secret. If no encoding options are
                 provided, defaults to using all available options.
    Usage:  stegh decode-bmp [-h] [-l] [-x] [-p] [--detailed] infile outfile
            -h:         display help
            -l:         use least significant bit encoding
            -x:         use pixel padding bit encoding
            -p:         use end of row padding bit encoding
            --detailed: display detailed image information
            infile:     bmp file to decode secret from
            outfile:    filepath to save decoded secret file

### stegh detect-bmp
    Description: Detects if data is stegonographically encoded in the
                 padding of a bitmap file. If dump option is used, saves
                 the complete raw padding data of the bitmap to a given
                 file if stegonography is detected.
    Usage:  stegh detect-bmp [-h] [--dump-file FILEPATH] infile
            -h:                     display help
            --dump-file FILEPATH:   save padding data to FILEPATH
            infile:                 bmp file to detect within

### stegh encode-jpg
    Description: Stegonographically encodes a given secret file into a
                 given jpeg file. Encoding can be performed by placing
                 data after the end of image marker, or in the image
                 metadata as comments. If no encoding options are
                 provided, defaults to placing data after the end of
                 image marker.
    Usage:  stegh encode-jpg [-h] [-m] [-e] [--show-sections] infile secret outfile
            -h:             display help
            -m:             encode secret as comment metadata
            -e:             encode secret after end of image marker
            --show-sections display jpeg section list
            infile:         jpg file to encode secret into
            secret:         file to stegonographically encode into
                            infile
            outfile:        filepath to save encoded jpg file

### stegh decode-jpg
    Description: Decodes a secret file from an encoded jpeg file.
                 Decoding must use the same encoding options used to
                 encode the secret. If no encoding options are
                 provided, defaults to using decoding data after the end
                 of image marker.
    Usage:  stegh decode-jpg [-h] [-m] [-e] [--show-sections] infile outfile
            -h:             display help
            -m:             decode data from comment metadata
            -e:             decode data from after end of image marker
            --show-sections display jpeg section list
            infile:         jpg file to decode secret from
            outfile:        filepath to save decoded secret file

### stegh detect-jpg
    Description: Detects if data is stegonographically encoded in the
                 comment metadata or after the end of image marker of
                 a jpeg file. If dump option is used, saves the complete
                 data of any comments or after the end of image marker
                 to a given file, if detected.
    Usage:  stegh detect-jpg [-h] [--dump-file FILEPATH] [--show-sections] infile
            -h:                     display help
            --dump-file FILEPATH:   save detected data to FILEPATH
            --show-sections         display jpeg section list
            infile:                 jpg file to detect within
