"""Build a cloud-init NoCloud seed ISO (volume label "cidata").

A Ubuntu cloud image takes its first boot configuration from such an ISO:
the ``user-data`` file with the cloud-config and the ``meta-data`` file with
the identity of the machine.

    python tools/make_seed_iso.py <user-data> <meta-data> <out.iso>

Needs pycdlib:  pip install pycdlib
"""

import io
import os
import sys

try:
    import pycdlib
except ImportError:
    print("This needs pycdlib:  pip install pycdlib", file=sys.stderr)
    sys.exit(1)


def build(user_data, meta_data, target):
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, joliet=3, vol_ident="CIDATA")
    # the file objects have to stay open until the image is written
    buffers = []
    for path, iso_path, joliet_path in (
        (user_data, "/USER_DAT.;1", "/user-data"),
        (meta_data, "/META_DAT.;1", "/meta-data"),
    ):
        with open(path, "rb") as handle:
            data = handle.read()
        buffer = io.BytesIO(data)
        buffers.append(buffer)
        iso.add_fp(
            buffer,
            length=len(data),
            iso_path=iso_path,
            joliet_path=joliet_path,
        )
    iso.write(target)
    iso.close()
    print("wrote %s" % target)


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        return 1
    build(sys.argv[1], sys.argv[2], sys.argv[3])
    return 0


if __name__ == "__main__":
    sys.exit(main())
