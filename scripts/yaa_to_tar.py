import struct
import tarfile
import io
import sys


def read_tag(f):
    tag = f.read(4)
    if not tag:
        return None
    return tag.decode("ascii", errors="ignore")


def read_u16(f):
    return struct.unpack("<H", f.read(2))[0]


def read_u32(f):
    return struct.unpack("<I", f.read(4))[0]


def read_u64(f):
    return struct.unpack("<Q", f.read(8))[0]


def parse_object(f, typetag):
    obj = {
        "type": typetag,
        "uid": 0,
        "gid": 0,
        "mode": 0o755,
        "path": None,
        "data": None,
    }

    while True:
        tag = read_tag(f)
        if not tag:
            break

        if tag == "UID1":
            obj["uid"] = read_u32(f)

        elif tag == "GID1":
            obj["gid"] = read_u32(f)

        elif tag == "MOD2":
            obj["mode"] = read_u16(f)

        elif tag == "PATH":
            l = read_u16(f)
            obj["path"] = f.read(l).decode("utf-8", errors="ignore")

        elif tag == "DATA":
            size = read_u64(f)
            obj["data"] = f.read(size)

        elif tag == "END!":
            break

        else:
            # unknown tag → skip length-prefixed payload if present
            # safe fallback: ignore
            pass

    return obj


def convert_yaa_to_tar(yaa_path, tar_path):

    with open(yaa_path, "rb") as f:

        magic = f.read(4)
        if magic != b"YAA1":
            raise RuntimeError("not a YAA archive")

        version = struct.unpack("<I", f.read(4))[0]
        print("YAA version:", version)

        with tarfile.open(tar_path, "w") as tar:

            while True:
                tag = read_tag(f)
                if not tag:
                    break

                if not tag.startswith("TYP1"):
                    continue

                obj = parse_object(f, tag)

                if not obj["path"]:
                    continue

                ti = tarfile.TarInfo(obj["path"])
                ti.uid = obj["uid"]
                ti.gid = obj["gid"]
                ti.mode = obj["mode"]

                if tag == "TYP1DPATP":  # directory
                    ti.type = tarfile.DIRTYPE
                    tar.addfile(ti)

                elif tag == "TYP1FPATP":  # file
                    data = obj["data"] or b""
                    ti.size = len(data)
                    tar.addfile(ti, io.BytesIO(data))

                elif tag == "TYP1LPATP":  # symlink
                    ti.type = tarfile.SYMTYPE
                    tar.addfile(ti)


if __name__ == "__main__":

    if len(sys.argv) != 3:
        print("usage: yaa_to_tar <yaa_stream> <output.tar>")
        sys.exit(1)

    convert_yaa_to_tar(sys.argv[1], sys.argv[2])
