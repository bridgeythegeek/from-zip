import argparse
import re
import zipfile
from enum import Enum

class MatchType(Enum):

    starts_with = 'starts_with'
    contains = 'contains'
    ends_with = 'ends_with'
    regex = 'regex'


class FromZip:

    def __init__(self, zip_path, match_type, pattern, match_case=False, passwords=None):
        try:
            self.match_type = MatchType(match_type)
            self.matcher = getattr(self, match_type)
        except ValueError as e:
            raise Exception(f'Invalid MatchType; valid types are {[e.value for e in MatchType]}').with_traceback(e.__traceback__)
        self.zip_path = zip_path
        self.pattern = pattern if match_case else pattern.lower()
        if passwords is None:
            passwords = [None]
        elif not None in passwords:
            passwords.insert(0, None)
        self.passwords = passwords
        self.match_case = match_case

    def __enter__(self):
        self.zip_file = zipfile.ZipFile(self.zip_path)
        return self

    def __exit__(self, exception_type, exception_value, exception_traceback):
        if self.zip_file:
            self.zip_file.close()

    def starts_with(self, item):
        if not self.match_case:
            item = item.lower()
        return item.startswith(self.pattern)

    def contains(self, item):
        if not self.match_case:
            item = item.lower()
        return self.pattern in item

    def ends_with(self, item):
        if not self.match_case:
            item = item.lower()
        return item.endswith(self.pattern)

    def regex(self, item):
        if not self.match_case:
            item = item.lower()
        return not (re.search(self.pattern, item) is None)

    def names(self):
        for zip_info in self.zip_file.infolist():
            if not zip_info.is_dir() and self.matcher(zip_info.filename):
                yield zip_info.filename

    def infos(self):
        for zip_info in self.zip_file.infolist():
            if not zip_info.is_dir() and self.matcher(zip_info.filename):
                yield zip_info

    def files(self):
        for zip_info in self.zip_file.infolist():
            if not zip_info.is_dir() and self.matcher(zip_info.filename):
                opened = False
                for password in self.passwords:
                    pwd = None if password is None else bytes(password, 'utf-8')
                    try:
                        with self.zip_file.open(zip_info, pwd=pwd) as f:
                            yield f
                        opened = True
                        break
                    except RuntimeError:
                        pass
                if not opened:
                    raise Exception('Unknown password')


if __name__ == '__main__':

    argp = argparse.ArgumentParser()
    argp.add_argument('zip_file')
    argp.add_argument('type')
    argp.add_argument('pattern')
    argp.add_argument('-c', action="store_true", help="pattern is case-sensitive")
    argp.add_argument('-p', nargs='+', default=[None])
    args = argp.parse_args()

    with FromZip(args.zip_file, args.type, args.pattern, args.c, args.p) as fz:
        print("Names\n=====")
        for e in fz.names():
            print(e)
        print("Infos\n=====")
        for e in fz.infos():
            print(e)
        print("Bytes\n=====")
        for e in fz.files():
            print(e.read())

