import argparse
import json
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

        self.zip_file = zipfile.ZipFile(self.zip_path)
        self.file_list = {}
        
        valid_manifest = False
        if 'manifest.json' in self.zip_file.namelist():
            with self.zip_file.open('manifest.json') as manifest:
                try:
                    j = json.load(manifest)
                    valid_manifest = True
                except:
                    pass
            if not 'audits' in j:
                raise Exception('audits missing from FireEye manifest')
            for audit in j['audits']:
                if not 'generator' in audit:
                    raise Exception('generator missing from audit')
                if audit['generator'] == 'multifile-acquisition-api':
                    if not 'results' in audit:
                        raise Exception('results missing from audit')
                    for i, result in enumerate(audit['results']):
                        if not 'payload' in result:
                            raise Exception(f'payload missing from audit result[{i}]')
                        if not 'metadata' in result:
                            raise Exception(f'metadata missing from audit result[{i}]')
                        filename = None
                        filepath = None                            
                        for meta in result['metadata']:
                            if 'name' in meta and 'value' in meta:
                                if meta['name'] == 'mandiant/mir/agent/FileName' and self.matcher(meta['value']):
                                    filename = meta['value']
                                if meta['name'] == 'mandiant/mir/agent/FilePath':
                                    filepath = meta['value']
                                if not filename is None and not filepath is None:
                                    if '\\' in filepath:
                                        self.file_list[result['payload']] = '\\'.join((filepath, filename))
                                    else:
                                        self.file_list[result['payload']] = '/'.join((filepath, filename))
        
        if not valid_manifest:
            for zip_info in self.zip_file.infolist():
                if not zip_info.is_dir() and self.matcher(zip_info.filename):
                    self.file_list[zip_info.filename] = zip_info.filename

    def __enter__(self):
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
        for filename in self.file_list:
            yield filename

    def infos(self):
        for zip_info in self.zip_file.infolist():
            if zip_info.filename in self.file_list:
                yield zip_info

    def files(self):
        for zip_info in self.zip_file.infolist():
            if not zip_info.is_dir() and zip_info.filename in self.file_list:
                opened = False
                for password in self.passwords:
                    pwd = None if password is None else bytes(password, 'utf-8')
                    try:
                        with self.zip_file.open(zip_info, pwd=pwd) as f:
                            yield zip_info.filename, f
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
        for filename, e in fz.files():
            print(filename)
            print(e.read())
