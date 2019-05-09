#!/usr/bin/env python3


"""
Copyright 2016 Aaron Stephens <aaronjst93@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""


from argparse import ArgumentParser, FileType, RawDescriptionHelpFormatter
from json import dump, dumps

from macholibre.parser import Parser


def output_file(out):
    """Convert file path to writeable file object."""

    try:
        return open(out, 'w')
    except IOError as exc:
        print('Error opening output file at path: {}.\n\n{}'.format(out, exc))
        exit(1)


def parse(macho, certs: bool=False, out=None):
    """Parse given mach-o file. Wrap ``parse()`` function from ``Parser``
    object in order to handle mulitple input files for script use.
    """

    parser = Parser(macho)

    if out is None:
        return parser.parse(certs=certs)
    else:
        parser.parse(certs=certs, out=out)


def main():
    """Main function for script."""

    parser = ArgumentParser(description='MachoLibre: Mach-O & Universal Binary'
                                        ' Parser\n  aaronjst93@gmail.com',
                            formatter_class=RawDescriptionHelpFormatter,
                            epilog='examples:\n  macholibre macho\n  macholibr'
                                   'e -o output.json macho \n  macholibre -o o'
                                   'utput.json machos/*')

    parser.add_argument('input', nargs='+',
                        help='input mach-o file(s) to parse')

    parser.add_argument('-c', '--certificates', action='store_true',
                        help='extract certificates')
    parser.add_argument('-o', '--output', default=None, type=output_file,
                        help='output JSON file')

    args = parser.parse_args()

    if len(args.input) == 1:
        if args.output is None:
            print(dumps(parse(args.input[0], certs=args.certificates)))
        else:
            parse(args.input[0], out=args.output, certs=args.certificates)
    else:
        if args.output is None:
            output = []

            for macho in args.input:
                output.append(Parser(macho).parse(certs=args.certificates))

            print(dumps(output))
        else:
            args.output.write('[')

            for i in range(len(args.input)):
                dump(Parser(args.input[i]).parse(certs=args.certificates),
                     args.output)

                if i < len(args.input) - 1:
                    args.output.write(',')

            args.output.write(']')
