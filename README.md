# macholibre

## Description

macholibre is a Mach-O and Universal binary parser.  It extracts information 
such as architectures, load commands, dynamic libraries, symbols, function 
imports, and tons more.  Then it packs all of that information into JSON for 
ease of analysis and integration.

## Python 2

With Python 2 in its sunset years, macholibre has moved on to Python 3.
However, for those of you that are stuck on Python 2, see the [python2](https://github.com/aaronst/macholibre/tree/python2)
branch. No promises on long-term support, but the code differences right now
are minimal and should be fairly easy to maintain.

## Dependencies

This project requires Python 3.4+ to run, due to API changes in `plistlib`.

I tried to make this tool with as little external dependencies as possible, and
I think I did pretty well on that front.  The only module I import is for
parsing CMS signatures.  I've configured `setup.py` to automatically install
it with the module, but you can also install it seperately with pip or manually
from github.

* [asn1crypto](https://github.com/wbond/asn1crypto)

## How To

### Installation

I recommend using pip to install macholibre.

```bash
pip3 install git+https://github.com/aaronst/macholibre.git
```

### Usage

#### As a Module

```python
from macholibre import parse

# mach-o file path
path = '/home/aaron/my_macho'

# return dict
data = parse(path)

# write json to file
out_file = open('/home/aaron/macholibre_output.json', 'w')
parse(path, out=out_file)
```

#### As a Script

```plain
usage: macholibre [-h] [-c] [-o OUTPUT] input [input ...]

MachoLibre: Mach-O & Universal Binary Parser
  aaronjst93@gmail.com

positional arguments:
  input                 input mach-o file(s) to parse

optional arguments:
  -h, --help            show this help message and exit
  -c, --certificates    extract certificates
  -o OUTPUT, --output OUTPUT
                        output JSON file

examples:
  macholibre macho
  macholibre -o output.json macho
  macholibre -o output.json machos/*
```

## Output Format

macholibre formats all of its output into a JSON blob.  Check out
[app_store.json](app_store.json) as an example using the App Store app.
