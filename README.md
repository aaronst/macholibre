# macholibre

## Description
macholibre is a Mach-O and Universal binary parser.  It extracts information 
such as architectures, load commands, dynamic libraries, symbols, function 
imports, and tons more.  Then it packs all of that information into JSON for 
ease of analysis and integration.

## Dependencies
I tried to make this tool with as little external dependencies as possible, and
I think I did pretty well on that front.  The only module I import is for
parsing CMS signatures.  I've configured the setup.py to automatically install
it with the module, but you can also install it seperately with pip or manually
from github.
* [Python 2.7](https://www.python.org/download/releases/2.7/)
  - [asn1crypto](https://github.com/wbond/asn1crypto)
    + May require `openssl` to be installed, I'm not sure.

## How To

### Installation
I recommend using pip to install macholibre.
```bash
pip install git+https://github.com/aaronst/macholibre.git
```

### Usage
#### As a Module
```python
from macholibre import parse

# mach-o file path
path = '/home/aaron/my_macho'

# return json
json_data = parse(path)

# write json to file
out_file = open('/home/aaron/macholibre_output.json', 'w')
parse(path, f=out_file)
```

#### As a Script
```
usage: macholibre [-h] [-o OUTPUT] input [input ...]

MachoLibre: Mach-O & Universal Binary Parser
  aaron@icebrg.io

positional arguments:
  input                 input mach-o file(s) to parse

optional arguments:
  -h, --help            show this help message and exit
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

