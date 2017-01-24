# macholibre

## Description
macholibre is a Mach-O and Universal binary parser.  It extracts information 
such as architectures, load commands, dynamic libraries, symbols, function 
imports, and tons more.  Then it packs all of that information into JSON for 
ease of analysis and integration.

## Dependencies
I tried to make this tool with as little external dependencies as possible, and
I think I did pretty well on that front.  The only module I import is for parsing
CMS signatures.  I've configured the setup.py to automatically install it with
the module, but you can also install it seperately with pip or manually from github.
* [Python 2.7](https://www.python.org/download/releases/2.7/)
  - [ctypescrypto](https://github.com/vbwagner/ctypescrypto)
    + ctypescrypto depends on openssl under the hood, on linux it should be
      installed by default but on other OS's you might have to do this
      yourself.  Anyways, make sure the version you install has CMS capabilities.

## How To

### Installation
I recommend using pip to install macholibre.
```bash
pip install git+https://github.com/aaronst/macholibre.git
```

#### OS X USERS: IMPORTANT NOTES
If you run into any errors while using macholibre on OS X, try the following
before creating a ticket.

Make sure your version of OpenSSL is up to date with `openssl version`.
macholibre has been confirmed working with `OpenSSL 1.0.2h  3 May 2016`.
```
brew update
brew install openssl
brew link --force openssl
```

pip may install an old version of the ctypescrypto dependency that crashes on OS X.
In order to fix this you'll need to install the current version from github.
```bash
pip uninstall ctypescrypto
pip install git+https://github.com/vbwagner/ctypescrypto.git
```

### Usage
#### As a Module
```python
from macholibre import macholibre

# mach-o file path
path = '/home/aaron/my_macho'

# return json
json_data = macholibre.parse(path)

# write json to file
out_file = open('/home/aaron/macholibre_output.json', 'w')
macholibre.parse(path, f=out_file)
```

#### As a Script
```
usage: macholibre.py [-h] [-o OUTPUT] input

MachoLibre: Mach-O & Universal Binary Parser
  aaron@icebrg.io

positional arguments:
  input                 input mach-o file (or glob in quotes) to parse

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        output JSON file

examples:
  python macholibre.py macho
  python macholibre.py -o output.json macho
  python macholibre.py -o output.json "machos/*"
```

## Output Format
macholibre formats all of its output into a JSON blob.  Check out
[app_store.json](app_store.json) as an example using the App Store app.

