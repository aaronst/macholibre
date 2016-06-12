# macholibre

## Description
macholibre is a Mach-O and Universal binary parser.  It extracts information 
such as architectures, load commands, dynamic libraries, symbols, function 
imports, and tons more.  Then it packs all of that information into JSON for 
ease of analysis and integration.

## TODO
1. ~~Parse code signatures~~ DONE!
2. Add different output formats (console-friendly, CSV, etc.)
3. Add degrees of verbosity
4. ????

## Dependencies
I tried to make this tool with as little external dependencies as possible, and
I think I did pretty well on that front.  The only module I import is for parsing
CMS signatures.  I've configured the setup.py to automatically install it with
the module, but you can also install it seperately with pip or manually from github.
* [Python 2.7](https://www.python.org/download/releases/2.7/)
  - [ctypescrypto](https://github.com/vbwagner/ctypescrypto)
    + ctypescrypto depends on openssl under the hood, on linux it should be
      installed by default but on other OS's you might have to do this
      yourself (maybe ctypescrypto will do it for you?).  Anyways, make sure
      the version you install has CMS capabilities.

## How To

### Usage
#### As a Module
```python
from macholibre import macholibre

# mach-o file path
path = '/home/aaron/my_macho'

# return json
json_data = macholibre.parseFile(path)

# write json to file
out_file = open('/home/aaron/macholibre_output.json', 'w')
macholibre.parseFile(path, f=out_file)
```

#### As a Script
```python
python macholibre.py (-r <directory|glob> | <file>) [options]
```

##### Options
* -h: Help
* -r: Parse directory of glob
* -o: Specify output file

##### Note
For single files, make sure you put the filename first, before any options.  
Also, globs need to be in quotes and paths need to be absolute.

##### Examples

###### Single File
```python
python macholibre.py otool -o otool.json
```

###### Glob
```python
python macholibre.py -r "machos/*" -o machos.json
```

## Output Format
macholibre formats all of its output into a JSON blob.  The hierarchy is 
roughly as follows (order may vary):

* File
  - Name
  - Size
  - Hashes
  * Universal Binary
    - Number of Mach-O Binaries
    * Mach-O
      - Offset
      - Size
      - CPU Type
      - CPU Sub-Type
      - File Type
      - Number of Load Commands
      - Size of Load Commands
      - Flags
      * Load Command
        - Command
        - Size
        - Data
      * Load Command (Segment)
        - Command
        - Size
        - Name
        - Offset
        - Segment Size
        - Number of Sections
        * Section
          - Name
          - Segment Name
          - Offset
          - Size
      - Dynamic Libraries
      * Code Signature
        - Size
        - Count (number of entries)
        - Offset
        * Code Directory
          - Number of Code Slots
          - Number of Special Slots
          - Identity Offset
          - Page Size
          - Hash Type
          - Version
          - Flags
          - Code Limit
          - Identity
          - Hashes
          - Hash Offset
          - Scatter Offset
          - Hash Size
          - Team ID Offset
          - Team ID
          - Platform
        * Requirements
          - Count
          * Requirement
            - Offset
            - Type
            - Expression
        * Entitlement
          - Size
          * Plist
        * Certificate
          - Serial
          - Certificate Authority (Boolean)
          * Issuer
            - Country
            - Organization
            - Organizational Unit
            - Common Name
          * Subject
            - Country
            - Organization
            - Organizational Unit
            - Common Name
      * Symbol Table
        - Offset
        - Number of Symbols
        - Index to Local Symbols
        - Number of Local Symbols
        - Index to External Symbols
        - Number of External Symbols
        - Index to Undefined Symbols
        - Number of Undefined Symbols
        * Symbol (Stab Entry)
          - Index (Byte Offset) into String Table
          - Stab Type
          - Section
          - Value
        * Symbol
          - Index (Byte Offset) into String Table
          - PEXT
          - Type
          - EXT
          - Dynamic Library
          - Reference
          - Section
          - Value
      * String Table
        - Offset
        - Size
        - Strings
      - Imports
      - Minimum OS Version
      * Analytics
        - Number of Function Imports
        - Number of Dynamic Libraries
        - Average Load Command Size
        - Entropy
