# potpie
potpie (POT password insights engine) is a tool developed to derive password metrics and insights based on passwords cracked during a penetration test.


## Install
```sh
> git clone https://github.com/asmtlab/potpie
> cd potpie
> pip3 install .
> poetry run potpie
```

## Usage
```sh
> poetry run potpie --help

Usage: potpie [OPTIONS]

╭─ Options ────────────────────────────────────────────────────────────────────────────────╮
│ *  --length   -l      INTEGER   Minimum password length (per policy)                     │
│                                 [default: None]                                          │
│                                 [required]                                               │
│    --complex                    Password complexity is enforced (per policy)             │
│ *  --ntds     -n      FILENAME  Path to the NTDS.dit file [default: None]                │
│                                 [required]                                               │
│ *  --potfile  -p      FILENAME  Path to the hashcat potfile [default: None]              │
│                                 [required]                                               │
│    --debug                      Enable DEBUG output                                      │
│    --help     -h                Show this message and exit.                              │
╰──────────────────────────────────────────────────────────────────────────────────────────╯
```

## Examples
Conduct password analysis for an environment with 8-character `Minimum Password Length` and `Domain Password Complex` bit set:
```sh
> poetry run potpie --length 8 --complex --ntds ntds.dit --potfile cracked.potfile
```

Conduct password analysis for an environment with no `Minimum Password Length` and `Domain Password Complex` bit not set:
```sh
> poetry run potpie --length 0 --ntds ntds.dit --potfile cracked.potfile
```
## Development
potpie uses Poetry to manage dependencies. Install from source and setup for development with:
```sh
> git clone https://github.com/asmtlab/potpie
> cd potpie
> poetry install
> poetry run potpie --help
```

## Credits
Cookiecutter Template: https://github.com/coffeegist/cookiecutter-app
