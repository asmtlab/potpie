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
│    --admins   -a      FILENAME  Path to file containing list of administrators           │
│                                 [default: None]                                          │
│    --kerb     -k      FILENAME  Path to file containing list of kerberoastable accounts  │
│                                 [default: None]                                          │
│    --breach                     Enable HaveIBeenPwned breach analysis                    │
│                                     (~1.6s per cracked password)                         │
│    --breach-data      FILENAME  Path to file containing HaveIBeenPwned breach data       │
│                                 [default: None]                                          │
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

Conduct password analysis with lists of administrator and kerberoastable accounts (account names should be identical to how they are shown in the NTDS.dit file, including the domain where relevant):
```sh
> poetry run potpie --length 8 --complex --ntds ntds.dit --potfile cracked.potfile --admins admins.txt --kerb kerberoastable.txt
```

Conduct password analysis, including HaveIBeenPwned breach analysis (note this will take ~1.6 seconds per cracked password due to HIBP rate limits):
```sh
> poetry run potpie --length 8 --complex --ntds ntds.dit --potfile cracked.potfile --breach
```

Conduct password analysis, including HaveIBeenPwned breach analysis with a HaveIBeenPwned JSON file output from a previous run of `potpie` (default output location is `reports/hibp_data.json`):
```sh
> poetry run potpie --length 8 --complex --ntds ntds.dit --potfile cracked.potfile --breach-data ./reports/hibp_data.json
```

## Report Formats
### Client Report
The client report is output to `reports/potpie_report.html` and is meant to be shared with clients as it does not include the full set of attributable password data.

### Operator Report
The operator report is output to `reports/operator_report/potpie_operator_report.html` and is a similar format to the client report, but contains customized links to a detailed report of all hashes/passwords. The detailed report is a sortable/filterable table that operators can use to run custom queries on the full password dataset.

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
