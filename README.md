## XRay shared link generator

Short guide on how to run the script that generates share links from your Xray config.

### Create virtual environment and install dependencies

Create virtual environment (Python 3):

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Setup Dependencies:

```bash
pip install -r requirements.txt
```

### Run

```bash
python main.py -i 1.2.3.4 -c config.json
```

where:
- **`-i`** — server public IP;
- **`-c`** — path to your Xray `config.json`.
