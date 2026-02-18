## XRay share link generator

Supports VLESS and ShadowSocks links. Work in XRay-based clients.

### Create virtual environment and install dependencies

Create virtual environment (Python 3):

```bash
$ python3 -m venv .venv
$ source .venv/bin/activate
```

Setup Dependencies:

```bash
$ pip install -r requirements.txt
```

### Run

```bash
$ python main.py --help
usage: main.py [-h] -i IP -c CONFIG

options:
  -h, --help            show this help message and exit
  -i IP, --ip IP        server IP address
  -c CONFIG, --config CONFIG
                        path to config file

$ python3 main.py -i 1.2.3.4 -c config.json
ss://YWVzLTI1Ni1nY206ZnVrY3JrbmluYWxscG9zc2libGVob2xlcw@1.2.3.4:2223
vless://267017ea-f664-42dc-9ebf-cb64528030ad@1.2.3.4:443?type=tcp&security=reality&encryption=none&pbk=yK5R8Nn74jM8lG3aQ1pP5sL8vX4cZ9yM6tR3eW2qA1Y&headerType=none&type=tcp&flow=xtls-rprx-vision&fp=chrome&sni=microsoft.com&sid=94ed93c58960d0d3
```