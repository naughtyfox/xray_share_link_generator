import argparse
from abc import ABC, abstractmethod
import json

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


class ShareLinkBase(ABC):
    @abstractmethod
    def ShareLink(self) -> str:
        pass


class ShadowSocksShareLink(ShareLinkBase):
    def __init__(self, ip: str, port: int, password: str, method: str):
        self.ip = ip
        self.port = port
        self.password = password
        self.method = method

    def ShareLink(self) -> str:
        import base64
        # Shadowsocks URI: ss://BASE64-ENCODED-METHOD:PASSWORD@IP:PORT
        userinfo = f"{self.method}:{self.password}"
        userinfo_b64 = base64.urlsafe_b64encode(userinfo.encode()).decode().rstrip("=")
        uri = f"ss://{userinfo_b64}@{self.ip}:{self.port}"

        return uri


class VlessShareLink(ShareLinkBase):
    def __init__(self, 
            client_uuid: str, 
            ip: str, 
            public_key: str, 
            fingerprint: str, 
            sni: str, 
            flow: str,
            security: str,
            shord_id: str):

        self.client_uuid = client_uuid
        self.ip = ip
        self.public_key = public_key
        self.fingerprint = fingerprint
        self.sni = sni
        self.flow = flow
        self.security = security
        self.short_id = shord_id

    def ShareLink(self) -> str:
        uri = (
            f"vless://{self.client_uuid}@{self.ip}:443"
            f"?type=tcp&security={self.security}&encryption=none"
            f"&pbk={self.public_key}&headerType=none"
            f"&type=tcp&flow={self.flow}"
            f"&fp={self.fingerprint}&sni={self.sni}"
            f"&sid={self.short_id}"
        )
        return uri


def make_shadowsocks_share_link(inbound, ip) -> ShadowSocksShareLink:
    port = inbound.get("port")
    settings = inbound.get("settings", {})
    password = settings.get("password")
    method = settings.get("method")

    if not(port and password and method):
        raise ValueError("invalid shadowsocks inbound: port, password and method must be set")

    return ShadowSocksShareLink(ip, port, password, method)


def make_vless_share_link(inbound, ip) -> list[VlessShareLink]:
    port = inbound.get("port")
    settings = inbound.get("settings", {})
    clients = settings.get("clients", [])
    if len(clients) == 0:
        raise ValueError("invalid vless inbound: clients section must not be empty")

    stream_settings = inbound.get("streamSettings", {})
    security = stream_settings.get("security", "")
    network = stream_settings.get("network", "")
    reality_settings = stream_settings.get("realitySettings", {})

    sni_list = reality_settings.get("serverNames", [])
    sni = sni_list[0] if sni_list else ""
    flow = clients[0].get("flow", "")  # Выбираем flow из первого клиента

    private_key = reality_settings.get("privateKey", "")
    short_ids = reality_settings.get("shortIds", [])
    if len(short_ids) == 0:
        raise ValueError("invalid vless inbound: shortIds must be set")

    # TODO: make support of multiple shortIds?
    reality_secret = short_ids[0]

    if not(sni != "" and flow != "" and private_key != "" and security != "" and network != ""):
        raise ValueError("invalid vless inbound: sni, flow, privateKey, security and network must be set")

    try:
        priv_bytes = None
        import base64
        priv_bytes = base64.urlsafe_b64decode(private_key + "==")
        priv_key_obj = X25519PrivateKey.from_private_bytes(priv_bytes)
        pub_key_obj = priv_key_obj.public_key()
        pub_key_bytes = pub_key_obj.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
        public_key = base64.urlsafe_b64encode(pub_key_bytes).decode('utf-8').rstrip('=')
    except Exception as e:
        raise ValueError(f"Faild to generate public key from private: {e}")

    fingerprint = "chrome"

    vless_links = []
    for client in clients:
        client_uuid = client.get("id", "")
        client_flow = client.get("flow", "")

        if client_uuid == "" or client_flow == "":
            raise ValueError("invalid vless inbound: client uuid and flow must be set")

        vless_links.append(
            VlessShareLink(
                client_uuid=client_uuid,
                ip=ip,
                public_key=public_key,
                fingerprint=fingerprint,
                sni=sni,
                flow=client_flow,
                security=security,
                shord_id=reality_secret
            )
        )
        
    return vless_links


def generate_links(config: dict, ip) -> list[ShareLinkBase]:
    result = []
    inbounds = config.get("inbounds", [])
    for inbound in inbounds:
        protocol = inbound.get("protocol")
        if protocol == "shadowsocks":
            result.append(make_shadowsocks_share_link(inbound, ip))
        elif protocol == "vless":
            result.extend(make_vless_share_link(inbound, ip))
    
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", type=str, help="server IP address", required=True)
    parser.add_argument("-c", "--config", type=str, help="path to config file", required=True)
    
    args = parser.parse_args()

    with open(args.config, 'r') as f:
        config_data = json.load(f)

    links = generate_links(config_data, args.ip)

    for link in links:
        print(link.ShareLink())


if __name__ == '__main__':
    main()