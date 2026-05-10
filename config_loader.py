import json
import os
import logging

# Enhanced Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("ZTA-Config")

def load_smart_config():
    """
    Detects the component type and loads the relevant local JSON config.
    Priority: Environment > Local JSON > Defaults.
    """
    config = {
        "idp_url": "http://localhost:8001",
        "controller_url": "http://localhost:8002",
        "gateway_url": "http://localhost:8081",
        "sdn_url": "http://localhost:8084",
        "ovp2_url": "http://localhost:8083",
        "jwt_secret": "CHANGE_ME_USE_RSA_OR_EC_IN_PRODUCTION",
        "resource_ip": "10.0.0.100"
    }

    # Search for local configs in order of specificity
    search_paths = [
        "Client_Agent/client_config.json",
        "SDP_Gateway/pep_config.json",
        "SDP_Controller/sdp_config.json",
        "zta_config.json"
    ]

    for path in search_paths:
        full_path = os.path.join(os.path.dirname(__file__), path)
        if os.path.exists(full_path):
            try:
                with open(full_path, "r") as f:
                    data = json.load(f)
                    # Mapping logic to normalize the split JSON keys
                    if "pdp_url" in data: config["controller_url"] = data["pdp_url"]
                    if "idp_url" in data: config["idp_url"] = data["idp_url"]
                    if "gateway_url" in data: config["gateway_url"] = data["gateway_url"]
                    if "sdn_url" in data: config["sdn_url"] = data["sdn_url"]
                    if "jwt_secret" in data: config["jwt_secret"] = data["jwt_secret"]
                    if "resource_ip" in data: config["resource_ip"] = data["resource_ip"]
                    
                logger.info(">>> SUCCESS: Plugged in config from: %s", path)
                break 
            except Exception as e:
                logger.error("Error loading %s: %s", path, e)

    return config

zta_settings = load_smart_config()

def log_important(component, action, data_dict):
    """Prints high-visibility security items to the terminal."""
    print(f"\n{'='*60}")
    print(f"[{component}] {action.upper()}")
    for k, v in data_dict.items():
        # Mask secrets
        val = f"{v[:12]}...{v[-8:]}" if isinstance(v, str) and len(v) > 30 else v
        print(f"  > {k:15}: {val}")
    print(f"{'='*60}\n")
