import os
import shutil
import msgpack
import requests
from base64 import b64encode
from datetime import datetime
#from webdav3.client import Client

import env

#Global envs
auth_mode = ''

# ------------------- HELPERS ---------------- #

def get_user_id():
    """Prompt the user for a user id to restore"""
    return input("Enter user id to restore: ").strip()

# ------------------- AUTH ------------------- #
def get_bearer_token():
    """Prompt the user for a Bearer token. Needs to be Admin Role"""
    return input("Enter your Bearer token: ").strip()


def build_headers(token):
    """Build request headers with a token."""
    global auth_mode
    if hasattr(env, 'OCIS_USER') and hasattr(env, 'OCIS_USER_TOKEN'):
        # Use as username/password
        auth_mode = "basic"
        print(f"Using USER/PASSWORD authentication with user: {env.OCIS_USER}")
        app_token = b64encode(f"{env.OCIS_USER}:{env.OCIS_USER_TOKEN}".encode('utf-8')).decode("ascii")

        return {
            'accept': 'application/json',
            'Authorization': f'Basic {app_token}'
        }
    else:
        # Ask for Bearer token
        auth_mode = "bearer"
        if token is None:
            token = get_bearer_token()
        print("Using Bearer token authentication.")
        
        return {
            'accept': 'application/json',
            'Authorization': f'Bearer {token}'
        }


# ------------------- PATH HELPERS ------------------- #
def get_base_directory(space_id):
    """Return base path to ./backup/<first_two>/<rest_of_id> for a space_id"""
    backup_dir = os.path.join(os.getcwd(), "backup")
    return os.path.join(backup_dir, space_id[:2], space_id[2:])


def get_nodes_directory(space_id):
    return os.path.join(get_base_directory(space_id), "nodes")


def get_blobs_directory(space_id):
    return os.path.join(get_base_directory(space_id), "blobs")


# ------------------- FILE OPERATIONS ------------------- #
def find_clean_mpk_files(space_id):
    """Find all .mpk files excluding .REV. and .T. versions."""
    nodes_dir = get_nodes_directory(space_id)
    mkp_files = []
    for root, _, files in os.walk(nodes_dir):
        for file in files:
            if file.endswith(".mpk") and ".REV." not in file and ".T." not in file:
                mkp_files.append(os.path.join(root, file))
    return mkp_files


def decode_mpk(file_path):
    """Decode a .mpk (MessagePack) file into Python objects."""
    with open(file_path, "rb") as f:
        unpacker = msgpack.Unpacker(f, raw=False)
        return list(unpacker)


def extract_user_ocis_fields(data, source_file=None):
    """Extract and decode user.ocis.* fields from decoded MessagePack data."""
    keys = {"user.ocis.parentid", "user.ocis.id", "user.ocis.name", "user.ocis.type", "user.ocis.blobid"}
    results = {}

    def normalize(val):
        if isinstance(val, bytes):
            try:
                return val.decode("utf-8")
            except Exception:
                return val.hex()
        return val

    def recurse(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in keys:
                    results[k] = normalize(v)
                recurse(v)
        elif isinstance(obj, list):
            for item in obj:
                recurse(item)

    recurse(data)

    if "user.ocis.id" not in results and source_file:
        parts = source_file.split(os.sep)
        if "nodes" in parts:
            idx = parts.index("nodes")
            node_id = os.path.splitext(os.path.join(*parts[idx + 1:]))[0]
            results["user.ocis.id"] = node_id.replace(os.sep, "")

    return results


# ------------------- RESTORE ------------------- #
def create_dir_recursively(node, nodes_dict, created_paths, output_dir, space_id):
    node_id = node["user.ocis.id"]
    if node_id in created_paths:
        return created_paths[node_id]

    parentid = node["user.ocis.parentid"]
    if parentid == space_id:
        parent_path = output_dir
    else:
        parent_node = nodes_dict.get(parentid)
        parent_path = (
            create_dir_recursively(parent_node, nodes_dict, created_paths, output_dir, space_id)
            if parent_node else output_dir
        )

    dir_path = os.path.join(parent_path, node["user.ocis.name"])
    os.makedirs(dir_path, exist_ok=True)
    created_paths[node_id] = dir_path
    print(f"[DIR] Created: {dir_path}")
    return dir_path


def build_directory_tree_and_restore_files(nodes, space_id, output_dir="output"):
    blobs_dir = get_blobs_directory(space_id)
    nodes_dict = {node["user.ocis.id"]: node for node in nodes}
    created_paths = {}

    # Create directories
    for node in nodes:
        if node.get("user.ocis.type") == "2":
            create_dir_recursively(node, nodes_dict, created_paths, output_dir, space_id)

    # Restore files
    for node in nodes:
        if node.get("user.ocis.type") != "1":
            continue

        filename = node["user.ocis.name"]
        blobid = node.get("user.ocis.blobid")
        if not blobid:
            print(f"[WARN] Skipping {filename}, no blobid")
            continue

        parent_path = created_paths.get(node.get("user.ocis.parentid"), output_dir)
        blob_path = os.path.join(blobs_dir, blobid[0:2], blobid[2:4], blobid[4:6], blobid[6:8], blobid[8:])

        if not os.path.exists(blob_path):
            print(f"[MISSING] Blob not found for {filename}: {blob_path}")
            continue

        shutil.copy2(blob_path, os.path.join(parent_path,filename))



# ------------------- MAIN ------------------- #
def restore_user_drive(user_id=None, token=None):
    user_id = token or get_user_id()
    
    headers = build_headers(token)

    # Get user + drive info
    url = f"{env.OCIS_URL}graph/v1.0/users/{user_id}?%24expand=drive"
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    user_data = resp.json()

    space_id = user_data["drive"]["id"].split("$")[1]
    space_name = f"Restore {user_data['displayName']} {datetime.today().strftime('%Y-%m-%d')}"
    space_description = f"Restore der Daten von {user_data['displayName']} am {datetime.today().strftime('%Y-%m-%d')}"

    # Process .mpk files
    mkp_files = find_clean_mpk_files(space_id)
    nodes_info = []
    for f in mkp_files:
        try:
            decoded = decode_mpk(f)
            for entry in decoded:
                fields = extract_user_ocis_fields(entry, source_file=f)
                if fields:
                    fields["source_file"] = f
                    nodes_info.append(fields)
        except Exception as e:
            print(f"[ERROR] Failed to decode {f}: {e}")

    build_directory_tree_and_restore_files(nodes_info, space_id, env.OUTPUT_DIR)

    # Create space
    space_create = {"name": space_name, "quota": {"total": 0}, "description": space_description}
    url = f"{env.OCIS_URL}graph/v1.0/drives"
    resp = requests.post(url, headers=headers, json=space_create)
    resp.raise_for_status()
    new_space = resp.json()

    # Add user
    add_user = {
        "recipients": [{"@libre.graph.recipient.type": "user", "objectId": user_data["id"]}],
        "roles": ["b1e2218d-eef8-4d4c-b82d-0f1a1b48f3b5"]
    }
    url = f"{env.OCIS_URL}v1beta1/drives/{new_space['id']}/root/invite"
    requests.post(url, headers=headers, json=add_user)

    print("[DONE] Restore completed.")

    #if os.path.exists(env.OUTPUT_DIR):
    #    shutil.rmtree(env.OUTPUT_DIR)
    #    print(f"Deleted temporary directory: {env.OUTPUT_DIR}")


if __name__ == "__main__":
    # Example usage: restore_user_drive("USER_ID")
    restore_user_drive()
