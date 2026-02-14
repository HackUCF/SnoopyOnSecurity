#!/usr/bin/env python3
"""
Sandbox Command Analyzer - Single-file consolidated version.

Captures and analyzes C2 commands from network traffic by running imix C2 agent
in a Docker sandbox and extracting tasks from encrypted gRPC/DNS traffic.
"""

# ============================================================================
# IMPORTS
# ============================================================================

import click
import logging
import sys
import time
import signal
import json
import re
import struct
import base64
import os
import tempfile
import threading
import queue
import socket
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple, Set, Callable

# External dependencies
import docker
from scapy.all import sniff, IP, TCP, UDP, Raw, DNS, DNSQR
try:
    from scapy.layers.http2 import H2Frame
except ImportError:
    H2Frame = None
from dnslib import DNSRecord, QTYPE
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section

# PyNaCl for XChaCha20-Poly1305 (24-byte nonce)
try:
    from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt
    HAS_NACL = True
except ImportError:
    HAS_NACL = False

# Protobuf imports - these files should be in the same directory
try:
    import c2_pb2
    import eldritch_pb2
    import dns_pb2
except ImportError:
    # Try importing from current directory or sandbox_cmd_analyzer
    import sys
    import os
    current_dir = os.path.dirname(os.path.abspath(__file__))
    if current_dir not in sys.path:
        sys.path.insert(0, current_dir)
    try:
        import c2_pb2
        import eldritch_pb2
        import dns_pb2
    except ImportError:
        try:
            from sandbox_cmd_analyzer import c2_pb2, eldritch_pb2, dns_pb2
        except ImportError:
            raise ImportError("Protobuf files (c2_pb2.py, eldritch_pb2.py, dns_pb2.py) not found. Run 'make build-proto' to generate them.")

# ============================================================================
# LOGGING SETUP
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# ============================================================================
# CONSTANTS
# ============================================================================

KEY_SIZE = 32
NONCE_SIZE = 24
HTTP2_FRAME_HEADER_LEN = 9
HTTP2_FRAME_DATA = 0x0
GRPC_HEADER_LEN = 5

# ============================================================================
# NETWORK UTILITIES
# ============================================================================

def get_interface_for_container(container_ip: str) -> Optional[str]:
    """Get network interface that routes to container IP."""
    try:
        result = subprocess.run(
            ["ip", "route", "get", container_ip],
            capture_output=True,
            text=True,
            check=True
        )
        parts = result.stdout.strip().split()
        for i, part in enumerate(parts):
            if part == "dev" and i + 1 < len(parts):
                return parts[i + 1]
    except Exception:
        pass
    return None


def get_docker_bridge_interface() -> Optional[str]:
    """Get Docker bridge interface name."""
    common_bridges = ["docker0", "br-", "veth"]
    try:
        result = subprocess.run(
            ["ip", "link", "show"],
            capture_output=True,
            text=True,
            check=True
        )
        for line in result.stdout.split("\n"):
            for bridge in common_bridges:
                if bridge in line and "state UP" in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        return parts[1].strip().split("@")[0]
    except Exception:
        pass
    return "docker0"  # Default fallback

# ============================================================================
# DOCKER UTILITIES
# ============================================================================

def get_docker_client() -> docker.DockerClient:
    """Get Docker client instance."""
    try:
        return docker.from_env()
    except Exception as e:
        raise RuntimeError(f"Failed to connect to Docker: {e}")


def create_bridge_network(client: docker.DockerClient, name: str) -> docker.models.networks.Network:
    """Create or get a Docker bridge network."""
    try:
        network = client.networks.get(name)
    except docker.errors.NotFound:
        network = client.networks.create(name, driver="bridge")
    return network


def remove_network(client: docker.DockerClient, name: str) -> None:
    """Remove a Docker network."""
    try:
        network = client.networks.get(name)
        network.remove()
    except docker.errors.NotFound:
        pass

# ============================================================================
# BINARY UTILITIES
# ============================================================================

def extract_server_pubkey_from_binary(binary_path: str) -> Optional[bytes]:
    """Extract SERVER_PUBKEY (32-byte X25519 public key) from imix binary."""
    path = Path(binary_path)
    if not path.exists():
        raise FileNotFoundError(f"Binary not found: {binary_path}")

    with open(path, "rb") as f:
        data = f.read()

    # Method 1: Search for known default key pattern
    default_key = bytes([
        165, 30, 122, 188, 50, 89, 111, 214, 247, 4, 189, 217,
        188, 37, 200, 190, 2, 180, 175, 107, 194, 147, 177, 98,
        103, 84, 99, 120, 72, 73, 87, 37
    ])
    idx = data.find(default_key)
    if idx != -1:
        logger.info("Found default server public key in binary")
        return default_key

    # Method 2: Parse ELF sections
    try:
        with open(path, "rb") as f:
            elf = ELFFile(f)
            for section in elf.iter_sections():
                if section.name in [".rodata", ".data"]:
                    section_data = section.data()
                    idx = section_data.find(default_key)
                    if idx != -1:
                        logger.info(f"Found server public key in {section.name} section")
                        return default_key
    except Exception as e:
        logger.debug(f"ELF parsing failed: {e}")

    logger.warning("Could not extract server public key from binary")
    return None

# ============================================================================
# HTTP/2 FRAME PARSING
# ============================================================================

def parse_http2_frames(data: bytes) -> Tuple[int, List[Tuple[int, int, bytes]]]:
    """Parse HTTP/2 frames from a byte buffer."""
    consumed = 0
    frames: List[Tuple[int, int, bytes]] = []
    offset = 0

    while offset + HTTP2_FRAME_HEADER_LEN <= len(data):
        length = struct.unpack(">I", b"\x00" + data[offset : offset + 3])[0]
        frame_type = data[offset + 3]
        flags = data[offset + 4]
        stream_id = struct.unpack(">I", data[offset + 5 : offset + 9])[0] & 0x7FFF_FFFF

        if offset + HTTP2_FRAME_HEADER_LEN + length > len(data):
            break

        payload = bytes(data[offset + HTTP2_FRAME_HEADER_LEN : offset + HTTP2_FRAME_HEADER_LEN + length])
        frames.append((frame_type, stream_id, payload))
        consumed = offset + HTTP2_FRAME_HEADER_LEN + length
        offset = consumed

    return consumed, frames

# ============================================================================
# gRPC FRAME PARSING
# ============================================================================

def extract_grpc_frames(data: bytes) -> Tuple[int, List[bytes]]:
    """Extract gRPC messages from a byte buffer."""
    consumed = 0
    messages: List[bytes] = []
    offset = 0

    while offset + GRPC_HEADER_LEN <= len(data):
        compression = data[offset]
        length = struct.unpack(">I", data[offset + 1 : offset + 5])[0]
        if offset + GRPC_HEADER_LEN + length > len(data):
            break
        msg = bytes(data[offset + GRPC_HEADER_LEN : offset + GRPC_HEADER_LEN + length])
        messages.append(msg)
        consumed = offset + GRPC_HEADER_LEN + length
        offset = consumed
        if compression != 0:
            logger.debug("gRPC compression flag set (unsupported)")

    return consumed, messages

# ============================================================================
# TCP STREAM REASSEMBLY
# ============================================================================

ConnKey = Tuple[str, int, str, int]

def conn_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> ConnKey:
    return (src_ip, src_port, dst_ip, dst_port)


class StreamReassembler:
    """Buffers TCP payloads per connection (direction) for reassembly."""

    def __init__(self, max_buffered_bytes: int = 2 * 1024 * 1024):
        self._buffers: Dict[ConnKey, bytearray] = {}
        self._max_buffered = max_buffered_bytes

    def add_segment(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, payload: bytes) -> None:
        """Append TCP payload to the stream buffer for that direction."""
        key = conn_key(src_ip, src_port, dst_ip, dst_port)
        if key not in self._buffers:
            self._buffers[key] = bytearray()
        buf = self._buffers[key]
        buf.extend(payload)
        if len(buf) > self._max_buffered:
            buf[:] = buf[-self._max_buffered // 2 :]
            logger.debug("Trimmed stream buffer for %s", key)

    def get_buffer(self, key: ConnKey) -> bytes:
        """Return current buffer contents for a connection."""
        return bytes(self._buffers.get(key, bytearray()))

    def consume(self, key: ConnKey, n: int) -> None:
        """Remove the first n bytes from the buffer."""
        if key not in self._buffers:
            return
        buf = self._buffers[key]
        if n >= len(buf):
            del self._buffers[key]
        else:
            buf[:] = buf[n:]

    def keys(self):
        return list(self._buffers.keys())

# ============================================================================
# PROTOBUF PARSING
# ============================================================================

def parse_claim_tasks_response(data: bytes) -> Optional[Dict[str, Any]]:
    """Parse ClaimTasksResponse protobuf message."""
    try:
        response = c2_pb2.ClaimTasksResponse()
        response.ParseFromString(data)
        
        tasks = []
        for task in response.tasks:
            task_dict = {
                "id": task.id,
                "quest_name": task.quest_name,
            }
            
            if task.HasField("tome"):
                tome_dict = parse_tome(task.tome.SerializeToString())
                if tome_dict:
                    task_dict["tome"] = tome_dict
            
            if task_dict:
                tasks.append(task_dict)
        
        if tasks:
            return {"tasks": tasks}
    except Exception as e:
        logger.debug(f"Error parsing ClaimTasksResponse: {e}")
    return None


def parse_task(data: bytes) -> Optional[Dict[str, Any]]:
    """Parse Task protobuf message."""
    try:
        if isinstance(data, bytes):
            task = c2_pb2.Task()
            task.ParseFromString(data)
        else:
            task = data
        
        result = {
            "id": task.id,
            "quest_name": task.quest_name,
        }
        
        if task.HasField("tome"):
            tome_dict = parse_tome(task.tome.SerializeToString())
            if tome_dict:
                result["tome"] = tome_dict
        
        return result
    except Exception as e:
        logger.debug(f"Error parsing Task: {e}")
    return None


def parse_tome(data: bytes) -> Optional[Dict[str, Any]]:
    """Parse Tome protobuf message to extract eldritch script."""
    try:
        if isinstance(data, bytes):
            tome = eldritch_pb2.Tome()
            tome.ParseFromString(data)
        else:
            tome = data
        
        return {
            "eldritch": tome.eldritch,
            "parameters": dict(tome.parameters),
            "file_names": list(tome.file_names),
        }
    except Exception as e:
        logger.debug(f"Error parsing Tome: {e}")
    return None


def parse_dns_packet(data: bytes) -> Optional[Dict[str, Any]]:
    """Parse DNSPacket protobuf message."""
    try:
        packet = dns_pb2.DNSPacket()
        packet.ParseFromString(data)
        
        return {
            "type": packet.type,
            "sequence": packet.sequence,
            "conversation_id": packet.conversation_id,
            "data": packet.data,
            "crc32": packet.crc32,
            "window_size": packet.window_size,
            "acks": [{"start_seq": ack.start_seq, "end_seq": ack.end_seq} for ack in packet.acks],
            "nacks": list(packet.nacks),
        }
    except Exception as e:
        logger.debug(f"Error parsing DNSPacket: {e}")
    return None

# ============================================================================
# CRYPTO UTILITIES
# ============================================================================

class XChaChaDecryptor:
    """Decrypts XChaCha20-Poly1305 encrypted messages using shared secrets."""

    def __init__(self, keylog_path: Optional[Path] = None):
        self.keylog_path = Path(keylog_path) if keylog_path else None
        self.key_cache: Dict[str, bytes] = {}
        if self.keylog_path:
            self._load_keylog()

    def _load_keylog(self) -> None:
        """Load shared secrets from key log file."""
        if self.keylog_path is None:
            return
        
        if not self.keylog_path.exists():
            logger.debug(f"Key log file not found: {self.keylog_path}")
            return

        logger.info(f"Loading key log from: {self.keylog_path}")
        with open(self.keylog_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                
                try:
                    parts = line.split(":")
                    if len(parts) == 2:
                        client_pub_key_hex = parts[0].strip()
                        shared_secret_hex = parts[1].strip()
                        self.key_cache[client_pub_key_hex] = bytes.fromhex(shared_secret_hex)
                except Exception as e:
                    logger.debug(f"Error parsing key log line: {e}")

        logger.info(f"Loaded {len(self.key_cache)} shared secrets from key log")

    def decrypt_message(self, encrypted_data: bytes) -> Optional[bytes]:
        """Decrypt XChaCha20-Poly1305 encrypted message."""
        if len(encrypted_data) < 56:  # 32 (pubkey) + 24 (nonce) minimum
            logger.warning("Encrypted data too short")
            return None

        client_pub_key = encrypted_data[:32]
        nonce = encrypted_data[32:56]
        ciphertext = encrypted_data[56:]

        client_pub_key_hex = client_pub_key.hex()
        shared_secret = self.key_cache.get(client_pub_key_hex)

        if not shared_secret:
            logger.warning(f"No shared secret found for client key: {client_pub_key_hex[:16]}...")
            return None

        try:
            if HAS_NACL:
                logger.debug(f"Attempting decryption: key={shared_secret.hex()[:16]}..., nonce={nonce.hex()[:16]}..., ct_len={len(ciphertext)}")
                plaintext = crypto_aead_xchacha20poly1305_ietf_decrypt(
                    ciphertext,
                    None,
                    nonce,
                    shared_secret
                )
                return plaintext
            else:
                logger.error("No XChaCha20-Poly1305 implementation available")
                return None
        except Exception as e:
            logger.warning(f"Decryption failed: {e}")
            return None

    def reload_keylog(self) -> None:
        """Reload key log file."""
        old_count = len(self.key_cache)
        self._load_keylog()
        new_count = len(self.key_cache) - old_count
        if new_count > 0:
            logger.info(f"Loaded {new_count} new keys from keylog")

    def add_key(self, client_pubkey: bytes, shared_secret: bytes) -> bool:
        """Add a key pair to the cache."""
        if len(client_pubkey) != 32 or len(shared_secret) != 32:
            logger.warning("Invalid key size (expected 32 bytes each)")
            return False
        
        pubkey_hex = client_pubkey.hex()
        if pubkey_hex in self.key_cache:
            return False
        
        self.key_cache[pubkey_hex] = shared_secret
        logger.debug(f"Added key from memory: {pubkey_hex[:16]}...")
        return True

    def add_keys(self, keys: Dict[bytes, bytes]) -> int:
        """Add multiple key pairs to the cache."""
        added = 0
        for pubkey, secret in keys.items():
            if self.add_key(pubkey, secret):
                added += 1
        if added > 0:
            logger.info(f"Added {added} keys from memory extraction")
        return added

    def has_key_for(self, client_pubkey: bytes) -> bool:
        """Check if we have a shared secret for the given client public key."""
        return client_pubkey.hex() in self.key_cache

    def get_missing_pubkeys(self, pubkeys: List[bytes]) -> List[bytes]:
        """Get list of pubkeys for which we don't have shared secrets."""
        return [pk for pk in pubkeys if pk.hex() not in self.key_cache]

    def key_count(self) -> int:
        """Get number of cached keys."""
        return len(self.key_cache)

# ============================================================================
# MEMORY DUMPING
# ============================================================================

def parse_proc_maps(pid: int) -> List[Tuple[int, int, str, str]]:
    """Parse /proc/<pid>/maps to get memory regions."""
    maps_path = Path(f"/proc/{pid}/maps")
    if not maps_path.exists():
        raise FileNotFoundError(f"Process {pid} not found or /proc not accessible")
    
    regions = []
    with open(maps_path, "r") as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) < 5:
                continue
            
            addr_range = parts[0]
            perms = parts[1]
            pathname = parts[5] if len(parts) > 5 else ""
            
            try:
                start_str, end_str = addr_range.split("-")
                start = int(start_str, 16)
                end = int(end_str, 16)
                regions.append((start, end, perms, pathname))
            except ValueError:
                continue
    
    return regions


def should_scan_region(perms: str, pathname: str, regions_filter: List[str]) -> bool:
    """Determine if a memory region should be scanned for keys."""
    if "r" not in perms:
        return False
    
    for region_type in regions_filter:
        if region_type == "heap" and "[heap]" in pathname:
            return True
        elif region_type == "stack" and "[stack]" in pathname:
            return True
        elif region_type == "anon" and pathname == "":
            return True
        elif region_type == "all":
            return True
        elif region_type in pathname:
            return True
    
    return False


def dump_process_memory(
    pid: int,
    regions_filter: Optional[List[str]] = None,
    max_size: int = 100 * 1024 * 1024,
) -> bytes:
    """Read process memory via /proc/pid/mem."""
    if regions_filter is None:
        regions_filter = ["heap", "anon"]
    
    maps = parse_proc_maps(pid)
    mem_path = Path(f"/proc/{pid}/mem")
    
    if not mem_path.exists():
        raise FileNotFoundError(f"Cannot access /proc/{pid}/mem")
    
    data_chunks = []
    total_size = 0
    regions_read = 0
    
    try:
        with open(mem_path, "rb") as mem:
            for start, end, perms, pathname in maps:
                if not should_scan_region(perms, pathname, regions_filter):
                    continue
                
                region_size = end - start
                
                if region_size > 50 * 1024 * 1024:  # 50MB per region max
                    logger.debug(f"Skipping large region {pathname}: {region_size} bytes")
                    continue
                
                if total_size + region_size > max_size:
                    logger.warning(f"Reached max memory size limit ({max_size} bytes)")
                    break
                
                try:
                    mem.seek(start)
                    chunk = mem.read(region_size)
                    data_chunks.append(chunk)
                    total_size += len(chunk)
                    regions_read += 1
                    logger.debug(f"Read {len(chunk)} bytes from {pathname or 'anon'} @ 0x{start:x}")
                except (OSError, IOError) as e:
                    logger.debug(f"Could not read region 0x{start:x}-0x{end:x}: {e}")
                    continue
    
    except PermissionError as e:
        raise PermissionError(
            f"Cannot read /proc/{pid}/mem. Need CAP_SYS_PTRACE or same user. Error: {e}"
        )
    
    logger.info(f"Read {total_size} bytes from {regions_read} memory regions")
    return b"".join(data_chunks)

# ============================================================================
# KEY FINDING
# ============================================================================

def is_valid_key_candidate(data: bytes) -> bool:
    """Check if a 32-byte sequence looks like a valid X25519 key/shared secret."""
    if len(data) != KEY_SIZE:
        return False
    
    zeros = sum(1 for b in data if b == 0)
    ones = sum(1 for b in data if b == 0xff)
    
    if zeros > 8 or ones > 8:
        return False
    
    unique_bytes = len(set(data))
    if unique_bytes < 12:
        return False
    
    if data[:4] == b'\x00\x00\x00\x00' or data[-4:] == b'\x00\x00\x00\x00':
        return False
    
    return True


def extract_client_pubkeys_from_traffic(encrypted_messages: List[bytes]) -> List[bytes]:
    """Extract client public keys from encrypted message payloads."""
    pubkeys = []
    seen = set()
    
    for msg in encrypted_messages:
        if len(msg) < KEY_SIZE + NONCE_SIZE:
            continue
        
        pubkey = msg[:KEY_SIZE]
        pubkey_hex = pubkey.hex()
        
        if pubkey_hex not in seen and is_valid_key_candidate(pubkey):
            seen.add(pubkey_hex)
            pubkeys.append(pubkey)
    
    logger.info(f"Extracted {len(pubkeys)} unique client public keys from traffic")
    return pubkeys


def find_shared_secrets_in_memory(
    memory: bytes,
    client_pubkeys: List[bytes],
    search_offsets: Optional[List[int]] = None,
) -> Dict[bytes, bytes]:
    """Search memory for client public keys and extract shared secrets from LRU cache."""
    results: Dict[bytes, bytes] = {}
    memory_len = len(memory)
    
    pubkey_set = {pk.hex() for pk in client_pubkeys}
    
    if search_offsets is None:
        search_offsets = [
            32, 48, 40, 56, 64,
            -32, -48, -40, -56, -64,
            24, -24, 16, -16,
        ]
    
    for pubkey in client_pubkeys:
        if pubkey in results:
            continue
        
        pubkey_hex = pubkey.hex()[:16]
        found = False
        
        offset = 0
        while offset < memory_len:
            idx = memory.find(pubkey, offset)
            if idx == -1:
                break
            
            for delta in search_offsets:
                secret_start = idx + delta
                secret_end = secret_start + KEY_SIZE
                
                if secret_start < 0 or secret_end > memory_len:
                    continue
                
                candidate = memory[secret_start:secret_end]
                candidate_hex = candidate.hex()
                
                if (is_valid_key_candidate(candidate) and 
                    candidate != pubkey and
                    candidate_hex not in pubkey_set):
                    results[pubkey] = candidate
                    logger.info(
                        f"Found shared secret for pubkey {pubkey_hex}... "
                        f"at offset 0x{secret_start:x} (delta={delta})"
                    )
                    found = True
                    break
                elif candidate_hex in pubkey_set:
                    logger.debug(
                        f"  Rejected at delta={delta}: candidate is a known pubkey, not shared_secret"
                    )
            
            if found:
                break
            offset = idx + 1
    
    # Strategy 2: Focused search for missing pubkeys
    missing_pubkeys = [pk for pk in client_pubkeys if pk not in results]
    if missing_pubkeys:
        logger.debug(f"Doing focused search for {len(missing_pubkeys)} missing pubkeys...")
        
        for pubkey in missing_pubkeys:
            pubkey_hex = pubkey.hex()[:16]
            offset = 0
            found_secret = False
            
            while offset < memory_len:
                idx = memory.find(pubkey, offset)
                if idx == -1:
                    break
                
                search_start = max(0, idx - 120)
                search_end = min(memory_len - KEY_SIZE, idx + 120)
                
                for secret_pos in range(search_start, search_end, 8):
                    if secret_pos == idx or abs(secret_pos - idx) < 16:
                        continue
                    
                    candidate = memory[secret_pos:secret_pos + KEY_SIZE]
                    
                    if (is_valid_key_candidate(candidate) and 
                        candidate != pubkey and
                        candidate.hex() not in pubkey_set and
                        len(set(candidate)) >= 20):
                        
                        results[pubkey] = candidate
                        logger.info(
                            f"Found shared secret for pubkey {pubkey_hex}... "
                            f"at offset 0x{secret_pos:x} (pubkey at 0x{idx:x}, delta={secret_pos - idx})"
                        )
                        found_secret = True
                        break
                
                if found_secret:
                    break
                offset = idx + 1
    
    # Final validation
    validated_results = {}
    for pubkey, secret in results.items():
        secret_hex = secret.hex()
        if secret_hex not in pubkey_set:
            validated_results[pubkey] = secret
        else:
            logger.warning(
                f"Rejected extracted 'secret' for pubkey {pubkey.hex()[:16]}...: "
                f"it's actually another pubkey, not a shared_secret"
            )
    
    if len(validated_results) < len(results):
        logger.warning(
            f"Filtered out {len(results) - len(validated_results)} invalid keys "
            f"(were pubkeys, not shared_secrets)"
        )
    
    logger.info(
        f"Found {len(validated_results)} validated shared secrets "
        f"out of {len(client_pubkeys)} pubkeys"
    )
    return validated_results

# ============================================================================
# ELDRITCH ANALYZER
# ============================================================================

class EldritchAnalyzer:
    """Analyzes Eldritch DSL scripts to extract command invocations."""

    def __init__(self):
        self.exec_pattern = re.compile(r'sys\.exec\s*\(([^)]+)\)')
        self.shell_pattern = re.compile(r'sys\.shell\s*\(([^)]+)\)')

    def analyze_script(self, script: str) -> List[Dict[str, Any]]:
        """Analyze Eldritch script and extract commands."""
        commands = []
        commands.extend(self._extract_exec_commands(script))
        commands.extend(self._extract_shell_commands(script))
        return commands

    def _extract_exec_commands(self, script: str) -> List[Dict[str, Any]]:
        """Extract sys.exec() command invocations."""
        commands = []
        lines = script.split("\n")

        for line_num, line in enumerate(lines, 1):
            matches = self.exec_pattern.finditer(line)
            for match in matches:
                try:
                    args_str = match.group(1)
                    args = self._parse_arguments(args_str)
                    
                    command = {
                        "type": "exec",
                        "function": "sys.exec",
                        "line_number": line_num,
                        "line": line.strip(),
                        "arguments": args,
                        "command": args.get("path", "") if isinstance(args, dict) else str(args[0]) if args else "",
                    }
                    commands.append(command)
                except Exception as e:
                    logger.debug(f"Error parsing exec command: {e}")

        return commands

    def _extract_shell_commands(self, script: str) -> List[Dict[str, Any]]:
        """Extract sys.shell() command invocations."""
        commands = []
        lines = script.split("\n")

        for line_num, line in enumerate(lines, 1):
            matches = self.shell_pattern.finditer(line)
            for match in matches:
                try:
                    cmd_str = match.group(1)
                    cmd = self._extract_string_value(cmd_str)
                    
                    command = {
                        "type": "shell",
                        "function": "sys.shell",
                        "line_number": line_num,
                        "line": line.strip(),
                        "command": cmd,
                    }
                    commands.append(command)
                except Exception as e:
                    logger.debug(f"Error parsing shell command: {e}")

        return commands

    def _parse_arguments(self, args_str: str) -> Dict[str, Any]:
        """Parse function arguments from string."""
        args = {}
        args_str = args_str.strip()

        try:
            path_match = re.search(r'path\s*=\s*["\']([^"\']+)["\']', args_str)
            if path_match:
                args["path"] = path_match.group(1)

            args_match = re.search(r'args\s*=\s*\[([^\]]+)\]', args_str)
            if args_match:
                args_list_str = args_match.group(1)
                args["args"] = [a.strip().strip('"\'') for a in args_list_str.split(",")]

            pos_match = re.match(r'["\']([^"\']+)["\']', args_str)
            if pos_match and "path" not in args:
                args["path"] = pos_match.group(1)
        except Exception as e:
            logger.debug(f"Error parsing arguments: {e}")

        return args if args else {"raw": args_str}

    def _extract_string_value(self, value_str: str) -> str:
        """Extract string value from quoted string."""
        value_str = value_str.strip()
        if value_str.startswith('"') and value_str.endswith('"'):
            return value_str[1:-1]
        elif value_str.startswith("'") and value_str.endswith("'"):
            return value_str[1:-1]
        return value_str

# ============================================================================
# DATA COLLECTOR
# ============================================================================

class DataCollector:
    """Collects and aggregates data from network capture to commands."""

    def __init__(self, container_id: Optional[str] = None, c2_framework: str = "imix"):
        self.container_id = container_id
        self.c2_framework = c2_framework
        self.eldritch_analyzer = EldritchAnalyzer()
        self.tasks: List[Dict[str, Any]] = []
        self.start_time = datetime.utcnow()

    def add_task(
        self,
        task_id: Optional[int],
        eldritch_script: str,
        transport: str,
        timestamp: Optional[datetime] = None,
        metadata: Optional[Dict[str, Any]] = None,
        c2_server: Optional[str] = None,
        c2_ip: Optional[str] = None,
        c2_port: Optional[int] = None,
    ) -> None:
        """Add a task with Eldritch script."""
        if timestamp is None:
            timestamp = datetime.utcnow()

        extracted_commands = self.eldritch_analyzer.analyze_script(eldritch_script)

        task = {
            "task_id": task_id,
            "timestamp": timestamp.isoformat(),
            "eldritch_script": eldritch_script,
            "transport": transport,
            "extracted_commands": extracted_commands,
            "metadata": metadata or {},
        }
        
        # Add C2 endpoint information
        if c2_server:
            task["c2_server"] = c2_server
        if c2_ip:
            task["c2_ip"] = c2_ip
        if c2_port:
            task["c2_port"] = c2_port
        if c2_ip and c2_port:
            task["c2_endpoint"] = f"{c2_ip}:{c2_port}"

        self.tasks.append(task)
        logger.info(f"Added task {task_id} with {len(extracted_commands)} commands")

    def to_dict(self) -> Dict[str, Any]:
        """Convert collected data to dictionary."""
        return {
            "container_id": self.container_id,
            "c2_framework": self.c2_framework,
            "start_time": self.start_time.isoformat(),
            "end_time": datetime.utcnow().isoformat(),
            "total_tasks": len(self.tasks),
            "total_commands": sum(len(t.get("extracted_commands", [])) for t in self.tasks),
            "tasks": self.tasks,
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert collected data to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def save_to_file(self, output_path: str) -> None:
        """Save collected data to JSON file."""
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, "w") as f:
            f.write(self.to_json())

        logger.info(f"Saved analysis results to: {output_file}")

    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics."""
        all_commands = []
        for task in self.tasks:
            all_commands.extend(task.get("extracted_commands", []))

        command_types = {}
        for cmd in all_commands:
            cmd_type = cmd.get("type", "unknown")
            command_types[cmd_type] = command_types.get(cmd_type, 0) + 1

        return {
            "total_tasks": len(self.tasks),
            "total_commands": len(all_commands),
            "command_types": command_types,
            "transports": list(set(t.get("transport") for t in self.tasks)),
        }

# ============================================================================
# IMIX ADAPTER
# ============================================================================

class ImixAdapter:
    """Adapter for imix C2 framework."""

    def __init__(self):
        self.binary_path: Optional[str] = None
        self.c2_server: Optional[str] = None
        self.transport_type: str = "grpc"
        self.server_pubkey: Optional[bytes] = None

    def setup(self, binary_path: str, c2_server: str, **kwargs) -> Dict[str, Any]:
        """Setup imix adapter."""
        self.binary_path = binary_path
        self.c2_server = c2_server

        if "dns://" in c2_server:
            self.transport_type = "dns"
        elif "http://" in c2_server or "https://" in c2_server:
            self.transport_type = "grpc"
        else:
            binary_name = Path(binary_path).name
            match = re.match(r'imix-(\w+)---', binary_name)
            if match:
                self.transport_type = match.group(1)

        try:
            self.server_pubkey = extract_server_pubkey_from_binary(binary_path)
            if self.server_pubkey:
                logger.info("Extracted server public key from binary")
        except Exception as e:
            logger.warning(f"Could not extract server public key: {e}")

        env_vars = {
            "IMIX_CALLBACK_URI": c2_server,
        }

        if self.transport_type == "dns":
            if "dns_domain" in kwargs:
                env_vars["IMIX_DNS_DOMAIN"] = kwargs["dns_domain"]

        return {
            "env_vars": env_vars,
            "transport_type": self.transport_type,
            "server_pubkey": self.server_pubkey.hex() if self.server_pubkey else None,
        }

    def extract_eldritch_scripts(self, messages: list) -> list:
        """Extract Eldritch scripts from imix messages."""
        scripts = []

        for message in messages:
            try:
                if isinstance(message, dict):
                    if "eldritch" in message:
                        scripts.append({
                            "script": message["eldritch"],
                            "task_id": message.get("task_id"),
                            "quest_name": message.get("quest_name"),
                            "metadata": message,
                        })
                    elif "tome" in message and isinstance(message["tome"], dict):
                        if "eldritch" in message["tome"]:
                            scripts.append({
                                "script": message["tome"]["eldritch"],
                                "task_id": message.get("task_id"),
                                "quest_name": message.get("quest_name"),
                                "metadata": message,
                            })
                    elif "data" in message:
                        scripts.append({
                            "script": None,
                            "raw_data": message["data"],
                            "metadata": message,
                        })
            except Exception as e:
                logger.debug(f"Error extracting Eldritch script: {e}")

        return scripts

    def get_transport_type(self) -> str:
        """Get transport type."""
        return self.transport_type

# ============================================================================
# NETWORK CAPTURE
# ============================================================================

class NetworkCapture:
    """Captures network traffic from Docker container."""

    def __init__(
        self,
        container_ip: Optional[str] = None,
        interface: Optional[str] = None,
        packet_callback: Optional[Callable] = None,
        c2_port: Optional[int] = None,
    ):
        self.container_ip = container_ip
        self.interface = interface or get_docker_bridge_interface()
        self.packet_callback = packet_callback
        self.c2_port = c2_port
        self.packet_queue = queue.Queue()
        self.capture_thread: Optional[threading.Thread] = None
        self.running = False
        self._discovered_endpoints: Set[Tuple[str, int]] = set()

    def _packet_handler(self, packet) -> None:
        """Handle captured packet."""
        try:
            if self.container_ip and packet.haslayer("IP"):
                src_ip = packet["IP"].src
                dst_ip = packet["IP"].dst
                if src_ip != self.container_ip and dst_ip != self.container_ip:
                    return

            self.packet_queue.put(packet.copy())

            if self.packet_callback:
                self.packet_callback(packet)
        except Exception as e:
            logger.debug(f"Error handling packet: {e}")

    def start(self) -> None:
        """Start network capture."""
        if self.running:
            logger.warning("Capture already running")
            return

        logger.info(f"Starting network capture on interface: {self.interface}")
        self.running = True

        bpf_filter = "ip"
        logger.info(f"BPF filter: {bpf_filter}")

        def capture_loop():
            try:
                while self.running:
                    pkts = sniff(
                        iface=self.interface,
                        timeout=1,
                        store=True,
                        filter=bpf_filter,
                    )
                    for pkt in pkts:
                        if not self.running:
                            break
                        self._packet_handler(pkt)
            except Exception as e:
                logger.error(f"Capture error: {e}")
                self.running = False

        self.capture_thread = threading.Thread(target=capture_loop, daemon=True)
        self.capture_thread.start()
        logger.info("Network capture started")

    def stop(self) -> None:
        """Stop network capture."""
        if not self.running:
            return

        logger.info("Stopping network capture...")
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        logger.info("Network capture stopped")

    def get_packets(self, timeout: Optional[float] = None) -> List:
        """Get captured packets from queue."""
        packets = []
        try:
            while True:
                packet = self.packet_queue.get(timeout=timeout if timeout else 0.1)
                packets.append(packet)
        except queue.Empty:
            pass
        return packets

    def get_discovered_endpoints(self) -> List[Tuple[str, int]]:
        """Return dynamically discovered C2 endpoints."""
        return sorted(self._discovered_endpoints, key=lambda x: (x[0], x[1]))

    def filter_grpc_traffic(self, packets: List) -> List:
        """Capture all TCP/UDP traffic from container."""
        grpc_packets = []
        seen_ports: Set[Tuple[int, int]] = set()
        seen_types: Set[str] = set()

        for packet in packets:
            try:
                if not packet.haslayer("IP"):
                    pkt_type = packet.__class__.__name__
                    if pkt_type not in seen_types and len(seen_types) < 10:
                        seen_types.add(pkt_type)
                        logger.debug(f"Non-IP packet type: {pkt_type}")
                    continue

                ip_layer = packet["IP"]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst

                if packet.haslayer("TCP"):
                    tcp = packet["TCP"]
                    src_port = tcp.sport
                    dst_port = tcp.dport
                    grpc_packets.append(packet)
                    port_pair = (src_port, dst_port)
                    if port_pair not in seen_ports and len(seen_ports) < 20:
                        seen_ports.add(port_pair)
                        logger.info(f"Capturing TCP {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                    if self.container_ip and src_ip == self.container_ip:
                        ep = (dst_ip, dst_port)
                        if ep not in self._discovered_endpoints:
                            self._discovered_endpoints.add(ep)
                            logger.info(f"Discovered C2 endpoint (outgoing): {dst_ip}:{dst_port}")

                elif packet.haslayer("UDP"):
                    udp = packet["UDP"]
                    src_port = udp.sport
                    dst_port = udp.dport
                    grpc_packets.append(packet)
                    port_pair = (src_port, dst_port)
                    if port_pair not in seen_ports and len(seen_ports) < 20:
                        seen_ports.add(port_pair)
                        logger.info(f"Capturing UDP {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                    if self.container_ip and src_ip == self.container_ip:
                        ep = (dst_ip, dst_port)
                        if ep not in self._discovered_endpoints:
                            self._discovered_endpoints.add(ep)
                            logger.info(f"Discovered C2 endpoint (outgoing): {dst_ip}:{dst_port}")

                else:
                    pkt_type = packet.lastlayer().__class__.__name__
                    if pkt_type not in seen_types and len(seen_types) < 10:
                        seen_types.add(pkt_type)
                        logger.debug(f"IP packet with {pkt_type} (no TCP/UDP)")
            except Exception as e:
                logger.debug(f"Error processing packet: {e}")

        if grpc_packets:
            logger.info(
                f"Captured {len(grpc_packets)} TCP/UDP packets (endpoints: {list(self._discovered_endpoints)})"
            )
        elif packets:
            logger.info(
                f"No TCP/UDP in {len(packets)} packets (saw types: {', '.join(seen_types)})"
            )
        return grpc_packets

    def filter_dns_traffic(self, packets: List) -> List:
        """Filter packets for DNS traffic (port 53)."""
        dns_packets = []
        for packet in packets:
            if packet.haslayer("IP") and packet.haslayer("UDP"):
                udp = packet["UDP"]
                if udp.sport == 53 or udp.dport == 53:
                    dns_packets.append(packet)
        return dns_packets

    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - stop capture."""
        self.stop()

# ============================================================================
# SANDBOX MANAGER
# ============================================================================

class SandboxManager:
    """Manages Docker container lifecycle for C2 agent sandboxing."""

    def __init__(
        self,
        imix_binary_path: str,
        c2_server: str,
        network_name: str = "sandbox-cmd-analyzer",
        keylog_dir: Optional[str] = None,
    ):
        self.imix_binary_path = Path(imix_binary_path)
        if not self.imix_binary_path.exists():
            raise FileNotFoundError(f"Imix binary not found: {imix_binary_path}")

        self.c2_server = c2_server
        self.network_name = network_name
        self.keylog_dir = Path(keylog_dir) if keylog_dir else Path(tempfile.mkdtemp())
        self.keylog_dir.mkdir(parents=True, exist_ok=True)

        self.client = get_docker_client()
        self.container: Optional[docker.models.containers.Container] = None
        self.network: Optional[docker.models.networks.Network] = None

        self.tls_keylog = self.keylog_dir / "tls_keys.log"
        self.xchacha_keylog = self.keylog_dir / "xchacha_keys.log"

    def setup_network(self) -> None:
        """Create bridge network for traffic capture."""
        logger.info(f"Creating bridge network: {self.network_name}")
        self.network = create_bridge_network(self.client, self.network_name)

    def create_container(
        self,
        image: str = "alpine:latest",
        keyhook_lib: Optional[str] = None,
        additional_env: Optional[Dict[str, str]] = None,
    ) -> docker.models.containers.Container:
        """Create Docker container with imix binary."""
        logger.info(f"Creating container with image: {image}")

        env_vars = {
            "IMIX_CALLBACK_URI": self.c2_server,
            "SSLKEYLOGFILE": "/keys/tls_keys.log",
            "XCHACHA_KEYLOG": "/keys/xchacha_keys.log",
        }
        if additional_env:
            env_vars.update(additional_env)

        volumes = {
            str(self.imix_binary_path.resolve()): {"bind": "/imix", "mode": "ro"},
            str(self.keylog_dir.resolve()): {"bind": "/keys", "mode": "rw"},
        }

        if keyhook_lib:
            keyhook_path = Path(keyhook_lib)
            if keyhook_path.exists():
                volumes[str(keyhook_path)] = {"bind": "/lib/keyhook.so", "mode": "ro"}
                env_vars["LD_PRELOAD"] = "/lib/keyhook.so"

        container_config = {
            "image": image,
            "command": ["/imix"],
            "environment": env_vars,
            "volumes": volumes,
            "network": self.network_name,
            "detach": True,
            "cap_add": ["NET_ADMIN", "NET_RAW", "SYS_PTRACE"],
            "security_opt": ["seccomp=unconfined"],
            "pid_mode": "host",
            "stdin_open": True,
            "tty": True,
        }

        try:
            container = self.client.containers.create(**container_config)
            logger.info(f"Container created: {container.id}")
            return container
        except Exception as e:
            logger.error(f"Failed to create container: {e}")
            raise

    def start(self, keyhook_lib: Optional[str] = None) -> None:
        """Start the sandbox container."""
        if self.container is None:
            self.setup_network()
            self.container = self.create_container(keyhook_lib=keyhook_lib)
        
        logger.info("Starting container...")
        self.container.start()
        logger.info(f"Container started: {self.container.id}")

    def stop(self) -> None:
        """Stop the sandbox container."""
        if self.container:
            logger.info("Stopping container...")
            try:
                self.container.stop(timeout=10)
            except Exception as e:
                logger.warning(f"Error stopping container: {e}")

    def remove(self) -> None:
        """Remove the sandbox container."""
        if self.container:
            logger.info("Removing container...")
            try:
                self.container.remove(force=True)
            except Exception as e:
                logger.warning(f"Error removing container: {e}")
            self.container = None

    def cleanup(self) -> None:
        """Clean up container and network."""
        self.stop()
        self.remove()
        if self.network:
            try:
                remove_network(self.client, self.network_name)
            except Exception as e:
                logger.warning(f"Error removing network: {e}")

    def get_container_ip(self) -> Optional[str]:
        """Get container IP address."""
        if not self.container:
            return None
        
        try:
            self.container.reload()
            network_settings = self.container.attrs.get("NetworkSettings", {})
            networks = network_settings.get("Networks", {})
            if self.network_name in networks:
                return networks[self.network_name].get("IPAddress")
        except Exception as e:
            logger.warning(f"Error getting container IP: {e}")
        return None

    def get_keylog_paths(self) -> Dict[str, Path]:
        """Get paths to key log files."""
        return {
            "tls": self.tls_keylog,
            "xchacha": self.xchacha_keylog,
        }

    def get_container_pid(self) -> Optional[int]:
        """Get the PID of the main process inside the container."""
        if not self.container:
            return None
        
        try:
            self.container.reload()
            pid = self.container.attrs.get("State", {}).get("Pid")
            if pid and pid > 0:
                return pid
        except Exception as e:
            logger.warning(f"Error getting container PID: {e}")
        
        return None

    def dump_memory(
        self,
        regions_filter: Optional[List[str]] = None,
    ) -> Tuple[Optional[bytes], Optional[int]]:
        """Dump memory from the container's main process."""
        pid = self.get_container_pid()
        if pid is None:
            logger.error("Could not get container PID for memory dump")
            return None, None
        
        logger.info(f"Dumping memory from container process PID {pid}")
        
        try:
            memory = dump_process_memory(pid, regions_filter)
            logger.info(f"Dumped {len(memory)} bytes from process {pid}")
            return memory, pid
        except PermissionError as e:
            logger.error(f"Permission denied reading process memory: {e}")
            logger.info("Ensure container has SYS_PTRACE capability and pid_mode=host")
            return None, None
        except Exception as e:
            logger.error(f"Failed to dump container memory: {e}")
            return None, None

    def get_container_id(self) -> Optional[str]:
        """Get the container ID."""
        if self.container:
            return self.container.id
        return None

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup."""
        self.cleanup()

# ============================================================================
# PROTOCOL PARSERS
# ============================================================================

class GRPCParser:
    """Parser for gRPC over HTTP/2 (imix C2)."""

    def __init__(
        self,
        xchacha_keylog: Optional[Path] = None,
        tls_keylog: Optional[Path] = None,
    ):
        if xchacha_keylog and xchacha_keylog.exists():
            self.xchacha_decryptor = XChaChaDecryptor(xchacha_keylog)
            logger.info("XChaCha decryptor initialized with keylog file")
        else:
            self.xchacha_decryptor = XChaChaDecryptor(None)
            logger.info("XChaCha decryptor initialized (will use memory-extracted keys)")

        self.tls_keylog = tls_keylog
        self.messages: List[Dict[str, Any]] = []
        self.reassembler = StreamReassembler()

    def parse_packets(self, packets: List) -> List[Dict[str, Any]]:
        """Reassemble TCP streams, parse HTTP/2 DATA, extract gRPC messages, decrypt, return message dicts."""
        parsed: List[Dict[str, Any]] = []

        for pkt in packets:
            try:
                if not pkt.haslayer(IP) or not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
                    continue
                ip = pkt[IP]
                tcp = pkt[TCP]
                payload = pkt[Raw].load
                self.reassembler.add_segment(ip.src, tcp.sport, ip.dst, tcp.dport, payload)
            except Exception as e:
                logger.debug("Error adding packet to reassembler: %s", e)

        for key in list(self.reassembler.keys()):
            buf = self.reassembler.get_buffer(key)
            if not buf:
                continue
            consumed_total = 0
            n, frames = parse_http2_frames(buf)
            for ft, sid, payload in frames:
                if ft != HTTP2_FRAME_DATA or not payload:
                    continue
                consumed_g, msgs = extract_grpc_frames(payload)
                for raw_msg in msgs:
                    decrypted = raw_msg
                    if self.xchacha_decryptor:
                        dec = self.xchacha_decryptor.decrypt_message(raw_msg)
                        if dec is not None:
                            decrypted = dec
                    msg = {"data": decrypted, "stream_id": sid}
                    parsed.append(msg)
                    self.messages.append(msg)
            if n > 0:
                self.reassembler.consume(key, n)

        return parsed

    def extract_tasks(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract tasks from gRPC messages (ClaimTasksResponse)."""
        tasks = []
        for m in messages:
            t = self._extract_task_from_message(m)
            if t:
                tasks.append(t)
        return tasks

    def _extract_task_from_message(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        data = message.get("data")
        if not data:
            return None
        try:
            resp = parse_claim_tasks_response(data)
            if not resp or "tasks" not in resp:
                return None
            out = []
            for task_data in resp["tasks"]:
                if "tome" not in task_data:
                    continue
                tome = task_data["tome"]
                if not isinstance(tome, dict) or "eldritch" not in tome:
                    continue
                out.append({
                    "task_id": task_data.get("id"),
                    "quest_name": task_data.get("quest_name"),
                    "eldritch_script": tome["eldritch"],
                    "parameters": tome.get("parameters", {}),
                })
            return {"tasks": out} if out else None
        except Exception as e:
            logger.debug("Error extracting task from message: %s", e)
            return None

    def reload_keylog(self) -> None:
        """Reload XChaCha keylog."""
        if self.xchacha_decryptor:
            self.xchacha_decryptor.reload_keylog()


class DNSParser:
    """Parser for DNS transport protocol."""

    def __init__(
        self,
        base_domain: str = "c2.example.com",
        xchacha_keylog: Optional[Path] = None,
    ):
        self.base_domain = base_domain
        self.xchacha_decryptor = None
        if xchacha_keylog and xchacha_keylog.exists():
            self.xchacha_decryptor = XChaChaDecryptor(xchacha_keylog)

        self.conversations: Dict[str, Dict[str, Any]] = {}
        self.messages: List[Dict[str, Any]] = []

    def parse_packets(self, packets: List) -> List[Dict[str, Any]]:
        """Parse DNS packets and extract messages."""
        parsed_messages = []

        for packet in packets:
            try:
                if DNS in packet:
                    message = self._parse_dns_packet(packet)
                    if message:
                        parsed_messages.append(message)
            except Exception as e:
                logger.debug(f"Error parsing DNS packet: {e}")

        self.messages.extend(parsed_messages)
        return parsed_messages

    def _parse_dns_packet(self, packet) -> Optional[Dict[str, Any]]:
        """Parse DNS packet and extract encoded data."""
        try:
            dns_layer = packet[DNS]

            if DNSQR in dns_layer:
                query_name = dns_layer[DNSQR].qname.decode("utf-8").rstrip(".")
                
                if self.base_domain in query_name:
                    encoded_part = query_name.replace(f".{self.base_domain}", "")
                    
                    try:
                        padding = (8 - len(encoded_part) % 8) % 8
                        decoded_data = base64.b32decode(encoded_part.upper() + "=" * padding)
                        
                        return {
                            "query_name": query_name,
                            "encoded_data": encoded_part,
                            "decoded_data": decoded_data,
                            "timestamp": packet.time if hasattr(packet, "time") else None,
                        }
                    except Exception as e:
                        logger.debug(f"Base32 decode error: {e}")
                        return None

            if dns_layer.an and dns_layer.an.type == 16:  # TXT record
                txt_data = dns_layer.an.rdata
                if isinstance(txt_data, bytes):
                    try:
                        padding = (8 - len(txt_data) % 8) % 8
                        decoded_data = base64.b32decode(txt_data.upper() + "=" * padding)
                        return {
                            "response": True,
                            "decoded_data": decoded_data,
                            "timestamp": packet.time if hasattr(packet, "time") else None,
                        }
                    except Exception as e:
                        logger.debug(f"Base32 decode error from TXT: {e}")

        except Exception as e:
            logger.debug(f"Error parsing DNS packet: {e}")

        return None

    def _reassemble_chunks(self, messages: List[Dict[str, Any]]) -> List[bytes]:
        """Reassemble chunked DNS transmissions."""
        reassembled = []
        
        for message in messages:
            if "decoded_data" in message:
                reassembled.append(message["decoded_data"])

        return reassembled

    def extract_tasks(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract tasks from DNS messages."""
        tasks = []

        reassembled_data = self._reassemble_chunks(messages)

        for data in reassembled_data:
            try:
                if self.xchacha_decryptor:
                    decrypted = self.xchacha_decryptor.decrypt_message(data)
                    if decrypted:
                        data = decrypted

                task = self._extract_task_from_dns_data(data)
                if task:
                    tasks.append(task)
            except Exception as e:
                logger.debug(f"Error extracting task from DNS data: {e}")

        return tasks

    def _extract_task_from_dns_data(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Extract task from DNS transport data."""
        try:
            dns_packet = parse_dns_packet(data)
            if not dns_packet:
                return None

            packet_data = dns_packet.get("data")
            if not packet_data:
                return None

            response = parse_claim_tasks_response(packet_data)
            if response and "tasks" in response:
                tasks = []
                for task_data in response["tasks"]:
                    if "tome" in task_data:
                        tome = task_data["tome"]
                        if isinstance(tome, dict) and "eldritch" in tome:
                            tasks.append({
                                "task_id": task_data.get("id"),
                                "quest_name": task_data.get("quest_name"),
                                "eldritch_script": tome["eldritch"],
                                "parameters": tome.get("parameters", {}),
                            })
                return {"tasks": tasks} if tasks else None
        except Exception as e:
            logger.debug(f"Error extracting task from DNS data: {e}")
        return None

# ============================================================================
# MAIN ANALYZER
# ============================================================================

class Analyzer:
    """Main analyzer orchestrator."""

    def __init__(
        self,
        imix_binary: str,
        c2_server: str,
        transport: str,
        output: str,
        timeout: Optional[int] = None,
        keyhook_lib: Optional[str] = None,
    ):
        """Initialize analyzer."""
        self.imix_binary = imix_binary
        self.c2_server = c2_server
        self.transport = transport
        self.output = output
        self.timeout = timeout
        self.keyhook_lib = keyhook_lib

        # Initialize components
        self.sandbox = SandboxManager(imix_binary, c2_server)
        logger.info("Using Docker-based sandbox")
        
        self.adapter = ImixAdapter()
        self.collector = DataCollector(c2_framework="imix")

        # Setup adapter
        adapter_config = self.adapter.setup(imix_binary, c2_server, transport=transport)
        logger.info(f"Adapter configured for transport: {self.adapter.get_transport_type()}")

        # Initialize parser based on transport
        keylog_paths = self.sandbox.get_keylog_paths()
        if self.transport == "dns":
            self.parser = DNSParser(xchacha_keylog=keylog_paths["xchacha"])
        else:
            self.parser = GRPCParser(
                xchacha_keylog=keylog_paths["xchacha"],
                tls_keylog=keylog_paths["tls"],
            )

        self.capture: Optional[NetworkCapture] = None
        self.running = False
        
        # For memory-based key extraction - keep running buffers
        self.encrypted_messages: List[dict] = []
        self.extracted_pubkeys: set = set()
        self.memory_scan_interval = 1.0
        self.last_memory_scan = 0.0
        self.max_message_buffer = 5000
        self.decrypted_message_ids: set = set()

    def _get_c2_endpoint(self) -> Tuple[Optional[str], Optional[int], Optional[str]]:
        """
        Get the current C2 endpoint information.
        
        Returns:
            Tuple of (c2_ip, c2_port, c2_server) or (None, None, None) if not discovered
        """
        if not self.capture:
            return None, None, None
        
        endpoints = self.capture.get_discovered_endpoints()
        if endpoints:
            # Use the first discovered endpoint (most common case: single C2 server)
            c2_ip, c2_port = endpoints[0]
            c2_server = f"{self.transport}://{c2_ip}:{c2_port}" if self.transport else f"{c2_ip}:{c2_port}"
            return c2_ip, c2_port, c2_server
        
        # Fallback to configured C2 server if available
        if self.c2_server and self.c2_server != "http://discover-from-traffic":
            # Try to parse IP:port from URL
            import re
            match = re.search(r'://([^:/]+):?(\d+)?', self.c2_server)
            if match:
                ip = match.group(1)
                port = int(match.group(2)) if match.group(2) else None
                return ip, port, self.c2_server
        
        return None, None, None

    def _collect_encrypted_payloads_from_messages(self, messages: List[dict]) -> None:
        """Collect encrypted message payloads from parsed gRPC messages into running buffer."""
        current_time = time.time()
        
        for msg in messages:
            data = msg.get("data")
            if data and isinstance(data, bytes) and len(data) >= 56:
                pubkey = data[:32]
                zeros = sum(1 for b in pubkey if b == 0)
                if zeros < 28:
                    pubkey_hex = pubkey.hex()
                    msg_id = f"{pubkey_hex}:{data[32:40].hex()}"
                    
                    if msg_id in self.decrypted_message_ids:
                        continue
                    
                    self.encrypted_messages.append({
                        "data": data,
                        "pubkey": pubkey,
                        "pubkey_hex": pubkey_hex,
                        "timestamp": current_time,
                        "decrypted": False,
                        "msg_id": msg_id,
                    })
                    
                    self.extracted_pubkeys.add(pubkey_hex)
                    
                    if len(self.encrypted_messages) > self.max_message_buffer:
                        self.encrypted_messages = [
                            m for m in self.encrypted_messages 
                            if m.get("decrypted", False) or (current_time - m["timestamp"]) < 300
                        ]
                        if len(self.encrypted_messages) > self.max_message_buffer:
                            self.encrypted_messages = sorted(
                                self.encrypted_messages, 
                                key=lambda x: x["timestamp"]
                            )[-self.max_message_buffer:]

    def _retry_decryption_on_buffered_messages(self, newly_found_keys: Optional[List[bytes]] = None) -> int:
        """Retry decryption on ALL buffered encrypted messages using ALL available keys."""
        if not self.encrypted_messages:
            return 0
        
        if not hasattr(self.parser, 'xchacha_decryptor') or not self.parser.xchacha_decryptor:
            return 0
        
        cached_keys = set(self.parser.xchacha_decryptor.key_cache.keys())
        undecrypted = [m for m in self.encrypted_messages if not m.get("decrypted", False)]
        
        if not undecrypted:
            return 0
        
        logger.debug(
            f"Retrying decryption: {len(undecrypted)} undecrypted messages, "
            f"{len(cached_keys)} keys available"
        )
        
        decrypted_count = 0
        
        for msg_entry in undecrypted:
            if msg_entry.get("decrypted", False):
                continue
                
            encrypted_data = msg_entry["data"]
            pubkey = msg_entry["pubkey"]
            pubkey_hex = msg_entry["pubkey_hex"]
            
            if pubkey_hex not in cached_keys:
                continue
            
            plaintext = self.parser.xchacha_decryptor.decrypt_message(encrypted_data)
            if not plaintext:
                continue
            
            logger.info(
                f"✓ Decrypted message: pubkey={pubkey_hex[:16]}..., "
                f"size={len(plaintext)} bytes"
            )
            
            msg_entry["decrypted"] = True
            msg_entry["plaintext"] = plaintext
            self.decrypted_message_ids.add(msg_entry["msg_id"])
            decrypted_count += 1
            
            try:
                resp = parse_claim_tasks_response(plaintext)
                if resp and "tasks" in resp:
                    c2_ip, c2_port, c2_server = self._get_c2_endpoint()
                    for task_data in resp["tasks"]:
                        if "tome" in task_data:
                            tome = task_data["tome"]
                            if isinstance(tome, dict) and "eldritch" in tome:
                                self.collector.add_task(
                                    task_id=task_data.get("id"),
                                    eldritch_script=tome["eldritch"],
                                    transport=self.transport,
                                    metadata=task_data,
                                    c2_server=c2_server,
                                    c2_ip=c2_ip,
                                    c2_port=c2_port,
                                )
                                logger.info(
                                    f"🎯 Extracted task {task_data.get('id', 'unknown')} "
                                    f"from decrypted message!"
                                )
            except Exception as e:
                logger.debug(f"Could not parse decrypted message: {e}")
        
        if decrypted_count > 0:
            logger.info(
                f"Successfully decrypted {decrypted_count} message(s) "
                f"({len([m for m in self.encrypted_messages if m.get('decrypted')])} total decrypted)"
            )
        
        return decrypted_count

    def _scan_memory_for_keys(self) -> int:
        """Continuously scan beacon memory for shared secrets."""
        memory, pid = self.sandbox.dump_memory(regions_filter=["heap", "anon"])
        if memory is None:
            logger.debug("Memory dump failed, skipping key scan")
            return 0
        
        pubkeys_to_find = []
        seen_pubkeys = set()
        
        for msg_entry in self.encrypted_messages:
            pubkey = msg_entry["pubkey"]
            pubkey_hex = msg_entry["pubkey_hex"]
            
            if hasattr(self.parser, 'xchacha_decryptor') and self.parser.xchacha_decryptor:
                if self.parser.xchacha_decryptor.has_key_for(pubkey):
                    continue
            
            if pubkey_hex not in seen_pubkeys:
                seen_pubkeys.add(pubkey_hex)
                pubkeys_to_find.append(pubkey)
        
        if not pubkeys_to_find:
            logger.debug(f"All {len(self.encrypted_messages)} messages already have keys or no pubkeys to search")
            return 0
        
        logger.info(
            f"Scanning memory for {len(pubkeys_to_find)} pubkeys "
            f"(out of {len(self.encrypted_messages)} total messages)..."
        )
        
        found_keys = find_shared_secrets_in_memory(memory, pubkeys_to_find)
        
        if found_keys:
            if hasattr(self.parser, 'xchacha_decryptor') and self.parser.xchacha_decryptor:
                verified_keys = {}
                for pubkey, secret in found_keys.items():
                    test_success = False
                    for msg_entry in self.encrypted_messages:
                        if msg_entry["pubkey"] == pubkey and not msg_entry.get("decrypted", False):
                            msg_data = msg_entry["data"]
                            if len(msg_data) < 56:
                                continue
                            
                            test_decryptor = type(self.parser.xchacha_decryptor)(None)
                            test_decryptor.add_key(pubkey, secret)
                            test_result = test_decryptor.decrypt_message(msg_data)
                            if test_result is not None:
                                test_success = True
                                logger.info(
                                    f"✓ Verified key for pubkey {pubkey.hex()[:16]}... "
                                    f"by successfully decrypting {len(msg_data)}-byte message "
                                    f"(plaintext: {len(test_result)} bytes)"
                                )
                                msg_entry["decrypted"] = True
                                msg_entry["plaintext"] = test_result
                                self.decrypted_message_ids.add(msg_entry["msg_id"])
                                try:
                                    resp = parse_claim_tasks_response(test_result)
                                    if resp and "tasks" in resp:
                                        c2_ip, c2_port, c2_server = self._get_c2_endpoint()
                                        for task_data in resp["tasks"]:
                                            if "tome" in task_data:
                                                tome = task_data["tome"]
                                                if isinstance(tome, dict) and "eldritch" in tome:
                                                    self.collector.add_task(
                                                        task_id=task_data.get("id"),
                                                        eldritch_script=tome["eldritch"],
                                                        transport=self.transport,
                                                        metadata=task_data,
                                                        c2_server=c2_server,
                                                        c2_ip=c2_ip,
                                                        c2_port=c2_port,
                                                    )
                                                    logger.info(
                                                        f"🎯 Extracted task {task_data.get('id', 'unknown')} "
                                                        f"from verified decryption!"
                                                    )
                                except Exception as e:
                                    logger.debug(f"Could not parse verified message: {e}")
                                break
                    
                    if test_success or len(self.encrypted_messages) == 0:
                        verified_keys[pubkey] = secret
                    else:
                        logger.debug(
                            f"⚠ Key for pubkey {pubkey.hex()[:16]}... failed verification "
                            f"(decryption test failed)"
                        )
                
                if verified_keys:
                    added = self.parser.xchacha_decryptor.add_keys(verified_keys)
                    if added > 0:
                        logger.info(
                            f"🔑 Found {added} verified shared secret(s) in memory! "
                            f"Total keys cached: {self.parser.xchacha_decryptor.key_count()}"
                        )
                        self._retry_decryption_on_buffered_messages(
                            newly_found_keys=list(verified_keys.keys())
                        )
                    return added
                else:
                    logger.warning(
                        f"Found {len(found_keys)} keys in memory but none passed verification"
                    )
        
        return 0

    def run(self) -> None:
        """Run the analysis."""
        logger.info("Starting sandbox command analyzer")

        try:
            self.sandbox.start(keyhook_lib=self.keyhook_lib)
            container_ip = self.sandbox.get_container_ip()
            logger.info(f"Container IP: {container_ip}")
            capture_iface = get_interface_for_container(container_ip) or get_docker_bridge_interface()
            logger.info(f"Capture interface (host): {capture_iface}")
            logger.info("Memory-based key extraction enabled")

            self.capture = NetworkCapture(
                container_ip=container_ip,
                interface=capture_iface,
                c2_port=None,
            )
            self.capture.start()
            logger.info(
                "Capturing all container traffic; C2 endpoints will be discovered dynamically"
            )

            start_time = time.time()
            self.running = True
            last_keylog_reload = 0.0
            keylog_reload_interval = 10.0

            logger.info("Capturing network traffic...")
            while self.running:
                if self.timeout and (time.time() - start_time) > self.timeout:
                    logger.info("Timeout reached, stopping analysis")
                    break

                now = time.time()
                
                if now - last_keylog_reload >= keylog_reload_interval:
                    last_keylog_reload = now
                    if hasattr(self.parser, "reload_keylog") and callable(getattr(self.parser, "reload_keylog")):
                        self.parser.reload_keylog()
                        logger.debug("Reloaded XChaCha keylog")
                
                if now - self.last_memory_scan >= self.memory_scan_interval:
                    self.last_memory_scan = now
                    keys_found = self._scan_memory_for_keys()
                    if keys_found == 0 and len(self.encrypted_messages) > 0:
                        self._retry_decryption_on_buffered_messages()

                packets = self.capture.get_packets(timeout=1.0)

                if packets:
                    logger.info(f"Captured {len(packets)} packets")
                    if self.transport == "dns":
                        filtered_packets = self.capture.filter_dns_traffic(packets)
                    else:
                        filtered_packets = self.capture.filter_grpc_traffic(packets)
                    
                    logger.info(f"Filtered to {len(filtered_packets)} {self.transport} packets")

                    messages = self.parser.parse_packets(filtered_packets)
                    logger.debug(f"Parsed {len(messages)} messages")
                    
                    before_count = len(self.encrypted_messages)
                    self._collect_encrypted_payloads_from_messages(messages)
                    new_count = len(self.encrypted_messages) - before_count
                    if new_count > 0:
                        logger.debug(
                            f"Collected {new_count} new encrypted payload(s) "
                            f"(total buffered: {len(self.encrypted_messages)})"
                        )
                        self._retry_decryption_on_buffered_messages()

                    tasks = self.parser.extract_tasks(messages)
                    if tasks:
                        logger.info(f"Extracted {len(tasks)} task(s) from messages")

                    c2_ip, c2_port, c2_server = self._get_c2_endpoint()
                    for task_data in tasks:
                        if isinstance(task_data, dict):
                            if "tasks" in task_data:
                                for task in task_data["tasks"]:
                                    if "eldritch_script" in task:
                                        self.collector.add_task(
                                            task_id=task.get("task_id"),
                                            eldritch_script=task["eldritch_script"],
                                            transport=self.transport,
                                            metadata=task,
                                            c2_server=c2_server,
                                            c2_ip=c2_ip,
                                            c2_port=c2_port,
                                        )
                            elif "eldritch_script" in task_data:
                                self.collector.add_task(
                                    task_id=task_data.get("task_id"),
                                    eldritch_script=task_data["eldritch_script"],
                                    transport=self.transport,
                                    metadata=task_data,
                                    c2_server=c2_server,
                                    c2_ip=c2_ip,
                                    c2_port=c2_port,
                                )

                    scripts = self.adapter.extract_eldritch_scripts(messages)
                    for script_data in scripts:
                        if script_data.get("script"):
                            self.collector.add_task(
                                task_id=script_data.get("task_id"),
                                eldritch_script=script_data["script"],
                                transport=self.transport,
                                metadata=script_data.get("metadata"),
                                c2_server=c2_server,
                                c2_ip=c2_ip,
                                c2_port=c2_port,
                            )

                time.sleep(0.1)

        except KeyboardInterrupt:
            logger.info("Interrupted by user")
        except Exception as e:
            logger.error(f"Error during analysis: {e}", exc_info=True)
        finally:
            self.cleanup()

    def cleanup(self) -> None:
        """Cleanup resources."""
        logger.info("Cleaning up...")
        if self.capture:
            self.capture.stop()
        self.sandbox.cleanup()

        endpoints = self.capture.get_discovered_endpoints() if self.capture else []
        if endpoints:
            logger.info(
                f"Discovered C2 endpoints from traffic: {[f'{ip}:{port}' for ip, port in endpoints]}"
            )

        if self.collector.tasks:
            self.collector.save_to_file(self.output)
            summary = self.collector.get_summary()
            logger.info(f"Analysis complete: {summary}")
        else:
            if endpoints:
                logger.warning(
                    "No tasks captured; beacon reached %s - check C2 is sending tasks",
                    [f"{ip}:{port}" for ip, port in endpoints],
                )
            else:
                logger.warning(
                    "No tasks captured; no TCP/UDP traffic from container - "
                    "beacon may not be connecting (C2 is discovered from traffic, not assumed)"
                )

# ============================================================================
# CLI ENTRY POINT
# ============================================================================

@click.command()
@click.option(
    "--imix-binary",
    required=True,
    type=click.Path(exists=True),
    help="Path to imix binary (can use samples from realm/imix-bins/)",
)
@click.option(
    "--c2-server",
    default="http://discover-from-traffic",
    help="C2 URL for IMIX_CALLBACK_URI (beacon may use compiled-in URL). "
    "C2 endpoints are discovered dynamically from captured traffic.",
)
@click.option(
    "--transport",
    type=click.Choice(["grpc", "dns"]),
    default="grpc",
    help="Transport type (default: auto-detect from binary name)",
)
@click.option(
    "--output",
    default="analysis_results.json",
    type=click.Path(),
    help="Output JSON file path",
)
@click.option(
    "--timeout",
    type=int,
    help="Analysis timeout in seconds",
)
@click.option(
    "--keyhook-library",
    type=click.Path(exists=True),
    help="Path to LD_PRELOAD hook library (optional)",
)
@click.option(
    "--test-mode",
    is_flag=True,
    help="Use test binaries from realm/imix-bins/ directory",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose logging",
)
def main(
    imix_binary: str,
    c2_server: str,
    transport: str,
    output: str,
    timeout: Optional[int],
    keyhook_library: Optional[str],
    test_mode: bool,
    verbose: bool,
):
    """
    Sandbox Command Analyzer - Capture and analyze C2 commands from network traffic.

    This tool runs imix C2 agent in a Docker sandbox and captures commands by
    intercepting network traffic. It supports gRPC and DNS transports.
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Handle test mode
    if test_mode:
        test_bin_dir = Path(__file__).parent.parent / "realm" / "imix-bins"
        if test_bin_dir.exists():
            test_binaries = list(test_bin_dir.glob("imix-*"))
            if test_binaries:
                imix_binary = str(test_binaries[0])
                logger.info(f"Using test binary: {imix_binary}")

    # Build keyhook library path if not provided
    if not keyhook_library:
        keyhook_path = Path(__file__).parent / "keyhook" / "keyhook.so"
        if keyhook_path.exists():
            keyhook_library = str(keyhook_path)
            logger.info(f"Using keyhook library: {keyhook_library}")

    # Create and run analyzer
    analyzer = Analyzer(
        imix_binary=imix_binary,
        c2_server=c2_server,
        transport=transport,
        output=output,
        timeout=timeout,
        keyhook_lib=keyhook_library,
    )

    # Handle signals
    def signal_handler(sig, frame):
        logger.info("Received signal, shutting down...")
        analyzer.running = False
        analyzer.cleanup()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    analyzer.run()


if __name__ == "__main__":
    main()
