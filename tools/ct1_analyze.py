#!/usr/bin/env python3
"""Analyze Chapto CT1 packets.

Usage examples:
  python tools/ct1_analyze.py "CT1...."
  python tools/ct1_analyze.py --file packet.txt
  echo "CT1...." | python tools/ct1_analyze.py
"""

import argparse
import base64
import json
import sys
import zlib


PACKET_PREFIX = "CT1."


def b64url_decode(text: str) -> bytes:
    padded = text.replace("-", "+").replace("_", "/")
    pad_len = (4 - (len(padded) % 4)) % 4
    padded += "=" * pad_len
    return base64.b64decode(padded, validate=True)


def load_input(args: argparse.Namespace) -> str:
    if args.packet:
        return args.packet.strip()
    if args.file:
        with open(args.file, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    data = sys.stdin.read().strip()
    if not data:
        raise SystemExit("No packet input provided.")
    return data


def warn(msg: str) -> None:
    print(f"[!] {msg}")


def analyze_packet(packet: str, show_raw: bool) -> None:
    if not packet.startswith(PACKET_PREFIX):
        raise SystemExit("Packet must start with CT1.")

    packed = packet[len(PACKET_PREFIX):]
    try:
        compressed = b64url_decode(packed)
    except Exception as exc:
        raise SystemExit(f"Base64url decode failed: {exc}") from exc

    try:
        raw = zlib.decompress(compressed)
    except Exception as exc:
        raise SystemExit(f"zlib decompress failed: {exc}") from exc

    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise SystemExit(f"JSON decode failed: {exc}") from exc

    if not isinstance(payload, dict):
        raise SystemExit("Packet JSON is not an object.")

    print("CT1 Packet Analysis")
    print("-" * 60)
    print(f"Full length:     {len(packet)}")
    print(f"Base64 length:   {len(packed)}")
    print(f"Compressed bytes:{len(compressed)}")
    print(f"JSON bytes:      {len(raw)}")
    if len(raw) > 0:
        ratio = len(compressed) / len(raw)
        print(f"Compression:     {ratio:.3f} (compressed/json)")

    version = payload.get("v")
    ptype = payload.get("t")
    print(f"Version:         {version}")
    print(f"Type:            {ptype}")

    if show_raw:
        print("\nJSON Payload:")
        print(json.dumps(payload, indent=2, ensure_ascii=True))

    missing = []
    if "v" not in payload:
        missing.append("v")
    if "t" not in payload:
        missing.append("t")
    if missing:
        warn(f"Missing keys: {', '.join(missing)}")

    if ptype in ("S", "A"):
        print("\nSession Fields")
        session_id = payload.get("s")
        session_name = payload.get("d")
        username = payload.get("u")
        uuid = payload.get("i")
        pubkey = payload.get("k")
        note = payload.get("m")
        print(f"Session id:      {session_id}")
        print(f"Session name:    {session_name}")
        print(f"Username:        {username}")
        print(f"UUID:            {uuid}")
        if pubkey is not None:
            print(f"Public key len:  {len(pubkey)}")
        else:
            print("Public key len:  (missing)")
        if note is not None:
            print(f"Note:            {note}")
        required = ["s", "u", "i", "k"]
        missing_req = [key for key in required if key not in payload]
        if missing_req:
            warn(f"Missing required session fields: {', '.join(missing_req)}")

    elif ptype == "M":
        print("\nMessage Fields")
        session_id = payload.get("s")
        sender_uuid = payload.get("f")
        recipient_uuid = payload.get("r")
        nonce = payload.get("n")
        ciphertext = payload.get("c")
        print(f"Session id:      {session_id}")
        print(f"Sender uuid:     {sender_uuid}")
        print(f"Recipient uuid:  {recipient_uuid}")
        if nonce is not None:
            print(f"Nonce length:    {len(nonce)}")
        else:
            print("Nonce length:    (missing)")
        if ciphertext is not None:
            print(f"Ciphertext len:  {len(ciphertext)}")
        else:
            print("Ciphertext len:  (missing)")
        required = ["s", "f", "r", "n", "c"]
        missing_req = [key for key in required if key not in payload]
        if missing_req:
            warn(f"Missing required message fields: {', '.join(missing_req)}")
    else:
        warn("Unknown packet type. Expected S, A, or M.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze Chapto CT1 packets")
    parser.add_argument("packet", nargs="?", help="CT1 packet string")
    parser.add_argument("--file", "-f", help="Read packet from file")
    parser.add_argument("--raw", action="store_true", help="Print full JSON payload")
    args = parser.parse_args()

    if args.packet and args.file:
        raise SystemExit("Provide either a packet argument or --file, not both.")

    packet = load_input(args)
    analyze_packet(packet, args.raw)


if __name__ == "__main__":
    main()
