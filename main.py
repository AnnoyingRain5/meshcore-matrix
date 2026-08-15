import asyncio
import hashlib
import time
from meshcore import MeshCore, EventType as mshEventType
import dotenv
import os
from mautrix.appservice import AppService
from mautrix.types import (
    MessageEvent,
    StateEvent,
    TextMessageEventContent,
    MessageType,
    EventType as mtxEventType,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hmac

dotenv.load_dotenv()

meshcore: MeshCore
meshcore_channels: dict[str, int] = {}
matrix_roomid_name: dict[str, str] = {}
appservice: AppService


def derive_channel_key(channel_secret: str | bytes) -> bytes:
    return channel_secret[:16]


def decrypt_channel_message(
    ciphertext: bytes, cipher_mac: bytes, channel_secret: bytes
) -> bytes:
    key = derive_channel_key(channel_secret)

    # meshcore-ha uses cipher_mac to pick the right key among multiple channels
    expected_mac = hmac.new(key, ciphertext, hashlib.sha256).digest()[:2]
    if cipher_mac != expected_mac:
        raise ValueError("cipher_mac mismatch")

    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def parse_rx_log_event(event, channel_secret: bytes) -> dict | None:
    payload = event.payload

    if payload.get("payload_type") != 5:
        return None
    print(payload)
    chan_hash = int(payload.get("chan_hash", "0"), 16)
    expected_chan_hash = hashlib.sha256(channel_secret).digest()[0]

    if chan_hash != expected_chan_hash:
        return None

    ciphertext = bytes.fromhex(payload["crypted"])
    cipher_mac = bytes.fromhex(payload["cipher_mac"])

    # Try multiple trim lengths
    for trim in [0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 32]:
        trimmed = ciphertext[: len(ciphertext) - trim] if trim else ciphertext
        if len(trimmed) % 16 != 0:
            continue

        try:
            key = derive_channel_key(channel_secret)
            expected_mac = hmac.new(key, trimmed, hashlib.sha256).digest()[:2]

            if cipher_mac == expected_mac:
                decrypted = decrypt_channel_message(trimmed, cipher_mac, channel_secret)
                timestamp = int.from_bytes(decrypted[:4], "little")
                text = decrypted[4:].decode("utf-8", errors="replace").rstrip("\x00")
                return {"timestamp": timestamp, "text": text}
        except Exception as e:
            print(f"trim={trim} failed: {e}")

    return None


async def match_rx_log_to_sent(
    rx_log_event,
    sent_timestamp: int,
    channel_secret: bytes,
    matrix_messageid: str,
    matrix_roomid: str,
) -> None:
    parsed = parse_rx_log_event(rx_log_event, channel_secret)
    if parsed is None:
        return

    print(f"parsed timestamp={parsed['timestamp']} sent_timestamp={sent_timestamp}")
    if parsed["timestamp"] == sent_timestamp:
        print("we got a repeat!")
        await appservice.intent.react(matrix_roomid, matrix_messageid, "rpt")


async def count_repeats(
    sent_timestamp: int, channel_idx: int, matrix_messageid: str, matrix_roomid: str
):
    channel_info = await meshcore.commands.get_channel(channel_idx)
    channel_secret = channel_info.payload["channel_secret"]

    async def match_rx_log_to_sent_outer(rx_log_event):
        await match_rx_log_to_sent(
            rx_log_event,
            sent_timestamp,
            channel_secret,
            matrix_messageid,
            matrix_roomid,
        )

    sub = meshcore.subscribe(mshEventType.RX_LOG_DATA, match_rx_log_to_sent_outer)
    try:
        await asyncio.sleep(10)
    finally:
        meshcore.unsubscribe(sub)


async def channel_recv(event: MeshCore.events.Event):
    channel: str = (
        await meshcore.commands.get_channel(event.payload["channel_idx"])
    ).payload["channel_name"]
    username, message = event.payload["text"].split(": ", maxsplit=1)
    mtx_room_id = ""
    body = ""
    try:
        mtx_room_id = list(matrix_roomid_name.keys())[
            list(matrix_roomid_name.values()).index(channel)
        ]
        body = f"{username}: {message}"

    except Exception as e:
        print(e)
        print("No channel for this message!")
        mtx_room_id = os.getenv("MATRIX_DEFAULT_ROOM")
        body = f"[{channel}] {username}: {message}"

    await appservice.intent.send_message(
        mtx_room_id,
        TextMessageEventContent(msgtype=MessageType.TEXT, body=body),
    )
    print(f"[{channel}] {username}: {message}")


async def contact_recv(event: MeshCore.events.Event):
    pubkey_prefix = event.payload["pubkey_prefix"]
    message = event.payload["text"]
    username = meshcore.get_contact_by_key_prefix(pubkey_prefix)["adv_name"]

    await appservice.intent.send_message(
        os.getenv("MATRIX_DEFAULT_ROOM"),
        TextMessageEventContent(
            msgtype=MessageType.TEXT, body=f"[DM] {username}: {message}"
        ),
    )
    print(f"[DM] {username}: {message}")


async def on_matrix_command(evt: MessageEvent):
    if evt.content.body.startswith("!msh join"):
        await appservice.intent.join_room_by_id(
            evt.content.body.removeprefix("!msh join ")
        )
        await appservice.intent.react(evt.room_id, evt.event_id, "✅")


async def on_matrix_message(evt: MessageEvent):
    content: TextMessageEventContent = evt.get("content")
    if evt.sender == os.environ.get("MATRIX_BOT_MXID") or evt.sender.startswith(
        "@_meshcore_"
    ):
        return
    if content.body.startswith("!msh"):
        await on_matrix_command(evt)
        return
    room = matrix_roomid_name[evt.room_id]
    msh_roomid: str
    try:
        msh_roomid = meshcore_channels[room]
    except Exception as e:
        print(e)
        print("room not configured!")
        await appservice.intent.react(evt.room_id, evt.event_id, "❌")
        return
    timestamp = int(time.time())
    resp = await meshcore.commands.send_chan_msg(msh_roomid, content.body, timestamp)
    print(resp)
    if resp.type == mshEventType.OK:
        await appservice.intent.react(evt.room_id, evt.event_id, "✅")
    else:
        await appservice.intent.react(evt.room_id, evt.event_id, "❌")
    await count_repeats(timestamp, msh_roomid, evt.event_id, evt.room_id)


async def on_matrix_event(evt: StateEvent):

    if isinstance(evt, MessageEvent):
        await on_matrix_message(evt)
    else:
        print("ignoring non-message state event")


async def ack_recv(evt: MeshCore.events.Event):
    print("got an ack")


async def msg_sent_recv(evt: MeshCore.events.Event):
    print(evt)


async def main():
    # Connect to your device
    global meshcore, appservice, botAPI
    appservice = AppService(
        server=os.environ.get("MATRIX_HOMESERVER_URL"),
        domain=os.environ.get("MATRIX_HOMESERVER"),
        as_token=os.environ.get("MATRIX_AS_TOKEN"),
        hs_token=os.environ.get("MATRIX_HS_TOKEN"),
        bot_localpart="meshcorebot",
        id="meshcore",
    )

    meshcore = await MeshCore.create_tcp(
        os.environ.get("MESHCORE_HOST"),
        os.environ.get("MESHCORE_PORT"),
        False,
        auto_reconnect=True,
    )
    for i in range(16):
        channel = await meshcore.commands.get_channel(i)
        if channel.payload["channel_name"] == "":
            break
        meshcore_channels[channel.payload["channel_name"]] = i

    await meshcore.start_auto_message_fetching()
    await meshcore.ensure_contacts()
    meshcore.subscribe(mshEventType.CHANNEL_MSG_RECV, channel_recv)
    meshcore.subscribe(mshEventType.CONTACT_MSG_RECV, contact_recv)
    meshcore.subscribe(mshEventType.ACK, ack_recv)
    meshcore.subscribe(mshEventType.MSG_SENT, msg_sent_recv)
    await appservice.start(host="0.0.0.0", port=8080)
    appservice.matrix_event_handler(on_matrix_event)
    for room_id in await appservice.intent.get_joined_rooms():
        room_name = (
            await appservice.intent.get_state_event(room_id, mtxEventType.ROOM_NAME)
        ).name
        matrix_roomid_name[room_id] = room_name
    print("ready!")
    await asyncio.Event().wait()


asyncio.run(main())
