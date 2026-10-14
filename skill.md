---
name: ble-reverse-engineer
description: Reverse-engineer an undocumented Bluetooth Low Energy gadget (LED panel, lamp, badge, scale, toy) so it can be driven from your own code instead of the vendor app. Covers scanning, dumping the GATT table, recovering the packet format from the vendor's Android app, proving it against the real device, and wrapping it in a small driver. Use when asked to "reverse engineer this BLE device", "control X without the app", "what does this app send over Bluetooth", or when handed a BLE device name, MAC address or APK.
---

# Reverse-engineer a BLE device

A BLE gadget is a table of characteristics. Its app writes bytes into one and gets
bytes notified back on another. So there are two unknowns: **which characteristic**
and **what bytes**. The app knows both. Read them out of the app, then use the radio
to prove each one. You do not need a sniffer.

This is the procedure that took a cheap 96×16 LED pixel panel from "only works with
its phone app" to showing live Claude Code usage from a Linux laptop. The worked
example further down is that device, with the real values.

## Rules

- Only devices you own.
- Never write to a firmware-update (OTA/DFU) characteristic. That is how a gadget
  gets bricked.
- Go in order of risk: read-only query, then one visible reversible command, then
  bulk data. Anything that saves to flash comes last, if at all.
- One central at a time. Close the vendor app (or turn the phone's Bluetooth off)
  before you connect, and stop your own daemon before you probe by hand.

## What you need

- A Linux machine with any Bluetooth adapter BlueZ can see. The built-in one is fine.
- Python with `bleak`, installed in a venv (`python -m venv .venv && .venv/bin/pip install bleak`).
  Recent distros refuse a system-wide `pip install`.
- `jadx` and the vendor's Android APK.
- Optional: `btmon` (ships with BlueZ) to watch every packet your own adapter
  sends and receives.

## Procedure

### 0. Check the radio you actually have

```bash
lsusb | grep -iE "bluetooth|nordic"
bluetoothctl list        # the adapters BlueZ can use
```

An nRF52840 dongle that shows up as `1915:521f Open DFU Bootloader` has no firmware
on it. It is not an adapter and not a sniffer until you flash it. Do not wait on it;
use the adapter BlueZ lists.

Two adapters listed (say the dongle after you flash it as a controller): bleak does not
use bluetoothctl's `[default]`, it takes the first powered adapter BlueZ reports, and that
can change from one run to the next. Pick one for the scripts below with `BLE_ADAPTER=hci0`.

### 1. Scan

```python
# probe.py: no argument = scan, with an address = dump that device's GATT table
import asyncio, os, sys
from bleak import BleakScanner, BleakClient

BLUEZ = {"adapter": os.environ["BLE_ADAPTER"]} if os.environ.get("BLE_ADAPTER") else {}

async def main(addr=None):
    if not addr:
        found = await BleakScanner.discover(timeout=8, return_adv=True, bluez=BLUEZ)
        for dev, adv in sorted(found.values(), key=lambda f: -f[1].rssi):
            print(dev.address, adv.rssi, adv.local_name, adv.service_uuids,
                  {k: v.hex() for k, v in adv.manufacturer_data.items()})
        return
    async with BleakClient(addr, timeout=30, bluez=BLUEZ) as c:
        for svc in c.services:
            print(svc.uuid)
            for ch in svc.characteristics:
                print("   ", ch.uuid, f"handle={ch.handle}", ",".join(ch.properties))

asyncio.run(main(*sys.argv[1:2]))
```

Record the name, the address, and any advertised service UUID. If the device is not
in the list, something else is already connected to it: most gadgets stop
advertising while a central holds them.

### 2. Dump the GATT table and sort it

`python probe.py <ADDRESS>`, then put every characteristic in one of four piles:

| Pile | How to spot it | What to do |
|---|---|---|
| Command channel | `write` or `write-without-response` | candidate, confirm in step 4 |
| Reply channel | `notify` or `indicate` | subscribe before you write anything |
| Standard | SIG-assigned: `18xx` services, `2axx`/`2bxx` characteristics (`180f` battery, `180a` device info) | just read them |
| Firmware update | its own service, touched only by the app's "update" screen; Nordic's is `fe59` | never write |

A short code on the Bluetooth base UUID is not automatically standard: vendors put
their own channels there too (`ff01`, `e0ad`). Sort those by their properties.

Several write/notify pairs is normal. Do not pick one by trial and error: a device
can carry a loopback characteristic that echoes every write straight back, which
looks exactly like a working command channel and is not one.

### 3. Get the vendor app and decompile it

Find the package id on the app's Play Store page, then:

```bash
adb shell pm path com.vendor.app     # prints package:/data/app/.../base.apk (maybe split APKs too)
adb pull /data/app/.../base.apk      # the path without the package: prefix
jadx -d out/ base.apk
```

No Android phone: download the APK from a mirror site instead. jadx exits non-zero
("finished with errors") when a few methods fail to decompile; the rest of `out/` is
still usable.

### 4. Find the protocol in the code

Search in this order. Each answer narrows the next search.

1. **The BLE layer.** `grep -rlE "BluetoothGatt|fastble|nordicsemi|rxandroidble" out/`.
   Apps wrap the BLE library in one class. Everything the app sends goes through
   that class's write method, so its callers are the whole protocol.
2. **The UUIDs.** `grep -rniE "[0-9a-f]{8}-[0-9a-f]{4}-|00805f9b34fb" out/`. If you only find
   the Bluetooth base suffix `-0000-1000-8000-00805f9b34fb` next to a format
   string, the UUIDs are built at runtime from short codes (a device catalog, a
   bundled JSON, a server response). Search for the short codes you saw in step 2.
3. **The packer.** The one function every command funnels through. It gives you
   the header byte, the length rule and the checksum. Search `crc`, `checksum`,
   `sum`, `xor`.
4. **The command table.** An enum or a block of constants: one byte per command.
5. **The handshake.** Whatever the app sends first after it enables notifications.
   If it waits for a reply and sends a second packet derived from it, that is a
   challenge-response and nothing works until you reproduce it.
6. **The bulk path.** Follow "send image" or "send file": chunk size, how chunks
   are numbered, what the per-chunk checksum covers.
7. **The reply parser.** It tells you what each byte of a notification means.

Decompiled Java prints bytes as signed decimals. `-96` is `0xA0`, `40961` is
`0xA001`, and `67, 67, 72, 73, 80` is the ASCII string `CCHIP`. Convert before you
conclude a constant is missing.

### 5. Rebuild the framing and test it with no device

```python
# frame.py: [direction][cmd][len][payload][checksum]. These constants are the worked example's.
def crc16_modbus(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc

def pack(cmd: int, *payload: int) -> bytes:
    body = bytes([0xA0, cmd, len(payload) + 3, *payload])
    return body + crc16_modbus(body).to_bytes(2, "little")

def parse(frame: bytes):
    """Return (cmd, payload), or None for a short frame or a bad checksum."""
    if len(frame) < 5 or crc16_modbus(frame[:-2]).to_bytes(2, "little") != frame[-2:]:
        return None
    return frame[1], frame[3:frame[2]]

assert crc16_modbus(b"123456789") == 0x4B37      # the standard CRC check value
assert parse(pack(0x41, 1)) == (0x41, b"\x01")
```

Every CRC variant has a published check value for the input `123456789`. Matching
it is how you know which variant the app uses before any radio is involved.

### 6. Prove it on the device, lowest risk first

The UUIDs and the handshake below are the worked example's. Swap in what steps 2
and 4 gave you; the shape (subscribe, handshake, ask and wait for the matching
reply) carries over.

```python
# session.py: subscribe, handshake, then request/reply. Needs frame.py above.
import asyncio, os
from bleak import BleakClient, BleakScanner

BLUEZ = {"adapter": os.environ["BLE_ADAPTER"]} if os.environ.get("BLE_ADAPTER") else {}
BASE = "0000{}-0000-1000-8000-00805f9b34fb"
WRITE, NOTIFY = BASE.format("a0ad"), BASE.format("f0ad")
MAGIC = b"CCHIP"

async def connect(addr):
    # A device BlueZ still holds a stale link to does not advertise, and neither a
    # scan nor connecting by address reaches it: `bluetoothctl disconnect` first.
    dev = await BleakScanner.find_device_by_address(addr, timeout=15, bluez=BLUEZ)
    c = BleakClient(dev or addr, timeout=30, bluez=BLUEZ)
    await c.connect()
    rx = asyncio.Queue()
    await c.start_notify(NOTIFY, lambda _, data: rx.put_nowait(parse(bytes(data))))

    async def ask(cmd, *payload, timeout=6):
        await c.write_gatt_char(WRITE, pack(cmd, *payload), response=False)
        while True:
            reply = await asyncio.wait_for(rx.get(), timeout)
            if reply and reply[0] == cmd:
                return reply[1]

    nonce = await ask(0x00, *MAGIC)                       # reply: "CCHIP" n1 n2
    verdict = await ask(0x01, *MAGIC, nonce[5] ^ 0x24, nonce[6] ^ 0x4C)
    if verdict[5] != 0:
        raise RuntimeError("handshake rejected")
    return c, ask
```

Then, in order:

```python
# inside an async function
c, ask = await connect(ADDRESS)
print((await ask(0x41, 1)).decode())     # firmware version: read-only
props = await ask(0x10, 1)               # properties: props[1] width, props[2] height
await c.write_gatt_char(WRITE, pack(0x04, 255, 0, 0, 0, 0), response=False)  # one red pixel
await c.disconnect()
```

A correct reply to a read-only query proves the characteristic, the framing, the
checksum and the handshake in one shot. Until you have that reply, send nothing else.

### 7. Measure the throughput, then find the bulk path

`write-without-response` has no delivery guarantee, and cheap firmware drops
packets when you write too fast. Send a few hundred of the same small command at a
fixed gap, each to a different target (a different pixel) so you can count how many
landed: by eye, from a photo, or from the device's replies if it sends one per
command. Repeat with a larger gap until loss reaches zero.

bleak returns from a write-without-response as soon as BlueZ has queued it, so a
loop's own timing says nothing about the radio. End each batch with a read-only
query and time its reply: it arrives only after every write queued before it. If the
zero-loss rate is too slow for what you want to show, go back to step 4.6: the app
has a faster path for images.

### 8. Wrap it

Three small files, in this order: a **driver** (framing, handshake, commands), a
**renderer** (your data to a `pixels[y][x] = (r, g, b)` grid), and a **daemon** that
reconnects with backoff when the device is switched off and holds a lock file so
only one copy runs.

### 9. Write the protocol down

A README with the GATT table, the frame layout, the handshake, the command table
and the measured limits. It is the only artifact that survives the session.

## Worked example: the PixelJoy 96×16 LED panel

| Step | What it turned up |
|---|---|
| 0 | The nRF52840 dongle was in DFU bootloader mode, so it was useless. The laptop's built-in Intel adapter did the whole job. |
| 1 | Name `P0AD_xxxx`, advertising service `0000c0ad-…`. |
| 2 | Service `e0ad`: write `a0ad` (write-without-response), notify `f0ad`. Also a loopback pair (`ae03` in, `ae05` out) that echoes writes verbatim, and firmware-update characteristics `ae3a`/`ae3b`/`ae3c`, left alone. |
| 3 | App package `com.th.pixeljoy`, BLE library FastBle (`com.clj.fastble`). |
| 4 | No UUID literals in the app: it builds them as `0000<code>-0000-1000-8000-00805f9b34fb` from a server-fetched device catalog. Frame is `[A0][cmd][len][payload][crc]`, replies start `A1`. |
| 5 | Checksum is CRC-16/MODBUS over everything before it, appended little-endian. `len` is payload length + 3. |
| 6 | Handshake: send `CCHIP`, get back `CCHIP` + 2 nonce bytes, send `CCHIP` + (`n1 ^ 0x24`, `n2 ^ 0x4C`), get back a status byte where 0 means accepted. Commands sent before that are silently ignored. Firmware query answered `1.6.5`. |
| 7 | Per-pixel writes need a 12 ms gap for zero loss, which is about 72 pixels a second, so 21 s for a full frame. The image path does a full frame in 7 packets and about a quarter of a second. |

Commands (the payload that goes after `[A0][cmd][len]`):

| Cmd | Name | Payload |
|---|---|---|
| `0x02` | clear | `01` |
| `0x04` | draw pixel | `r, g, b, x, y` |
| `0x10` | read properties | `01` |
| `0x11` | power | `01` / `00` |
| `0x13` | brightness | `0..100` |
| `0x26` | full image | palette image, sent as `A2` multi-packets |
| `0x41` | firmware version | `01` |

Measured loss for per-pixel writes against the gap between them:

| gap | 0 ms | 2 ms | 4 ms | 6 ms | 8 ms | 12 ms |
|---|---|---|---|---|---|---|
| lost | 64% | 39% | 4.5% | 1.5% | 0.5% | 0% |

The full-frame path. A multi-packet is
`[A2][session16][total16][index16][chunk_len16][chunk][crc16(chunk)]`, all
little-endian, index starting at 1, and the CRC covers the chunk only:

```python
# image.py: push a whole frame. Needs frame.py and session.py above.
import random

def quant332(r, g, b):       # the panel's colour space: 3 bits red, 3 green, 2 blue
    return int(int(r / 255 * 7) * 255 / 7), int(int(g / 255 * 7) * 255 / 7), int(b / 255 * 3) * 85

def encode_image(px, w, h):
    """px[y][x] = (r, g, b)  ->  [w16][h16][n][r,g,b * n][one palette index per pixel]"""
    palette, idx = {(0, 0, 0): 0}, bytearray()
    for row in px:
        for colour in row:
            idx.append(palette.setdefault(quant332(*colour), len(palette)))
    assert len(palette) < 256, "the colour count is a single byte"
    head = w.to_bytes(2, "little") + h.to_bytes(2, "little") + bytes([len(palette)])
    return head + bytes(v for colour in palette for v in colour) + bytes(idx)

async def draw_image(c, px, w=96, h=16, chunk=236, gap=0.03):
    pic = encode_image(px, w, h)
    n = len(pic).to_bytes(4, "big")
    body = bytes([0x26, n[3], n[0], n[1], n[2]]) + pic   # length bytes in the app's order
    session, total = random.randrange(500), -(-len(body) // chunk)
    for i in range(total):
        part = body[i * chunk:(i + 1) * chunk]
        head = b"\xA2" + b"".join(v.to_bytes(2, "little") for v in (session, total, i + 1, len(part)))
        await c.write_gatt_char(WRITE, head + part + crc16_modbus(part).to_bytes(2, "little"),
                                response=False)
        await asyncio.sleep(gap)
```

**Putting data on it.** The daemon runs `ccburn --json` every 10 seconds, which
reports Claude Code usage limits. For the session limit and the weekly limit it
draws one row each: a label and percentage in a 5×7 bitmap font, a bar with a white
tick where the pace says you should be, and the time until reset. The bar is blue
when you are behind pace, green on pace, red when burning too fast. A second mode
draws CPU and RAM bars from `psutil`. Dropping a line of text into a file the daemon
polls flashes that text for four seconds, which is how anything else on the machine
gets a message onto the panel.

## When the gadget is the client

Some gadgets do not serve data, they fetch it: they connect to a phone and read
the phone's services (notifications, time, media). Then the phone is the thing to
imitate. For an ESP32 pager that shows iPhone notifications through Apple's
notification service (ANCS), the test rig is a fake iPhone on the laptop:

- A BlueZ GATT server registered over D-Bus (`GattManager1.RegisterApplication`)
  exposing the ANCS service and its three characteristics.
- A pairing agent registered as `NoInputNoOutput`, which selects Just Works
  pairing so nobody has to press anything.
- The laptop connects out to the pager, then pushes scripted notifications, each
  one typed as a line into a named pipe.
- `btmon` running alongside, recording every ATT request the pager makes.

What that taught:

- Turn the real phone's Bluetooth off first. It reconnects faster than you do, and
  the gadget stops advertising once anything is connected.
- The gadget discovers services once per connection. Register your service before
  the link comes up, and drop any link that existed before it.
- The gadget treated a chunk of exactly MTU − 3 bytes as "more is coming" and
  anything shorter as the end. Split long replies at exactly that size.
- It had one slot for a notification in flight. Send the next only after it has
  fetched the last.

## If the app gives you nothing

Not used for the panel above, but the fallbacks in the order to try them:

1. **Android HCI snoop log.** Developer options, enable Bluetooth HCI snoop log,
   use the app, pull the log with `adb bugreport`, open it in Wireshark and filter
   `btatt`. You get the exact bytes the app wrote, with no extra hardware.
2. **`btmon`** on your own machine while you replay those bytes, to compare.
3. **A sniffer** (an nRF52840 dongle with Nordic's sniffer firmware). Last resort:
   it has to catch the connection being made, and an encrypted link is ciphertext
   unless you give it the key.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Device never appears in a scan | Something is connected to it (phone app, or a stale link your own machine still holds) | Close the app. For a stale link, only `bluetoothctl disconnect <ADDRESS>` clears it; rescanning or connecting by address does not |
| Writes succeed, nothing happens | No handshake yet, so commands are silently ignored | Find what the app sends first (step 4.5) |
| Every write comes straight back | You found a loopback characteristic | Use the pair the app uses, not the first pair that answers |
| UUIDs from step 2 are nowhere in the APK | Built at runtime from short codes | Search for the 4 hex digits and for the base UUID suffix |
| Replies never arrive | Subscribed after writing, or to the wrong characteristic | `start_notify` before the first write |
| Checksum never matches | Wrong variant, or wrong span | Test variants against `123456789`; check whether it covers the header or only the chunk |
| Several frames joined into one write do not work | Device parses one frame per write | One frame per `write_gatt_char` |
| Pixels missing at random | Writing faster than the firmware drains | Add a gap (step 7) or use the bulk path |
| Colours or coordinates scrambled | Field order is whatever the app does | Copy the order from the code; here it is `r, g, b, x, y` |
| Smooth gradients come out banded | The device's image format has 256 colours | Design for flat colours |
| Constant you expect is not in the code | It is there in signed decimal | `-96` is `0xA0` |
| Connects, then drops during service discovery; `journalctl -u bluetooth` says `No agent available` | Something on the device needs an encrypted link, so BlueZ starts pairing and has no agent to answer it | `bluetoothctl`, then `agent on`, `default-agent`, `pair <ADDRESS>` once |
| Scan or connect uses the wrong adapter | bleak takes the first powered adapter, not bluetoothctl's `[default]` | `BLE_ADAPTER=hci0` (step 0) |
| Dongle shows as `Open DFU Bootloader` | No application firmware on it | Flash it, or use the built-in adapter |
| Daemon logs "device not found" forever | The gadget is switched off | Expected; reconnect loop with backoff capped at 30 s |
| Vendor app can no longer connect | Your daemon is holding the device | Stop the daemon |

## WIRELESS reply flow

How this file gets handed out from the BLE 02 reel.

| Step | What happens |
|---|---|
| 1 | Someone comments `WIRELESS` on the reel. |
| 2 | They get a DM with the link to this repo, [cyberneel/ble](https://github.com/cyberneel/ble). |

DM template:

> Hey, thanks for commenting WIRELESS! Here's skill.md, the file I use to reverse-engineer BLE devices: https://github.com/cyberneel/ble
> Drop it into Claude Code and point it at your gadget, or just read it as a checklist.
