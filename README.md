# ble

[`skill.md`](skill.md) is the file I use to reverse-engineer Bluetooth LE gadgets: how to
work out what a vendor's app sends to a device, so you can drive it from your own code.
Its worked example is a 96×16 LED pixel panel that now shows live Claude Code usage
from a Linux laptop.

## Use it

It is a Claude Code skill:

```bash
mkdir -p ~/.claude/skills/ble-reverse-engineer
cp skill.md ~/.claude/skills/ble-reverse-engineer/SKILL.md
```

Claude Code only picks it up under the name `SKILL.md`. Then ask: "reverse engineer my
`<device name>` so I can control it from this machine". It also reads fine as a
checklist for a person.

You need a Linux machine with a Bluetooth adapter, Python with `bleak`, `jadx`, and the
vendor's Android APK. Only use it on devices you own.

## Tested against

- **A fake of the worked-example panel**: a BlueZ GATT server on an nRF52840 dongle
  running Zephyr's `hci_usb`, driven from a laptop's Intel AX210 with bleak 3.0.2.
  Steps 0–2, 5 and 6, the image path and the step 7 sweep all passed, using the code
  blocks exactly as written. The fake never drops packets, so it cannot confirm the
  loss figures.
- **A third-party LED controller nearby**, read-only: scan, GATT dump, reads, and
  notify subscriptions.
- **Steps 3–4 on Nordic's open-source nRF Blinky APK** with jadx 1.5.6. There was no
  phone, so `adb pull` is untested.
- **The real panel**: the worked-example numbers were measured on it. The code blocks
  here match its working driver's framing (checked offline) but have not been run
  against the panel itself, which was switched off during testing.

License: MIT, see [LICENSE](LICENSE).
