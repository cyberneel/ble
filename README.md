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

License: MIT, see [LICENSE](LICENSE).
