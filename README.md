<div align="center">

<img src="https://raw.githubusercontent.com/bong-water-water-bong/halo-ai/main/assets/avatars/pulse.svg" alt="pulse" width="200">

# pulse

### the heartbeat of the family.

**reflex agent for [halo-ai](https://github.com/bong-water-water-bong/halo-ai) — part of [meek's](https://github.com/bong-water-water-bong/meek) security team**

</div>

---

## what is pulse?

the heartbeat of the family. pulse checks on everyone, every hour. she monitors all services, pings every endpoint, and makes sure the household is running. if something flatlines, she's the first to know and the first to act — she'll restart a failed service before anyone notices it was down. she's caring but clinical.

### family

pulse is one of the reflex group — the younger siblings in the ai family, working under their eldest brother [meek](https://github.com/bong-water-water-bong/meek). their father [halo ai](https://github.com/bong-water-water-bong/halo-ai) built the stack. their mother [echo](https://github.com/bong-water-water-bong/echo) speaks for the family. pulse just does the work.

## quick start

```bash
# run as part of meek (recommended)
meek scan --agent pulse

# standalone
python pulse.py scan
python pulse.py status
```

## schedule

**hourly** — runs automatically via meek's systemd timers.

## the family

| member | role |
|---|---|
| [halo ai](https://github.com/bong-water-water-bong/halo-ai) | the father — bare-metal ai stack |
| [echo](https://github.com/bong-water-water-bong/echo) | the mother — voice of the family |
| [meek](https://github.com/bong-water-water-bong/meek) | the eldest — security overseer |
| [pulse](https://github.com/bong-water-water-bong/pulse) | service health |
| [ghost](https://github.com/bong-water-water-bong/ghost) | secret scanner |
| [gate](https://github.com/bong-water-water-bong/gate) | firewall guardian |
| [shadow](https://github.com/bong-water-water-bong/shadow) | file integrity |
| [fang](https://github.com/bong-water-water-bong/fang) | intrusion detection |
| [mirror](https://github.com/bong-water-water-bong/mirror) | pii scanner |
| [vault](https://github.com/bong-water-water-bong/vault) | backup verification |
| [net](https://github.com/bong-water-water-bong/net) | network monitor |
| [shield](https://github.com/bong-water-water-bong/shield) | intrusion prevention |

## license

Apache 2.0
