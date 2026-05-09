# Braiins Monitor

Haskell-based operational monitor for the Braiins bot fleet.

Runtime responsibilities:
- check system services and user-scoped bot gateways
- check critical listener ports and health endpoints
- track incidents in SQLite
- send immediate Telegram alerts for confirmed incidents and resolutions
- send a daily summary at 00:00 UTC
- suppress planned restart noise via explicit maintenance windows

Live paths:
- binary: `/usr/local/bin/braiins-monitor`
- config: `/etc/braiins-monitor/config.json`
- env: `/etc/braiins-monitor/env`
- state snapshot: `/var/lib/braiins-monitor/state.json`
- incident DB: `/var/lib/braiins-monitor/incidents.sqlite`
- systemd unit: `/etc/systemd/system/braiins-monitor.service`
- timer: `/etc/systemd/system/braiins-monitor.timer`

Repo layout:
- `app/Main.hs`
- `src/BraiinsMonitor.hs`
- `deploy/config.json`
- `deploy/systemd/braiins-monitor.service`
- `deploy/systemd/braiins-monitor.timer`
- `legacy/monitor.py`

Build:
```bash
cabal build
```

Install compiled binary:
```bash
install -m 0755 \
  dist-newstyle/build/x86_64-linux/ghc-9.6.6/braiins-monitor-2.0.0.0/x/braiins-monitor/build/braiins-monitor/braiins-monitor \
  /usr/local/bin/braiins-monitor
```

Useful commands:
```bash
/usr/local/bin/braiins-monitor debug issues
/usr/local/bin/braiins-monitor maintenance start bot admin scheduled_restart
systemctl restart braiins-monitor.service braiins-monitor.timer
sqlite3 /var/lib/braiins-monitor/incidents.sqlite '.schema'
```
