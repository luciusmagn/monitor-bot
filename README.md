# Braiins Monitor

Local Telegram-based monitor for the bot fleet and supporting services.

Tracked in Git:
- `monitor.py`
- `deploy/config.json`
- `deploy/systemd/braiins-monitor.service`
- `deploy/systemd/braiins-monitor.timer`

Not tracked:
- `/etc/braiins-monitor/env`
- `/var/lib/braiins-monitor/state.json`
- `/var/lib/braiins-monitor/incidents.sqlite`

Deploy notes:
- Live code path: `/opt/braiins-monitor/monitor.py`
- Live config path: `/etc/braiins-monitor/config.json`
- Live systemd unit: `/etc/systemd/system/braiins-monitor.service`
- Live timer unit: `/etc/systemd/system/braiins-monitor.timer`

Useful commands:
```bash
python3 -m py_compile /opt/braiins-monitor/monitor.py
systemctl restart braiins-monitor.timer braiins-monitor.service
journalctl -u braiins-monitor.service -n 50 --no-pager
sqlite3 /var/lib/braiins-monitor/incidents.sqlite 'select issue_id, severity, first_seen, resolved_at from incidents order by id desc limit 20;'
```
