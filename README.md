# Server Monitoring + DDoS Detection Dashboard

## Cara Setting (Paling Gampang)

Semua setting ada di file **config.json**.

Buka file `config.json` lalu edit:

```json
{
  "password": "ganti_password_ini",
  "secret_key": "kunci_rahasia_acak_panjang",
  "discord_webhook": "https://discord.com/api/webhooks/ID/TOKEN",
  "host": "0.0.0.0",
  "port": 5000,
  "thresholds": {
    "rx_mbps": 150.0,
    "pps": 5000,
    "syn_recv": 50,
    "conntrack_percent": 30.0,
    "duration_sec": 3
  },
  "alert_cooldown": 120
}
```

**Yang wajib diisi:**
- `password` → password login dashboard
- `discord_webhook` → URL webhook Discord (boleh dikosongkan dulu)
- `secret_key` → ganti dengan teks acak

Simpan file, lalu jalankan aplikasi.

---

## Cara Menjalankan (Local / VPS)

### 1. Install dependency (sudah kamu lakukan)
```bash
pip install -r requirements.txt
```

### 2. Edit config.json
Isi password + webhook sesuai keinginan.

### 3. Jalankan
```bash
python app.py
```

Buka browser:
- Dari komputer yang sama: http://localhost:5000
- Dari komputer lain / HP: http://IP-SERVER:5000

Login pakai password yang ada di `config.json`.

---

## Cara Deploy di VPS (biar selalu nyala)

### Opsi 1: Pakai screen / tmux (paling simpel)
```bash
screen -S monitor
python app.py
# tekan Ctrl+A lalu D untuk detach
```

### Opsi 2: Pakai systemd (lebih rapi)

Buat file `/etc/systemd/system/server-monitor.service`:

```ini
[Unit]
Description=Server Monitor Dashboard
After=network.target

[Service]
User=root
WorkingDirectory=/path/ke/server-monitor
ExecStart=/path/ke/venv/bin/python app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Lalu:
```bash
sudo systemctl daemon-reload
sudo systemctl enable server-monitor
sudo systemctl start server-monitor
```

### Opsi 3: Pakai gunicorn (lebih stabil)
```bash
pip install gunicorn
gunicorn -w 2 -b 0.0.0.0:5000 app:app
```

---

## Cara ambil Discord Webhook
1. Buka Discord → Server kamu
2. Klik kanan channel → Edit Channel → Integrations → Webhooks
3. New Webhook → Copy Webhook URL
4. Paste ke `config.json` bagian "discord_webhook"

---

## Catatan
- Setelah edit config.json, restart aplikasi supaya perubahan terbaca.
- Threshold & webhook juga bisa diubah dari tab Settings di dashboard (akan otomatis tersimpan ke config.json).
- Jangan buka port 5000 langsung ke internet tanpa firewall / reverse proxy.
