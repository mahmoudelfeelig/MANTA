# Cloudflare Tunnel

This directory holds the local Cloudflare Tunnel config for exposing the backend and dashboard on a stable hostname.

Target hostname:

- `https://www.example.com`

## One-time setup on Windows

From the project root:

```powershell
.\cloudflared.exe tunnel login
.\cloudflared.exe tunnel create manta
.\cloudflared.exe tunnel route dns manta www.example.com
```

After `tunnel create`, Cloudflare prints a tunnel UUID and creates a credentials JSON file under:

- `C:\Users\user\.cloudflared\<TUNNEL_UUID>.json`

Update `cloudflared/config.yml` and replace:

- `REPLACE_WITH_TUNNEL_UUID`

with the real UUID from the create step.

## Run

With the backend already running on `127.0.0.1:8080`:

```powershell
.\cloudflared.exe tunnel --config .\cloudflared\config.yml run manta
```

Then open:

- `https://www.example.com/dashboard/login`