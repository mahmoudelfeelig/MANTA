# MANTA thesis website

Small public website for the MANTA thesis.

It has:

- a landing page explaining the overall thesis
- a demo page for the app/backend flow
- a thesis PDF download button
- the elephant logo and footer pattern from the other projects
- same-domain assumptions for the FastAPI backend

## Run locally

```bash
npm install
cp ../main.pdf public/manta-thesis.pdf
npm run dev
```

Open `http://localhost:3000`.

The demo page uses simulated events by default. It can also read backend data when the app and backend share the same origin and you type the private adapter token locally in the browser.

Keep the backend token private. The public demo page does not bake a token into the bundle.
