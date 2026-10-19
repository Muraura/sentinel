# Deploying the Sentinel demo to a Hugging Face Space

The Space runs the Gradio page and Sentinel's API in one Docker container. The model is an open model served by
Hugging Face Inference Providers; the database is a hosted Postgres. **Only synthetic data is deployed.**

## 1. Database (one time)

Create a free Postgres database (e.g. [Neon](https://neon.tech)) and copy its connection string. Then load the
schema and the synthetic data **from your machine**. The command-line value wins over `Sentinel/.env`:

```bash
cd Sentinel
DATABASE_URL='postgresql://USER:PASSWORD@HOST/DB?sslmode=require' \
  .venv/bin/python scripts/ingest_security.py --reset
```

This loads `data/synthetic/` only.

## 2. Hugging Face token

On huggingface.co: Settings → Access Tokens → create a fine-grained token with **"Make calls to Inference
Providers"**. Check that your chosen model supports tool calling with a provider: open the model page
(e.g. `Qwen/Qwen3-32B`) → "Deploy" → "Inference Providers". Free accounts get a small monthly credit; heavy
demo traffic needs a PRO subscription or pay-as-you-go, so keep the demo limits low.

## 3. Create the Space and push the code

1. huggingface.co → New Space → SDK **Docker** → blank template → public.
2. Settings → Variables and secrets:

   | Name | Type | Value |
   |---|---|---|
   | `DATABASE_URL` | secret | the Postgres connection string from step 1 |
   | `HF_TOKEN` | secret | the token from step 2 |
   | `HF_MODEL` | variable | `Qwen/Qwen3-32B` (or another tool-calling model) |
   | `DEMO_REPO_URL` | variable | your GitHub repo URL (shown on the page) |
   | `DEMO_DAILY_LIMIT` | variable | e.g. `50` |
   | `DEMO_PER_VISITOR_PER_HOUR` | variable | e.g. `3` |

   Leave `SENTINEL_API_USERS` unset: the API then refuses everything except `/health`, and the page still works.

3. Assemble the files from the allowlist (the script refuses to finish if anything private is included), then push:

```bash
cd Sentinel
deploy/huggingface/prepare_space.sh ../sentinel-space
cd ../sentinel-space
git init && git remote add origin https://huggingface.co/spaces/<your-username>/sentinel
git add . && git commit -m "Sentinel demo" && git push origin main   # use your HF token as the password
```

The Space builds the image (a few minutes) and starts. Check `https://<your-username>-sentinel.hf.space/health`.

## 4. Before sharing the link

- Ask the example questions yourself and read the reports.
- Watch the Space logs during the first visits.
- On LinkedIn, link both the Space (the demo) and the GitHub repo (the code).

## Test the image locally first

```bash
deploy/huggingface/prepare_space.sh /tmp/sentinel-space
docker build -t sentinel-space /tmp/sentinel-space
docker run --rm -p 7860:7860 \
  -e DATABASE_URL=postgresql://sentinel:change-me@host.docker.internal:5433/sentinel \
  -e DEMO_PROVIDER=ollama -e OLLAMA_HOST=http://host.docker.internal:11434 -e OLLAMA_MODEL=qwen3:8b \
  sentinel-space
# open http://127.0.0.1:7860
```
