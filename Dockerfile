# Sentinel public demo (Hugging Face Docker Space). Serves the Gradio page and the API on port 7860.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    DEMO_PROVIDER=huggingface SENTINEL_EXPLAIN=1
# Hugging Face runs Spaces as user 1000
RUN useradd -m -u 1000 user
WORKDIR /home/user/app

COPY requirements.txt requirements-demo.txt ./
RUN pip install -r requirements.txt -r requirements-demo.txt

COPY --chown=user . .
USER user
EXPOSE 7860
CMD ["uvicorn", "demo.app:app", "--host", "0.0.0.0", "--port", "7860"]
