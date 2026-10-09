## Run locally
pip install -r requirements.txt
python -m uvicorn app:app --port 8000
MCP endpoint: http://127.0.0.1:8000/mcp (Streamable HTTP)

## Deploy to AWS Lambda
Package the dependencies and app.py into function.zip, then deploy with the
AWS Lambda Web Adapter layer. run.sh is the handler. Full steps will be added.# sentinel-mcp
