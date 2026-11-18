@echo off
REM IAM Sentinel - Windows one-command start (see run.sh)
cd /d "%~dp0"
python -c "import fastapi, uvicorn, networkx, multipart" 2>NUL || python -m pip install -q -r requirements.txt
if not "%~1"=="" (
  python cli.py %*
  exit /b %ERRORLEVEL%
)
set PYTHONIOENCODING=utf-8
python cli.py scan iam-small.json
python main.py
