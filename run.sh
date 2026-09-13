#!/bin/bash

# WDash Kibana Alternative - Startup Script

set -e

echo "🚀 Starting WDash - Minimal Kibana Alternative"

# Check if .env file exists
if [ ! -f .env ]; then
    echo "⚠️  .env file not found. Creating from template..."
    cp .env.example .env
    echo "📝 Please edit .env file with your configuration before running again."
    exit 1
fi

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    exit 1
fi

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 is required but not installed."
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "🔧 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Install/upgrade dependencies
echo "📦 Installing dependencies..."
pip install -r requirements.txt

# The process's own settings. No data source is among them: sources are
# declared on the configuration page once the application is up.
source .env

# Create dashboards.json if it doesn't exist — only for a deployment that
# asked for the file store. Dashboards live in the metadata database by
# default, and writing an empty JSON file nothing reads leaves a decoy
# beside the real store for whoever goes looking next.
if [ "${DASHBOARD_STORAGE:-database}" = "file" ] && [ ! -f data/dashboards.json ]; then
    echo "📊 Creating empty dashboards file..."
    mkdir -p data
    echo "[]" > data/dashboards.json
fi

# Display configuration summary
echo ""
echo "📋 Configuration Summary:"
echo "   Sources: declared on the configuration page after sign-in"
echo "   OIDC Configured: $([ ! -z "$OIDC_CLIENT_ID" ] && echo "Yes" || echo "No")"
echo ""

# Start the application
echo "🎯 Starting WDash application..."
echo "   Access URL: http://localhost:5000"
echo "   Press Ctrl+C to stop"
echo ""

# Run with development server or gunicorn based on environment
if [ "${FLASK_ENV:-production}" = "development" ]; then
    echo "🔧 Running in development mode..."
    export FLASK_APP=main.py
    export FLASK_ENV=development
    python main.py
else
    echo "🚀 Running in production mode with gunicorn..."
    gunicorn --bind 0.0.0.0:5000 --workers 4 --timeout 120 main:app
fi