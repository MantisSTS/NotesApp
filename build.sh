#!/bin/bash

# Build script for Notes App Docker container

echo "🐳 Building Notes App Docker container..."

# Build the Docker image
docker build -t notes-app . 

if [ $? -eq 0 ]; then
    echo "✅ Docker image built successfully!"
    echo ""
    echo "To run the application:"
    echo "  docker-compose up"
    echo ""
    echo "To run in development mode:"
    echo "  docker-compose -f docker-compose.yml -f docker-compose.dev.yml up"
    echo ""
    echo "The app will be available at: http://localhost:5000"
    echo ""
    echo "🔧 Creating CLI alias..."
    echo ""
    echo "Add this alias to your ~/.bashrc or ~/.zshrc:"
    echo "  alias notes='docker-compose exec notesapp python notes.py'"
    echo ""
    echo "Or for one-time use without running container:"
    echo "  alias notes-run='docker run --rm -v notesapp_notes_data:/app/data notes-app python notes.py'"
    echo ""
    echo "Examples:"
    echo "  notes add --type example --body 'docker command'"
    echo "  notes get"
    echo "  notes get --tags docker"
else
    echo "❌ Docker build failed!"
    exit 1
fi
