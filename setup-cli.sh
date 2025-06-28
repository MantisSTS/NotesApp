#!/bin/bash

# Setup script for Notes App CLI alias

echo "🔧 Setting up Notes App CLI alias..."

# Check if docker-compose is running
if ! docker-compose ps | grep -q "notes-app.*Up"; then
    echo "⚠️  Docker container is not running. Starting it now..."
    docker-compose up -d
fi

# Create alias for current session
alias notes='docker-compose exec notesapp python notes.py'

# Check which shell config file to use
if [ -n "$ZSH_VERSION" ]; then
    SHELL_CONFIG="$HOME/.zshrc"
elif [ -n "$BASH_VERSION" ]; then
    SHELL_CONFIG="$HOME/.bashrc"
else
    SHELL_CONFIG="$HOME/.profile"
fi

# Add alias to shell config if not already present
if ! grep -q "alias notes=" "$SHELL_CONFIG" 2>/dev/null; then
    echo "" >> "$SHELL_CONFIG"
    echo "# Notes App Docker CLI alias" >> "$SHELL_CONFIG"
    echo "alias notes='docker-compose exec notesapp python notes.py'" >> "$SHELL_CONFIG"
    echo "✅ Added alias to $SHELL_CONFIG"
else
    echo "ℹ️  Alias already exists in $SHELL_CONFIG"
fi

echo ""
echo "🎉 Setup complete! You can now use:"
echo ""
echo "  notes add --type example --body 'test command'"
echo "  notes get"
echo "  notes get --tags docker"
echo "  notes search --query 'example'"
echo ""
echo "💡 To activate the alias in your current terminal:"
echo "  source $SHELL_CONFIG"
echo ""
echo "   OR restart your terminal"
