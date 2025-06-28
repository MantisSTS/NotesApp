#!/bin/bash

# Notes App Setup Script
# This script sets up the notes app for command-line usage

echo "Setting up Notes App..."

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install -r requirements.txt --break-system-packages # --break-system-packages for Kali - remove if not needed

# Make the notes.py script executable
chmod +x notes.py

# Create a symbolic link or alias for easy access
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NOTES_SCRIPT="$SCRIPT_DIR/notes.py"

# Check if /usr/local/bin is writable, otherwise suggest adding to PATH
if [ -w "/usr/local/bin" ]; then
    echo "Creating symlink in /usr/local/bin..."
    sudo ln -sf "$NOTES_SCRIPT" /usr/local/bin/notes
    echo "You can now use 'notes' command from anywhere!"
else
    echo "Add this to your ~/.bashrc or ~/.zshrc to use 'notes' command:"
    echo "    alias notes='python3 $NOTES_SCRIPT'"
    echo ""
    echo "Or add this directory to your PATH:"
    echo "    export PATH=\"$SCRIPT_DIR:\$PATH\""
fi

echo ""
echo "Setup complete!"
echo ""
echo "Usage examples:"
echo "  notes add --type=git --cmd='git log --oneline'"
echo "  notes get --type=git"
echo "  notes get                    # Show all notes"
echo "  notes delete --id=5"
echo "  notes server --host=0.0.0.0 --port=8080"
echo ""
echo "Run 'notes --help' for more information"
