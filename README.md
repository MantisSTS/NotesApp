# Notes App

A secure, feature-rich notes application with both CLI and web interfaces, featuring encryption, tagging, file attachments, and Docker deployment.

![Notes App](https://img.shields.io/badge/Python-3.11+-blue.svg)
![Docker](https://img.shields.io/badge/Docker-Ready-brightgreen.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## ✨ Features

- 🔐 **Encrypted Notes** - Secure note content with password-based encryption using PBKDF2 + AES
- 🏷️ **Tagging System** - Organize notes with tags and powerful tag-based filtering
- 📎 **File Attachments** - Attach files to notes (automatically encrypted for encrypted notes)
- 🌐 **Modern Web Interface** - Responsive UI built with Tailwind CSS
- 💻 **Powerful CLI** - Full-featured command-line interface with secure password prompting
- 🐳 **Docker Ready** - Easy deployment with Docker and Docker Compose
- 💾 **Persistent Storage** - SQLite database with Docker volume persistence
- 🔍 **Advanced Search** - Search by content, tags, type, or description
- 📤 **Export Functionality** - Export search results to Markdown

## 🚀 Quick Start

### Using Docker (Recommended)

1. **Clone and build:**
   ```bash
   git clone https://github.com/MantisSTS/NotesApp.git
   cd NotesApp
   ./build.sh
   ```

2. **Start the application:**
   ```bash
   docker-compose up -d
   ```

3. **Set up CLI alias:**
   ```bash
   ./setup-cli.sh
   source ~/.bashrc  # or ~/.zshrc
   ```

4. **Access the app:**
   - 🌐 **Web UI**: http://localhost:5000
   - 💻 **CLI**: `notes get`

### Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python notes.py server --debug

# Or use CLI directly
python notes.py add --type example --body "Hello World"
python notes.py get
```

## 💻 CLI Usage

### Basic Commands

```bash
# Add a simple note
notes add --type docker --body 'docker-compose up -d' --description 'Start services'

# Add an encrypted note (secure password prompting)
notes add --type secret --body 'confidential data' --prompt-encrypt

# Add note with tags
notes add --type web --body 'npm start' --tags 'nodejs,development,frontend'
```

### Retrieving Notes

```bash
# Get all notes of a specific type
notes get docker

# Filter by tags
notes get --tags web,security
notes get docker --tags production  # Intersection: docker notes with production tag

# Search across content
notes get --search 'database'

# Get specific note by ID (with decryption prompt if encrypted)
notes get --id 5 --prompt-decrypt

# Show additional fields
notes get docker --show-description --show-output
```

### Managing Notes

```bash
# Update a note
notes update --id 3 --body 'new content' --description 'updated description'

# Decrypt a note (remove encryption)
notes update --id 3 --body 'new content' --decrypt

# Delete a note
notes delete --id 3
```

### Advanced Features

```bash
# JSON output for scripting
notes get docker --json

# Only show commands (useful for scripts)
notes get docker --only-commands

# Export search results
notes get --search 'web' --json > web_notes.json
```

## 🌐 Web Interface Features

### Note Management
- 📝 **Add/Edit/Delete** notes with rich form interface
- 🔐 **Encryption Toggle** with secure password modal
- 📎 **File Upload** with automatic encryption for encrypted notes
- 🏷️ **Tag Management** with autocomplete and suggestion

### Search & Discovery
- 🔍 **Real-time Search** across all note content
- 🏷️ **Tag Filtering** with visual tag display
- 📊 **Statistics** showing note counts by type
- 📤 **Markdown Export** of search results

### Security Features
- 🔒 **Secure Password Input** with hidden modal dialogs
- 🔐 **In-browser Decryption** without exposing passwords
- 📁 **Encrypted Attachments** with password-protected downloads
- 🛡️ **XSS Protection** with proper input sanitization

## 🔒 Security

### Encryption Details
- **Algorithm**: AES-256 via Fernet (cryptography library)
- **Key Derivation**: PBKDF2 with SHA-256, 100,000 iterations
- **Salt**: Unique random salt per note (128-bit)
- **No Password Storage**: Passwords never stored, only used for encryption/decryption

### Security Best Practices
- 🚫 **No Plaintext Passwords** - Secure password prompting prevents bash history exposure
- 📁 **Encrypted Attachments** - File attachments use same encryption as parent note
- 🛡️ **Non-root Docker User** - Container runs with unprivileged user
- 🔐 **Secure Defaults** - Encryption enabled by default for sensitive content

## 🐳 Docker Deployment

### Production Deployment

```bash
# Start with persistent data
docker-compose up -d

# View logs
docker-compose logs -f notesapp

# Stop services
docker-compose down
```

### Development with Live Reload

```bash
# Development mode with code mounting
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up
```

### Data Management

```bash
# Backup database
docker run --rm -v notesapp_notes_data:/data -v $(pwd):/backup alpine tar czf /backup/notes-backup.tar.gz -C /data .

# Restore database
docker run --rm -v notesapp_notes_data:/data -v $(pwd):/backup alpine sh -c "cd /data && tar xzf /backup/notes-backup.tar.gz"

# View volume information
docker volume inspect notesapp_notes_data
```

## 🏗️ Architecture

### Backend
- **Framework**: Python Flask with Jinja2 templating
- **Database**: SQLite with encryption support
- **Encryption**: cryptography library (Fernet + PBKDF2)
- **CLI**: argparse with secure password prompting

### Frontend
- **Styling**: Tailwind CSS for responsive design
- **JavaScript**: Vanilla JS with fetch API for AJAX
- **Icons**: Font Awesome for visual elements
- **Security**: CSP headers and XSS protection

### Infrastructure
- **Container**: Alpine Linux for minimal footprint
- **Storage**: Docker volumes for data persistence
- **Networking**: Single port exposure (5000)
- **Health Checks**: Built-in container health monitoring

## 📁 Project Structure

```
NotesApp/
├── notes.py              # Main application (CLI + Web server)
├── requirements.txt      # Python dependencies
├── Dockerfile           # Alpine-based container
├── docker-compose.yml   # Production deployment
├── docker-compose.dev.yml # Development overrides
├── build.sh            # Docker build script
├── setup-cli.sh        # CLI alias setup
├── notes-cli           # Standalone CLI wrapper
├── templates/          # HTML templates
│   ├── base.html       # Base template with Tailwind CSS
│   ├── index.html      # Main notes dashboard
│   ├── add_note.html   # Add note form
│   ├── edit_note.html  # Edit note form
│   ├── search.html     # Search interface
│   └── attachment_password.html # Encrypted attachment access
└── README.md           # This file
```

## 🔧 Development

### Prerequisites
- Python 3.11+
- Docker and Docker Compose (for containerized deployment)
- Modern web browser

### Local Setup
```bash
# Clone repository
git clone https://github.com/MantisSTS/NotesApp.git
cd NotesApp

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run development server
python notes.py server --debug --host 0.0.0.0 --port 5000
```

### Testing
```bash
# Test CLI functionality
python notes.py add --type test --body "Test note"
python notes.py get test
python notes.py delete --id 1

# Test encryption
python notes.py add --type secret --body "Secret content" --prompt-encrypt
python notes.py get --id 2 --prompt-decrypt
```

## 📋 Requirements

### System Requirements
- **Memory**: 512MB RAM minimum
- **Storage**: 100MB for application + your notes data
- **Network**: Port 5000 (configurable)

### Dependencies
- `flask` - Web framework
- `cryptography` - Encryption library
- `requests` - HTTP client library

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- 📚 **Documentation**: This README covers most use cases
- 🐛 **Issues**: Report bugs via GitHub Issues
- 💡 **Feature Requests**: Suggest improvements via GitHub Issues
- 🔧 **Development**: See the Development section above

## 🙏 Acknowledgments

- Built with [Flask](https://flask.palletsprojects.com/) and [cryptography](https://cryptography.io/)
- UI powered by [Tailwind CSS](https://tailwindcss.com/)
- Icons from [Font Awesome](https://fontawesome.com/)

---

⭐ **Star this repository if you find it useful!**
