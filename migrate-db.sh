#!/bin/bash

# Migration script to copy local notes.db to Docker volume

echo "🔄 Migrating local notes.db to Docker volume..."

# Check if local notes.db exists
if [ ! -f "notes.db" ]; then
    echo "❌ No local notes.db file found!"
    echo "   Make sure you're in the directory with your notes.db file."
    exit 1
fi

# Show info about local database
echo "📊 Local database info:"
echo "   File: $(ls -lh notes.db | awk '{print $5 " " $9}')"
echo "   Notes count: $(sqlite3 notes.db 'SELECT COUNT(*) FROM notes;' 2>/dev/null || echo 'Unable to count')"

# Create Docker volume if it doesn't exist
echo "📦 Ensuring Docker volume exists..."
docker volume create notesapp_notes_data >/dev/null 2>&1

# Copy local database to Docker volume
echo "📋 Copying notes.db to Docker volume..."
docker run --rm \
    -v "$(pwd)/notes.db:/source/notes.db:ro" \
    -v notesapp_notes_data:/target \
    alpine sh -c "
        cp /source/notes.db /target/notes.db && 
        chown 1000:1000 /target/notes.db &&
        echo '✅ Database copied successfully!'
    "

if [ $? -eq 0 ]; then
    echo ""
    echo "🎉 Migration completed successfully!"
    echo ""
    echo "Next steps:"
    echo "1. Start the application: docker-compose up -d"
    echo "2. Set up CLI alias: ./setup-cli.sh"
    echo "3. Access your notes: http://localhost:5000"
    echo ""
    echo "Your existing notes should now be available in the Docker app!"
else
    echo "❌ Migration failed!"
    exit 1
fi
