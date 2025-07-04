#!/bin/bash

# Configuration variables
LOCAL_DIR="."  # Path to your local app directory
REMOTE_USER="quadra"            # Your SSH username
REMOTE_HOST="inovatoraw"     # Your server hostname or IP
REMOTE_DIR="/home/quadra/eli-domain-monitor" # Destination path on remote server

# Parse command line arguments
DRY_RUN="--dry-run"
if [[ "$1" == "--real" ]]; then
    DRY_RUN=""
    echo "Running REAL deployment (no dry-run)"
else
    echo "Running DRY-RUN deployment (use --real to actually deploy)"
fi

# Create commit.txt file with current commit hash
git rev-parse HEAD > commit.txt
echo `date` >> commit.txt
echo "Created commit.txt with commit hash: $(cat commit.txt)"

# Deploy using rsync
# --delete: Remove files on destination that don't exist in source
# --exclude: Skip .git directory and any other files you don't want to transfer
# -avz: Archive mode, verbose output, compress during transfer
# -e ssh: Use SSH for remote connection

rsync -avz $DRY_RUN --delete \
      --include='commit.txt' \
      --exclude='.git' \
      --exclude='.gitignore' \
      --exclude='output/*' \
      --exclude='data/*' \
      --exclude='.env' \
      --exclude='.claude' \
      --exclude='config.yaml' \
      --exclude='src/__pycache__' \
      --exclude='logs/*' \
      --exclude='*.db' \
      --exclude='*.png' \
      --include='domains.txt' \
      --filter=':- .gitignore' \
      -e "ssh -o RemoteCommand=none" \
      $LOCAL_DIR/ $REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR/

# Set executable permissions for all shell scripts on the remote server
if [[ -z "$DRY_RUN" ]]; then
    ssh -o RemoteCommand=none $REMOTE_USER@$REMOTE_HOST "chmod +x $REMOTE_DIR/*.sh"
    echo "Deployment completed successfully!"
else
    echo "DRY-RUN: Would set executable permissions for shell scripts on remote server"
    echo "DRY-RUN completed successfully! Use --real to actually deploy."
fi
