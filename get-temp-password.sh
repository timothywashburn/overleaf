#!/bin/bash

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <email>"
    exit 1
fi

EMAIL="$1"
NAMESPACE="overleaf"

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [ ! -f "$SCRIPT_DIR/.env" ]; then
    echo "Error: .env file not found at $SCRIPT_DIR/.env"
    echo "Please create a .env file with: TEMP_PASSWORD=YourPasswordHere"
    exit 1
fi

source "$SCRIPT_DIR/.env"

if [ -z "$TEMP_PASSWORD" ]; then
    echo "Error: TEMP_PASSWORD not set in .env file"
    exit 1
fi

echo "Fetching original password hash..."

# Get the original hashed password
ORIGINAL_HASH=$(kubectl exec -n $NAMESPACE deployment/mongodb -- mongosh --quiet --eval "
    EJSON.stringify(db.getSiblingDB('sharelatex').users.findOne({email: '$EMAIL'}, {hashedPassword: 1, _id: 0}))
" 2>/dev/null | jq -r '.hashedPassword')

if [ -z "$ORIGINAL_HASH" ] || [ "$ORIGINAL_HASH" == "null" ]; then
    echo "Error: User not found or has no password set"
    exit 1
fi

echo "Setting temporary password..."

# Run the Node.js command in background and capture output to a temp file
TEMP_OUTPUT="/tmp/overleaf-pass-$$.txt"
kubectl exec -n $NAMESPACE deployment/overleaf -- /bin/bash -c "cd /overleaf/services/web && node -e \"
const AuthenticationManager = require('./app/src/Features/Authentication/AuthenticationManager.js');
const UserGetter = require('./app/src/Features/User/UserGetter.js');

const email = '$EMAIL';
const password = '$TEMP_PASSWORD';

UserGetter.getUserByAnyEmail(email, (err, user) => {
    if (err || !user) {
        console.error('User not found');
        process.exit(1);
    }

    AuthenticationManager.setUserPassword(user, password, (err) => {
        if (err) {
            console.error('Error setting password:', err);
            process.exit(1);
        }
        console.log('OK');
        process.exit(0);
    });
});
\" 2>&1" > "$TEMP_OUTPUT" &

# Store the PID
CMD_PID=$!

# Wait for "OK" to appear in output (max 10 seconds)
for i in {1..20}; do
    if grep -q "OK" "$TEMP_OUTPUT" 2>/dev/null; then
        break
    fi
    sleep 0.5
done

# Kill the background process
kill $CMD_PID 2>/dev/null || true
wait $CMD_PID 2>/dev/null || true

# Read the result
RESULT=$(cat "$TEMP_OUTPUT" 2>/dev/null || echo "")
rm -f "$TEMP_OUTPUT"

if echo "$RESULT" | grep -q "PasswordMustBeDifferentError"; then
    echo "Error: The temporary password is the same as the user's current password"
    echo "Please use a different TEMP_PASSWORD in .env"
    exit 1
elif ! echo "$RESULT" | grep -q "OK"; then
    echo "Error: Failed to set temporary password"
    echo "$RESULT"
    exit 1
fi

echo ""
echo "========================================="
echo "  TEMPORARY ACCESS CREDENTIALS"
echo "========================================="
echo ""
echo "  Email: $EMAIL"
echo "  Password: $TEMP_PASSWORD"
echo "  Original Hash: $ORIGINAL_HASH"
echo ""
echo "⚠️  Copy these credentials and use them to log in."
echo "⚠️  The original password will be restored after you press Enter."
echo ""
read -p "Press Enter after you've finished to restore the original password..."

echo ""
echo "Restoring original password hash..."

# Restore the original hashed password directly in the database
kubectl exec -n $NAMESPACE deployment/mongodb -- mongosh --quiet --eval "
    db.getSiblingDB('sharelatex').users.updateOne(
        {email: '$EMAIL'},
        {\$set: {hashedPassword: '$ORIGINAL_HASH'}}
    )
" 2>/dev/null > /dev/null

if [ $? -eq 0 ]; then
    echo "✓ Original password restored successfully!"
else
    echo "✗ ERROR: Failed to restore original password!"
    echo "✗ Original hash was: $ORIGINAL_HASH"
    echo "✗ You may need to manually restore it in the database."
    exit 1
fi
