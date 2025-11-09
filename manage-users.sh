#!/bin/bash

set -e

NAMESPACE="overleaf"
MONGODB_POD="pod/mongodb-0"
OVERLEAF_DEPLOYMENT="deployment/overleaf"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_color() {
    local color=$1
    shift
    echo -e "${color}$@${NC}"
}

# Function to print header
print_header() {
    echo ""
    print_color "$BLUE" "========================================="
    print_color "$BLUE" "$1"
    print_color "$BLUE" "========================================="
    echo ""
}

# Function to list all users
list_users() {
    print_header "All Users"

    echo "Fetching users..."

    # Fetch data from MongoDB using EJSON format for proper JSON output
    local users_json=$(kubectl exec -n $NAMESPACE $MONGODB_POD -- mongosh --quiet --eval "
        EJSON.stringify(db.getSiblingDB('sharelatex').users.find({}, {
            email: 1,
            isAdmin: 1,
            lastActive: 1,
            'emails.confirmedAt': 1,
            _id: 0
        }).toArray())
    " 2>/dev/null)

    # Check if jq is available
    if command -v jq &> /dev/null; then
        # Parse and format with jq
        printf "%-40s %-10s %-15s %s\n" "EMAIL" "ROLE" "STATUS" "LAST ACTIVE"
        printf "%-40s %-10s %-15s %s\n" "----------------------------------------" "----------" "---------------" "-------------------------"
        echo "$users_json" | jq -r '.[] | "\(.email)|\(if .isAdmin then "ADMIN" else "USER" end)|\(if .emails[0].confirmedAt then "✓ Verified" else "✗ Unverified" end)|\(if .lastActive then (.lastActive."$date" | sub("\\.[0-9]+Z$"; "Z") | fromdate | strftime("%Y-%m-%d %H:%M")) else "Never" end)"' 2>/dev/null | while IFS='|' read -r email role status lastActive; do
            printf "%-40s %-10s %-15s %s\n" "$email" "$role" "$status" "$lastActive"
        done
    else
        # Fallback without jq - simple line-by-line output
        echo "$users_json" | grep -o '"email":"[^"]*"' | sed 's/"email":"\([^"]*\)"/\1/'
    fi
}

# Function to view user details
view_user() {
    local email=$1

    if [ -z "$email" ]; then
        read -p "Enter user email: " email
    fi

    print_header "User Details: $email"

    local user_data=$(kubectl exec -n $NAMESPACE $MONGODB_POD -- mongosh --quiet --eval "
        EJSON.stringify(db.getSiblingDB('sharelatex').users.findOne({email: '$email'}))
    " 2>/dev/null)

    if command -v jq &> /dev/null; then
        echo "$user_data" | jq '.'
    else
        echo "$user_data"
    fi
}

# Function to create a new user
create_user() {
    local email=$1
    local is_admin=$2

    if [ -z "$email" ]; then
        read -p "Enter email address: " email
    fi

    if [ -z "$is_admin" ]; then
        read -p "Make this user an admin? (y/n): " make_admin
        if [[ $make_admin == "y" || $make_admin == "Y" ]]; then
            is_admin="--admin"
        else
            is_admin=""
        fi
    fi

    print_header "Creating User: $email"

    kubectl exec -n $NAMESPACE $OVERLEAF_DEPLOYMENT -- /bin/bash -c "cd /overleaf/services/web && node modules/server-ce-scripts/scripts/create-user.mjs $is_admin --email=$email" 2>&1

    if [ $? -eq 0 ]; then
        print_color "$GREEN" "✓ User created successfully!"
    else
        print_color "$RED" "✗ Failed to create user"
    fi
}

# Function to delete a user
delete_user() {
    local email=$1

    if [ -z "$email" ]; then
        echo ""
        list_users
        echo ""
        read -p "Enter email of user to delete: " email
    fi

    if [ -z "$email" ]; then
        print_color "$RED" "No email provided. Aborting."
        return 1
    fi

    # Check if user exists
    local user_exists=$(kubectl exec -n $NAMESPACE $MONGODB_POD -- mongosh --quiet --eval "db.getSiblingDB('sharelatex').users.countDocuments({email: '$email'})" 2>/dev/null)

    if [ "$user_exists" == "0" ]; then
        print_color "$RED" "✗ User $email not found"
        return 1
    fi

    print_header "Delete User: $email"
    print_color "$RED" "⚠️  WARNING: This will delete the user AND all their projects!"
    echo ""
    read -p "Are you sure you want to delete $email? (type 'yes' to confirm): " confirm

    if [ "$confirm" != "yes" ]; then
        print_color "$YELLOW" "Deletion cancelled."
        return 0
    fi

    read -p "Skip sending notification email? (y/n): " skip_email
    if [[ $skip_email == "y" || $skip_email == "Y" ]]; then
        skip_flag="--skip-email"
    else
        skip_flag=""
    fi

    echo ""
    print_color "$YELLOW" "Deleting user..."

    kubectl exec -n $NAMESPACE $OVERLEAF_DEPLOYMENT -- /bin/bash -c "cd /overleaf/services/web && node modules/server-ce-scripts/scripts/delete-user.mjs $skip_flag --email=$email" 2>&1

    if [ $? -eq 0 ]; then
        print_color "$GREEN" "✓ User deleted successfully!"
    else
        print_color "$RED" "✗ Failed to delete user"
    fi
}

# Function to toggle admin status
toggle_admin() {
    local email=$1

    if [ -z "$email" ]; then
        echo ""
        list_users
        echo ""
        read -p "Enter email of user: " email
    fi

    if [ -z "$email" ]; then
        print_color "$RED" "No email provided. Aborting."
        return 1
    fi

    # Get current admin status using EJSON
    local current_status=$(kubectl exec -n $NAMESPACE $MONGODB_POD -- mongosh --quiet --eval "EJSON.stringify(db.getSiblingDB('sharelatex').users.findOne({email: '$email'}, {isAdmin: 1, _id: 0}))" 2>/dev/null | jq -r '.isAdmin // false')

    if [ "$current_status" == "null" ]; then
        print_color "$RED" "✗ User $email not found"
        return 1
    fi

    print_header "Toggle Admin Status: $email"

    if [ "$current_status" == "true" ]; then
        echo "Current status: ADMIN"
        read -p "Remove admin privileges? (y/n): " confirm
        if [[ $confirm == "y" || $confirm == "Y" ]]; then
            kubectl exec -n $NAMESPACE $MONGODB_POD -- mongosh --quiet --eval "db.getSiblingDB('sharelatex').users.updateOne({email: '$email'}, {\$set: {isAdmin: false}})" 2>/dev/null > /dev/null
            print_color "$GREEN" "✓ Admin privileges removed"
        else
            print_color "$YELLOW" "Cancelled"
        fi
    else
        echo "Current status: USER"
        read -p "Grant admin privileges? (y/n): " confirm
        if [[ $confirm == "y" || $confirm == "Y" ]]; then
            kubectl exec -n $NAMESPACE $MONGODB_POD -- mongosh --quiet --eval "db.getSiblingDB('sharelatex').users.updateOne({email: '$email'}, {\$set: {isAdmin: true}})" 2>/dev/null > /dev/null
            print_color "$GREEN" "✓ Admin privileges granted"
        else
            print_color "$YELLOW" "Cancelled"
        fi
    fi
}

# Function to verify user email
verify_email() {
    local email=$1

    if [ -z "$email" ]; then
        echo ""
        list_users
        echo ""
        read -p "Enter email of user to verify: " email
    fi

    if [ -z "$email" ]; then
        print_color "$RED" "No email provided. Aborting."
        return 1
    fi

    print_header "Verify Email: $email"

    kubectl exec -n $NAMESPACE $MONGODB_POD -- mongosh --quiet --eval "db.getSiblingDB('sharelatex').users.updateOne({email: '$email'}, {\$set: {'emails.0.confirmedAt': new Date()}})" 2>/dev/null > /dev/null

    if [ $? -eq 0 ]; then
        print_color "$GREEN" "✓ Email verified successfully!"
    else
        print_color "$RED" "✗ Failed to verify email"
    fi
}

# Function to get temporary access password
get_temp_password() {
    local email=$1

    if [ -z "$email" ]; then
        echo ""
        list_users
        echo ""
        read -p "Enter email of user to access: " email
    fi

    if [ -z "$email" ]; then
        print_color "$RED" "No email provided. Aborting."
        return 1
    fi

    # Get the directory where this script is located
    local SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

    # Call the standalone script
    "$SCRIPT_DIR/get-temp-password.sh" "$email"
}

# Function to change user password
change_password() {
    local email=$1
    local password=$2

    if [ -z "$email" ]; then
        echo ""
        list_users
        echo ""
        read -p "Enter email of user: " email
    fi

    if [ -z "$email" ]; then
        print_color "$RED" "No email provided. Aborting."
        return 1
    fi

    if [ -z "$password" ]; then
        read -p "Enter new password: " password
    fi

    print_header "Change Password: $email"

    # Run the Node.js command in background and capture output to a temp file
    local TEMP_OUTPUT="/tmp/overleaf-changepass-$$.txt"
    kubectl exec -n $NAMESPACE $OVERLEAF_DEPLOYMENT -- /bin/bash -c "cd /overleaf/services/web && node -e \"
const AuthenticationManager = require('./app/src/Features/Authentication/AuthenticationManager.js');
const UserGetter = require('./app/src/Features/User/UserGetter.js');

const email = '$email';
const password = '$password';

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
    local CMD_PID=$!

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
    local RESULT=$(cat "$TEMP_OUTPUT" 2>/dev/null || echo "")
    rm -f "$TEMP_OUTPUT"

    if echo "$RESULT" | grep -q "PasswordMustBeDifferentError"; then
        print_color "$RED" "✗ New password must be different from current password"
    elif echo "$RESULT" | grep -q "OK"; then
        print_color "$GREEN" "✓ Password changed successfully!"
    else
        print_color "$RED" "✗ Failed to change password"
        echo "$RESULT"
    fi
}

# Function to show statistics
show_stats() {
    print_header "User Statistics"

    local total=$(kubectl exec -n $NAMESPACE $MONGODB_POD -- mongosh --quiet --eval "db.getSiblingDB('sharelatex').users.countDocuments()" 2>/dev/null)
    local admins=$(kubectl exec -n $NAMESPACE $MONGODB_POD -- mongosh --quiet --eval "db.getSiblingDB('sharelatex').users.countDocuments({isAdmin: true})" 2>/dev/null)
    local verified=$(kubectl exec -n $NAMESPACE $MONGODB_POD -- mongosh --quiet --eval "db.getSiblingDB('sharelatex').users.countDocuments({'emails.confirmedAt': {\$exists: true}})" 2>/dev/null)

    echo "Total users:      $total"
    echo "Administrators:   $admins"
    echo "Verified emails:  $verified"
    echo "Unverified:       $((total - verified))"
}

# Main menu
show_menu() {
    print_header "Overleaf User Management"

    echo "1) List all users"
    echo "2) View user details"
    echo "3) Create new user"
    echo "4) Delete user"
    echo "5) Toggle admin status"
    echo "6) Verify user email"
    echo "7) Change user password"
    echo "8) Get temporary access password"
    echo "9) Show statistics"
    echo "10) Exit"
    echo ""
}

# Main loop
main() {
    # Check if kubectl is available
    if ! command -v kubectl &> /dev/null; then
        print_color "$RED" "Error: kubectl is not installed or not in PATH"
        exit 1
    fi

    # Check if jq is available
    if ! command -v jq &> /dev/null; then
        print_color "$YELLOW" "Warning: jq is not installed. Some features may not work properly."
    fi

    while true; do
        show_menu
        read -p "Select an option (1-10): " choice

        case $choice in
            1)
                list_users
                ;;
            2)
                view_user
                ;;
            3)
                create_user
                ;;
            4)
                delete_user
                ;;
            5)
                toggle_admin
                ;;
            6)
                verify_email
                ;;
            7)
                change_password
                ;;
            8)
                get_temp_password
                ;;
            9)
                show_stats
                ;;
            10)
                print_color "$GREEN" "Goodbye!"
                exit 0
                ;;
            *)
                print_color "$RED" "Invalid option. Please try again."
                ;;
        esac

        echo ""
        read -p "Press Enter to continue..."
    done
}

if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi
