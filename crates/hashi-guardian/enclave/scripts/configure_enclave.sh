# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
#!/bin/bash
# configure_enclave.sh

# Additional information on this script. 
show_help() {
    echo "configure_enclave.sh - Launch AWS EC2 instance with Nitro Enclaves and configure allowed endpoints. "
    echo ""
    echo "This script launches an AWS EC2 instance (m5.xlarge) with Nitro Enclaves enabled."
    echo "By default, it uses the AMI ami-085ad6ae776d8f09c, which works in us-east-1."
    echo "If you change the REGION, you must also supply a valid AMI for that region."
    echo ""
    echo "Pre-requisites:"
    echo "  - AWS CLI is installed and configured with proper credentials"
    echo "  - The environment variable KEY_PAIR is set (e.g., export KEY_PAIR=my-key)"
    echo "  - The instance type 'm5.xlarge' must be supported in your account/region for Nitro Enclaves"
    echo ""
    echo "Usage:"
    echo "  export KEY_PAIR=<your-key-pair-name>"
    echo "  # optional: export REGION=<your-region>  (defaults to us-east-1)"
    echo "  # optional: export AMI_ID=<your-ami-id>  (defaults to ami-085ad6ae776d8f09c)"
    echo "  ./configure_enclave.sh"
    echo ""
    echo "Options:"
    echo "  -h, --help    Show this help message"
}

# Check for help flag
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    show_help
    exit 0
fi

############################
# Configurable Defaults
############################
# Sets the region by default to us-east-1
REGION="${REGION:-us-east-1}"
export AWS_DEFAULT_REGION="$REGION"

# The default AMI for us-east-1. Change this if your region is different.
AMI_ID="${AMI_ID:-ami-085ad6ae776d8f09c}"

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Define file paths relative to script directory
USER_DATA_FILE="${SCRIPT_DIR}/user-data.sh"

if [ ! -f "$USER_DATA_FILE" ]; then
    echo "Error: Required file not found: $USER_DATA_FILE"
    exit 1
fi

if [ -z "$KEY_PAIR" ]; then
    echo "Error: Environment variable KEY_PAIR is not set. Please export KEY_PAIR=<your-key-name>."
    exit 1
fi

############################
# Set the EC2 Instance Name
############################
if [ -z "$EC2_INSTANCE_NAME" ]; then
    read -p "Enter EC2 instance base name: " EC2_INSTANCE_NAME
fi

if command -v shuf >/dev/null 2>&1; then
    RANDOM_SUFFIX=$(shuf -i 100000-999999 -n 1)
else
    RANDOM_SUFFIX=$(printf "%06d" $(( RANDOM % 900000 + 100000 )))
fi

FINAL_INSTANCE_NAME="${EC2_INSTANCE_NAME}-${RANDOM_SUFFIX}"
echo "Instance will be named: $FINAL_INSTANCE_NAME"

############################
# Create or Use Security Group
############################
SECURITY_GROUP_NAME="instance-script-sg"

SECURITY_GROUP_ID=$(aws ec2 describe-security-groups \
  --region "$REGION" \
  --group-names "$SECURITY_GROUP_NAME" \
  --query "SecurityGroups[0].GroupId" \
  --output text 2>/dev/null)

if [ "$SECURITY_GROUP_ID" = "None" ] || [ -z "$SECURITY_GROUP_ID" ]; then
  echo "Creating security group $SECURITY_GROUP_NAME..."
  SECURITY_GROUP_ID=$(aws ec2 create-security-group \
    --region "$REGION" \
    --group-name "$SECURITY_GROUP_NAME" \
    --description "Security group allowing SSH (22), HTTPS (443), and port 3000" \
    --query "GroupId" --output text)

  # Ensure that the security group is created successfully
  if [ $? -ne 0 ]; then
    echo "Error creating security group."
    exit 1
  fi

  aws ec2 authorize-security-group-ingress --region "$REGION" \
    --group-id "$SECURITY_GROUP_ID" --protocol tcp --port 22 --cidr 0.0.0.0/0

  aws ec2 authorize-security-group-ingress --region "$REGION" \
    --group-id "$SECURITY_GROUP_ID" --protocol tcp --port 443 --cidr 0.0.0.0/0

  aws ec2 authorize-security-group-ingress --region "$REGION" \
    --group-id "$SECURITY_GROUP_ID" --protocol tcp --port 3000 --cidr 0.0.0.0/0
else
  echo "Using existing security group $SECURITY_GROUP_NAME ($SECURITY_GROUP_ID)"
fi

############################
# Launch EC2
############################
echo "Launching EC2 instance with Nitro Enclaves enabled..."

INSTANCE_ID=$(aws ec2 run-instances \
  --region "$REGION" \
  --image-id "$AMI_ID" \
  --instance-type m5.xlarge \
  --key-name "$KEY_PAIR" \
  --user-data file://$USER_DATA_FILE \
  --block-device-mappings '[{"DeviceName":"/dev/xvda","Ebs":{"VolumeSize":200}}]' \
  --enclave-options Enabled=true \
  --security-group-ids "$SECURITY_GROUP_ID" \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${FINAL_INSTANCE_NAME}},{Key=instance-script,Value=true}]" \
  --query "Instances[0].InstanceId" --output text)

echo "Instance launched with ID: $INSTANCE_ID"

echo "Waiting for instance $INSTANCE_ID to run..."
aws ec2 wait instance-running --instance-ids "$INSTANCE_ID" --region "$REGION"

sleep 10

PUBLIC_IP=$(aws ec2 describe-instances \
  --instance-ids "$INSTANCE_ID" \
  --region "$REGION" \
  --query "Reservations[].Instances[].PublicIpAddress" \
  --output text)

echo "[*] Please wait 2-3 minutes for the instance to finish the init script before sshing into it."
echo "[*] ssh inside the launched EC2 instance. e.g. \`ssh ec2-user@\"$PUBLIC_IP\"\` assuming the ssh-key is loaded into the agent."
echo "[*] Clone or copy the repo."
echo "[*] Inside repo directory: 'make' and then 'make run'"
echo "[*] Run expose_enclave.sh from within the EC2 instance to expose the enclave to the internet."
