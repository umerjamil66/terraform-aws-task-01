#!/bin/bash

# Ouput all log
exec > >(tee /var/log/user-data.log|logger -t user-data-extra -s 2>/dev/console) 2>&1

echo 'START initialization'

# Update and install required packages
apt update -y
apt-get update -y
apt install awscli -y
apt install -y apache2
apt-get install postgresql-client -y
# Get the private IP address of the instance
private_ip=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)

# Create a simple HTML file with IP and message
echo "<html><body><h1>Hello, world</h1><p>Instance Private IP: $private_ip</p></body></html>" | tee /var/www/html/index.html

# Open port 80 in the firewall
ufw allow 80/tcp

# Start the Apache web server
systemctl start apache2
systemctl enable apache2

echo 'START: Configure Cloudwatch agent'

apt-get update -y
apt-get install collectd -y

# Configure Cloudwatch agent
wget https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb
dpkg -i ./amazon-cloudwatch-agent.deb
apt-get install -f -y

# Use cloudwatch config from SSM
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl  -a fetch-config  -m ec2  -c ssm:/cloudwatch-agent/config -s

echo 'END: Configure Cloudwatch agent'

echo 'Done initialization'
#apt-get update -y
#apt-get install -y httpd
#systemctl start httpd.service
#systemctl enable httpd.service
#EC2_AVAIL_ZONE=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone)
#echo "<h1>Hello World From Rokkitt at at $(hostname -f) in AZ $EC2_AVAIL_ZONE </h1>" > /var/www/html/index.html



# Update the package repositories
#apt-get update -y

# Install OpenSSH and Nginx
#apt-get install -y openssh-server ec2-instance-connect stress

# Enable SSH service
#systemctl enable ssh

# Restart SSH service
#systemctl restart ssh

# Install Apache web server
#apt-get install -y apache2

# Start Apache service
#systemctl start apache2

# Get instance metadata to retrieve IP addresses
#PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)
#PRIVATE_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)

# Create an HTML page that displays instance IP addresses
#cat <<EOF > /var/www/html/index.html
#<html>
#<head>
#    <title>Instance IP Addresses</title>
#</head>
#<body>
#    <h1>Hello, World!</h1>
#    <p>Public IP: $PUBLIC_IP</p>
#    <p>Private IP: $PRIVATE_IP</p>
#</body>
#</html>
#EOF
