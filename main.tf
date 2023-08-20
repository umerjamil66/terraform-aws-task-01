terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.16"
    }
  }

  required_version = ">= 1.2.0"
}

provider "aws" {
  region = var.aws_region
}

locals {
  availability_zones = ["${var.aws_region}a", "${var.aws_region}b"]
}

# Add the public key data source to read the content of the key2.pub file
data "local_file" "ssh_public_key" {
  filename = "./key2.pub"
}

# Use the retrieved public key content in the aws_key_pair resource
resource "aws_key_pair" "key2" {
  key_name   = "key2"
  public_key = data.local_file.ssh_public_key.content
}

#######################################
################# 01 - VPC
#######################################

resource "aws_vpc" "vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${var.environment}-vpc"
    Environment = var.environment
  }
}

# Public subnet
resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.vpc.id
  count                   = length(var.public_subnets_cidr)
  cidr_block              = element(var.public_subnets_cidr, count.index)
  availability_zone       = element(local.availability_zones, count.index)
  map_public_ip_on_launch = true

  tags = {
    Name        = "${var.environment}-${element(local.availability_zones, count.index)}-public-subnet"
    Environment = "${var.environment}"
  }
}

# Private Subnet
resource "aws_subnet" "private_subnet" {
  vpc_id                  = aws_vpc.vpc.id
  count                   = length(var.private_subnets_cidr)
  cidr_block              = element(var.private_subnets_cidr, count.index)
  availability_zone       = element(local.availability_zones, count.index)
  map_public_ip_on_launch = false

  tags = {
    Name        = "${var.environment}-${element(local.availability_zones, count.index)}-private-subnet"
    Environment = "${var.environment}"
  }
}

#Internet gateway
resource "aws_internet_gateway" "ig" {
  vpc_id = aws_vpc.vpc.id
  tags = {
    "Name"        = "${var.environment}-igw"
    "Environment" = var.environment
  }
}

# Elastic-IP (eip) for NAT
resource "aws_eip" "nat_eip" {
  vpc        = true
  depends_on = [aws_internet_gateway.ig]
}

# NAT Gateway
resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = element(aws_subnet.public_subnet.*.id, 0)
  tags = {
    Name        = "nat-gateway-${var.environment}"
    Environment = "${var.environment}"
  }
}

# Routing tables to route traffic for Private Subnet
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.vpc.id
  tags = {
    Name        = "${var.environment}-private-route-table"
    Environment = "${var.environment}"
  }
}

# Routing tables to route traffic for Public Subnet
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.vpc.id

  tags = {
    Name        = "${var.environment}-public-route-table"
    Environment = "${var.environment}"
  }
}

# Route for Internet Gateway
resource "aws_route" "public_internet_gateway" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.ig.id
}

# Route for NAT Gateway
resource "aws_route" "private_internet_gateway" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_nat_gateway.nat.id
}

# Route table associations for both Public & Private Subnets
resource "aws_route_table_association" "public" {
  count          = length(var.public_subnets_cidr)
  subnet_id      = element(aws_subnet.public_subnet.*.id, count.index)
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count          = length(var.private_subnets_cidr)
  subnet_id      = element(aws_subnet.private_subnet.*.id, count.index)
  route_table_id = aws_route_table.private.id
}


#######################################
################# 02 - Auto Scaling Group configuration
#######################################

# Create security group for instances in ASG
resource "aws_security_group" "instance_sg" {
  name_prefix = "instance-sg-"
  vpc_id      = aws_vpc.vpc.id

  # SSH from bastion - ingress
  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion-sg.id]
  }

  # PORT 80 from ALB - ingress
  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }


  # Ping from bastion host
  ingress {
    from_port       = -1 # ICMP (ping)
    to_port         = -1
    protocol        = "icmp"
    security_groups = [aws_security_group.bastion-sg.id]
  }

  # sending traffic to RDS/connecting to it - egress
  egress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.rds_primary_sg.id]
  }

  # Ping google.com - egress
  egress {
    from_port   = -1 # ICMP (ping)
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # reaching internet - port ALL - egress
  egress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}


#Launch template
resource "aws_launch_template" "my_launch_template" {
  # Name of the launch template
  name = "my_launch_template"

  # ID of the Amazon Machine Image (AMI) to use for the instance
  image_id = "ami-04e601abe3e1a910f"

  iam_instance_profile {
    name = aws_iam_instance_profile.asg_ec2_instance_profile.name
  }

  # Instance type for the EC2 instance
  instance_type = "t2.micro"

  # SSH key pair name for connecting to the instance
  key_name = aws_key_pair.key2.key_name

  ebs_optimized = false

  # Block device mappings for the instance
  block_device_mappings {
    device_name = "/dev/sda1"

    ebs {
      # Size of the EBS volume in GB
      volume_size = 20

      # Type of EBS volume (General Purpose SSD in this case)
      volume_type = "gp2"
    }
  }

  # Network interface configuration
  network_interfaces {
    associate_public_ip_address = false
    security_groups             = ["${aws_security_group.instance_sg.id}"]
  }

  user_data = filebase64("${path.module}/user-data.sh")

  tags = {
    Environment = var.environment
  }
}

resource "aws_ssm_parameter" "cw_agent" {
  description = "Cloudwatch agent config to configure custom log"
  name        = "/cloudwatch-agent/config"
  type        = "String"
  value       = file("cw_agent_config.json")

  tags = {
    Environment = var.environment
  }
}

# Define your Auto Scaling Group
resource "aws_autoscaling_group" "my_asg" {
  name = "my-asg"

  launch_template {
    id      = aws_launch_template.my_launch_template.id
    version = aws_launch_template.my_launch_template.latest_version
  }

  min_size                  = 2
  max_size                  = 2
  desired_capacity          = 2
  vpc_zone_identifier       = aws_subnet.private_subnet[*].id # Use your private subnets here
  health_check_grace_period = 300
  health_check_type         = "ELB"
  force_delete              = true

}

resource "aws_sns_topic" "notification_topic" {
  name = "my-notification-topic"
  tags = {
    Environment = var.environment
  }
}


## Alarms
# Scaling up
resource "aws_autoscaling_policy" "example-cpu-policy-scaling-up" {
  name                   = "example-cpu-policy-scaling-up"
  autoscaling_group_name = aws_autoscaling_group.my_asg.name
  adjustment_type        = "ChangeInCapacity"
  scaling_adjustment     = 1
  cooldown               = "60"
  policy_type            = "SimpleScaling"

}

resource "aws_cloudwatch_metric_alarm" "example-cpu-alarm-scaling-up" {
  alarm_name          = "example-cpu-alarm-up"
  alarm_description   = "example-cpu-alarm-up"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "30"
  statistic           = "Average"
  threshold           = "120"
  treat_missing_data  = "breaching"

  dimensions = {
    AutoScalingGroupName = "${aws_autoscaling_group.my_asg.name}"
  }
  actions_enabled = true
  alarm_actions = [
    aws_sns_topic.notification_topic.arn,
    aws_autoscaling_policy.example-cpu-policy-scaling-up.arn
  ]
  tags = {
    Environment = var.environment
  }
}


## Descaling
resource "aws_autoscaling_policy" "example-cpu-policy-scaling-down" {
  name                   = "example-cpu-policy-scaling-down"
  autoscaling_group_name = aws_autoscaling_group.my_asg.name
  adjustment_type        = "ChangeInCapacity"
  scaling_adjustment     = -1
  cooldown               = "60"
  policy_type            = "SimpleScaling"

}

resource "aws_cloudwatch_metric_alarm" "example-cpu-alarm-scaling-down" {
  alarm_name          = "example-cpu-alarm-down"
  alarm_description   = "example-cpu-alarm-down"
  comparison_operator = "LessThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "10"
  treat_missing_data  = "breaching"

  dimensions = {
    AutoScalingGroupName = "${aws_autoscaling_group.my_asg.name}"
  }
  actions_enabled = true

  alarm_actions = [
    aws_sns_topic.notification_topic.arn,
    aws_autoscaling_policy.example-cpu-policy-scaling-up.arn
  ]
  tags = {
    Environment = var.environment
  }
}

#######################################
################# 03 - Application Load Balancer configuration
#######################################

# Create security group for ALB
resource "aws_security_group" "alb_sg" {
  name_prefix = "alb-sg-"
  vpc_id      = aws_vpc.vpc.id

  # Allow incoming HTTP traffic from anywhere
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Update with allowed IPs
  }
  tags = {
    Environment = var.environment
  }
}

# ALB and Target Group
resource "aws_lb" "my_alb" {
  name               = "my-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id] # Use the ALB security group
  subnets            = aws_subnet.public_subnet[*].id # Use your public subnets here
  tags = {
    Environment = var.environment
  }
}

resource "aws_lb_target_group" "my_target_group" {
  name        = "my-target-group"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = aws_vpc.vpc.id
  target_type = "instance"

  health_check {
    enabled  = true
    path     = "/"
    port     = "80"
    protocol = "HTTP"
  }
  tags = {
    Environment = var.environment
  }
}

resource "aws_lb_listener" "my_listener" {
  load_balancer_arn = aws_lb.my_alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    target_group_arn = aws_lb_target_group.my_target_group.arn
    type             = "forward"
  }
  tags = {
    Environment = var.environment
  }
}

# Add target group to ASG
resource "aws_autoscaling_attachment" "asg_attachment" {
  autoscaling_group_name = aws_autoscaling_group.my_asg.name
  alb_target_group_arn   = aws_lb_target_group.my_target_group.arn

}

## Alarm for cloudwatch
resource "aws_cloudwatch_metric_alarm" "unhealthy_host_count" {
  alarm_name          = "alb-alarams"
  alarm_description   = "unhealthy"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  threshold           = 1
  period              = 60
  unit                = "Count"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "UnHealthyHostCount"
  statistic           = "Sum"
  alarm_actions = [
    aws_sns_topic.notification_topic.arn
  ]

  dimensions = {
    TargetGroup  = aws_lb_target_group.my_target_group.arn_suffix,
    LoadBalancer = aws_lb.my_alb.arn_suffix
  }

  tags = {
    Environment = var.environment
  }
}

#######################################
################# 04 - Bastion server configuration configuration
#######################################

resource "aws_security_group" "bastion-sg" {
  vpc_id = aws_vpc.vpc.id
  name   = "bastion-sg-name"


  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Update with allowed IPs
  }

  ingress {
    from_port   = -1 # ICMP (ping)
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = ["0.0.0.0/0"] # Update with allowed IPs
  }

  egress {
    from_port   = -1 # ICMP (ping)
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = ["0.0.0.0/0"] # Update with allowed IPs
  }

}

resource "aws_instance" "bastion-server" {
  ami           = "ami-04e601abe3e1a910f"
  instance_type = "t2.micro" # Replace with your desired instance type

  subnet_id              = aws_subnet.public_subnet[0].id
  vpc_security_group_ids = [aws_security_group.bastion-sg.id]


  associate_public_ip_address = true
  key_name                    = aws_key_pair.key2.key_name
  tags = {
    Name        = "Bastion-server" # Replace with your desired instance name
    Environment = var.environment
  }
}

#######################################
################# 05 - NGINX server configuration
#######################################

resource "aws_security_group" "nginx-sg" {
  name = "nginx-sg-name"

  vpc_id = aws_vpc.vpc.id


  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Update with allowed IPs
  }

  ingress {
    from_port   = -1 # ICMP (ping)
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = ["0.0.0.0/0"] # Update with allowed IPs
  }

  egress {
    from_port   = -1 # ICMP (ping)
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = ["0.0.0.0/0"] # Update with allowed IPs
  }

}

resource "aws_instance" "nginx-server" {
  ami           = "ami-04e601abe3e1a910f"
  instance_type = "t2.micro" # Replace with your desired instance type

  subnet_id              = aws_subnet.public_subnet[0].id
  vpc_security_group_ids = [aws_security_group.nginx-sg.id]


  user_data                   = <<-EOF
              #!/bin/bash
              exec > >(tee /var/log/user-data.log|logger -t user-data-extra -s 2>/dev/console) 2>&1

              # Update and install Nginx
              sudo apt-get update
              sudo apt-get install -y nginx

              # Configure Nginx to forward traffic to ALB
              sudo tee /etc/nginx/sites-available/default <<EOCFG
              server {
                  listen 80 default_server;
                  listen [::]:80 default_server;

                  server_name _;

                  location / {
                      proxy_pass http://${aws_lb.my_alb.dns_name};
                      proxy_set_header Host \$host;
                      proxy_set_header X-Real-IP \$remote_addr;
                      proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
                      proxy_set_header X-Forwarded-Proto \$scheme;
                  }
              }
              EOCFG
              # Reload Nginx to apply the configuration
              sudo systemctl reload nginx
              EOF
  associate_public_ip_address = true
  key_name                    = aws_key_pair.key2.key_name
  tags = {
    Name        = "NGINX-server" # Replace with your desired instance name
    Environment = var.environment
  }
}

#######################################
################# 06 - RDS configuration
#######################################

resource "aws_db_subnet_group" "rds_subnet_group" {
  name       = "rds_subnet_group"
  subnet_ids = aws_subnet.private_subnet[*].id
  tags = {
    Environment = var.environment
  }
}

resource "aws_security_group" "rds_primary_sg" {
  name        = "rds_primary_sg"
  description = "RDS Primary Instance Security Group"

  vpc_id = aws_vpc.vpc.id


  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  #  tags = local.common_tags
}

resource "aws_db_parameter_group" "custom_param_group" {
  name        = "custom-db-parameter-group"
  family      = "postgres15" # Make sure to match the engine family with the engine_version in your aws_db_instance
  description = "Custom DB parameter group with rds.force_ssl set to 0"

  parameter {
    name  = "rds.force_ssl"
    value = "0"
  }

  tags = {
    Environment = var.environment
  }
}

resource "random_password" "master_password" {
  length           = 16
  special          = false
  override_special = "_%@"
}

resource "aws_db_instance" "proddb" {
  identifier           = "proddb"
  engine               = "postgres"
  engine_version       = "15.2"
  instance_class       = "db.t3.micro"
  allocated_storage    = 50
  db_name              = "proddb"
  username             = "latter_user"
  password             = random_password.master_password.result
  db_subnet_group_name = aws_db_subnet_group.rds_subnet_group.name
  port                 = 5432

  vpc_security_group_ids = [aws_security_group.rds_primary_sg.id]

  backup_retention_period = 35
  backup_window           = "20:10-20:40"
  maintenance_window      = "Sun:09:00-Sun:09:30"

  skip_final_snapshot       = true
  final_snapshot_identifier = "db-final-snapshot-cluster2"

  parameter_group_name = aws_db_parameter_group.custom_param_group.name

  tags = {
    Environment = var.environment
  }
}


resource "aws_secretsmanager_secret" "rds_credentials_5" {
  name                    = "rds_credentials_5"
  recovery_window_in_days = 0
  tags = {
    Environment = var.environment
  }
}

resource "aws_secretsmanager_secret_version" "rds_credentials_5" {
  secret_id     = aws_secretsmanager_secret.rds_credentials_5.id
  secret_string = <<EOF
{
  "username": "${aws_db_instance.proddb.username}",
  "password": "${random_password.master_password.result}",
  "host": "${aws_db_instance.proddb.endpoint}",
  "port": ${aws_db_instance.proddb.port}
  }
EOF

}
