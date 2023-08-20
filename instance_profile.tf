locals {
  role_policy_arns = [
    "arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM",
    "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
  ]
}

resource "aws_iam_role" "asg_ec2_instance_role" {
  name = "EC2-Role"
  path = "/"

  assume_role_policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Action" : "sts:AssumeRole",
          "Principal" : {
            "Service" : "ec2.amazonaws.com"
          },
          "Effect" : "Allow"
        }
      ]
    }
  )
}



resource "aws_iam_role_policy_attachment" "asg_ec2_policy_attachment" {
  count = length(local.role_policy_arns)

  role       = aws_iam_role.asg_ec2_instance_role.name
  policy_arn = element(local.role_policy_arns, count.index)
}

resource "aws_iam_role_policy" "asg_ec2_role_policy" {
  name = "EC2-Inline-Policy"
  role = aws_iam_role.asg_ec2_instance_role.id
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Action" : [
          "ssm:GetParameter"
        ],
        "Resource" : "*"
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "secretsmanager:ListSecrets",
          "secretsmanager:DescribeSecret",
          "secretsmanager:GetSecretValue"
        ],
        "Resource" : "*"
      }
    ]
  })
}



resource "aws_iam_instance_profile" "asg_ec2_instance_profile" {
  name = "ASG-EC2-Profile"
  role = aws_iam_role.asg_ec2_instance_role.name
}