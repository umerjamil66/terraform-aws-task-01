## Terraform scripts - Solution - AWS DevOps Engineer Assessment Test 

This repository contains a Terraform scripts to provision in as given in an assessment. Link: https://docs.google.com/document/d/1hHZXW_xji2ZdZN16tGxhTRCrzKKg2-UWej3TlBoZL_M/edit?usp=sharing  
  

### Configuration

Clone the repository:

    git clone <repository_url>  
    cd <repository_directory>

(Before initializing Terraform, please make sure you have installed aws cli and configure access keys)

Initialize the Terraform workspace:

    terraform init

Review the changes that Terraform will apply:

  

    terraform plan

If the plan looks good, apply the changes:

  

    terraform apply

Terraform will provision the necessary AWS resources based on the configuration in the script.

Output will show the nginx ip and ALB DNS.   

## More info:

 - Once the provisioning is complete, you can access the dummy
   application base by nginx ip or ALB url.
- The given ssh key2.pub can be used to SSH into bastion ec2 and ASG
   ec2 instances.