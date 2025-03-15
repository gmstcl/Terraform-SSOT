locals {
  az_count    = 2
  az_override = ["a", "b"] # Example: ["a", "b"]

  # Enable/disable NAT Gateways and Internet Gateway via locals.
  enable_natgw = true
  enable_igw   = true

  # Naming format strings; placeholders: 
  # $1 = project_name, $2 = AZ (lowercase), $3 = AZ (uppercase)
  vpc_cidr         = "10.0.0.0/16"
  vpc_name         = "$1-vpc"
  igw_name         = "$1-igw"
  natgw_name       = "$1-natgw-$2"
  default_rtb_name = "$1-rtb-default"

  #eks_discovery_tag = "$1-cluster"

  # Define one or more subnet groups.
  # type=public, Attach Internet Gateway Route
  # type=private, Attach NAT Gateway Route
  # type=intra, No internet connections
  subnets = [
    {
      type = "public"

      separate_rtb_per_az = true

      create_rds_subnet_group         = false
      create_elasticache_subnet_group = false
      create_redshift_subnet_group    = false

      create_vpc_endpoint = false
      create_client_vpn   = false

      create_eks_controlplane = false
      tag_eks_node            = false

      tag_tgw_attachment = false
      tag_alb_public     = false
      tag_alb_private    = false

      name     = "$1-subnet-public-$2"
      rtb_name = "$1-rtb-public-$2"
      cidr_pattern = {
        start_index     = 0
        step_per_subnet = 1
      }
    },
    {
      type = "private"

      separate_rtb_per_az = true

      create_rds_subnet_group         = false
      create_elasticache_subnet_group = false
      create_redshift_subnet_group    = false

      create_vpc_endpoint = false
      create_client_vpn   = false

      create_eks_controlplane = false
      tag_eks_node            = false

      tag_tgw_attachment = false
      tag_alb_public     = false
      tag_alb_private    = false

      name     = "$1-subnet-private-$2"
      rtb_name = "$1-rtb-private-$2"
      cidr_pattern = {
        start_index     = 10
        step_per_subnet = 1
      }
    }
  ]

  enabled_gateway_endpoints = [
    "s3",
    "dynamodb"
  ]

  enabled_interface_endpoints = [
    "autoscaling",
    "logs",
    "ec2",
    "sts",
    "ssm",
    # "sqs",
    # "sns",
    # "glue",
    "ssmmessages",
    "ec2messages",
    "ecr.api",
    "ecr.dkr",
    # "rds",
    # "ecs",
    # "ecs-agent",
    # "ecs-telemetry",
    "secretsmanager",
    # "vpc-lattice",
    # "elasticloadbalancing",
    # "elasticfilesystem"
  ]
}

###############################################################################
# Compute Availability Zones & Suffixes
###############################################################################

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  final_azs   = length(local.az_override) > 0 ? [for suffix in local.az_override : "${var.region}${suffix}"] : slice(data.aws_availability_zones.available.names, 0, local.az_count)
  az_suffixes = [for az in local.final_azs : substr(az, length(az) - 1, 1)]
}

###############################################################################
# Flatten Subnet Definitions Across AZs
###############################################################################

locals {
  all_subnets = flatten([
    for group_index, s in local.subnets : [
      for az_index, az in local.final_azs : {
        group_index = group_index
        az_index    = az_index
        group       = s
        az          = az
        az_suffix   = local.az_suffixes[az_index]
        cidr_index  = s.cidr_pattern.start_index + az_index * s.cidr_pattern.step_per_subnet
        key         = "${group_index}-${az_index}"
      }
    ]
  ])
  all_subnets_map = { for item in local.all_subnets : item.key => item }
}

###############################################################################
# Build a Mapping of Subnets
###############################################################################

locals {
  public_subnets_per_az = { for az in local.final_azs :
    az => [for item in local.all_subnets : item if item.group.type == "public" && item.az == az]
  }
  private_subnets_per_az = { for az in local.final_azs :
    az => [for item in local.all_subnets : item if item.group.type == "private" && item.az == az]
  }
  intra_subnets_per_az = { for az in local.final_azs :
    az => [for item in local.all_subnets : item if item.group.type == "intra" && item.az == az]
  }

  endpoint_subnets = [for item in local.all_subnets : item if item.group.create_vpc_endpoint == true]
  vpn_subnets      = [for item in local.all_subnets : item if item.group.create_client_vpn == true]

  eks_node_subnets         = [for item in local.all_subnets : item if item.group.tag_eks_node == true]
  eks_controlplane_subnets = [for item in local.all_subnets : item if item.group.create_eks_controlplane == true]
}

###############################################################################
# VPC & Optional Internet Gateway
###############################################################################

resource "aws_vpc" "this" {
  cidr_block = local.vpc_cidr

  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = replace(replace(replace(local.vpc_name, "$1", var.project_name), "$2", ""), "$3", "")
  }
}

resource "aws_internet_gateway" "this" {
  count  = local.enable_igw ? 1 : 0
  vpc_id = aws_vpc.this.id
  tags = {
    Name = replace(replace(replace(local.igw_name, "$1", var.project_name), "$2", ""), "$3", "")
  }
}

###############################################################################
# Create Subnets Dynamically
###############################################################################

resource "aws_subnet" "this" {
  for_each                = { for item in local.all_subnets : item.key => item }
  vpc_id                  = aws_vpc.this.id
  cidr_block              = cidrsubnet(local.vpc_cidr, 8, each.value.cidr_index)
  availability_zone       = each.value.az
  map_public_ip_on_launch = each.value.group.type == "public" ? true : false
  tags = {
    Name = replace(replace(replace(each.value.group.name, "$1", var.project_name), "$2", each.value.az_suffix), "$3", upper(each.value.az_suffix))
    Type = each.value.group.type

    Peer                              = each.value.group.tag_tgw_attachment ? "true" : "false"
    "kubernetes.io/role/elb"          = each.value.group.tag_alb_public ? "1" : "0"
    "kubernetes.io/role/internal-elb" = each.value.group.tag_alb_private ? "1" : "0"

    #"karpenter.sh/discovery" = each.value.group.tag_eks_node ? replace(replace(replace(local.eks_discovery_tag, "$1", var.project_name), "$2", ""), "$3", "") : "nothing"

    #"kubernetes.io/cluster/${replace(replace(replace(local.eks_discovery_tag, "$1", var.project_name), "$2", ""), "$3", "")}" = "owned"
  }
}

###############################################################################
# Create Route Tables Dynamically
###############################################################################

locals {
  route_tables = flatten([
    for group_index, s in local.subnets : concat(
      (lookup(s, "separate_rtb_per_az", false) || (s.type == "private" && local.enable_natgw)) ?
      [for az_index, az in local.final_azs : {
        group_index = group_index
        az_index    = az_index
        az_suffix   = local.az_suffixes[az_index]
        group       = s
        key         = "${group_index}-${az_index}"
      }]
      : [{
        group_index = group_index,
        az_index    = null, # Added to ensure consistent type
        az_suffix   = null, # Added to ensure consistent type
        group       = s,
        key         = "${group_index}"
      }],
      []
    )
  ])
  rt_mapping = { for rt in local.route_tables : rt.key => rt }
}

resource "aws_route_table" "this" {
  for_each = { for rt in local.route_tables : rt.key => rt }
  vpc_id   = aws_vpc.this.id
  tags = {
    Name = (each.value.group.separate_rtb_per_az || (each.value.group.type == "private" && local.enable_natgw)) ? replace(replace(replace(each.value.group.rtb_name, "$1", var.project_name), "$2", each.value.az_suffix), "$3", upper(each.value.az_suffix)) : replace(replace(replace(each.value.group.rtb_name, "$1", var.project_name), "$2", ""), "$3", "")
  }
}

###############################################################################
# Associate Subnets with Route Tables
###############################################################################

resource "aws_route_table_association" "this" {
  for_each       = aws_subnet.this
  subnet_id      = each.value.id
  route_table_id = (local.all_subnets_map[each.key].group.separate_rtb_per_az || (local.all_subnets_map[each.key].group.type == "private" && local.enable_natgw)) ? aws_route_table.this["${local.all_subnets_map[each.key].group_index}-${local.all_subnets_map[each.key].az_index}"].id : aws_route_table.this["${local.all_subnets_map[each.key].group_index}"].id
}

###############################################################################
# NAT Gateways (One per AZ)
###############################################################################

resource "aws_eip" "nat" {
  for_each = local.enable_natgw ? { for az in local.final_azs : az => az } : {}
}

resource "aws_nat_gateway" "this" {
  for_each      = local.enable_natgw ? { for az in local.final_azs : az => az } : {}
  allocation_id = aws_eip.nat[each.key].id
  # Choose a public subnet from the given AZ (first one found)
  subnet_id = length(local.public_subnets_per_az[each.key]) > 0 ? aws_subnet.this[local.public_subnets_per_az[each.key][0].key].id : ""
  tags = {
    Name = length(local.public_subnets_per_az[each.key]) > 0 ? replace(replace(replace(local.natgw_name, "$1", var.project_name), "$2", local.public_subnets_per_az[each.key][0].az_suffix), "$3", upper(local.public_subnets_per_az[each.key][0].az_suffix)) : ""
  }
}

###############################################################################
# Create Private Routes for NAT Gateway (using subnet type for filtering)
###############################################################################

resource "aws_route" "private_nat" {
  for_each = local.enable_natgw ? {
    for rt in local.route_tables : rt.key => rt if rt.group.type == "private"
  } : {}

  route_table_id         = aws_route_table.this[each.key].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this[local.final_azs[tonumber(each.value.az_index)]].id
}

###############################################################################
# Create Public Routes for Internet Gateway (using subnet type for filtering)
###############################################################################

resource "aws_route" "public_igw" {
  for_each = local.enable_igw ? {
    for rt in local.route_tables : rt.key => rt if rt.group.type == "public"
  } : {}

  route_table_id         = aws_route_table.this[each.key].id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this[0].id
}

###############################################################################
# Subnet Groups for Intra Subnets (if Enabled)
###############################################################################

resource "aws_db_subnet_group" "rds" {
  for_each   = { for idx, s in local.subnets : idx => s if lookup(s, "create_rds_subnet_group", false) }
  name       = "${var.project_name}-subnets-${each.key}"
  subnet_ids = [for item in local.all_subnets : aws_subnet.this[item.key].id if tostring(item.group_index) == each.key]
  tags = {
    Name = "${var.project_name}-subnets-${each.key}"
  }
}

resource "aws_elasticache_subnet_group" "elasticache" {
  for_each   = { for idx, s in local.subnets : idx => s if lookup(s, "create_elasticache_subnet_group", false) }
  name       = "${var.project_name}-subnets-${each.key}"
  subnet_ids = [for item in local.all_subnets : aws_subnet.this[item.key].id if tostring(item.group_index) == each.key]
  tags = {
    Name = "${var.project_name}-subnets-${each.key}"
  }
}

resource "aws_redshift_subnet_group" "redshift" {
  for_each   = { for idx, s in local.subnets : idx => s if lookup(s, "create_redshift_subnet_group", false) }
  name       = "${var.project_name}-subnets-${each.key}"
  subnet_ids = [for item in local.all_subnets : aws_subnet.this[item.key].id if tostring(item.group_index) == each.key]
  tags = {
    Name = "${var.project_name}-subnets-${each.key}"
  }
}

###############################################################################
# Default Route Table
###############################################################################

resource "aws_default_route_table" "default" {
  default_route_table_id = aws_vpc.this.default_route_table_id
  tags = {
    Name = replace(replace(replace(local.default_rtb_name, "$1", var.project_name), "$2", ""), "$3", "")
  }
}

###############################################################################
# Outputs
###############################################################################

output "vpc_id" {
  description = "ID of the created VPC"
  value       = aws_vpc.this.id
}

locals {
  vpc_id  = aws_vpc.this.id
  vpc_azs = local.final_azs

  vpc_subnet_ids_by_group         = [for group_index, _ in local.subnets : [for subnet in local.all_subnets : aws_subnet.this[subnet.key].id if group_index == subnet.group_index]]
  vpc_public_subnet_ids_by_group  = [for group_index, group in local.subnets : [for subnet in local.all_subnets : aws_subnet.this[subnet.key].id if group_index == subnet.group_index] if group.type == "public"]
  vpc_private_subnet_ids_by_group = [for group_index, group in local.subnets : [for subnet in local.all_subnets : aws_subnet.this[subnet.key].id if group_index == subnet.group_index] if group.type == "private"]
  vpc_intra_subnet_ids_by_group   = [for group_index, group in local.subnets : [for subnet in local.all_subnets : aws_subnet.this[subnet.key].id if group_index == subnet.group_index] if group.type == "intra"]

  vpc_rds_subnet_group_names         = [for group in aws_db_subnet_group.rds : group.name]
  vpc_redshift_subnet_group_names    = [for group in aws_redshift_subnet_group.redshift : group.name]
  vpc_elasticache_subnet_group_names = [for group in aws_elasticache_subnet_group.elasticache : group.name]
}

locals {
  bastion_sg_name       = "${var.project_name}-sg-apps"
  bastion_key_name      = "${var.project_name}-keypair"
  bastion_role_name     = "${var.project_name}-role-apps"
  bastion_instance_name = "${var.project_name}-apps"
  bastion_ip_name       = "${var.project_name}-apps"

  bastion_subnet_id = local.vpc_public_subnet_ids_by_group[0][0]

  keypair_file_path = "${path.cwd}/temp/kp.pem"
  ssh_port          = 22

  ingress_port_from_my_ip = true
  ingress_ports = [
    { port = local.ssh_port, protocol = "tcp" },
    { port = 80, protocol = "tcp" }
  ]

  egress_ports = [
    { port = 80, protocol = "tcp" },
    { port = 443, protocol = "tcp" }
  ]

  iam_policies = [
    "arn:aws:iam::aws:policy/AdministratorAccess"
  ]

  bastion_instance_type = "t3.small"

  ami_architecture = "x86_64" # Possible values: "arm64", "x86_64"
  ami_os           = "al2023" # Possible values: "al2023", "al2"
}

locals {
  ami_ssm_pattern = {
    al2023 = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-${local.ami_architecture}",
    al2    = "/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-${local.ami_architecture}-gp2"
  }
}

data "aws_ssm_parameter" "bastion_ami" {
  name = local.ami_ssm_pattern[local.ami_os]
}

resource "aws_security_group" "bastion" {
  name   = local.bastion_sg_name
  vpc_id = aws_vpc.this.id

  dynamic "ingress" {
    for_each = local.ingress_ports
    content {
      protocol    = ingress.value.protocol
      from_port   = ingress.value.port
      to_port     = ingress.value.port
      #cidr_blocks = local.ingress_port_from_my_ip ? ["${chomp(data.http.myip.response_body)}/32"] : ["0.0.0.0/0"]
      cidr_blocks = 80 ? ["0.0.0.0/0"] : (local.ingress_port_from_my_ip ? ["${chomp(data.http.myip.response_body)}/32"] : ["0.0.0.0/0"])
    }
  }

  dynamic "egress" {
    for_each = local.egress_ports
    content {
      protocol    = egress.value.protocol
      from_port   = egress.value.port
      to_port     = egress.value.port
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  lifecycle {
    ignore_changes = [
      ingress,
      egress
    ]
  }
}

resource "tls_private_key" "rsa" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "keypair" {
  key_name   = local.bastion_key_name
  public_key = tls_private_key.rsa.public_key_openssh
}

resource "local_file" "keypair" {
  content  = tls_private_key.rsa.private_key_pem
  filename = local.keypair_file_path
}

resource "aws_iam_role" "bastion" {
  name = local.bastion_role_name
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "bastion_policies" {
  for_each   = toset(local.iam_policies)
  role       = aws_iam_role.bastion.name
  policy_arn = each.value
}

resource "aws_iam_instance_profile" "bastion" {
  name = local.bastion_role_name
  role = aws_iam_role.bastion.name
}

resource "aws_instance" "bastion" {
  subnet_id            = local.bastion_subnet_id
  security_groups      = [aws_security_group.bastion.id]
  ami                  = data.aws_ssm_parameter.bastion_ami.value
  iam_instance_profile = aws_iam_instance_profile.bastion.name
  key_name             = aws_key_pair.keypair.key_name
  instance_type        = local.bastion_instance_type
  tags                 = { Name = local.bastion_instance_name }

  root_block_device {
    volume_type = "gp3"
    volume_size = 8
    encrypted   = true
  }

  user_data = <<-EOT
    #!/bin/bash
    echo "Port ${local.ssh_port}" >> /etc/ssh/sshd_config
    systemctl restart sshd
    dnf install httpd -y 
    echo "Cloud CTF Project" > /var/www/html/index.html
  EOT

  lifecycle {
    ignore_changes = [security_groups]
  }
}

resource "aws_eip" "bastion" {
  instance = aws_instance.bastion.id
  tags = {
    Name = local.bastion_ip_name
  }
}

output "bastion_details" {
  value = {
    ip_address        = aws_eip.bastion.public_ip
    instance_id       = aws_instance.bastion.id
    availability_zone = aws_instance.bastion.availability_zone
    ssh_port          = local.ssh_port
    ssh_keypair       = local.keypair_file_path
  }
}

resource "aws_ebs_encryption_by_default" "default" {
  enabled = true
}
