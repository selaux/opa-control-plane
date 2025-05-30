# Create a VPC
resource "aws_vpc" "app_vpc" {
  cidr_block = var.vpc_cidr

  tags = {
    Name = "app-vpc"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.app_vpc.id

  tags = {
    Name = "vpc_igw"
  }
}

resource "aws_route_table" "vpc_rt" {
  vpc_id = aws_vpc.app_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "vpc_rt"
  }
}


resource "aws_subnet" "subnet_a" {
  vpc_id     = aws_vpc.app_vpc.id
  cidr_block = var.subnet_a_cidr
  availability_zone = "us-west-2a"

  tags = {
    Name = "vpc-subnet-2a"
  }
}

resource "aws_subnet" "subnet_b" {
  vpc_id     = aws_vpc.app_vpc.id
  cidr_block = var.subnet_b_cidr
  availability_zone = "us-west-2b"

  tags = {
    Name = "vpc-subnet-2b"
  }
}