# DELIBERATELY VULNERABLE - test fixture for the VAPT scanner. Do not apply.
resource "aws_s3_bucket" "uploads" {
  bucket = "vulnerable-app-uploads"
}

resource "aws_s3_bucket_acl" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  acl    = "public-read"
}

resource "aws_security_group" "web" {
  name = "web"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "main" {
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  username            = "app"
  password            = "Sup3rS3cretPassw0rd!"
  publicly_accessible = true
  storage_encrypted   = false
  skip_final_snapshot = true
}
