terraform {
  required_providers {
    aws = {
      version = "~> 4.51.0"
    }
    archive = {
      version = ">= 2.3.0"
    }
  }

  required_version = "~> 1.3.7"
}

data "aws_partition" "current" {}

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

resource "aws_iam_role" "update_ip_ranges" {
  name_prefix = "UpdateIPRanges"
  description = "Managed by update IP ranges Lambda"
  assume_role_policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Effect" : "Allow",
          "Principal" : {
            "Service" : "lambda.amazonaws.com"
          },
          "Action" : "sts:AssumeRole"
        }
      ]
    }
  )

  inline_policy {
    name = "CloudWatchLogsPermissions"

    policy = jsonencode(
      {
        "Version" : "2012-10-17",
        "Statement" : [
          {
            "Effect" : "Allow",
            "Action" : [
              "logs:CreateLogGroup"
            ],
            "Resource" : "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
          },
          {
            "Effect" : "Allow",
            "Action" : [
              "logs:CreateLogStream",
              "logs:PutLogEvents"
            ],
            "Resource" : "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/*LambdaUpdateIPRanges*:*"
          }
        ]
      }
    )
  }

  inline_policy {
    name = "WAFPermissions"

    policy = jsonencode(
      {
        "Version" : "2012-10-17",
        "Statement" : [
          {
            "Effect" : "Allow",
            "Action" : [
              "wafv2:ListIPSets"
            ],
            "Resource" : "*"
          },
          {
            "Effect" : "Allow",
            "Action" : [
              "wafv2:CreateIPSet",
              "wafv2:TagResource"
            ],
            "Resource" : "*",
            "Condition" : {
              "StringEquals" : {
                "aws:RequestTag/UpdatedAt" : "Not yet",
                "aws:RequestTag/ManagedBy" : "update-aws-ip-ranges"
              },
              "StringLike" : {
                "aws:RequestTag/Name" : [
                  "aws-ip-ranges-*-ipv4",
                  "aws-ip-ranges-*-ipv6"
                ]
              },
              "ForAllValues:StringEquals" : {
                "aws:TagKeys" : [
                  "Name",
                  "ManagedBy",
                  "CreatedAt",
                  "UpdatedAt"
                ]
              }
            }
          },
          {
            "Effect" : "Allow",
            "Action" : [
              "wafv2:TagResource"
            ],
            "Resource" : [
              "arn:${data.aws_partition.current.partition}:wafv2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*/ipset/aws-ip-ranges-*-ipv4/*",
              "arn:${data.aws_partition.current.partition}:wafv2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*/ipset/aws-ip-ranges-*-ipv6/*"
            ],
            "Condition" : {
              "StringEquals" : {
                "aws:ResourceTag/ManagedBy" : "update-aws-ip-ranges"
              },
              "StringLike" : {
                "aws:ResourceTag/Name" : [
                  "aws-ip-ranges-*-ipv4",
                  "aws-ip-ranges-*-ipv6"
                ]
              },
              "ForAllValues:StringEquals" : {
                "aws:TagKeys" : [
                  "UpdatedAt"
                ]
              }
            }
          },
          {
            "Effect" : "Allow",
            "Action" : [
              "wafv2:ListTagsForResource",
              "wafv2:GetIPSet",
              "wafv2:UpdateIPSet"
            ],
            "Resource" : [
              "arn:${data.aws_partition.current.partition}:wafv2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*/ipset/aws-ip-ranges-*-ipv4/*",
              "arn:${data.aws_partition.current.partition}:wafv2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*/ipset/aws-ip-ranges-*-ipv6/*"
            ],
            "Condition" : {
              "StringEquals" : {
                "aws:ResourceTag/ManagedBy" : "update-aws-ip-ranges"
              },
              "StringLike" : {
                "aws:ResourceTag/Name" : [
                  "aws-ip-ranges-*-ipv4",
                  "aws-ip-ranges-*-ipv6"
                ]
              }
            }
          }
        ]
      }
    )
  }

  inline_policy {
    name = "EC2Permissions"

    policy = jsonencode(
      {
        "Version" : "2012-10-17",
        "Statement" : [
          {
            "Effect" : "Allow",
            "Action" : [
              "ec2:DescribeTags",
              "ec2:DescribeManagedPrefixLists"
            ],
            "Resource" : "*",
            "Condition" : {
              "StringEquals" : {
                "ec2:Region" : "${data.aws_region.current.name}"
              }
            }
          },
          {
            "Effect" : "Allow",
            "Action" : [
              "ec2:GetManagedPrefixListEntries",
              "ec2:ModifyManagedPrefixList",
              "ec2:CreateTags"
            ],
            "Resource" : "arn:${data.aws_partition.current.partition}:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:prefix-list/*",
            "Condition" : {
              "StringEquals" : {
                "aws:ResourceTag/ManagedBy" : "update-aws-ip-ranges",
                "ec2:Region" : "${data.aws_region.current.name}"
              },
              "StringLike" : {
                "aws:ResourceTag/Name" : [
                  "aws-ip-ranges-*-ipv4",
                  "aws-ip-ranges-*-ipv6"
                ]
              }
            }
          },
          {
            "Effect" : "Allow",
            "Action" : [
              "ec2:CreateManagedPrefixList"
            ],
            "Resource" : "arn:${data.aws_partition.current.partition}:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:prefix-list/*",
            "Condition" : {
              "StringEquals" : {
                "aws:RequestTag/UpdatedAt" : "Not yet",
                "aws:RequestTag/ManagedBy" : "update-aws-ip-ranges",
                "ec2:Region" : "${data.aws_region.current.name}"
              },
              "StringLike" : {
                "aws:RequestTag/Name" : [
                  "aws-ip-ranges-*-ipv4",
                  "aws-ip-ranges-*-ipv6"
                ]
              },
              "ForAllValues:StringEquals" : {
                "aws:TagKeys" : [
                  "Name",
                  "ManagedBy",
                  "CreatedAt",
                  "UpdatedAt"
                ]
              }
            }
          },
          {
            "Effect" : "Allow",
            "Action" : [
              "ec2:CreateTags"
            ],
            "Resource" : "arn:${data.aws_partition.current.partition}:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:prefix-list/*",
            "Condition" : {
              "StringEquals" : {
                "ec2:Region" : "${data.aws_region.current.name}",
                "ec2:CreateAction" : "CreateManagedPrefixList"
              }
            }
          }
        ]
      }
    )
  }
}

# Zip lambda source code.
data "archive_file" "lambda_source" {
  type = "zip"
  #source_dir  = var.src_path
  output_path = "/tmp/update_aws_ip_ranges.zip"

  source {
    filename = "update_aws_ip_ranges.py"
    content  = file("../lambda/update_aws_ip_ranges.py")
  }

  source {
    filename = "services.json"
    content  = file("../lambda/services.json")
  }
}
resource "aws_lambda_function" "update_ip_ranges" {
  # checkov:skip=CKV_AWS_50:X-ray tracing not required
  # checkov:skip=CKV_AWS_116:Code log errors on CloudWatch logs
  # checkov:skip=CKV_AWS_117:Not required to run inside a VPC
  # checkov:skip=CKV_AWS_173:Variable is not sensitive
  # checkov:skip=CKV_AWS_272:Code signer not required

  filename                       = data.archive_file.lambda_source.output_path
  source_code_hash               = filebase64sha256(data.archive_file.lambda_source.output_path)
  function_name                  = "UpdateIPRanges"
  description                    = "This Lambda function, invoked by an incoming SNS message, updates the IPv4 and IPv6 ranges with the addresses from the specified services"
  role                           = aws_iam_role.update_ip_ranges.arn
  handler                        = "update_aws_ip_ranges.lambda_handler"
  runtime                        = "python3.12"
  timeout                        = 300
  reserved_concurrent_executions = 2
  memory_size                    = 256
  architectures                  = ["arm64"]

  environment {
    variables = {
      LOG_LEVEL = "INFO"
    }
  }
}

resource "aws_lambda_permission" "amazon_ip_space_changed" {
  statement_id   = "AllowExecutionFromSNS"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.update_ip_ranges.function_name
  principal      = "sns.amazonaws.com"
  source_arn     = "arn:aws:sns:us-east-1:806199016981:AmazonIpSpaceChanged"
  source_account = "806199016981"
}

# provider to manage SNS topics
provider "aws" {
  alias  = "sns"
  region = "us-east-1"
}
resource "aws_sns_topic_subscription" "amazon_ip_space_changed" {
  provider  = aws.sns
  topic_arn = "arn:aws:sns:us-east-1:806199016981:AmazonIpSpaceChanged"
  protocol  = "lambda"
  endpoint  = aws_lambda_function.update_ip_ranges.arn
}

output "lambda_name" {
  value = aws_lambda_function.update_ip_ranges.function_name
}