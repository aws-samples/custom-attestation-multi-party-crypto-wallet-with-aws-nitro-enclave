#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
import os
import ipaddress
import aws_cdk as cdk
from aws_cdk import (
    Stack,
    Fn,
    Duration,
    CfnOutput,
    RemovalPolicy,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_ecr_assets as ecr_assets,
    aws_autoscaling as autoscaling,
    aws_elasticloadbalancingv2 as elasticloadbalancingv2,
    aws_kms as kms,
    aws_s3_assets as s3_assets,
    aws_dynamodb as ddb,
    aws_ssm as ssm,
    aws_lambda as _lambda,
)
from cdk_nag import NagSuppressions, NagPackSuppression
from constructs import Construct


class NitroWalletStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        params = kwargs.pop("params")
        super().__init__(scope, construct_id, **kwargs)

        application_type = params["application_type"]
        deployment = params["deployment"]

        c9_public_ip = os.getenv("C9_PUBLIC_IP")
        try:
            c9_public_ip_parsed = ipaddress.ip_address(c9_public_ip)
        except ValueError as e:
            print(f"Ensure C9_PUBLIC_IP is set to an valid IPv4 address: {e}")
            exit(1)

        key_shard_table = ddb.Table(
            self,
            "KeyShards",
            table_name=f"{deployment}SSSKeyShards",
            partition_key=ddb.Attribute(
                name="PublicKey", type=ddb.AttributeType.STRING
            ),
            billing_mode=ddb.BillingMode.PROVISIONED,
            removal_policy=RemovalPolicy.DESTROY,
            encryption=ddb.TableEncryption.AWS_MANAGED,
            point_in_time_recovery=True,
        )

        # key to encrypt stored private keys - key rotation can be enabled in this scenario since that the
        # key id is encoded in the cipher text metadata
        encryption_key = kms.Key(self, "EncryptionKey", enable_key_rotation=True)
        encryption_key.apply_removal_policy(cdk.RemovalPolicy.DESTROY)

        app_folder = f"./application/{application_type}"
        outbound_proxy_image = ecr_assets.DockerImageAsset(
            self,
            "gvproxy",
            directory=app_folder,
            platform=ecr_assets.Platform.LINUX_AMD64,
            file="gvproxy/Dockerfile",
            asset_name="gvisor-tap-vsock",
        )

        signing_enclave_image = ecr_assets.DockerImageAsset(
            self,
            "enclave",
            directory=app_folder,
            platform=ecr_assets.Platform.LINUX_AMD64,
            file="enclave/Dockerfile",
            asset_name="enclave",
            build_args={"DEPLOYMENT_ARG": deployment, "REGION_ARG": self.region},
        )

        watchdog = s3_assets.Asset(
            self,
            "AWSNitroEnclaveWatchdog",
            path="./application/{}/watchdog/watchdog.py".format(application_type),
        )

        watchdog_systemd = s3_assets.Asset(
            self,
            "AWSNitroEnclaveWatchdogService",
            path="./application/{}/systemd/enclave-watchdog.service".format(
                application_type
            ),
        )

        imds_systemd = s3_assets.Asset(
            self,
            "AWSNitroEnclaveIMDSService",
            path="./application/{}/systemd/enclave-imds-proxy.service".format(
                application_type
            ),
        )

        vpc = ec2.Vpc(
            self,
            "VPC",
            nat_gateways=1,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="public", subnet_type=ec2.SubnetType.PUBLIC
                ),
                ec2.SubnetConfiguration(
                    name="private", subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
                ),
            ],
            enable_dns_support=True,
            enable_dns_hostnames=True,
        )

        ec2.InterfaceVpcEndpoint(
            self,
            "KMSEndpoint",
            vpc=vpc,
            subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            service=ec2.InterfaceVpcEndpointAwsService.KMS,
            private_dns_enabled=True,
        )

        ec2.InterfaceVpcEndpoint(
            self,
            "SSMEndpoint",
            vpc=vpc,
            subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            service=ec2.InterfaceVpcEndpointAwsService.SSM,
            private_dns_enabled=True,
        )

        ec2.InterfaceVpcEndpoint(
            self,
            "ECREndpoint",
            vpc=vpc,
            subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            service=ec2.InterfaceVpcEndpointAwsService.ECR,
            private_dns_enabled=True,
        )

        vpc.add_gateway_endpoint(
            "DynamoDbEndpoint", service=ec2.GatewayVpcEndpointAwsService.DYNAMODB
        )

        nitro_instance_sg = ec2.SecurityGroup(
            self,
            "NitroInstanceSG",
            vpc=vpc,
            allow_all_outbound=True,
            description="Private SG for NitroWallet EC2 instance",
        )

        # external members (nlb) can run a health check on the EC2 instance 443 port
        nitro_instance_sg.add_ingress_rule(
            ec2.Peer.ipv4(vpc.vpc_cidr_block), ec2.Port.tcp(443)
        )

        # public C9 ip should be able to interact with the REST api
        # todo value_as_string (use env variable or other parameter instead) validate cidr with python /32
        cloud9_ip = f"{c9_public_ip_parsed.compressed}/32"
        nitro_instance_sg.add_ingress_rule(
            ec2.Peer.ipv4(cloud9_ip), ec2.Port.tcp(443)
        )

        # all members of the sg can access each others https ports (443)
        nitro_instance_sg.add_ingress_rule(nitro_instance_sg, ec2.Port.tcp(443))

        # all members of the sg can ping each other
        nitro_instance_sg.add_ingress_rule(nitro_instance_sg, ec2.Port.icmp_ping())

        # AMI
        amzn_linux = ec2.MachineImage.latest_amazon_linux2023()

        # Instance Role and SSM Managed Policy
        role = iam.Role(
            self,
            "InstanceSSM",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
        )
        role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "AmazonSSMManagedInstanceCore"
            )
        )

        # grant EC2 role access to watchdog assets
        watchdog.grant_read(role)
        watchdog_systemd.grant_read(role)

        block_device = ec2.BlockDevice(
            device_name="/dev/xvda",
            volume=ec2.BlockDeviceVolume(
                ebs_device=ec2.EbsDeviceProps(
                    volume_size=32,
                    volume_type=ec2.EbsDeviceVolumeType.GP2,
                    encrypted=True,
                    delete_on_termination=True if deployment == "dev" else False,
                )
            ),
        )

        mappings = {
            "__DEV_MODE__": deployment,
            "__OUTBOUND_PROXY_IMAGE_URI__": outbound_proxy_image.image_uri,
            "__SIGNING_ENCLAVE_IMAGE_URI__": signing_enclave_image.image_uri,
            "__WATCHDOG_S3_URL__": watchdog.s3_object_url,
            "__WATCHDOG_SYSTEMD_S3_URL__": watchdog_systemd.s3_object_url,
            "__IMDS_SYSTEMD_S3_URL__": imds_systemd.s3_object_url,
            "__REGION__": self.region,
        }

        with open("./user_data/user_data.sh") as f:
            user_data_raw = Fn.sub(f.read(), mappings)

        signing_enclave_image.repository.grant_pull(role)
        outbound_proxy_image.repository.grant_pull(role)
        key_shard_table.grant_read_write_data(role)
        encryption_key.grant_encrypt(role)

        nitro_launch_template = ec2.LaunchTemplate(
            self,
            "NitroEC2LauchTemplate",
            instance_type=ec2.InstanceType("m6i.xlarge"),
            user_data=ec2.UserData.custom(user_data_raw),
            nitro_enclave_enabled=True,
            machine_image=amzn_linux,
            block_devices=[block_device],
            role=role,
            security_group=nitro_instance_sg,
        )
        # cdk v2.112.0 (2023-12-01) / security group support
        # curl http://checkip.amazonaws.com
        #  https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-security-groups.html#filter-client-traffic-recommended-rules
        nitro_nlb_sg = ec2.SecurityGroup(
            self,
            "NitroEC2NetworkLoadBalancerSecurityGroup",
            vpc=vpc,
            allow_all_outbound=True,
            disable_inline_rules=True,
            description="Private SG for NitroWallet NLB",
        )
        # todo value_as_string (use env variable or other parameter instead) validate cidr with python /32
        nitro_nlb_sg.add_ingress_rule(nitro_instance_sg, ec2.Port.tcp(443))
        nitro_nlb_sg.add_ingress_rule(ec2.Peer.ipv4(cloud9_ip), ec2.Port.tcp(443))

        nitro_nlb = elasticloadbalancingv2.NetworkLoadBalancer(
            self,
            "NitroEC2NetworkLoadBalancer",
            internet_facing=True,
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PUBLIC
            ),
            security_groups=[nitro_nlb_sg]
        )

        nitro_asg = autoscaling.AutoScalingGroup(
            self,
            "NitroEC2AutoScalingGroup",
            max_capacity=2,
            min_capacity=1,
            desired_capacity=1,
            launch_template=nitro_launch_template,
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
            ),
            update_policy=autoscaling.UpdatePolicy.rolling_update(),
            health_check=autoscaling.HealthCheck.elb(grace=Duration.minutes(5)),
        )

        nitro_target = elasticloadbalancingv2.NetworkTargetGroup(
            self,
            "NitroEC2AutoScalingGroupTarget",
            targets=[nitro_asg],
            protocol=elasticloadbalancingv2.Protocol.TCP,
            port=443,
            vpc=vpc,
        )

        nitro_nlb.add_listener(
            "HTTPSListener",
            port=443,
            protocol=elasticloadbalancingv2.Protocol.TCP,
            default_target_groups=[
                nitro_target
            ],
        )

        # e2e test integration stack just for dev
        if deployment == "test":
            invoke_lambda = _lambda.Function(
                self,
                "NitroInvokeLambda",
                code=_lambda.Code.from_asset(
                    path="application/{}/lambda/NitroInvoke".format(
                        params["application_type"]
                    )
                ),
                handler="lambda_function.lambda_handler",
                runtime=_lambda.Runtime.PYTHON_3_12,
                timeout=Duration.minutes(2),
                memory_size=256,
                environment={
                    "LOG_LEVEL": "DEBUG",
                    "NITRO_INSTANCE_PRIVATE_DNS": nitro_nlb.load_balancer_dns_name,
                },
                vpc=vpc,
                vpc_subnets=ec2.SubnetSelection(
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
                ),
                security_groups=[nitro_instance_sg],
            )

            CfnOutput(
                self,
                "Lambda Function Name",
                value=invoke_lambda.function_name,
                description="Lambda Execution Role ARN",
            )

        CfnOutput(
            self,
            "Nitro Load Balancer Target Group Arn",
            value=nitro_target.target_group_arn,
            description="Nitro Load Balancer Taret Group Arn",
        )

        ssm.StringParameter(
            self,
            "ShardsTableName",
            string_value=key_shard_table.table_name,
            parameter_name=f"/{deployment}/NitroWalletSSS/ShardsTableName",
        )

        ssm.StringParameter(
            self,
            "KMSKeyID",
            string_value=encryption_key.key_id,
            parameter_name=f"/{deployment}/NitroWalletSSS/KMSKeyID",
        )

        # output parameters below are required for manual KMS key resource policy configuration
        CfnOutput(
            self,
            "EC2 Instance Role ARN",
            value=role.role_arn,
            description="EC2 Instance Role ARN",
        )

        CfnOutput(
            self,
            "ASG Group Name",
            value=nitro_asg.auto_scaling_group_name,
            description="ASG Group Name",
        )

        CfnOutput(
            self, "KMS Key ID", value=encryption_key.key_id, description="KMS Key ID"
        )

        CfnOutput(
            self,
            "NLB DNS Address",
            value=nitro_nlb.load_balancer_dns_name,
            description="NLB DNS Address",
        )

        NagSuppressions.add_resource_suppressions(
            construct=self,
            suppressions=[
                NagPackSuppression(
                    id="AwsSolutions-VPC7",
                    reason="No VPC Flow Log required for PoC-grade deployment",
                ),
                NagPackSuppression(
                    id="AwsSolutions-ELB2",
                    reason="No ELB Access Log required for PoC-grade deployment",
                ),
                NagPackSuppression(
                    id="AwsSolutions-IAM5",
                    reason="Permission to read CF stack is restrictive enough",
                ),
                NagPackSuppression(
                    id="AwsSolutions-IAM4",
                    reason="AmazonSSMManagedInstanceCore is a restrictive role",
                ),
                NagPackSuppression(
                    id="AwsSolutions-AS3",
                    reason="No Auto Scaling Group notifications required for PoC-grade deployment",
                ),
                NagPackSuppression(
                    id="AwsSolutions-EC23",
                    reason="Intrinsic functions referenced for cleaner private link creation",
                ),
                NagPackSuppression(
                    id="AwsSolutions-SMG4",
                    reason="Private key cannot be rotated",
                ),
                NagPackSuppression(
                    id="AwsSolutions-APIG2",
                    reason="request validation not required for workshop",
                ),
                NagPackSuppression(
                    id="AwsSolutions-APIG1",
                    reason="API access logs not required for workshop",
                ),
                NagPackSuppression(
                    id="AwsSolutions-COG4",
                    reason="Cognito authentication not required for workshop",
                ),
            ],
            apply_to_children=True,
        )
