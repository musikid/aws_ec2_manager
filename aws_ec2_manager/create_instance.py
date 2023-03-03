import boto3
from mypy_boto3_ec2.service_resource import Instance as EC2Instance

from typing import Optional


ec2 = boto3.resource("ec2")


def create_instance(
    name: str,
    key_name: str,
    image_id: str,
    subnet_id: Optional[str] = None,
    security_group_ids: Optional[list[str]] = None,
    dry_run: bool = True,
    instance_type: str = "t2.nano",
) -> EC2Instance:
    """Create an instance with the given name, type, key name, image id,
    subnet id and security group ids."""

    return ec2.create_instances(
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}
        ],
        InstanceType=instance_type,
        SecurityGroupIds=security_group_ids or [],
        ImageId=image_id,
        SubnetId=subnet_id or "",
        KeyName=key_name,
        DryRun=dry_run,
        MinCount=1,
        MaxCount=1,
    )[0]
