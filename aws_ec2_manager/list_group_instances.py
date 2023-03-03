import boto3

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Iterable
    from mypy_boto3_ec2.service_resource import Instance as EC2Instance

ec2 = boto3.resource("ec2")


def list_group_instances(key: str, value: str) -> "Iterable[EC2Instance]":
    """List all instances in a group."""

    return ec2.instances.filter(Filters=[{"Name": f"tag:{key}", "Values": [value]}])
