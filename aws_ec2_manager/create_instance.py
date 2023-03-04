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


# CLI

import typer

app = typer.Typer()


@app.callback(invoke_without_command=True, help="Create an EC2 instance.")
def main(
    name: str = typer.Option(..., help="Instance name"),
    key: str = typer.Option(..., help="Key name"),
    image_id: str = typer.Option(..., help="AMI ID"),
    subnet_id: str = typer.Option(None, help="Subnet ID"),
    security_group: list[str] = typer.Option([], help="Security Group IDs"),
    instance_type: str = typer.Option("t2.nano", "--type", help="Instance type"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Dry run"),
):
    instance = create_instance(
        name,
        key,
        security_group_ids=security_group,
        subnet_id=subnet_id,
        dry_run=dry_run,
        image_id=image_id,
        instance_type=instance_type,
    )
    typer.echo(f"Created instance {name} as {instance.id}", err=True)


if __name__ == "__main__":
    app()
