import boto3

ec2 = boto3.resource("ec2")


def add_tag_instances(
    tag_name: str,
    tag_value: str,
    instance_ids: list[str],
    dry_run: bool = True,
) -> None:
    """Create/overwrite a group tag for the given instances."""

    return ec2.create_tags(
        Resources=instance_ids,
        Tags=[{"Key": tag_name, "Value": tag_value}],
        DryRun=dry_run,
    )
