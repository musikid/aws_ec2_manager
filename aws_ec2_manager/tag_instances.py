import boto3
from botocore.exceptions import ClientError

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

# CLI

import typer

app = typer.Typer()


def split_list(value: list[str], sep: str = ",") -> list[list[str]]:
    """Split a list of strings by a separator."""

    return [s.split(sep) for s in value]


@app.callback(
    invoke_without_command=True, help="Create/overwrite a tag for the given instances."
)
def tag_instances(
    tags: list[str] = typer.Option(
        ...,
        "--tag",
        "-T",
        help="Tag key-value (e.g. --tag key=value or --tag key)",
        callback=lambda val: split_list(val, "="),
    ),
    instances: list[str] = typer.Argument(..., help="Instance IDs"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Dry run"),
):
    tags = [tag if len(tag) == 2 else [*tag, ""] for tag in tags]

    for key, value in tags:
        try:
            add_tag_instances(key, value, instances, dry_run=dry_run)
            typer.echo(
                f"""Added tag {key} with value {value} for instances {', '.join(instances)}""",
                err=True,
            )
        except ClientError as e:
            if "DryRunOperation" not in str(e):
                raise

            typer.echo(
                f"Applying tag {key} with value {value} to instances {', '.join(instances)} would have succeeded",
                err=True,
            )


if __name__ == "__main__":
    app()
