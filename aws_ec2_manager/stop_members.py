from aws_ec2_manager import list_members

from botocore.exceptions import ClientError
import typer


app = typer.Typer()


@app.callback(
    invoke_without_command=True,
    help="Stop all instances of a group of instances with the same tag.",
)
def stop_members(
    key: str = typer.Argument(..., help="Tag name"),
    value: str = typer.Argument(
        None, help="Tag value (can be empty or have wildcards)"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Dry run"),
):
    for instance in list_members.list_group_instances(key, value or ""):
        try:
            if instance.state["Name"] == "stopped":
                typer.echo(f"Instance {instance.id} is already stopped", err=True)
                continue

            typer.echo(f"Stopping instance {instance.id}", err=True)
            instance.stop(DryRun=dry_run)
        except ClientError as e:
            if "DryRunOperation" in str(e):
                typer.echo(f"Would have stopped instance {instance.id}", err=True)
                continue

            raise


if __name__ == "__main__":
    app()
