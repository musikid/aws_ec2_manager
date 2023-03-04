import boto3
from mypy_boto3_ec2.service_resource import Instance as EC2Instance

from typing import Iterable, Optional

ec2 = boto3.resource("ec2")


def list_group_instances(key: str, value: str) -> Iterable[EC2Instance]:
    """List all instances in a group."""

    return ec2.instances.filter(Filters=[{"Name": f"tag:{key}", "Values": [value]}])

# CLI

import typer
import json

from rich.console import Console
from rich.table import Table

app = typer.Typer()


@app.callback(
    invoke_without_command=True,
    help="List base properties of all instances grouped by a tag.",
)
def list_members(
    key: str = typer.Argument(..., help="Tag key"),
    value: Optional[str] = typer.Argument(
        None,
        help="Tag value (can be empty or have wildcards, * or ? respectively for any number of characters or a single character)",
    ),
    json_flag: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    instances = list_group_instances(key, value or "")

    console = Console()

    json_output = not console.is_terminal or json_flag

    if not json_output:
        table = (
            Table(
                title=f"Instances tagged with {key} {f'with {value} as value' if value else ''}"
            )
            if console.is_terminal
            else Table.grid(padding=(0, 1), collapse_padding=False)
        )
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="cyan")
        table.add_column("Instance type", style="purple")
        table.add_column("Private IP addresses", style="magenta")
        table.add_column("State")
        table.add_column("Security groups", style="blue")
        table.add_column("Subnet ID", style="yellow")
        table.add_column("VPC ID", style="magenta")
        table.add_column("Tags", style="cyan")
        table.add_column("Launch time", style="green")
        table.add_column("Public IP address", style="blue")
    else:
        output = []

    for instance in instances:
        name = next(
            (
                tag.get("Value", None)
                for tag in instance.tags
                if tag.get("Key", None) == "Name"
            ),
            None,
        )
        security_groups = [sg["GroupId"] for sg in instance.security_groups]
        addresses = [
            addr_info["PrivateIpAddress"]
            for iface in instance.network_interfaces
            for addr_info in iface.private_ip_addresses
        ]

        if not json_output:
            tags = [
                f'{tag["Key"]}={tag["Value"]}'
                for tag in instance.tags
                if "Value" in tag and tag["Key"] != "Name"
            ]
            if instance.state["Name"] == "running":
                state = "[bold green]running[/bold green]"
            else:
                state = f"[bold red]{instance.state['Name']}[/bold red]"

            launch_time = instance.launch_time.strftime("%Y-%m-%d %H:%M:%S")
            public_ip = instance.public_ip_address or "None"

            table.add_row(
                instance.id,
                name or "",
                instance.instance_type,
                ", ".join(addresses),
                state,
                ", ".join(security_groups),
                instance.subnet_id,
                instance.vpc_id,
                ", ".join(tags),
                launch_time,
                public_ip,
            )
        else:
            output.append(
                {
                    "id": instance.id,
                    "name": name,
                    "instance_type": instance.instance_type,
                    "private_ip_addresses": addresses,
                    "state": instance.state["Name"],
                    "security_groups": security_groups,
                    "subnet_id": instance.subnet_id,
                    "vpc_id": instance.vpc_id,
                    "tags": instance.tags,
                    "launch_time": instance.launch_time.isoformat(),
                    "public_ip_address": instance.public_ip_address,
                }
            )

    if not json_output:
        console.print(table)
    else:
        typer.echo(json.dumps(output, indent=4))


if __name__ == "__main__":
    app()
