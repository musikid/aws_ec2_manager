import typer
from rich.table import Table
from rich.console import Console
from botocore.exceptions import ClientError

from typing import Optional, TYPE_CHECKING, cast

from .create_instance import create_instance as create_instance_func
from .group_instances import add_tag_instances
from .list_group_instances import list_group_instances
from .security_group import Operation, OperationType, Chain

app = typer.Typer()


def split_list(value: list[str], sep: str = ",") -> list[list[str]]:
    """Split a list of strings by a separator."""

    return [s.split(sep) for s in value]


@app.command(help="Create a nano instance.")
def create_instance(
    name: str = typer.Option(..., help="Instance name"),
    key: str = typer.Option(..., help="Key name"),
    image_id: str = typer.Option(..., help="AMI ID"),
    subnet_id: str = typer.Option(None, help="Subnet ID"),
    security_group: list[str] = typer.Option([], help="Security Group IDs"),
    instance_type: str = typer.Option("t2.nano", "--type", help="Instance type"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Dry run"),
):
    instance = create_instance_func(
        name,
        key,
        security_group_ids=security_group,
        subnet_id=subnet_id,
        dry_run=dry_run,
        image_id=image_id,
        instance_type=instance_type,
    )
    typer.echo(f"Created instance {name} as {instance.id}", err=True)


@app.command(help="Create/overwrite a tag for the given instances.")
def tag_instances(
    tags: list[str] = typer.Option(
        ...,
        "--tag",
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


@app.command(help="List base properties of all instances grouped by a tag.")
def list_members(
    key: str = typer.Argument(..., help="Tag key"),
    value: Optional[str] = typer.Argument(
        None,
        help="Tag value (can be empty or have wildcards, * or ? respectively for any number of characters or a single character)",
    ),
):
    instances = list_group_instances(key, value or "")

    console = Console()

    if console.is_terminal:
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

    for instance in instances:
        name = next(
            (
                tag.get("Value", None)
                for tag in instance.tags
                if tag.get("Key", None) == "Name"
            ),
            "",
        )
        ins_type = instance.instance_type
        addresses = [
            addr_info["PrivateIpAddress"]
            for iface in instance.network_interfaces
            for addr_info in iface.private_ip_addresses
        ]
        info = (instance.id, name, ins_type, ", ".join(addresses))
        if console.is_terminal:
            table.add_row(*info)
        else:
            typer.echo(" ".join(info))

    if console.is_terminal:
        console.print(table)


@app.command(help="Stop all instances of a group of instances with the same tag.")
def stop_members(
    key: str = typer.Argument(..., help="Tag name"),
    value: str = typer.Argument(
        None, help="Tag value (can be empty or have wildcards)"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Dry run"),
):
    for instance in list_group_instances(key, value or ""):
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


security_group = typer.Typer()
app.add_typer(
    security_group,
    name="security-group",
    help="""Manage security groups.
    Please note that this is a very basic implementation
    and does not support all features of security groups.
    Besides, only allow rules can be specified with security groups,
    not deny rules.""",
)

authorize = typer.Typer()
security_group.add_typer(
    authorize, name="authorize", help="Authorize security group rules."
)


def port_range(value: str) -> tuple[int, int]:
    """Convert a port range string to a tuple of ints."""

    try:
        if "-" not in value:
            value = int(value)
            if not 0 < value < 65535:
                raise typer.BadParameter("Port must be in the range 0-65535")

            return int(value), int(value)

        from_port, to_port = value.split("-")
        from_port, to_port = int(from_port), int(to_port)
        if not 0 < from_port < 65535 or not 0 < to_port < 65535:
            raise typer.BadParameter("Port must be in the range 0-65535")

        return int(from_port), int(to_port)
    except ValueError:
        raise typer.BadParameter(
            "Port range must be in the form of '80-90' or a single port"
        )


@authorize.command("in", help="Authorize ingress security group rules.")
def au_ingress(
    group_id: str = typer.Argument(..., help="Security group ID"),
    port: str = typer.Option(
        ...,
        "--port",
        "-p",
        help="Single port or port range (e.g. 80-90), represents a tuple (type, code) for ICMP",
        callback=port_range,
    ),
    protocol: str = typer.Option(
        ...,
        "--protocol",
        "-P",
        help="Protocol (e.g. tcp, udp, icmp or the protocol number), with -1 for all protocols",
    ),
    ip_range: Optional[list[str]] = typer.Option(
        None, "--ip-range", "-4", help="IP ranges (e.g. 192.168.1.0/24, 10.0.0.1/32)"
    ),
    ipv6_range: Optional[list[str]] = typer.Option(
        None, "--ipv6-range", "-6", help="IPv6 ranges (e.g. 2001:db8:1234:1a00::/56)"
    ),
    prefix_list_id: Optional[list[str]] = typer.Option(
        None, "--prefix-list-id", "-L", help="Prefix list IDs (e.g. pl-12345678)"
    ),
    user_id_group_pair: Optional[list[str]] = typer.Option(
        None,
        "--user-id-group-pair",
        "-G",
        help="Source group IDs or tuples (group ID, user ID) (e.g. sg-12345678 or sg-12345678,123456789012)",
        callback=split_list,
    ),
    tag: Optional[list[str]] = typer.Option(
        None,
        "--tag",
        "-T",
        help="Tag (e.g. --tag key=value)",
        callback=lambda val: split_list(val, "="),
    ),
    dry_run: bool = typer.Option(False, "--dry-run", "-d", help="Dry run"),
):
    if TYPE_CHECKING:
        port: tuple[int, int] = cast(tuple, port)
        user_id_group_pair: list[list[str]] = cast(list, user_id_group_pair)
        tag: list[list[str]] = cast(list, tag)

    from_port, to_port = port

    op = Operation(
        OperationType.AUTHORIZE,
        Chain.INGRESS,
        group_id,
        from_port=from_port,
        to_port=to_port,
        protocol=protocol,
        ip_ranges=ip_range,
        ipv6_ranges=ipv6_range,
        prefix_list_ids=prefix_list_id,
        user_id_group_pairs=user_id_group_pair,
        tags=tag,
    )

    op.execute(dry_run)


@authorize.command("out", help="Authorize egress security group rules.")
def au_egress(
    group_id: str = typer.Argument(..., help="Security group ID"),
    port: str = typer.Option(
        ...,
        "--port",
        "-p",
        help="Single port or port range (e.g. 80-90), represents a tuple (type, code) for ICMP",
        callback=port_range,
    ),
    protocol: str = typer.Option(
        ...,
        "--protocol",
        "-P",
        help="Protocol (e.g. tcp, udp, icmp or the protocol number), with -1 for all protocols",
    ),
    ip_range: Optional[list[str]] = typer.Option(
        None, "--ip-range", "-4", help="IP ranges (e.g. 192.168.1.0/24, 10.0.0.1/32)"
    ),
    ipv6_range: Optional[list[str]] = typer.Option(
        None, "--ipv6-range", "-6", help="IPv6 ranges (e.g. 2001:db8:1234:1a00::/56)"
    ),
    prefix_list_id: Optional[list[str]] = typer.Option(
        None, "--prefix-list-id", "-L", help="Prefix list IDs (e.g. pl-12345678)"
    ),
    user_id_group_pair: Optional[list[str]] = typer.Option(
        None,
        "--user-id-group-pair",
        "-G",
        help="Source group IDs or tuples (group ID, user ID) (e.g. sg-12345678 or sg-12345678,123456789012)",
        callback=split_list,
    ),
    tag: Optional[list[str]] = typer.Option(
        None,
        "--tag",
        "-T",
        help="Tag (e.g. --tag key=value)",
        callback=lambda val: split_list(val, "="),
    ),
    dry_run: bool = typer.Option(False, "--dry-run", "-d", help="Dry run"),
):
    if TYPE_CHECKING:
        port: tuple[int, int] = cast(tuple, port)
        user_id_group_pair: list[list[str]] = cast(list, user_id_group_pair)
        tag: list[list[str]] = cast(list, tag)

    from_port, to_port = port

    op = Operation(
        OperationType.AUTHORIZE,
        Chain.EGRESS,
        group_id,
        from_port=from_port,
        to_port=to_port,
        protocol=protocol,
        ip_ranges=ip_range,
        ipv6_ranges=ipv6_range,
        prefix_list_ids=prefix_list_id,
        user_id_group_pairs=user_id_group_pair,
        tags=tag,
    )

    op.execute(dry_run)


revoke = typer.Typer()
security_group.add_typer(revoke, name="revoke", help="Revoke security group rules.")


@revoke.command("in", help="Revoke ingress security group rules.")
def re_ingress(
    group_id: str = typer.Argument(..., help="Security group ID"),
    port: str = typer.Option(
        ...,
        "--port",
        "-p",
        help="Single port or port range (e.g. 80-90), represents a tuple (type, code) for ICMP",
        callback=port_range,
    ),
    protocol: str = typer.Option(
        ...,
        "--protocol",
        "-P",
        help="Protocol (e.g. tcp, udp, icmp or the protocol number), with -1 for all protocols",
    ),
    ip_range: Optional[list[str]] = typer.Option(
        None, "--ip-range", "-4", help="IP ranges (e.g. 192.168.1.0/24, 10.0.0.1/32)"
    ),
    ipv6_range: Optional[list[str]] = typer.Option(
        None, "--ipv6-range", "-6", help="IPv6 ranges (e.g. 2001:db8:1234:1a00::/56)"
    ),
    prefix_list_id: Optional[list[str]] = typer.Option(
        None, "--prefix-list-id", "-L", help="Prefix list IDs (e.g. pl-12345678)"
    ),
    user_id_group_pair: Optional[list[str]] = typer.Option(
        None,
        "--user-id-group-pair",
        "-G",
        help="Source group IDs or tuples (group ID, user ID) (e.g. sg-12345678 or sg-12345678,123456789012)",
        callback=split_list,
    ),
    dry_run: bool = typer.Option(False, "--dry-run", "-d", help="Dry run"),
):
    if TYPE_CHECKING:
        port: tuple[int, int] = cast(tuple, port)
        user_id_group_pair: list[list[str]] = cast(list, user_id_group_pair)

    from_port, to_port = port

    op = Operation(
        OperationType.REVOKE,
        Chain.INGRESS,
        group_id,
        from_port=from_port,
        to_port=to_port,
        protocol=protocol,
        ip_ranges=ip_range,
        ipv6_ranges=ipv6_range,
        prefix_list_ids=prefix_list_id,
        user_id_group_pairs=user_id_group_pair,
    )

    op.execute(dry_run)


@revoke.command("out", help="Revoke egress security group rules.")
def re_egress(
    group_id: str = typer.Argument(..., help="Security group ID"),
    port: str = typer.Option(
        ...,
        "--port",
        "-p",
        help="Single port or port range (e.g. 80-90), represents a tuple (type, code) for ICMP",
        callback=port_range,
    ),
    protocol: str = typer.Option(
        ...,
        "--protocol",
        "-P",
        help="Protocol (e.g. tcp, udp, icmp or the protocol number), with -1 for all protocols",
    ),
    ip_range: Optional[list[str]] = typer.Option(
        None, "--ip-range", "-4", help="IP ranges (e.g. 192.168.1.0/24, 10.0.0.1/32)"
    ),
    ipv6_range: Optional[list[str]] = typer.Option(
        None, "--ipv6-range", "-6", help="IPv6 ranges (e.g. 2001:db8:1234:1a00::/56)"
    ),
    prefix_list_id: Optional[list[str]] = typer.Option(
        None, "--prefix-list-id", "-L", help="Prefix list IDs (e.g. pl-12345678)"
    ),
    user_id_group_pair: Optional[list[str]] = typer.Option(
        None,
        "--user-id-group-pair",
        "-G",
        help="Source group IDs or tuples (group ID, user ID) (e.g. sg-12345678 or sg-12345678,123456789012)",
        callback=split_list,
    ),
    dry_run: bool = typer.Option(False, "--dry-run", "-d", help="Dry run"),
):
    if TYPE_CHECKING:
        port: tuple[int, int] = cast(tuple, port)
        user_id_group_pair: list[list[str]] = cast(list, user_id_group_pair)

    from_port, to_port = port

    op = Operation(
        OperationType.REVOKE,
        Chain.EGRESS,
        group_id,
        from_port=from_port,
        to_port=to_port,
        protocol=protocol,
        ip_ranges=ip_range,
        ipv6_ranges=ipv6_range,
        prefix_list_ids=prefix_list_id,
        user_id_group_pairs=user_id_group_pair,
    )

    op.execute(dry_run)


app()
