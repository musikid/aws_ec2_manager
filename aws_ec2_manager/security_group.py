import boto3
from mypy_boto3_ec2.type_defs import (
    IpPermissionTypeDef,
    UserIdGroupPairTypeDef,
    IpRangeTypeDef,
    Ipv6RangeTypeDef,
    PrefixListIdTypeDef,
    TagSpecificationTypeDef,
)
from mypy_boto3_ec2.service_resource import SecurityGroup

from enum import Enum, auto
from typing import Optional, NewType, TYPE_CHECKING, cast


ec2 = boto3.resource("ec2")


class OperationType(Enum):
    REVOKE = auto()
    AUTHORIZE = auto()


class Chain(Enum):
    INGRESS = auto()
    EGRESS = auto()


GroupId = NewType("GroupId", str)
GroupName = NewType("GroupName", str)


class Operation:
    """Represents an operation on a security group."""

    operation: OperationType
    """Operation type (authorize or revoke)"""

    chain: Chain
    """Chain (ingress or egress)"""

    group: SecurityGroup
    """Security group"""

    rule: IpPermissionTypeDef
    """Rule to apply"""

    tags: list[tuple[str, str]]
    """Tags to apply (only for authorize)"""

    def __init__(
        self,
        operation: OperationType,
        chain: Chain,
        group_id: str,
        protocol: str,
        from_port: int,
        to_port: int,
        ip_ranges: Optional[list[str]] = None,
        ipv6_ranges: Optional[list[str]] = None,
        prefix_list_ids: Optional[list[str]] = None,
        user_id_group_pairs: Optional[list[list[str]]] = None,
        tags: Optional[list[list[str]]] = None,
    ):
        """Represents an operation on a security group.

        Parameters:
        -----------
        :param operation: Operation type (authorize or revoke)
        :param chain: Chain (ingress or egress)
        :param group_id: Security group ID (e.g. sg-12345678)
        :param protocol: Protocol (e.g. tcp, udp, icmp, -1)
        :param from_port: Port range start (or ICMP type)
        :param to_port: Port range end (or ICMP code)
        :param ip_ranges: IP CIDR ranges (e.g. 192.168.1.0/24, 10.0.0.1/32)
        :param ipv6_ranges: IPv6 CIDR ranges (e.g. 2001:db8:1234:1a00::/56)
        :param prefix_list_ids: Prefix list IDs (e.g. pl-12345678)
        :param user_id_group_pairs: Group IDs or tuples of (group ID, user ID)"""

        self.operation = operation
        self.chain = chain
        self.group = ec2.SecurityGroup(group_id)

        self.rule = IpPermissionTypeDef(
            FromPort=from_port,
            IpProtocol=protocol,
            IpRanges=[
                IpRangeTypeDef(CidrIp=ip, Description="") for ip in ip_ranges or []
            ],
            Ipv6Ranges=[
                Ipv6RangeTypeDef(CidrIpv6=ip, Description="")
                for ip in ipv6_ranges or []
            ],
            PrefixListIds=[
                PrefixListIdTypeDef(PrefixListId=prefix_list, Description="")
                for prefix_list in prefix_list_ids or []
            ],
            ToPort=to_port,
            UserIdGroupPairs=[
                UserIdGroupPairTypeDef(GroupId=pair[0])
                if len(pair) == 1
                else UserIdGroupPairTypeDef(GroupId=pair[0], UserId=pair[1])
                for pair in user_id_group_pairs or []
            ],
        )

        self.tags = tags or []

    def execute(self, dry_run: bool = True):
        """Execute the operation."""
        if self.chain == Chain.INGRESS:
            if self.operation == OperationType.REVOKE:
                self.group.revoke_ingress(IpPermissions=[self.rule], DryRun=dry_run)
            elif self.operation == OperationType.AUTHORIZE:
                self.group.authorize_ingress(
                    IpPermissions=[self.rule],
                    TagSpecifications=[
                        TagSpecificationTypeDef(
                            ResourceType="security-group-rule",
                            Tags=[{"Key": k, "Value": v} for k, v in self.tags],
                        )
                    ]
                    if self.tags
                    else [],
                    DryRun=dry_run,
                )
        elif self.chain == Chain.EGRESS:
            if self.operation == OperationType.REVOKE:
                self.group.revoke_egress(IpPermissions=[self.rule], DryRun=dry_run)
            elif self.operation == OperationType.AUTHORIZE:
                self.group.authorize_egress(
                    IpPermissions=[self.rule],
                    TagSpecifications=[
                        TagSpecificationTypeDef(
                            ResourceType="security-group-rule",
                            Tags=[{"Key": k, "Value": v} for k, v in self.tags],
                        )
                    ]
                    if self.tags
                    else [],
                    DryRun=dry_run,
                )


# CLI

import typer


app = typer.Typer()

authorize = typer.Typer()
app.add_typer(authorize, name="authorize", help="Authorize security group rules.")

revoke = typer.Typer()
app.add_typer(revoke, name="revoke", help="Revoke security group rules.")


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


def split_list(value: list[str], sep: str = ",") -> list[list[str]]:
    """Split a list of strings by a separator."""

    return [s.split(sep) for s in value]


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


if __name__ == "__main__":
    app()
