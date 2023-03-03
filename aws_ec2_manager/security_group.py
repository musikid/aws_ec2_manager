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
from typing import Optional, NewType


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
