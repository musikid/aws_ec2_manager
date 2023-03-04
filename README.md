# AWS EC2 Manager

> A simple tool to manage AWS EC2 instances from the command line.

## Installation

```bash
pip install aws_ec2_manager-23.3.3-py3-none-any.whl
```

## Usage

### Instances management

#### Create instances

To create a new instance, the subcommand `create-instance` should be used:

```bash
aws_ec2_manager create-instance --name my-instance --image ami-0c2b8ca1dad447f8a \
    --type t2.micro --key my-key --security-group my-security-group --region us-east-1
```

#### Tag instances

To create a group of instances, you can use the `tag-instances` subcommand,
which allows to add tags to instances:

```bash
aws_ec2_manager tag-instances --tag=Group=my-group --tag NoValue my-instance-1 my-instance-2
```

#### List group instances

To list the instances with a common tag, run the following command:

```bash
aws_ec2_manager list-members Group my-group

aws_ec2_manager list-members --json NoValue
```

#### Stop instances

To stop the instances of a group, run the following command:

```bash
aws_ec2_manager stop-members Group my-group
```

### Security group rules management

#### Authorize rule

To authorize a rule in a security group,
the subcommand `authorize` is used, combined with the chain `in` or `out`,
depending on the direction of the rule, for example to authorize SSH access to the instances
from a range of IP addresses:

```bash
aws_ec2_manager authorize in --group my-security-group --port 22 --protocol tcp \
    --ip-range 10.0.0.0/16 --ip-range 1.0.0.0/8
```

Or to authorize HTTP access to the instances of another security group:

```bash
aws_ec2_manager authorize out --group my-security-group --port 80 \
    --protocol tcp --user-id-group-pair my-other-security-group
```

#### Revoke rule

Please note that security groups are allow-lists, so there is no need to
add rules to deny access by default.

To revoke an existing rule in a security group,
the subcommand `revoke` is used, combined with the chain `in` or `out`,
depending on the direction of the rule, for example to revoke SSH access to the instances:

```bash
aws_ec2_manager revoke in --group my-security-group --port 22 --protocol tcp \
    --ip-range 10.0.0.0/16 --ip-range 1.0.0.0/8
```

Or to revoke HTTP access to the instances of another security group:

```bash
aws_ec2_manager revoke out --group my-security-group --port 80 \
    --protocol tcp --user-id-group-pair my-other-security-group
```

### Help

```sh
$ aws_ec2_manager security-group authorize in --help

 Usage: aws_ec2_manager security-group authorize in [OPTIONS] GROUP_ID

 Authorize ingress security group rules.

╭─ Arguments ────────────────────────────────────────────────────────────────────────────╮
│ *    group_id      TEXT  Security group ID [default: None] [required]                  │
╰────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ──────────────────────────────────────────────────────────────────────────────╮
│ *  --port                -p      TEXT  Single port or port range (e.g. 80-90),         │
│                                        represents a tuple (type, code) for ICMP        │
│                                        [default: None]                                 │
│                                        [required]                                      │
│ *  --protocol            -P      TEXT  Protocol (e.g. tcp, udp, icmp or the protocol   │
│                                        number), with -1 for all protocols              │
│                                        [default: None]                                 │
│                                        [required]                                      │
│    --ip-range            -4      TEXT  IP ranges (e.g. 192.168.1.0/24, 10.0.0.1/32)    │
│                                        [default: None]                                 │
│    --ipv6-range          -6      TEXT  IPv6 ranges (e.g. 2001:db8:1234:1a00::/56)      │
│                                        [default: None]                                 │
│    --prefix-list-id      -L      TEXT  Prefix list IDs (e.g. pl-12345678)              │
│                                        [default: None]                                 │
│    --user-id-group-pair  -G      TEXT  Source group IDs or tuples (group ID, user ID)  │
│                                        (e.g. sg-12345678 or sg-12345678,123456789012)  │
│                                        [default: None]                                 │
│    --tag                 -T      TEXT  Tag (e.g. --tag key=value) [default: None]      │
│    --dry-run             -d            Dry run                                         │
│    --help                              Show this message and exit.                     │
╰────────────────────────────────────────────────────────────────────────────────────────╯
```

```sh
$ aws_ec2_manager security-group authorize out --help

 Usage: aws_ec2_manager security-group authorize out [OPTIONS] GROUP_ID

 Authorize egress security group rules.

╭─ Arguments ────────────────────────────────────────────────────────────────────────────╮
│ *    group_id      TEXT  Security group ID [default: None] [required]                  │
╰────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ──────────────────────────────────────────────────────────────────────────────╮
│ *  --port                -p      TEXT  Single port or port range (e.g. 80-90),         │
│                                        represents a tuple (type, code) for ICMP        │
│                                        [default: None]                                 │
│                                        [required]                                      │
│ *  --protocol            -P      TEXT  Protocol (e.g. tcp, udp, icmp or the protocol   │
│                                        number), with -1 for all protocols              │
│                                        [default: None]                                 │
│                                        [required]                                      │
│    --ip-range            -4      TEXT  IP ranges (e.g. 192.168.1.0/24, 10.0.0.1/32)    │
│                                        [default: None]                                 │
│    --ipv6-range          -6      TEXT  IPv6 ranges (e.g. 2001:db8:1234:1a00::/56)      │
│                                        [default: None]                                 │
│    --prefix-list-id      -L      TEXT  Prefix list IDs (e.g. pl-12345678)              │
│                                        [default: None]                                 │
│    --user-id-group-pair  -G      TEXT  Source group IDs or tuples (group ID, user ID)  │
│                                        (e.g. sg-12345678 or sg-12345678,123456789012)  │
│                                        [default: None]                                 │
│    --tag                 -T      TEXT  Tag (e.g. --tag key=value) [default: None]      │
│    --dry-run             -d            Dry run                                         │
│    --help                              Show this message and exit.                     │
╰────────────────────────────────────────────────────────────────────────────────────────╯
```

```sh
$ aws_ec2_manager security-group revoke in --help

 Usage: aws_ec2_manager security-group revoke in [OPTIONS] GROUP_ID

 Revoke ingress security group rules.

╭─ Arguments ────────────────────────────────────────────────────────────────────────────╮
│ *    group_id      TEXT  Security group ID [default: None] [required]                  │
╰────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ──────────────────────────────────────────────────────────────────────────────╮
│ *  --port                -p      TEXT  Single port or port range (e.g. 80-90),         │
│                                        represents a tuple (type, code) for ICMP        │
│                                        [default: None]                                 │
│                                        [required]                                      │
│ *  --protocol            -P      TEXT  Protocol (e.g. tcp, udp, icmp or the protocol   │
│                                        number), with -1 for all protocols              │
│                                        [default: None]                                 │
│                                        [required]                                      │
│    --ip-range            -4      TEXT  IP ranges (e.g. 192.168.1.0/24, 10.0.0.1/32)    │
│                                        [default: None]                                 │
│    --ipv6-range          -6      TEXT  IPv6 ranges (e.g. 2001:db8:1234:1a00::/56)      │
│                                        [default: None]                                 │
│    --prefix-list-id      -L      TEXT  Prefix list IDs (e.g. pl-12345678)              │
│                                        [default: None]                                 │
│    --user-id-group-pair  -G      TEXT  Source group IDs or tuples (group ID, user ID)  │
│                                        (e.g. sg-12345678 or sg-12345678,123456789012)  │
│                                        [default: None]                                 │
│    --dry-run             -d            Dry run                                         │
│    --help                              Show this message and exit.                     │
╰────────────────────────────────────────────────────────────────────────────────────────╯
```

```sh
$ aws_ec2_manager security-group revoke out --help

 Usage: aws_ec2_manager security-group revoke out [OPTIONS] GROUP_ID

 Revoke egress security group rules.

╭─ Arguments ────────────────────────────────────────────────────────────────────────────╮
│ *    group_id      TEXT  Security group ID [default: None] [required]                  │
╰────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ──────────────────────────────────────────────────────────────────────────────╮
│ *  --port                -p      TEXT  Single port or port range (e.g. 80-90),         │
│                                        represents a tuple (type, code) for ICMP        │
│                                        [default: None]                                 │
│                                        [required]                                      │
│ *  --protocol            -P      TEXT  Protocol (e.g. tcp, udp, icmp or the protocol   │
│                                        number), with -1 for all protocols              │
│                                        [default: None]                                 │
│                                        [required]                                      │
│    --ip-range            -4      TEXT  IP ranges (e.g. 192.168.1.0/24, 10.0.0.1/32)    │
│                                        [default: None]                                 │
│    --ipv6-range          -6      TEXT  IPv6 ranges (e.g. 2001:db8:1234:1a00::/56)      │
│                                        [default: None]                                 │
│    --prefix-list-id      -L      TEXT  Prefix list IDs (e.g. pl-12345678)              │
│                                        [default: None]                                 │
│    --user-id-group-pair  -G      TEXT  Source group IDs or tuples (group ID, user ID)  │
│                                        (e.g. sg-12345678 or sg-12345678,123456789012)  │
│                                        [default: None]                                 │
│    --dry-run             -d            Dry run                                         │
│    --help                              Show this message and exit.                     │
╰────────────────────────────────────────────────────────────────────────────────────────╯
```
