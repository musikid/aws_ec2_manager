import typer

from .create_instance import app as create_instance
from .tag_instances import app as tag_instances
from .list_members import app as list_members
from .stop_members import app as stop_members
from .security_group import app as security_group

app = typer.Typer()


app.add_typer(create_instance, name="create-instance", help="Create an EC2 instance.")

app.add_typer(
    tag_instances,
    name="tag-instances",
    help="Create/overwrite a tag for the given instances.",
)

app.add_typer(
    list_members,
    name="list-members",
    help="List base properties of all instances grouped by a tag.",
)

app.add_typer(
    stop_members,
    name="stop-members",
    help="Stop all instances of a group of instances with the same tag.",
)

app.add_typer(
    security_group,
    name="security-group",
    help="""Manage security groups.
        Please note that this is a very basic implementation
        and does not support all features of security groups.
        Besides, only allow rules can be specified with security groups,
        not deny rules.""",
)

app()
