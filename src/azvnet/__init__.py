"""Explicit Azure authentication, checked remote execution, and private-VNet OpenTofu."""

from .auth import AzureSession, AzvnetError, checked, credentials, private_text
from .remote import Remote
from .tofu import Bootstrap, Host, Identity, VnetTofu, variable_values

__all__ = [
    "AzureSession",
    "AzvnetError",
    "Bootstrap",
    "Host",
    "Identity",
    "Remote",
    "VnetTofu",
    "checked",
    "credentials",
    "private_text",
    "variable_values",
]
