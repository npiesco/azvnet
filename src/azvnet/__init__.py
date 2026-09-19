"""Explicit Azure authentication, checked remote execution, and private-VNet OpenTofu."""

from .auth import AzureSession, AzvnetError, checked, credentials, non_azure_env, private_text
from .remote import Remote, RemoteExecutionError
from .tofu import Bootstrap, Host, Identity, VnetTofu, tf_var_environment

__all__ = [
    "AzureSession",
    "AzvnetError",
    "Bootstrap",
    "Host",
    "Identity",
    "Remote",
    "RemoteExecutionError",
    "VnetTofu",
    "checked",
    "credentials",
    "private_text",
    "non_azure_env",
    "tf_var_environment",
]
