"""
app/core/providers/azure.py
"""

def credential(credentials: dict):
    from azure.identity import ClientSecretCredential, DefaultAzureCredential
    if all(credentials.get(k) for k in ("tenant_id", "client_id", "client_secret")):
        return ClientSecretCredential(
            tenant_id=credentials["tenant_id"],
            client_id=credentials["client_id"],
            client_secret=credentials["client_secret"],
        )
    return DefaultAzureCredential()


def get_client(client_class, credentials: dict, **kwargs):
    cred = credential(credentials)
    sub  = credentials.get("subscription_id", "")
    return client_class(cred, sub, **kwargs)


def graph_token(credentials: dict) -> str:
    return credential(credentials).get_token("https://graph.microsoft.com/.default").token


def mgmt_token(credentials: dict) -> str:
    return credential(credentials).get_token("https://management.azure.com/.default").token
