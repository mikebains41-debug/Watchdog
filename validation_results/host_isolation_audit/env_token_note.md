# Environment Token Note

printenv reveals CONTAINER_API_KEY and JUPYTER_TOKEN as plaintext
environment variables. These are standard Vast.ai-provisioned
container-scoped access tokens (not confirmed account-wide), used for
authenticating to this instance's Jupyter/portal services. Worth
noting for operational hygiene: these values are now present in
committed git history via the printenv output saved in attempt4.
No evidence these tokens grant access beyond this container instance.
