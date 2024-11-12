import os
from typing import Optional
from pydantic import SecretStr

from langchain.tools import BaseTool

try:
    from pangea import PangeaConfig
    from pangea.services import Redact
except ImportError as e:
    raise ImportError(
        "Cannot import pangea, please install `pip install pangea-sdk==5.1.0`."
    ) from e


class PangeaRedactGuard(BaseTool):
    """
    This tool guard redacts sensitive information from prompts using the Pangea Redact service.
    Details of the service can be found here:
        [Redact API Reference docs](https://pangea.cloud/docs/api/redact)

    Requirements:
        - Environment variable ``PANGEA_REDACT_TOKEN`` must be set,
          or passed as a named parameter to the constructor.

    How to use:
        .. code-block:: python
            import os
            from langchain_community.tools.pangea.redact_guard import PangeaRedactGuard, PangeaConfig
            from pydantic import SecretStr

            # Initialize parameters
            pangea_token = SecretStr(os.getenv("PANGEA_REDACT_TOKEN"))
            config = PangeaConfig(domain="gcp.us.pangea.cloud")

            # Setup Pangea Redact Tool Guard
            redact_guard = PangeaRedactGuard(pangea_token=pangea_token, config_id="", config=config)

            # Run as a tool for agents
            redact_guard.run("My name is Dennis Nedry and my email is you.didnt.say.the.magic.word@gmail.com")

            # Run as a Runnable for chains
            redact_guard.invoke("My name is Dennis Nedry and my email is you.didnt.say.the.magic.word@gmail.com")
    """

    name: str = "Pangea Redact Tool"
    """Name of the tool."""
    description: str = "This tool redacts sensitive information from prompts using the Pangea Redact service."
    """Description of the tool."""

    def __init__(
        self,
        *,
        pangea_token: Optional[SecretStr] = None,
        config: PangeaConfig | None = None,
        config_id: str | None = None,
        pangea_token_env_key_name: str = "PANGEA_REDACT_TOKEN",
    ) -> None:
        """
        Args:
            pangea_token: Pangea Redact API token.
            config_id: Pangea Redact configuration ID.
            config: PangeaConfig object.
        """

        if not pangea_token:
            pangea_token = SecretStr(os.getenv(pangea_token_env_key_name, ""))

        if not pangea_token or not pangea_token.get_secret_value() or pangea_token.get_secret_value() == "":
            raise ValueError(f"'{pangea_token_env_key_name}' must be set or passed")

        super().__init__()

        self._redact_client = Redact(token=pangea_token.get_secret_value(), config=config, config_id=config_id)

    def _run(self, input_text: str) -> str:
        # Redact the input_text
        redacted = self._redact_client.redact(text=input_text)
        assert redacted.result

        # Return the redacted text or the input_text if no redacted text is found
        return redacted.result.redacted_text or input_text
