import os
import re
from langchain.tools import BaseTool

from pydantic import SecretStr
from typing import Optional, ClassVar

try:
    from pangea import PangeaConfig
    from pangea.services import DomainIntel
except ImportError as e:
    raise ImportError(
        "Cannot import pangea, please install `pip install pangea-sdk==5.1.0`."
    ) from e


class PangeaDomainGuardError(RuntimeError):
    """
    Exception raised for unexpected scenarios or when malicious IPs are found.
    """
    def __init__(self, message: str) -> None:
        super().__init__(message)

class PangeaDomainIntelGuard(BaseTool):
    """
    Find malicious domains in the input text using the Pangea Domain Intel service.

    Details of the service can be found here:
        [Domain Intel API Reference docs](https://pangea.cloud/docs/api/domain-intel)

    Requirements:
        - Environment variable ``PANGEA_DOMAIN_INTEL_TOKEN`` must be set,
          or passed as a named parameter to the constructor.

    How to use:
        .. code-block:: python
            import os
            from langchain_community.tools.pangea import PangeaDomainIntelGuard, PangeaConfig
            from pydantic import SecretStr

            # Initialize parameters
            token = SecretStr(os.getenv("PANGEA_DOMAIN_INTEL_TOKEN"))
            config = PangeaConfig(domain="aws.us.pangea.cloud")

            # Setup Pangea Domain Intel Tool
            tool = PangeaDomainIntelGuard(token=token, config_id="", config=config)
            tool.run("Please click here to confirm your order:http://737updatesboeing.com/order/123 .  Leave us a feedback here: http://malware123.com/feedback")
    """

    name: str = "pangea-domain-intel-guard-tool"
    """Name of the tool."""

    description: str = "This tool finds malicious domains in the input text using the Pangea Domain Intel service."
    """Description of the tool."""

    _threshold: int = 80
    _domain_pattern: ClassVar[str] = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"

    def __init__(
        self,
        *,
        token: Optional[SecretStr] = None,
        config: PangeaConfig | None = None,
        threshold: int = 80,
        token_env_key_name: str = "PANGEA_DOMAIN_INTEL_TOKEN",
    ) -> None:
        """
        Args:
            token: Pangea API token.
            config: PangeaConfig object.
        """

        if not token:
            token = SecretStr(os.getenv(token_env_key_name, ""))

        if not token or not token.get_secret_value() or token.get_secret_value() == "":
            raise ValueError(f"'{token_env_key_name}' must be set or passed")

        super().__init__()

        self._threshold = threshold
        self._domain_intel_client = DomainIntel(token=token.get_secret_value(), config=config)

    def _run(self, input_text: str) -> str:

        # Find all Domains using the regex pattern
        domains = re.findall(self._domain_pattern, input_text)

        # If no domains found return the original text
        if len(domains) == 0:
            return input_text

        # Check the reputation of each Domain found
        intel = self._domain_intel_client.reputation_bulk(domains)

        if not intel.result:
            raise PangeaDomainGuardError("Result is invalid or missing")

        # Check if the score is higher than the set threshold for any domain
        if any(domain_data.score >= self._threshold for domain_data in intel.result.data.values()):
            raise PangeaDomainGuardError("Malicious domains found in the provided input.")

        # Return unchanged input_text
        return input_text
