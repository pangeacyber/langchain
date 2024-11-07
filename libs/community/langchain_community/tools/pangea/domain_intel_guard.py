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
        "Cannot import pangea, please install `pip install pangea-sdk==5.2.0b2`."
    ) from e


class MaliciousDomainsError(RuntimeError):
    """
    MaliciousDomainsError is a exception raised when malicious domains are found in the input text.
    """
    def __init__(self, message: str) -> None:
        super().__init__(message)

class PangeaDomainIntelGuard(BaseTool):
    """
    This tool guard finds malicious domains in the input text using the Pangea Domain Intel service.
    Details of the service can be found here:
        [Domain Intel API Reference docs](https://pangea.cloud/docs/api/domain-intel)

    Requirements:
        - Environment variable ``PANGEA_DOMAIN_INTEL_TOKEN`` must be set,
          or passed as a named parameter to the constructor.

    How to use:
        import os
        from langchain_community.tools.pangea import PangeaDomainIntelGuard, PangeaConfig
        from pydantic import SecretStr

        # Initialize parameters
        pangea_token = SecretStr(os.getenv("PANGEA_DOMAIN_INTEL_TOKEN"))
        config = PangeaConfig(domain="dev.aws.pangea.cloud")

        # Setup Pangea Domain Intel Tool
        tool = PangeaDomainIntelGuard(pangea_token=pangea_token, config_id="", config=config)
        tool.run("Please click here to confirm your order:http://737updatesboeing.com/order/123 .  Leave us a feedback here: http://malware123.com/feedback")
    """

    name: str = "Pangea Domain Intel Tool"
    """Name of the tool."""
    description: str = "This tool finds malicious domains in the input text using the Pangea Domain Intel service."
    """Description of the tool."""

    _threshold: int = 80
    _domain_pattern: ClassVar[str] = r"https?://(?:www\.)?([a-zA-Z0-9.-]+)(?::\d+)?"

    def __init__(
        self,
        *,
        pangea_token: Optional[SecretStr] = None,
        config: PangeaConfig | None = None,
        threshold: int = 80,
        pangea_token_env_key_name: str = "PANGEA_DOMAIN_INTEL_TOKEN",
    ) -> None:
        """
        Args:
            pangea_token: Pangea API token.
            config: PangeaConfig object.
        """
        # add an option to get the token from vautl
        # an insecure way is to pass is thro env variable...
        if not pangea_token:
            pangea_token = SecretStr(os.getenv(pangea_token_env_key_name, ""))

        if not pangea_token or not pangea_token.get_secret_value() or pangea_token.get_secret_value() == "":
            raise ValueError(f"'{pangea_token_env_key_name}' must be or set or passed")

        super().__init__()

        self._threshold = threshold
        self._domain_intel_client = DomainIntel(token=pangea_token.get_secret_value(), config=config)

    def _run(self, input_text: str) -> str:

        # Find all Domains using the regex pattern
        domains = re.findall(self._domain_pattern, input_text)
        
        # If no domains found return the original text
        if len(domains) == 0:
            return input_text

        # Check the reputation of each Domain found
        intel = self._domain_intel_client.reputation_bulk(domains)
        assert intel.result

        # Check if the score is higher than the set threshold for any domain
        if any(domain_data.score >= self._threshold for domain_data in intel.result.data.values()):
            raise MaliciousDomainsError("Malicious domains found in the provided input")

        # Return unchanged input_text
        return input_text
