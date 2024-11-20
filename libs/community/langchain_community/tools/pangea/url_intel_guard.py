import os
import re
from langchain.tools import BaseTool

from pydantic import SecretStr
from typing import Optional, ClassVar

try:
    from pangea import PangeaConfig
    from pangea.services import UrlIntel
except ImportError as e:
    raise ImportError(
        "Cannot import pangea, please install `pip install pangea-sdk==5.1.0`."
    ) from e


class PangeaUrlGuardError(RuntimeError):
    """
    Exception raised for unexpected scenarios or when malicious URLs are found.
    """
    def __init__(self, message: str) -> None:
        super().__init__(message)


class PangeaUrlIntelGuard(BaseTool):
    """
    This tool finds malicious urls in the input text using the Pangea URL Intel service.
    Details of the service can be found here:
        [URL Intel API Reference docs](https://pangea.cloud/docs/api/url-intel)

    Requirements:
        - Environment variable ``PANGEA_URL_INTEL_TOKEN`` must be set,
          or passed as a named parameter to the constructor.

    How to use:
        .. code-block:: python
            import os
            from langchain_community.tools.pangea import PangeaUrlIntelGuard
            from pydantic import SecretStr

            # Initialize parameters
            token = SecretStr(os.getenv("PANGEA_URL_INTEL_TOKEN"))
            config = PangeaConfig(domain="aws.us.pangea.cloud")

            # Setup Pangea Url Intel Tool
            tool = PangeaUrlIntelGuard(token=token, config_id="", config=config)
            tool.run("Please click here to confirm your order:http://113.235.101.11:54384/order/123 .  Leave us a feedback here: http://malware123.com/feedback")
    """

    """Name of the tool."""
    name: str = "pangea-url-intel-guard-tool"

    """Description of the tool."""
    description: str = "This tool finds malicious urls in the input text using the Pangea URL Intel service."

    _threshold: int = 80
    _url_pattern: ClassVar[str] = r"https?://(?:[-\w.]|%[\da-fA-F]{2})+(?::\d+)?(?:/[\w./?%&=-]*)?(?<!\.)"

    def __init__(
        self,
        *,
        token: Optional[SecretStr] = None,
        config: PangeaConfig | None = None,
        threshold: int = 80,
        token_env_key_name: str = "PANGEA_URL_INTEL_TOKEN",
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
        self._url_intel_client = UrlIntel(token=token.get_secret_value(), config=config)

    def _run(self, input_text: str) -> str:

        # Find all URLs using the regex pattern
        urls = re.findall(self._url_pattern, input_text)

        # If no urls found return the original text
        if len(urls) == 0:
            return input_text

        # Check the reputation of each URL found
        intel = self._url_intel_client.reputation_bulk(urls)

        if not intel.result:
            raise PangeaUrlGuardError("Result is invalid or missing")

        # Check if the score is higher than the set threshold for any url
        if any(url_data.score >= self._threshold for url_data in intel.result.data.values()):
            raise PangeaUrlGuardError("Malicious URLs found in the provided input.")

        # Return unchanged input_text
        return input_text
