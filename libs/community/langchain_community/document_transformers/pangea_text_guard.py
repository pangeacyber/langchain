import os
from typing import Any, Optional, Sequence
from pydantic import SecretStr

from langchain_core._api import beta
from langchain_core.documents import BaseDocumentTransformer, Document

try:
    from pangea import PangeaConfig
    from pangea.services import AIGuard
except ImportError as e:
    raise ImportError(
        "Cannot import pangea, please install `pip install pangea-sdk==5.2.0b2`."
    ) from e

@beta(message="Pangea AI Guard service is in beta. Subject to change.")
class PangeaGuardTransformer(BaseDocumentTransformer):
    """Guard documents to monitor, sanitize, and protect sensitive data using Pangea's AI Guard service.

    Requirements:
        - Environment variable ``PANGEA_AI_GUARD_TOKEN`` must be set,
          or passed as a named parameter to the constructor.

    Example:
        .. code-block:: python

            from langchain_community.document_transformers.pangea_text_guard import PangeaGuardTransformer, PangeaConfig

            # Initialize parameters
            pangea_token = SecretStr(os.getenv("PANGEA_AI_GUARD_TOKEN"))
            config = PangeaConfig(domain="aws.us.pangea.cloud")
            recipe="pangea_ingestion_guard"

            pangea_guard_transformer = PangeaGuardTransformer(pangea_token=pangea_token, config_id="", config=config, recipe=recipe)
            guarded_documents = pangea_guard_transformer.transform_documents(docs)
    """

    _client: AIGuard
    _recipe: str

    def __init__(
        self,
        pangea_token: Optional[SecretStr] = None,
        config: PangeaConfig | None = None,
        config_id: str | None = None,
        recipe: str = "pangea_ingestion_guard",
        pangea_token_env_key_name: str = "PANGEA_AI_GUARD_TOKEN",
    ) -> None:
        """
        Args:
            pangea_token: Pangea AI Guard API token.
            config_id: Pangea AI Guard configuration ID.
            config: PangeaConfig object.
            recipe: Pangea AI Guard recipe.
            pangea_token_env_key_name: Environment variable key name for Pangea AI Guard token.
        """
                
        if not pangea_token:
            pangea_token = SecretStr(os.getenv(pangea_token_env_key_name, ""))

        if not pangea_token or not pangea_token.get_secret_value() or pangea_token.get_secret_value() == "":
            raise ValueError(f"'{pangea_token_env_key_name}' must be set or passed")
        
        self._recipe = recipe
        self._client = AIGuard(token=pangea_token.get_secret_value(), config=config, config_id=config_id)

    async def atransform_documents(
        self, documents: Sequence[Document], **kwargs: Any
    ) -> Sequence[Document]:
        raise NotImplementedError

    def transform_documents(
        self, documents: Sequence[Document], **kwargs: Any
    ) -> Sequence[Document]:
        """
        Guard documents to monitor, sanitize, and protect sensitive data 
        using Pangea's AI Guard service.
        """ 
        
        guarded_documents = []
        for document in documents:
            guarded = self._client.guard_text(document.page_content, recipe=self._recipe)

            if not guarded.result:
                raise AssertionError(f"Guard operation failed for document: {document}")

            guarded_content = guarded.result.redacted_prompt or document.page_content
            guarded_documents.append(document.model_copy(update={"page_content": guarded_content}))

        return guarded_documents
