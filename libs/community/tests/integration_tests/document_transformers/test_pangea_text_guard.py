"""Integration test Pangea AI Guard transformer."""

import os
from pydantic import SecretStr

from langchain_core.documents import Document
from langchain_community.document_transformers.pangea_text_guard import PangeaGuardTransformer, PangeaConfig

try:
    from pangea.tools import (
        TestEnvironment,
        get_test_domain,
        get_test_token,
    )
except ImportError as e:
    raise ImportError(
        "Cannot import pangea, please install `pip install pangea-sdk==5.2.0b2`."
    ) from e

def test_pangea_text_guard() -> None:
    texts = [
        "John Doe logged into the system from IP address 192.168.1.101.",
        "The server located in Frankfurt, Germany is currently offline.",
        "Alice's recent login was traced to IP 10.0.0.45.",
        "My credit card number is 5555555555554444.",
        "The headquarters are located at 1234 Elm Street, Springfield, USA.",
    ]

    docs = [Document(page_content=t) for t in texts]

    # Initialize parameters
    env = TestEnvironment.DEVELOP
    config = PangeaConfig(domain=get_test_domain(env))
    recipe="pangea_ingestion_guard"

    pangea_guard_transformer = PangeaGuardTransformer(token=SecretStr(get_test_token(env)), config=config, recipe=recipe)
    guarded_documents = pangea_guard_transformer.transform_documents(docs)

    assert len(guarded_documents) == 5
    assert guarded_documents[0].page_content == "<PERSON> logged into the system from IP address 192.168.1.101."
    assert guarded_documents[1].page_content == "The server located in <LOCATION>, <LOCATION> is currently offline."
    assert guarded_documents[2].page_content == "<PERSON>'s recent login was traced to IP 10.0.0.45."
    assert guarded_documents[3].page_content == "My credit card number is ****************."
    assert guarded_documents[4].page_content == "The headquarters are located at 1234 Elm Street, <LOCATION>, <LOCATION>."
